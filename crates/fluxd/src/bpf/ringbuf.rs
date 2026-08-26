//! Minimal `BPF_MAP_TYPE_RINGBUF` consumer.

use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use flux_core::abi::FaultEvent;

const HEADER_BYTES: usize = 8;
const BUSY_BIT: u32 = 1 << 31;
const DISCARD_BIT: u32 = 1 << 30;
const LENGTH_MASK: u32 = !(BUSY_BIT | DISCARD_BIT);

struct Mapping {
    base: NonNull<u8>,
    len: usize,
}

impl Mapping {
    fn new(
        fd: RawFd,
        len: usize,
        protection: libc::c_int,
        offset: libc::off_t,
    ) -> io::Result<Self> {
        // SAFETY: the kernel validates the ring-buffer fd, length and offset;
        // the returned region is retained until `Drop` calls `munmap`.
        let base = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                protection,
                libc::MAP_SHARED,
                fd,
                offset,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            base: NonNull::new(base.cast()).expect("mmap cannot return null on success"),
            len,
        })
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: this is the exact address and length returned by `mmap`.
        let result = unsafe { libc::munmap(self.base.as_ptr().cast(), self.len) };
        debug_assert_eq!(result, 0);
    }
}

/// An epoll-able view of the `fault_events` map.
pub struct RingBuffer {
    fd: OwnedFd,
    consumer: Mapping,
    producer: Mapping,
    capacity: usize,
}

impl RingBuffer {
    pub fn open(map_fd: RawFd, capacity: usize) -> io::Result<Self> {
        let page_size = page_size()?;
        if capacity == 0
            || !capacity.is_power_of_two()
            || !capacity.is_multiple_of(page_size)
            || capacity > isize::MAX as usize / 2
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ring-buffer capacity must be a non-zero page-aligned power of two",
            ));
        }

        // A duplicate keeps the epoll source alive independently of Runtime.
        // SAFETY: `fcntl` returns a new descriptor on success.
        let duplicate = unsafe { libc::fcntl(map_fd, libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the successful fcntl call transferred a new owned fd.
        let fd = unsafe { OwnedFd::from_raw_fd(duplicate) };

        let consumer = Mapping::new(
            fd.as_raw_fd(),
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            0,
        )?;
        let producer_len = page_size
            .checked_add(capacity.checked_mul(2).expect("capacity checked above"))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "mapping too large"))?;
        let producer = Mapping::new(
            fd.as_raw_fd(),
            producer_len,
            libc::PROT_READ,
            page_size as libc::off_t,
        )?;

        Ok(Self {
            fd,
            consumer,
            producer,
            capacity,
        })
    }

    /// Drains all complete records currently published by the kernel.
    pub fn drain_faults(&mut self) -> io::Result<Vec<FaultEvent>> {
        let consumer_position = self.consumer.base.as_ptr().cast::<AtomicU64>();
        let producer_position = self.producer.base.as_ptr().cast::<AtomicU64>();
        // SAFETY: both position pages are page-aligned and hold kernel u64s.
        let mut consumer = unsafe { &*consumer_position }.load(Ordering::Acquire);
        // SAFETY: the producer position page is page-aligned and holds a
        // kernel u64. Acquire pairs with the kernel's release publication.
        let producer = unsafe { &*producer_position }.load(Ordering::Acquire);

        let page_size = page_size()?;
        // SAFETY: the producer mapping contains its position page followed by
        // two virtual copies of the ring data.
        let data = unsafe { self.producer.base.as_ptr().add(page_size) };
        let mut events = Vec::new();
        while consumer < producer {
            let offset = (consumer as usize) & (self.capacity - 1);
            // The ring data is mapped twice, so a record wrapping the logical
            // end remains contiguous in this virtual range.
            // SAFETY: offset is masked below capacity, inside the first copy.
            let header = unsafe { data.add(offset) };
            // SAFETY: records are 8-byte aligned and `header` is in-range.
            let raw_len = unsafe { &*header.cast::<AtomicU32>() }.load(Ordering::Acquire);
            if raw_len & BUSY_BIT != 0 {
                break;
            }
            let payload_len = (raw_len & LENGTH_MASK) as usize;
            let record_len = align8(
                HEADER_BYTES
                    .checked_add(payload_len)
                    .ok_or_else(|| invalid_record("record length overflow"))?,
            )?;
            if record_len > self.capacity || consumer + record_len as u64 > producer {
                return Err(invalid_record("record exceeds published ring range"));
            }
            if raw_len & DISCARD_BIT == 0 {
                if payload_len != size_of::<FaultEvent>() {
                    return Err(invalid_record("fault event has unexpected size"));
                }
                // SAFETY: the length was checked and the double mapping makes
                // all payload bytes contiguous. `FaultEvent` contains no
                // invalid bit patterns.
                let event =
                    unsafe { ptr::read_unaligned(header.add(HEADER_BYTES).cast::<FaultEvent>()) };
                events.push(event);
            }
            consumer = consumer
                .checked_add(record_len as u64)
                .ok_or_else(|| invalid_record("consumer position overflow"))?;
        }

        // SAFETY: the consumer page is writable and page-aligned.
        unsafe { &*consumer_position }.store(consumer, Ordering::Release);
        Ok(events)
    }
}

impl AsRawFd for RingBuffer {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

fn align8(value: usize) -> io::Result<usize> {
    value
        .checked_add(7)
        .map(|value| value & !7)
        .ok_or_else(|| invalid_record("aligned record length overflow"))
}

fn invalid_record(detail: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, detail)
}

fn page_size() -> io::Result<usize> {
    // SAFETY: `_SC_PAGESIZE` has no pointer arguments or side effects.
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(value)
        .ok()
        .filter(|value| value.is_power_of_two())
        .ok_or_else(io::Error::last_os_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_alignment_matches_ringbuf_uapi() {
        assert_eq!(align8(HEADER_BYTES + size_of::<FaultEvent>()).unwrap(), 40);
        assert_eq!(align8(9).unwrap(), 16);
    }

    #[test]
    fn fault_event_is_the_fixed_contract_size() {
        assert_eq!(size_of::<FaultEvent>(), 32);
        assert_eq!(LENGTH_MASK, 0x3fff_ffff);
    }
}
