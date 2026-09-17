//! Completeness evidence for kernel dumps (blueprint §8.5, §10.5).
//!
//! An incomplete dump cannot become a [`TrustedSnapshot`]. "Not seen" is not
//! "absent": two incomplete-but-equal views are not a deletion permit.

use std::fmt;

/// Why a dump cannot be used to decide ownership or absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncompleteDump {
    /// `NLM_F_DUMP_INTR` was set on a message.
    pub interrupted: bool,
    /// The receive was truncated (`MSG_TRUNC`).
    pub truncated: bool,
    /// `NLMSG_OVERRUN` or `ENOBUFS`.
    pub overrun: bool,
    /// `NLMSG_DONE` payload status; 0 means the dump finished cleanly.
    pub done_status: i32,
}

impl fmt::Display for IncompleteDump {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "incomplete kernel dump (interrupted={}, truncated={}, overrun={}, done_status={})",
            self.interrupted, self.truncated, self.overrun, self.done_status
        )
    }
}

/// A value produced only from a dump whose integrity evidence passed.
///
/// The inner value is private so a `Vec` from a half-read cannot be labeled
/// trusted by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedSnapshot<T> {
    inner: T,
}

impl<T> TrustedSnapshot<T> {
    /// Constructs a snapshot only when every integrity bit is clean.
    pub fn try_from_parts(
        value: T,
        interrupted: bool,
        truncated: bool,
        overrun: bool,
        done_status: i32,
    ) -> Result<Self, IncompleteDump> {
        if interrupted || truncated || overrun || done_status != 0 {
            Err(IncompleteDump {
                interrupted,
                truncated,
                overrun,
                done_status,
            })
        } else {
            Ok(Self { inner: value })
        }
    }

    /// Borrow the trusted inner value.
    pub fn get(&self) -> &T {
        &self.inner
    }

    /// Unwrap the trusted inner value.
    pub fn into_inner(self) -> T {
        self.inner
    }
}

/// Switch-file observation. Unknown is a distinct state (blueprint §11.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// The path exists (follow the symlink_metadata success).
    Present,
    /// `NotFound`.
    Absent,
    /// Any other metadata failure. MUST NOT be treated as Absent.
    Unreadable,
}

impl Presence {
    /// Capture may start only when the disable file is absent.
    ///
    /// `Unreadable` is not enabled: I10 forbids expanding capture when the
    /// switch cannot be confirmed.
    pub fn capture_permitted(self) -> bool {
        matches!(self, Self::Absent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_evidence_constructs() {
        let snap = TrustedSnapshot::try_from_parts(vec![1u8, 2], false, false, false, 0).unwrap();
        assert_eq!(snap.get(), &vec![1, 2]);
        assert_eq!(snap.into_inner(), vec![1, 2]);
    }

    #[test]
    fn interrupted_dump_is_not_trusted() {
        let err = TrustedSnapshot::try_from_parts((), true, false, false, 0).unwrap_err();
        assert!(err.interrupted);
        assert_eq!(err.done_status, 0);
    }

    #[test]
    fn truncated_dump_is_not_trusted() {
        assert!(TrustedSnapshot::try_from_parts((), false, true, false, 0).is_err());
    }

    #[test]
    fn overrun_dump_is_not_trusted() {
        assert!(TrustedSnapshot::try_from_parts((), false, false, true, 0).is_err());
    }

    #[test]
    fn done_negative_is_not_trusted() {
        let err = TrustedSnapshot::try_from_parts((), false, false, false, -2).unwrap_err();
        assert_eq!(err.done_status, -2);
    }

    #[test]
    fn unreadable_switch_does_not_permit_capture() {
        assert!(Presence::Absent.capture_permitted());
        assert!(!Presence::Present.capture_permitted());
        assert!(!Presence::Unreadable.capture_permitted());
    }
}
