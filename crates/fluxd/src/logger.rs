//! Daemon log ownership: append, accounting and retention happen at the write
//! boundary, so a long-lived process needs no rotation timer (§11.2.4).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::time::SystemTime;

use flux_core::config::LogConfig;

use crate::{layout::Layout, time::format_utc};

pub struct Logger {
    path: PathBuf,
    file: Option<File>,
    bytes: u64,
    policy: LogConfig,
}

impl Logger {
    pub fn open(layout: &Layout) -> Self {
        let mut logger = Self {
            path: layout.log_file(),
            file: None,
            bytes: 0,
            policy: LogConfig::default(),
        };
        let _ = logger.reopen();
        logger
    }

    /// Apply only the policy of an accepted configuration candidate.
    pub fn configure(&mut self, policy: LogConfig) {
        self.policy = policy;
    }

    pub fn log(&mut self, line: &str) {
        let full = format!("[{}] {line}\n", format_utc(SystemTime::now()));
        eprint!("{full}");
        if let Err(error) = self.append(full.as_bytes()) {
            // stderr remains available; don't recursively log a logging error.
            eprintln!("fluxd log: {error}");
        }
    }

    fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.file.is_none() {
            self.reopen()?;
        }
        if self.bytes >= self.policy.max_bytes {
            self.rotate()?;
        }
        let file = self.file.as_mut().expect("opened above");
        match file.write_all(bytes) {
            Ok(()) => self.bytes = self.bytes.saturating_add(bytes.len() as u64),
            Err(error) => {
                self.file = None; // next write re-observes a possibly partial write
                return Err(error);
            }
        }
        Ok(())
    }

    fn reopen(&mut self) -> io::Result<()> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .mode(0o600)
            .open(&self.path)?;
        self.bytes = file.metadata()?.len();
        self.file = Some(file);
        Ok(())
    }

    fn rotated(&self, index: u32) -> PathBuf {
        self.path.with_file_name(format!("fluxd.log.{index}"))
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.file = None;
        // Enumerate existing files instead of doing `retain` syscalls: large
        // user limits should not make a sparse directory expensive to rotate.
        let mut indices = Vec::new();
        if let Some(parent) = self.path.parent() {
            for entry in fs::read_dir(parent)? {
                let entry = entry?;
                let name = entry.file_name();
                let Some(suffix) = name
                    .to_str()
                    .and_then(|name| name.strip_prefix("fluxd.log."))
                else {
                    continue;
                };
                let Ok(index) = suffix.parse::<u32>() else {
                    continue;
                };
                if index == 0 || suffix != index.to_string() || !entry.file_type()?.is_file() {
                    continue;
                }
                indices.push(index);
            }
        }
        indices.sort_unstable_by(|a, b| b.cmp(a));
        for index in indices {
            if index >= self.policy.retain {
                fs::remove_file(self.rotated(index))?;
            } else {
                fs::rename(self.rotated(index), self.rotated(index + 1))?;
            }
        }
        if self.policy.retain == 0 {
            fs::remove_file(&self.path)?;
        } else {
            fs::rename(&self.path, self.rotated(1))?;
        }
        self.reopen()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_lived_writes_rotate_and_reduced_retention_removes_old_files() {
        let root = std::env::temp_dir().join(format!("flux-logger-{}", std::process::id()));
        let layout = Layout::at(root.clone());
        layout.ensure().unwrap();
        let mut logger = Logger::open(&layout);
        logger.configure(LogConfig {
            max_bytes: 4,
            retain: 2,
        });
        logger.append(b"first").unwrap();
        logger.append(b"next").unwrap();
        logger.append(b"last").unwrap();
        assert_eq!(fs::read(layout.log_file()).unwrap(), b"last");
        assert_eq!(fs::read(logger.rotated(1)).unwrap(), b"next");
        assert_eq!(fs::read(logger.rotated(2)).unwrap(), b"first");
        logger.configure(LogConfig {
            max_bytes: 4,
            retain: 0,
        });
        logger.append(b"now").unwrap();
        assert_eq!(fs::read(layout.log_file()).unwrap(), b"now");
        assert!(!logger.rotated(1).exists());
        assert!(!logger.rotated(2).exists());
        drop(logger);
        fs::remove_dir_all(root).unwrap();
    }
}
