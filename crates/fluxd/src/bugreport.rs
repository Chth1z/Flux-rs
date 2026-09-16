//! `fluxd bugreport`: one self-contained diagnostic zip.
//!
//! Rules from `docs/spec/interaction.md` §27.6:
//!
//! * Default output is REDACTED: IPv4 addresses keep only their first octet;
//!   IPv6-looking strings, MAC addresses and NFLOG cookies are masked. These
//!   are the same implementation used by the manual `observe.sh` probe.
//!   `--raw` disables them.
//! * `logcat` is NEVER captured by default — it contains other apps' output.
//!   `--with-logcat` opts in, filtered to Flux-related lines only.
//! * Raw configuration files are never included: `template.json` carries
//!   proxy credentials. The check output and status JSON describe the config
//!   without quoting it.
//!
//! The zip writer is deliberately minimal (stored entries, one central
//! directory, no compression): a bug report is small and a zip dependency is
//! not worth a governance §1.2 exception.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use flux_core::control_wire::{self, Request};

use crate::checks;
use crate::engine::EngineSpec;
use crate::layout::Layout;

/// Bytes of the daemon log tail included.
const LOG_TAIL_BYTES: u64 = 256 * 1024;

/// Deadline for each external capture command (`dmesg`, `logcat`).
const CAPTURE_DEADLINE: Duration = Duration::from_secs(10);

/// Options parsed from the CLI.
#[derive(Debug, Default)]
pub struct BugreportOptions {
    /// Include filtered logcat output (opt-in, `docs/spec/interaction.md` §27.6).
    pub with_logcat: bool,
    /// Disable redaction.
    pub raw: bool,
    /// Output directory; the state root when `None` (§27.4).
    pub output_dir: Option<PathBuf>,
}

/// Collects the report and writes the zip. Returns the written path.
pub fn run(layout: &Layout, options: &BugreportOptions) -> io::Result<PathBuf> {
    let redact_on = !options.raw;
    let mut zip = ZipWriter::new();
    let now = SystemTime::now();

    let commit = option_env!("FLUX_COMMIT").unwrap_or("unknown");
    zip.add("meta.txt", meta_text(commit, now).as_bytes());

    // Daemon status over the control socket; absence is itself a finding.
    let status = match control_status(layout) {
        Ok(json) => json,
        Err(e) => format!("{{\"error\":\"daemon not reachable: {e}\"}}\n"),
    };
    zip.add("status.json", maybe_redact(&status, redact_on).as_bytes());

    // The full local check, engine subprocess included.
    let spec = EngineSpec::product(layout);
    let report = checks::full_check(layout, &spec);
    let mut check_text = String::new();
    check_text.push_str(if report.ok() {
        "check: ok\n"
    } else {
        "check: FAILED\n"
    });
    for error in &report.errors {
        check_text.push_str(&format!("error: {error}\n"));
    }
    for warning in &report.warnings {
        check_text.push_str(&format!("warning: {warning}\n"));
    }
    zip.add("check.txt", maybe_redact(&check_text, redact_on).as_bytes());

    // Daemon log tail. The engine's captured output lives here too (§13.3).
    let log_tail = tail_file(&layout.log_file(), LOG_TAIL_BYTES)
        .unwrap_or_else(|e| format!("(log unreadable: {e})\n"));
    zip.add(
        "fluxd.log.txt",
        maybe_redact(&log_tail, redact_on).as_bytes(),
    );

    // Kernel and sysctl facts, read-only.
    let proc_version =
        fs::read_to_string("/proc/version").unwrap_or_else(|e| format!("(unreadable: {e})\n"));
    zip.add("proc-version.txt", proc_version.as_bytes());
    let rp_filter = fs::read_to_string("/proc/sys/net/ipv4/conf/all/rp_filter")
        .map(|v| format!("net.ipv4.conf.all.rp_filter = {}\n", v.trim()))
        .unwrap_or_else(|e| format!("(rp_filter unreadable: {e})\n"));
    zip.add("sysctl.txt", rp_filter.as_bytes());

    // Installed Magisk/KernelSU modules: id/name/version plus flag files.
    // No redaction needed — module.prop carries no addresses.
    zip.add("modules.txt", modules_inventory().as_bytes());

    // Read-only network observation is collected in-process. The manual Phase
    // 0 probe feeds its output through this binary's same redactor.
    let observe = capture_network_observation();
    zip.add("observe.txt", maybe_redact(&observe, redact_on).as_bytes());

    match fs::read("/proc/config.gz") {
        Ok(config) => zip.add("proc-config.gz", &config),
        Err(e) => zip.add(
            "proc-config.txt",
            format!("(/proc/config.gz unreadable: {e})\n").as_bytes(),
        ),
    }

    // dmesg needs root on Android; a failure is recorded, not fatal.
    let dmesg = capture_command("dmesg", &[], CAPTURE_DEADLINE)
        .unwrap_or_else(|e| format!("(dmesg failed: {e})\n"));
    // Default reports must not become a device-wide activity transcript.
    // Keep only kernel lines that can diagnose this data plane. `--raw` is an
    // explicit opt-in to the full command output.
    let dmesg = if redact_on {
        filter_kernel_lines(&dmesg)
    } else {
        dmesg
    };
    zip.add("dmesg.txt", maybe_redact(&dmesg, redact_on).as_bytes());

    if options.with_logcat {
        let logcat = capture_command("logcat", &["-d", "-b", "all"], CAPTURE_DEADLINE)
            .map(|out| filter_flux_lines(&out))
            .unwrap_or_else(|e| format!("(logcat failed: {e})\n"));
        zip.add("logcat.txt", maybe_redact(&logcat, redact_on).as_bytes());
    }

    zip.add("README.txt", readme_text(options).as_bytes());

    let stamp = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let name = format!(
        "flux-rs-bugreport-{}-{commit}-{stamp}.zip",
        flux_core::VERSION
    );
    let dir = options
        .output_dir
        .clone()
        .unwrap_or_else(|| layout.run_dir());
    let path = dir.join(name);
    let comment = format!(
        "flux-rs {} commit {commit} {}",
        flux_core::VERSION,
        if redact_on { "redacted" } else { "RAW" }
    );
    fs::write(&path, zip.finish(now, comment.as_bytes()))?;
    Ok(path)
}

fn meta_text(commit: &str, now: SystemTime) -> String {
    let uname = read_uname();
    format!(
        "product: flux-rs\nversion: {}\ncommit: {commit}\nabi_magic: {:#010X}\n\
         debug_build: {}\ntimestamp: {}\nkernel: {uname}\n",
        flux_core::VERSION,
        flux_core::abi::FLUX_ABI_MAGIC,
        cfg!(debug_assertions),
        crate::time::format_utc(now),
    )
}

fn read_uname() -> String {
    // SAFETY: utsname is plain-old-data the kernel fills; zeroing is valid.
    unsafe {
        let mut uts: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut uts) != 0 {
            return "unknown".to_string();
        }
        let field = |a: &[libc::c_char]| -> String {
            let bytes: Vec<u8> = a
                .iter()
                .take_while(|c| **c != 0)
                .map(|c| c.to_ne_bytes()[0])
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        };
        format!(
            "{} {} {} {}",
            field(&uts.sysname),
            field(&uts.release),
            field(&uts.version),
            field(&uts.machine)
        )
    }
}

fn control_status(layout: &Layout) -> io::Result<String> {
    let response = crate::control::request(
        &layout.control_socket(),
        &Request::Status,
        Duration::from_secs(5),
    )?;
    control_wire::to_line(&response)
        .map(|mut line| {
            line.push('\n');
            line
        })
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

fn modules_inventory() -> String {
    let mut out = String::new();
    let Ok(entries) = fs::read_dir("/data/adb/modules") else {
        out.push_str("(no /data/adb/modules: not a rooted Android device?)\n");
        return out;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        out.push_str(&format!("[{}]\n", entry.file_name().to_string_lossy()));
        if let Ok(prop) = fs::read_to_string(dir.join("module.prop")) {
            for line in prop.lines().take(8) {
                out.push_str(&format!("  {line}\n"));
            }
        }
        for flag in ["disable", "remove", "update"] {
            if dir.join(flag).exists() {
                out.push_str(&format!("  ({flag} flag present)\n"));
            }
        }
    }
    if out.is_empty() {
        out.push_str("(no modules installed)\n");
    }
    out
}

/// Runs an external capture command with a hard deadline; output capped.
fn capture_command(program: &str, args: &[&str], deadline: Duration) -> io::Result<String> {
    use std::process::{Command, Stdio};
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn()?;
    let start = std::time::Instant::now();
    let mut stdout = child.stdout.take().expect("stdout piped");
    let mut out = Vec::new();
    // The reader thread lets the deadline hold even when the pipe stalls.
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.by_ref().take(4 * 1024 * 1024).read_to_end(&mut buf);
        buf
    });
    loop {
        match child.try_wait()? {
            Some(_) => break,
            None if start.elapsed() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    if let Ok(buf) = reader.join() {
        out = buf;
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

fn capture_network_observation() -> String {
    let mut output = String::new();
    for (heading, program, args) in [
        ("ip-address", "ip", &["-details", "address", "show"][..]),
        ("ip-rule-v4", "ip", &["-4", "rule", "show"][..]),
        ("ip-rule-v6", "ip", &["-6", "rule", "show"][..]),
        (
            "route-table-v4",
            "ip",
            &["-4", "route", "show", "table", "20260"][..],
        ),
        (
            "route-table-v6",
            "ip",
            &["-6", "route", "show", "table", "20260"][..],
        ),
        ("tc-qdisc", "tc", &["qdisc", "show"][..]),
        ("tc-filter", "tc", &["filter", "show"][..]),
        ("bpf-net", "bpftool", &["net", "show"][..]),
    ] {
        output.push_str(&format!("########## {heading}\n"));
        match capture_command(program, args, CAPTURE_DEADLINE) {
            Ok(text) => output.push_str(&text),
            Err(error) => output.push_str(&format!("({program} failed: {error})\n")),
        }
        if !output.ends_with('\n') {
            output.push('\n');
        }
    }
    output
}

fn filter_flux_lines(text: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        if line.to_ascii_lowercase().contains("flux") {
            out.push_str(line);
            out.push('\n');
        }
    }
    if out.is_empty() {
        out.push_str("(no flux-related lines)\n");
    }
    out
}

fn filter_kernel_lines(text: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if ["flux", "flx_", "bpf", "verifier", "sched_cls"]
            .iter()
            .any(|needle| lower.contains(needle))
        {
            out.push_str(line);
            out.push('\n');
        }
    }
    if out.is_empty() {
        out.push_str("(no Flux/BPF-related kernel lines)\n");
    }
    out
}

fn readme_text(options: &BugreportOptions) -> String {
    let mut text = String::from(
        "flux-rs bug report\n\
         ==================\n\n\
         Contents are read-only diagnostics. Raw configuration files\n\
         (template.json, flux.toml) are NEVER included: they may contain\n\
         proxy server credentials. check.txt describes their validity.\n\n",
    );
    text.push_str(if options.raw {
        "Redaction: OFF (--raw). This report may contain IP and MAC addresses.\n"
    } else {
        "Redaction: ON. IPv4 keeps its first octet; IPv6-like, MAC-like and\n\
         NFLOG-cookie values are masked.\n"
    });
    text.push_str(if options.with_logcat {
        "logcat: included on explicit request, filtered to flux-related lines.\n"
    } else {
        "logcat: NOT included (default). Re-run with --with-logcat to opt in.\n"
    });
    text.push_str(
        "\nobserve.txt includes read-only ip, rule, reserved-table, tc and\n\
         bpftool diagnostics. Missing device tools are recorded as findings.\n",
    );
    text
}

fn tail_file(path: &Path, max: u64) -> io::Result<String> {
    use std::io::Seek;
    let mut file = fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len > max {
        file.seek(io::SeekFrom::Start(len - max))?;
    }
    let mut buf = String::new();
    file.take(max).read_to_string(&mut buf).or_else(|_| {
        buf = "(log tail is not valid UTF-8)".to_string();
        Ok::<usize, io::Error>(0)
    })?;
    Ok(buf)
}

fn maybe_redact(text: &str, on: bool) -> String {
    if on {
        redact(text)
    } else {
        text.to_string()
    }
}

// ------------------------------------------------------------------ redaction

/// Masks IPv4 (keeping the first octet), MAC-like, IPv6-like and quoted
/// decimal NFLOG-cookie tokens.
/// Hand-rolled scanning: a regex crate is not worth a dependency exception.
pub fn redact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        out.push_str(&redact_domains(&redact_line(line)));
    }
    out
}

/// Masks domain/package-like tokens so default engine-log tails cannot reveal
/// browsing habits. Third-party package names are allowed by the Phase 8
/// contract, but masking them too is the safer and simpler privacy boundary.
fn redact_domains(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut index = 0;
    while index < bytes.len() {
        if !is_domain_byte(bytes[index]) {
            let width = utf8_len(bytes[index]);
            out.push_str(&line[index..(index + width).min(bytes.len())]);
            index += width;
            continue;
        }
        let start = index;
        while index < bytes.len() && is_domain_byte(bytes[index]) {
            index += 1;
        }
        let token = &line[start..index];
        if is_domain_like(token) {
            out.push_str("[domain-redacted]");
        } else {
            out.push_str(token);
        }
    }
    out
}

fn is_domain_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

fn is_domain_like(token: &str) -> bool {
    let token = token.trim_matches(|character| matches!(character, '.' | '-' | '_'));
    let labels = token.split('.').collect::<Vec<_>>();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || !label.as_bytes()[0].is_ascii_alphanumeric()
                || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
        })
    {
        return false;
    }
    let suffix = labels[labels.len() - 1].to_ascii_lowercase();
    if ["json", "toml", "log", "txt", "zip", "srs", "rs", "md", "so"].contains(&suffix.as_str()) {
        return false;
    }
    suffix.len() >= 2 && suffix.bytes().all(|byte| byte.is_ascii_alphabetic())
}

fn redact_line(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            out.push('"');
            i += 1;
            let digits = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if i - digits >= 6 && bytes.get(i) == Some(&b':') {
                out.push_str("[cookie-redacted]:");
                i += 1;
                continue;
            }
            i = digits;
            continue;
        }
        // Token = maximal run of [0-9a-fA-F.:]. Everything else passes through.
        if !is_addr_byte(bytes[i]) {
            // Advance one UTF-8 scalar, not one byte.
            let ch_len = utf8_len(bytes[i]);
            out.push_str(&line[i..(i + ch_len).min(bytes.len())]);
            i += ch_len;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_addr_byte(bytes[i]) {
            i += 1;
        }
        let token = &line[start..i];
        out.push_str(&classify_and_mask(token));
    }
    out
}

fn is_addr_byte(b: u8) -> bool {
    b.is_ascii_hexdigit() || b == b'.' || b == b':'
}

fn utf8_len(b: u8) -> usize {
    match b {
        _ if b >= 0xF0 => 4,
        _ if b >= 0xE0 => 3,
        _ if b >= 0xC0 => 2,
        _ => 1,
    }
}

fn classify_and_mask(token: &str) -> String {
    if let Some(masked) = mask_ipv4(token) {
        return masked;
    }
    if is_mac(token) {
        return "[mac-redacted]".to_string();
    }
    if is_ipv6_like(token) {
        return "[v6-redacted]".to_string();
    }
    token.to_string()
}

/// `a.b.c.d` (optionally `:port`) with valid octets → `a.x.x.x[:port]`.
fn mask_ipv4(token: &str) -> Option<String> {
    let (addr, port) = match token.split_once(':') {
        Some((addr, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            (addr, Some(port))
        }
        Some(_) => return None,
        None => (token, None),
    };
    let octets: Vec<&str> = addr.split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    for octet in &octets {
        if octet.is_empty() || octet.len() > 3 || !octet.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if octet.parse::<u32>().ok()? > 255 {
            return None;
        }
    }
    let mut masked = format!("{}.x.x.x", octets[0]);
    if let Some(port) = port {
        masked.push_str(&format!(":{port}"));
    }
    Some(masked)
}

/// Six `:`-separated two-hex-digit groups.
fn is_mac(token: &str) -> bool {
    let groups: Vec<&str> = token.split(':').collect();
    groups.len() == 6
        && groups
            .iter()
            .all(|g| g.len() == 2 && g.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// At least two `:` and at least one hex letter or a `::` — conservative
/// enough to leave timestamps (`12:34:56`) alone.
fn is_ipv6_like(token: &str) -> bool {
    let colons = token.bytes().filter(|b| *b == b':').count();
    if colons < 2 {
        return false;
    }
    if token.contains("::") {
        return token.bytes().any(|b| b.is_ascii_hexdigit());
    }
    let has_hex_letter = token
        .bytes()
        .any(|b| b.is_ascii_hexdigit() && !b.is_ascii_digit());
    let groups_ok = token
        .split(':')
        .all(|g| g.len() <= 4 && g.bytes().all(|b| b.is_ascii_hexdigit()));
    has_hex_letter && groups_ok && colons >= 3
}

// ----------------------------------------------------------------- zip writer

/// Minimal stored-format zip writer: local headers, central directory, EOCD
/// with a build-identity comment. No compression — diagnostics are small.
struct ZipWriter {
    data: Vec<u8>,
    entries: Vec<(String, u32, u32, u32)>, // name, crc, size, local offset
}

impl ZipWriter {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            entries: Vec::new(),
        }
    }

    fn add(&mut self, name: &str, content: &[u8]) {
        let offset = self.data.len() as u32;
        let crc = crc32(content);
        let size = content.len() as u32;
        self.data.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        self.data.extend_from_slice(&20u16.to_le_bytes()); // version needed
        self.data.extend_from_slice(&0u16.to_le_bytes()); // flags
        self.data.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        self.data.extend_from_slice(&0u16.to_le_bytes()); // mod time (set in cdir)
        self.data.extend_from_slice(&0u16.to_le_bytes()); // mod date
        self.data.extend_from_slice(&crc.to_le_bytes());
        self.data.extend_from_slice(&size.to_le_bytes()); // compressed
        self.data.extend_from_slice(&size.to_le_bytes()); // uncompressed
        self.data
            .extend_from_slice(&(name.len() as u16).to_le_bytes());
        self.data.extend_from_slice(&0u16.to_le_bytes()); // extra len
        self.data.extend_from_slice(name.as_bytes());
        self.data.extend_from_slice(content);
        self.entries.push((name.to_string(), crc, size, offset));
    }

    fn finish(self, now: SystemTime, comment: &[u8]) -> Vec<u8> {
        let (dos_time, dos_date) = dos_datetime(now);
        let mut out = self.data;
        let cdir_offset = out.len() as u32;
        for (name, crc, size, offset) in &self.entries {
            out.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes()); // made by
            out.extend_from_slice(&20u16.to_le_bytes()); // needed
            out.extend_from_slice(&0u16.to_le_bytes()); // flags
            out.extend_from_slice(&0u16.to_le_bytes()); // method
            out.extend_from_slice(&dos_time.to_le_bytes());
            out.extend_from_slice(&dos_date.to_le_bytes());
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra
            out.extend_from_slice(&0u16.to_le_bytes()); // comment
            out.extend_from_slice(&0u16.to_le_bytes()); // disk
            out.extend_from_slice(&0u16.to_le_bytes()); // int attrs
            out.extend_from_slice(&0o100600u32.to_le_bytes()); // ext attrs (rw-------)
            out.extend_from_slice(&offset.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
        }
        let cdir_size = out.len() as u32 - cdir_offset;
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // this disk
        out.extend_from_slice(&0u16.to_le_bytes()); // cdir disk
        let count = self.entries.len() as u16;
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&cdir_size.to_le_bytes());
        out.extend_from_slice(&cdir_offset.to_le_bytes());
        out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
        out.extend_from_slice(comment);
        out
    }
}

fn dos_datetime(t: SystemTime) -> (u16, u16) {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (year, month, day) = crate::time::civil_from_days(days);
    let year = year.clamp(1980, 2107) as u16;
    let time = ((h as u16) << 11) | ((m as u16) << 5) | ((s as u16) / 2);
    let date = ((year - 1980) << 9) | ((month as u16) << 5) | (day as u16);
    (time, date)
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_masks_addresses_but_not_timestamps() {
        let input = "peer 192.168.1.5:8443 via fe80::1 mac aa:bb:cc:dd:ee:11 cookie \"123456789: at 12:34:56 host api.example.com package com.example.app template.json\n\
                     plain 10.0.0.1 and version 1.2.3 and 300.1.2.3 stay sane\n";
        let out = redact(input);
        assert!(out.contains("192.x.x.x:8443"), "{out}");
        assert!(out.contains("[v6-redacted]"), "{out}");
        assert!(out.contains("[mac-redacted]"), "{out}");
        assert!(out.contains("\"[cookie-redacted]:"), "{out}");
        assert!(out.contains("12:34:56"), "timestamps must survive: {out}");
        assert!(out.contains("10.x.x.x"), "{out}");
        assert!(
            out.contains("1.2.3"),
            "a three-part version is not an IP: {out}"
        );
        assert!(out.contains("300.1.2.3"), "octet >255 is not an IP: {out}");
        assert!(!out.contains("192.168.1.5"), "{out}");
        assert!(!out.contains("123456789"), "{out}");
        assert!(!out.contains("api.example.com"), "{out}");
        assert!(!out.contains("com.example.app"), "{out}");
        assert!(
            out.contains("template.json"),
            "file names remain diagnostic: {out}"
        );
    }

    #[test]
    fn default_kernel_filter_excludes_unrelated_activity() {
        let filtered = filter_kernel_lines(
            "audit: unrelated app launch\nBPF: verifier rejected flx_cap_l2\nfluxd denied\n",
        );
        assert!(!filtered.contains("app launch"));
        assert!(filtered.contains("verifier rejected"));
        assert!(filtered.contains("fluxd denied"));
    }

    #[test]
    fn zip_output_is_structurally_valid() {
        let mut zip = ZipWriter::new();
        zip.add("a.txt", b"hello");
        zip.add("dir/b.txt", b"world");
        let bytes = zip.finish(SystemTime::UNIX_EPOCH, b"test comment");
        // Local header magic at 0.
        assert_eq!(&bytes[0..4], &0x0403_4b50u32.to_le_bytes());
        // EOCD magic present with the comment at the very end.
        let eocd = bytes.len() - 22 - "test comment".len();
        assert_eq!(&bytes[eocd..eocd + 4], &0x0605_4b50u32.to_le_bytes());
        assert!(bytes.ends_with(b"test comment"));
        // Entry count in the EOCD.
        assert_eq!(bytes[eocd + 10], 2);
    }

    #[test]
    fn crc32_matches_the_reference_vector() {
        // The canonical test vector: crc32("123456789") = 0xCBF43926.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }
}
