// Copyright 2026 The cladefs Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! What the signal handlers log, and the metric they set, written as a signal handler may:
//! async-signal-safe, taking no lock and allocating nothing.
//!
//! A handler interrupts its thread anywhere, holding whatever it holds: the logger's lock, in the
//! middle of a line (a `SIGPIPE` raised by its own write to a log pipe whose reader went), or the
//! allocator's (a stack overflow or a fault in `malloc`). A handler that logs through the logger,
//! formats into a `String` or writes the metrics through serde then waits for ever for what its
//! own thread holds, and the VM hangs rather than exiting with the signal's code. So the handlers
//! format their line on the stack, write it with `write(2)` to a descriptor the logger keeps for
//! them, and write a metrics line of their own signal alone the same way.
//!
//! A deviation from upstream Firecracker, whose handlers log through `LOGGER` and write the
//! whole of `METRICS`: resources/cladefs/README.md lists it.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
use std::fs::File;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicI32, Ordering};

use super::logging::{DEFAULT_INSTANCE_ID, INSTANCE_ID};

/// The descriptor the handlers write their lines to: standard output, the logger's target until
/// it is given one, then a duplicate of its target, which a target given later replaces with
/// `dup3`, at once, so that a handler never writes to a descriptor closed or reused meanwhile.
static LOG_FD: AtomicI32 = AtomicI32::new(libc::STDOUT_FILENO);

/// The metrics' file, once they are given one: -1 until then.
static METRICS_FD: AtomicI32 = AtomicI32::new(-1);

/// Pre-serialized top-level JSON fields (`,"id":...` and/or `,"properties":...`) configured once
/// at `init_metrics`, so [`write_metric`] emits them without locking or allocating.
static METRICS_META: OnceLock<String> = OnceLock::new();

/// Makes `target` the descriptor the handlers write their lines to: a duplicate of it, made once,
/// and replaced by each target after, at once. Called with the logger's lock held, which
/// serializes the calls.
pub(crate) fn set_log_target(target: &File) -> std::io::Result<()> {
    let fd = LOG_FD.load(Ordering::Acquire);
    if fd == libc::STDOUT_FILENO {
        // SAFETY: Duplicates a descriptor the caller holds, checking the result.
        let duplicate = unsafe { libc::fcntl(target.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            return Err(std::io::Error::last_os_error());
        }
        LOG_FD.store(duplicate, Ordering::Release);
    } else {
        // SAFETY: Replaces the duplicate made before, which only this module uses, with one of a
        // descriptor the caller holds, checking the result.
        if unsafe { libc::dup3(target.as_raw_fd(), fd, libc::O_CLOEXEC) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Makes `fd`, the metrics' file, which stays open as long as the process, the descriptor the
/// handlers write their metrics line to.
pub(crate) fn set_metrics_fd(fd: RawFd) {
    METRICS_FD.store(fd, Ordering::Release);
}

/// Records the configured metrics metadata (`emit_id` and `properties`), pre-serialized as JSON
/// fields for [`write_metric`]. Must be called before [`set_metrics_fd`].
pub(crate) fn set_metrics_meta(emit_id: bool, properties: Option<&BTreeMap<String, String>>) {
    let mut meta = String::new();
    if emit_id {
        let id = INSTANCE_ID
            .get()
            .map_or(DEFAULT_INSTANCE_ID, String::as_str);
        if let Ok(json_id) = serde_json::to_string(id) {
            let _ = write!(meta, ",\"id\":{json_id}");
        }
    }
    if let Some(properties) = properties
        && let Ok(json_props) = serde_json::to_string(properties)
    {
        let _ = write!(meta, ",\"properties\":{json_props}");
    }
    let _ = METRICS_META.set(meta);
}

/// The name of a thread, as much of it as fits, for a handler to say which thread it interrupted,
/// as it can't ask the standard library, which may allocate.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ThreadName {
    bytes: [u8; 32],
    len: usize,
}

impl ThreadName {
    /// The calling thread's, cut at a character's boundary: "-" for a thread with no name, as
    /// the logger says.
    fn current() -> Self {
        let mut bytes = [0; 32];
        let current = std::thread::current();
        let whole = current.name().unwrap_or("-");
        let mut len = whole.len().min(bytes.len());
        while !whole.is_char_boundary(len) {
            len -= 1;
        }
        bytes[..len].copy_from_slice(&whole.as_bytes()[..len]);
        ThreadName { bytes, len }
    }

    pub(crate) fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len]).unwrap_or("-")
    }
}

thread_local! {
    /// The calling thread's name, as [`record_thread_name`] recorded it. It doesn't drop, so a
    /// handler reads it with no more than a load: no destructor to register, nor lock to take.
    static THREAD_NAME: Cell<Option<ThreadName>> = const { Cell::new(None) };
}

/// Records the calling thread's name, for the handlers to say: each thread does as it starts,
/// with its alternate signal stack (`install_signal_stack`).
pub(crate) fn record_thread_name() {
    THREAD_NAME.set(Some(ThreadName::current()));
}

/// The calling thread's name, if it recorded it: what a handler may read.
pub(crate) fn thread_name() -> Option<ThreadName> {
    THREAD_NAME.get()
}

/// How long a log line a handler writes is at most: longer ones are cut.
const LINE_BYTES: usize = 512;

/// How long a metrics line a handler writes is at most (well within `SIGNAL_STACK_SIZE`): if
/// configured `properties` would overflow this, [`write_metric`] omits the metadata rather than
/// emitting truncated JSON.
const METRICS_LINE_BYTES: usize = 4096;

/// A line formatted on the stack, cut at a character's boundary where it fills, always room left
/// for its end of line.
struct Line<const N: usize = LINE_BYTES> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Line<N> {
    fn new() -> Self {
        Line {
            bytes: [0; N],
            len: 0,
        }
    }

    /// Bytes remaining before the trailing newline.
    fn remaining(&self) -> usize {
        N - 1 - self.len
    }

    /// The line, ended.
    fn ended(&mut self) -> &[u8] {
        self.bytes[self.len] = b'\n';
        &self.bytes[..=self.len]
    }
}

impl<const N: usize> fmt::Write for Line<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let room = self.remaining();
        let mut len = s.len().min(room);
        while !s.is_char_boundary(len) {
            len -= 1;
        }
        self.bytes[self.len..self.len + len].copy_from_slice(&s.as_bytes()[..len]);
        self.len += len;
        Ok(())
    }
}

/// The time now, UTC, as the logger's lines start (`utils::time::LocalTime`), which it can't
/// give, as the local time zone takes a lock to read.
struct UtcNow(libc::timespec);

impl UtcNow {
    fn now() -> Self {
        let mut now = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: Fills `now`, which outlives the call. `clock_gettime` is async-signal-safe.
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut now) };
        UtcNow(now)
    }

    /// Milliseconds since the epoch, as the metrics' `utc_timestamp_ms`.
    fn millis(&self) -> i64 {
        self.0.tv_sec * 1000 + self.0.tv_nsec / 1_000_000
    }
}

impl fmt::Display for UtcNow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (days, secs) = (
            self.0.tv_sec.div_euclid(86_400),
            self.0.tv_sec.rem_euclid(86_400),
        );
        let (year, month, day) = civil_from_days(days);
        write!(
            f,
            "{year}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:09}Z",
            secs / 3600,
            secs / 60 % 60,
            secs % 60,
            self.0.tv_nsec
        )
    }
}

/// The year, month and day of `days` days since 1970-01-01, in the proleptic Gregorian calendar
/// (Howard Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Writes `bytes` to `fd` whole, as `write(2)` writes them, async-signal-safe; or the `errno`
/// it couldn't for, `EPIPE` saying the reader went.
fn write_all(fd: RawFd, mut bytes: &[u8]) -> Result<(), i32> {
    while !bytes.is_empty() {
        // SAFETY: Writes from `bytes`, as long as said. `write` is async-signal-safe.
        let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        match usize::try_from(written) {
            Ok(0) => return Err(libc::EIO),
            Ok(written) => bytes = &bytes[written..],
            Err(_) => match errno() {
                libc::EINTR => {}
                errno => return Err(errno),
            },
        }
    }
    Ok(())
}

/// The calling thread's `errno`.
fn errno() -> i32 {
    // SAFETY: The calling thread's errno, which it alone writes.
    unsafe { *libc::__errno_location() }
}

/// The calling thread's `errno`, kept while the handler that holds it runs, and put back as it
/// returns, as the code it interrupted may read it next: a handler that returns, as
/// `SIGPIPE`'s does, must leave it as it found it.
pub(crate) struct KeptErrno(i32);

impl KeptErrno {
    pub(crate) fn keep() -> Self {
        KeptErrno(errno())
    }
}

impl Drop for KeptErrno {
    fn drop(&mut self) {
        // SAFETY: The calling thread's errno, which it alone writes.
        unsafe { *libc::__errno_location() = self.0 };
    }
}

/// Writes a line of `args` where the logger writes, as its lines are: the time (UTC), the
/// instance and the thread, then `args`; async-signal-safe, for a signal handler. True if its
/// write found the reader gone (`EPIPE`): its `SIGPIPE` is pending, raised on the calling
/// thread, which the handler is to take for its own, rather than write again for it, for ever.
pub(crate) fn log(args: fmt::Arguments<'_>) -> bool {
    let mut line = Line::<LINE_BYTES>::new();
    let instance = INSTANCE_ID
        .get()
        .map_or(DEFAULT_INSTANCE_ID, String::as_str);
    let thread = thread_name();
    let thread = thread.as_ref().map_or("-", ThreadName::as_str);
    // Line's writes never fail: they cut.
    let _ = write!(line, "{} [{instance}:{thread}] {args}", UtcNow::now());
    match write_all(LOG_FD.load(Ordering::Acquire), line.ended()) {
        Err(libc::EPIPE) => true,
        // As the logger counts a line it couldn't write, and says nothing of it.
        Err(_) | Ok(()) => false,
    }
}

/// Writes a metrics line, as the metrics' are, of the metric `name` of `group` alone, set to 1:
/// the fatal signal a handler is about to exit for, which the metrics in memory, set already,
/// would never show otherwise, the process gone before their next write. Async-signal-safe, for
/// a signal handler: the whole of the metrics, written through serde, takes locks and allocates.
pub(crate) fn write_metric(group: &str, name: &str) {
    let fd = METRICS_FD.load(Ordering::Acquire);
    if fd < 0 {
        return;
    }
    let mut line = Line::<METRICS_LINE_BYTES>::new();
    let millis = UtcNow::now().millis();
    let meta = METRICS_META.get().map_or("", String::as_str);
    let mut suffix = Line::<LINE_BYTES>::new();
    let _ = write!(suffix, ",\"{group}\":{{\"{name}\":1}}}}");
    // Line's writes never fail: they cut. Emit `meta` only when the full record fits so the
    // resulting line is always valid JSON.
    let _ = write!(line, "{{\"utc_timestamp_ms\":{millis}");
    if meta.len() + suffix.len <= line.remaining() {
        let _ = line.write_str(meta);
    }
    let _ = line.write_str(std::str::from_utf8(&suffix.bytes[..suffix.len]).unwrap_or("}"));
    // Nothing more to do of it, the process exiting: the metrics count a line they couldn't
    // write nowhere.
    let _ = write_all(fd, line.ended());
}

/// Logs as `error!` does, from a signal handler: async-signal-safe ([`log`]).
macro_rules! log_from_signal_handler {
    ($($arg:tt)+) => {
        $crate::logger::signal_safe::log(format_args!($($arg)+))
    };
}
pub(crate) use log_from_signal_handler;

#[cfg(test)]
mod tests {
    use super::*;

    // The calendar's edges: the epoch, before it, leap days, and centuries leaping or not.
    #[test]
    fn test_civil_from_days() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(11_017), (2000, 3, 1));
        assert_eq!(civil_from_days(47_540), (2100, 2, 28));
        assert_eq!(civil_from_days(47_541), (2100, 3, 1));
        assert_eq!(civil_from_days(20_780), (2026, 11, 23));
    }

    // A line too long for its buffer is cut at a character's boundary, its end of line kept.
    #[test]
    fn test_line_cut() {
        let mut line = Line::<LINE_BYTES>::new();
        write!(line, "{}", "é".repeat(LINE_BYTES)).unwrap();
        let ended = line.ended();
        assert_eq!(ended.len(), LINE_BYTES - 1);
        assert_eq!(ended.last(), Some(&b'\n'));
        assert_eq!(
            std::str::from_utf8(&ended[..ended.len() - 1]).unwrap(),
            "é".repeat((LINE_BYTES - 2) / 2)
        );
    }
}
