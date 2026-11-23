// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::cell::RefCell;
use std::ptr::null_mut;

use libc::{
    SIGBUS, SIGHUP, SIGILL, SIGPIPE, SIGSEGV, SIGSYS, SIGXCPU, SIGXFSZ, c_int, c_void, siginfo_t,
};
use vmm_sys_util::errno;

use crate::FcExitCode;
use crate::arch::host_page_size;
use crate::logger::signal_safe::{self, KeptErrno, log_from_signal_handler};
use crate::logger::{IncMetric, METRICS, StoreMetric, error};
use crate::utils::signal::SignalHandler;

// The offset of `si_syscall` (offending syscall identifier) within the siginfo structure
// expressed as an `(u)int*`.
// Offset `6` for an `i32` field means that the needed information is located at `6 * sizeof(i32)`.
// See /usr/include/linux/signal.h for the C struct definition.
// See https://github.com/rust-lang/libc/issues/716 for why the offset is different in Rust.
const SI_OFF_SYSCALL: isize = 6;

const SYS_SECCOMP_CODE: i32 = 1;

/// Ends the process with `exit_code`, at once, as a signal's handler may: no lock taken, nothing
/// allocated, no destructor nor `atexit` handler run.
#[inline]
fn exit_with_code(exit_code: FcExitCode) -> ! {
    // SAFETY: Safe because we're terminating the process anyway.
    unsafe { libc::_exit(exit_code as i32) }
}

// The handlers are async-signal-safe: they log and write their metric through
// `logger::signal_safe`, taking no lock and allocating nothing, as a signal on a thread holding
// the logger's lock, or the allocator's, would wait for ever for it. A fatal signal's metric is
// written in a line of its own, `metric_group` and `metric`, the metrics' JSON names of
// `signal_metric`, set to 1.
macro_rules! generate_handler {
    (
        $fn_name:ident,
        $signal_name:ident,
        $exit_code:ident,
        $signal_metric:expr,
        $metric_group:literal,
        $metric:literal,
        $body:ident
    ) => {
        #[inline(always)]
        extern "C" fn $fn_name(num: c_int, info: *mut siginfo_t, _unused: *mut c_void) {
            // SAFETY: Safe because we're just reading some fields from a supposedly valid argument.
            let si_signo = unsafe { (*info).si_signo };
            // SAFETY: Safe because we're just reading some fields from a supposedly valid argument.
            let si_code = unsafe { (*info).si_code };

            if num != si_signo || num != $signal_name {
                exit_with_code(FcExitCode::UnexpectedError);
            }
            $signal_metric.store(1);

            log_from_signal_handler!(
                "Shutting down VM after intercepting signal {}, code {}.",
                si_signo,
                si_code
            );

            $body(si_code, info);

            signal_safe::write_metric($metric_group, $metric);
            exit_with_code(crate::FcExitCode::$exit_code);
        }
    };
}

fn log_sigsys_err(si_code: c_int, info: *mut siginfo_t) {
    if si_code != SYS_SECCOMP_CODE {
        // We received a SIGSYS for a reason other than `bad syscall`.
        exit_with_code(FcExitCode::UnexpectedError);
    }

    // SAFETY: Other signals which might do async unsafe things incompatible with the rest of this
    // function are blocked due to the sa_mask used when registering the signal handler.
    let syscall = unsafe { *(info as *const i32).offset(SI_OFF_SYSCALL) };
    log_from_signal_handler!(
        "Shutting down VM after intercepting a bad syscall ({}).",
        syscall
    );
}

fn empty_fn(_si_code: c_int, _info: *mut siginfo_t) {}

#[cfg(feature = "cladefs")]
use fault::log_fault;
// Without the cladefs feature, a fault's handler says no more than its signal.
#[cfg(not(feature = "cladefs"))]
use self::empty_fn as log_fault;

generate_handler!(
    sigxfsz_handler,
    SIGXFSZ,
    SIGXFSZ,
    METRICS.signals.sigxfsz,
    "signals",
    "sigxfsz",
    empty_fn
);

generate_handler!(
    sigxcpu_handler,
    SIGXCPU,
    SIGXCPU,
    METRICS.signals.sigxcpu,
    "signals",
    "sigxcpu",
    empty_fn
);

generate_handler!(
    sigbus_handler,
    SIGBUS,
    SIGBUS,
    METRICS.signals.sigbus,
    "signals",
    "sigbus",
    log_fault
);

generate_handler!(
    sigsegv_handler,
    SIGSEGV,
    SIGSEGV,
    METRICS.signals.sigsegv,
    "signals",
    "sigsegv",
    log_fault
);

generate_handler!(
    sigsys_handler,
    SIGSYS,
    BadSyscall,
    METRICS.seccomp.num_faults,
    "seccomp",
    "num_faults",
    log_sigsys_err
);

generate_handler!(
    sighup_handler,
    SIGHUP,
    SIGHUP,
    METRICS.signals.sighup,
    "signals",
    "sighup",
    empty_fn
);
generate_handler!(
    sigill_handler,
    SIGILL,
    SIGILL,
    METRICS.signals.sigill,
    "signals",
    "sigill",
    log_fault
);

thread_local! {
    /// Whether the `SIGPIPE` pending on the calling thread is its handler's own: raised
    /// by its write of its line, the reader of the logger's target gone, as the one it handled
    /// was, most likely ([`signal_safe::log`]), and delivered as it returns.
    static OWN_SIGPIPE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[inline(always)]
extern "C" fn sigpipe_handler(num: c_int, info: *mut siginfo_t, _unused: *mut c_void) {
    // Just record the metric and allow the process to continue, the EPIPE error needs
    // to be handled at caller level.
    // Async-signal-safe, as the fatal signals' handlers (`generate_handler!`), errno left as it
    // was found, and its own write's SIGPIPE taken for none.
    let _errno = KeptErrno::keep();
    if OWN_SIGPIPE.replace(false) {
        return;
    }

    // SAFETY: Safe because we're just reading some fields from a supposedly valid argument.
    let si_signo = unsafe { (*info).si_signo };
    // SAFETY: Safe because we're just reading some fields from a supposedly valid argument.
    let si_code = unsafe { (*info).si_code };

    if num != si_signo || num != SIGPIPE {
        let broke =
            log_from_signal_handler!("Received invalid signal {}, code {}.", si_signo, si_code);
        OWN_SIGPIPE.set(broke);
        return;
    }

    METRICS.signals.sigpipe.inc();

    let broke = log_from_signal_handler!("Received signal {}, code {}.", si_signo, si_code);
    OWN_SIGPIPE.set(broke);
}

/// Registers `handler` for `num` as `register_signal_handler` does, all signals blocked while it
/// runs, and to run on the thread's alternate signal stack ([`install_signal_stack`]): a thread
/// that overflowed its stack has none left to run it on, and the kernel, unable to deliver the
/// signal, kills the process with it, the handler never run.
fn register_signal_handler_on_stack(num: c_int, handler: SignalHandler) -> errno::Result<()> {
    // SAFETY: Safe, because this is a POD struct.
    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = handler as *const () as usize;
    act.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
    // SAFETY: Safe because the parameter is valid and we check the return value.
    if unsafe { libc::sigfillset(&mut act.sa_mask) } < 0 {
        return errno::errno_result();
    }
    // SAFETY: Safe because the parameters are valid and we check the return value.
    match unsafe { libc::sigaction(num, &act, null_mut()) } {
        0 => Ok(()),
        _ => errno::errno_result(),
    }
}

/// Registers all the required signal handlers, and gives the calling thread an alternate stack
/// to run them on ([`install_signal_stack`]).
///
/// Custom handlers are installed for: `SIGBUS`, `SIGSEGV`, `SIGSYS`
/// `SIGXFSZ` `SIGXCPU` `SIGPIPE` `SIGHUP` and `SIGILL`.
pub fn register_signal_handlers() -> errno::Result<()> {
    // Call to unsafe register_signal_handler which is considered unsafe because it will
    // register a signal handler which will be called in the current thread and will interrupt
    // whatever work is done on the current thread, so we have to keep in mind that the registered
    // signal handler must only do async-signal-safe operations.
    register_signal_handler_on_stack(SIGSYS, sigsys_handler)?;
    register_signal_handler_on_stack(SIGBUS, sigbus_handler)?;
    register_signal_handler_on_stack(SIGSEGV, sigsegv_handler)?;
    register_signal_handler_on_stack(SIGXFSZ, sigxfsz_handler)?;
    register_signal_handler_on_stack(SIGXCPU, sigxcpu_handler)?;
    register_signal_handler_on_stack(SIGPIPE, sigpipe_handler)?;
    register_signal_handler_on_stack(SIGHUP, sighup_handler)?;
    register_signal_handler_on_stack(SIGILL, sigill_handler)?;
    install_signal_stack();
    Ok(())
}

/// The size of each thread's alternate signal stack, besides its guard page: room for the
/// handlers, which format their line on it, and for the frame the kernel saves the registers in,
/// some kilobytes on hosts with large vector registers (`AT_MINSIGSTKSZ`); Rust's standard
/// library gives a thread `SIGSTKSZ`, 8 KiB, not enough for both. Only the pages a handler touches
/// are ever allocated.
const SIGNAL_STACK_SIZE: usize = 256 << 10;

/// An alternate signal stack, which unmaps it as it drops, at its thread's end, once not the
/// thread's any more.
#[derive(Debug)]
struct SignalStack {
    /// The mapping: its guard page, then the stack, from `stack`.
    map: *mut c_void,
    len: usize,
    stack: *mut c_void,
}

impl SignalStack {
    /// Maps one, below its guard page.
    fn new() -> errno::Result<Self> {
        let guard_size = host_page_size();
        let len = guard_size + SIGNAL_STACK_SIZE;
        // SAFETY: Safe because the mapping is new and anonymous, and we check the result. The
        // flags are those Rust's standard library maps its threads' alternate signal stacks with.
        let map = unsafe {
            libc::mmap(
                null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_STACK,
                -1,
                0,
            )
        };
        if map == libc::MAP_FAILED {
            return errno::errno_result();
        }
        let signal_stack = SignalStack {
            map,
            len,
            // SAFETY: Safe because the stack starts within the mapping, past its guard page.
            stack: unsafe { map.add(guard_size) },
        };
        // SAFETY: Safe because the page is the mapping's first, which nothing uses.
        if unsafe { libc::mprotect(map, guard_size, libc::PROT_NONE) } != 0 {
            return errno::errno_result();
        }
        Ok(signal_stack)
    }

    /// Makes it the calling thread's alternate signal stack.
    fn install(&self) -> errno::Result<()> {
        let stack = libc::stack_t {
            ss_sp: self.stack,
            ss_flags: 0,
            ss_size: SIGNAL_STACK_SIZE,
        };
        // SAFETY: Safe because the stack is mapped as long as `self` is, which disables it, if
        // still the thread's, before unmapping it.
        match unsafe { libc::sigaltstack(&stack, null_mut()) } {
            0 => Ok(()),
            _ => errno::errno_result(),
        }
    }
}

impl Drop for SignalStack {
    fn drop(&mut self) {
        // SAFETY: Safe, because this is a POD struct.
        let mut current: libc::stack_t = unsafe { std::mem::zeroed() };
        // SAFETY: Safe because it only reads the thread's alternate signal stack.
        unsafe { libc::sigaltstack(std::ptr::null(), &mut current) };
        if current.ss_flags & libc::SS_DISABLE == 0 && current.ss_sp == self.stack {
            let disable = libc::stack_t {
                ss_sp: null_mut(),
                ss_flags: libc::SS_DISABLE,
                ss_size: 0,
            };
            // SAFETY: Safe because it only disables the thread's alternate signal stack.
            unsafe { libc::sigaltstack(&disable, null_mut()) };
        }
        // SAFETY: Safe because the mapping is ours, and no thread's alternate signal stack.
        unsafe { libc::munmap(self.map, self.len) };
    }
}

thread_local! {
    /// The calling thread's alternate signal stack, which [`install_signal_stack`] mapped.
    static SIGNAL_STACK: RefCell<Option<SignalStack>> = const { RefCell::new(None) };
}

/// Gives the calling thread an alternate stack, of 256 KiB below a guard page, for the fatal
/// signals' handlers [`register_signal_handlers`] registers to run on. Each thread that can fault
/// calls it as it starts, as Rust's standard library maps its own, and with the same calls: before
/// the thread installs a seccomp filter of its own, as the vCPUs' and the API's allow neither its
/// `mmap` nor its `mprotect`. If it can't, it says why, and the thread goes on with the alternate
/// stack Rust's standard library gave it: too small for the handlers, which overflow it, and the
/// kernel kills the process with the signal.
pub fn install_signal_stack() {
    // Its name, for the handlers to say (`logger::signal_safe`).
    signal_safe::record_thread_name();
    #[cfg(feature = "cladefs")]
    fault::record_thread();
    SIGNAL_STACK.with_borrow_mut(|installed| {
        if installed.is_some() {
            return;
        }
        match SignalStack::new().and_then(|stack| stack.install().map(|()| stack)) {
            Ok(stack) => *installed = Some(stack),
            Err(err) => error!(
                "Failed to install the thread's alternate signal stack: {}",
                err
            ),
        }
    });
}

/// cladefs: what the handlers of faults say of them: on which thread, where, and whether in the
/// guard below the thread's stack, a stack overflow (cladefs TASK-137).
#[cfg(feature = "cladefs")]
mod fault {
    use std::cell::Cell;
    use std::ptr::null_mut;

    use libc::{c_int, siginfo_t};

    use crate::arch::host_page_size;
    use crate::logger::signal_safe::{self, log_from_signal_handler};

    /// Says on which thread a fault was, where, and whether in the guard below the thread's
    /// stack: a stack overflow. Async-signal-safe, as its handler (board 8499).
    pub(super) fn log_fault(si_code: c_int, info: *mut siginfo_t) {
        let thread = THREAD.get();
        let name = signal_safe::thread_name();
        let name = name
            .as_ref()
            .map_or("<unknown>", signal_safe::ThreadName::as_str);
        // A signal sent, by `kill` or the like, rather than raised by a fault, has no address.
        if si_code <= 0 {
            log_from_signal_handler!("Thread {} was sent the signal: no fault.", name);
            return;
        }
        // SAFETY: Safe because `info` is the kernel's, for a fault, which carries its address.
        let addr = unsafe { (*info).si_addr() } as usize;
        if thread.is_some_and(|thread| thread.guard.0 <= addr && addr < thread.guard.1) {
            log_from_signal_handler!(
                "Thread {} faulted at {:#x}, in the guard below its stack: it overflowed its stack.",
                name,
                addr
            );
        } else {
            log_from_signal_handler!("Thread {} faulted at {:#x}.", name, addr);
        }
    }

    /// What the fatal signals' handlers say of the thread they interrupt, which they can't ask for
    /// then: recorded as it starts, by [`record_thread`], beside its name
    /// (`signal_safe::record_thread_name`).
    #[derive(Debug, Clone, Copy)]
    struct ThreadInfo {
        /// The addresses, from and up to, of the guard below the thread's stack, where it faults
        /// as it overflows. On the main thread, with musl, those below the stack as it was when
        /// recorded, which the kernel grows as it needs: an overflow there faults lower, and is not
        /// told.
        guard: (usize, usize),
    }

    impl ThreadInfo {
        fn current() -> Self {
            ThreadInfo {
                guard: stack_guard().unwrap_or((0, 0)),
            }
        }
    }

    /// The addresses, from and up to, of the guard below the calling thread's stack, found as
    /// Rust's standard library finds it to tell a stack overflow.
    fn stack_guard() -> Option<(usize, usize)> {
        let mut attr = std::mem::MaybeUninit::<libc::pthread_attr_t>::zeroed();
        // SAFETY: Safe because `attr` is the calling thread's to fill in, and we check the result.
        if unsafe { libc::pthread_getattr_np(libc::pthread_self(), attr.as_mut_ptr()) } != 0 {
            return None;
        }
        let mut guard_size = 0;
        let mut stack = null_mut();
        let mut stack_size = 0;
        // SAFETY: Safe because `attr` was filled in, and is destroyed once read.
        let read = unsafe {
            let read = libc::pthread_attr_getguardsize(attr.as_ptr(), &mut guard_size) == 0
                && libc::pthread_attr_getstack(attr.as_ptr(), &mut stack, &mut stack_size) == 0;
            libc::pthread_attr_destroy(attr.as_mut_ptr());
            read
        };
        if !read {
            return None;
        }
        // musl before 1.1.19 says there is none.
        let guard_size = match guard_size {
            0 => host_page_size(),
            size => size,
        };
        let lowest = stack as usize;
        if cfg!(target_env = "musl") {
            Some((lowest - guard_size, lowest))
        } else {
            // glibc put the guard in the stack before 2.27, and below it since.
            Some((lowest - guard_size, lowest + guard_size))
        }
    }

    thread_local! {
        /// The calling thread, as [`record_thread`] recorded it. It doesn't drop, so a signal's
        /// handler reads it with no more than a load: no destructor to register, nor lock to take.
        static THREAD: Cell<Option<ThreadInfo>> = const { Cell::new(None) };
    }

    /// Records the calling thread, where its stack's guard is, for the handlers of faults to say:
    /// [`super::install_signal_stack`] does, as each thread starts.
    pub(super) fn record_thread() {
        THREAD.set(Some(ThreadInfo::current()));
    }
}

#[cfg(test)]
mod tests {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Output, Stdio};
    use std::time::Duration;

    use super::*;
    use crate::logger::{LOGGER, error_unrestricted};

    /// Set, to the fault to make, in the process a test runs again for it alone, as the handler
    /// exits.
    const FAULT: &str = "FC_TEST_SIGNAL_HANDLER_FAULT";

    /// How long the process [`run_alone`] starts has to exit: a handler that waits for a lock its
    /// thread holds never does.
    const EXIT_WITHIN: Duration = Duration::from_secs(20);

    /// The exit status of a process in which a signal's handler allocated
    /// ([`Forbidding`]).
    const ALLOCATED: i32 = 99;

    /// The test binary's allocator, the system's, which ends the process with [`ALLOCATED`] at
    /// once if a thread that forbade it allocates ([`forbid_allocation`]): a signal's handler,
    /// which would wait for ever for the allocator's lock if its thread held it.
    struct Forbidding;

    thread_local! {
        /// Whether the calling thread forbade allocation. It doesn't drop, so the allocator reads
        /// it with no more than a load.
        static FORBIDDEN: Cell<bool> = const { Cell::new(false) };
    }

    /// Forbids the calling thread to allocate: it ends the process with [`ALLOCATED`] if it does.
    fn forbid_allocation() {
        FORBIDDEN.set(true);
    }

    impl Forbidding {
        fn check() {
            if FORBIDDEN.get() {
                let said = b"allocated where it was forbidden\n";
                // SAFETY: Writes `said`, then ends the process, allocating nothing.
                unsafe {
                    libc::write(libc::STDERR_FILENO, said.as_ptr().cast(), said.len());
                    libc::_exit(ALLOCATED);
                }
            }
        }
    }

    // SAFETY: The system's allocator, which it calls as it is called.
    unsafe impl GlobalAlloc for Forbidding {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            Self::check();
            // SAFETY: As the caller promises.
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            Self::check();
            // SAFETY: As the caller promises.
            unsafe { System.dealloc(ptr, layout) }
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            Self::check();
            // SAFETY: As the caller promises.
            unsafe { System.realloc(ptr, layout, new_size) }
        }
    }

    #[global_allocator]
    static ALLOCATOR: Forbidding = Forbidding;

    /// Runs the test `name` of this module again, in a process of its own, with `FAULT` set to
    /// `fault`, which must exit within [`EXIT_WITHIN`]: killed then, the test fails.
    fn run_alone(name: &str, fault: &str) -> Output {
        let (_crate, module) = module_path!().split_once("::").unwrap();
        let test = format!("{module}::{name}");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([test.as_str(), "--exact", "--nocapture"])
            .env(FAULT, fault)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let read = |mut pipe: Box<dyn Read + Send>| {
            std::thread::spawn(move || {
                let mut read = Vec::new();
                pipe.read_to_end(&mut read).unwrap();
                read
            })
        };
        let stdout = read(Box::new(child.stdout.take().unwrap()));
        let stderr = read(Box::new(child.stderr.take().unwrap()));
        // SAFETY: Opens a pidfd of the child, which isn't waited for yet, checking the result.
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) };
        assert!(
            pidfd >= 0,
            "pidfd_open: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: Just opened, and owned here.
        let pidfd = unsafe { OwnedFd::from_raw_fd(i32::try_from(pidfd).unwrap()) };
        let mut exited = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let within = i32::try_from(EXIT_WITHIN.as_millis()).unwrap();
        // SAFETY: Polls the pidfd, which outlives the call.
        let ready = unsafe { libc::poll(&mut exited, 1, within) };
        assert!(ready >= 0, "poll: {}", std::io::Error::last_os_error());
        if ready == 0 {
            child.kill().unwrap();
        }
        let status = child.wait().unwrap();
        let output = Output {
            status,
            stdout: stdout.join().unwrap(),
            stderr: stderr.join().unwrap(),
        };
        assert_ne!(
            ready, 0,
            "{fault}: the process didn't exit within {EXIT_WITHIN:?}: {output:?}"
        );
        output
    }

    /// In the process [`run_alone`] starts, registers the handlers and runs `fault` on a thread of
    /// its own, `fc_fault`, as Firecracker starts its threads, which the handler ends with the
    /// process.
    fn fault_on_a_thread(fault: impl FnOnce() + Send + 'static) -> ! {
        LOGGER.init().unwrap();
        register_signal_handlers().unwrap();
        let faulting = std::thread::Builder::new()
            .name("fc_fault".to_owned())
            .stack_size(256 << 10)
            .spawn(move || {
                install_signal_stack();
                fault();
            })
            .unwrap();
        panic!("The fault returned: {:?}", faulting.join());
    }

    /// Recurses until the thread's stack overflows: each frame kept until the call it makes
    /// returns, which it never does, so no optimization makes the recursion a loop.
    #[allow(unconditional_recursion)]
    fn overflow(depth: u64) -> u64 {
        let frame = std::hint::black_box([depth; 64]);
        overflow(depth + 1) + std::hint::black_box(frame)[63]
    }

    // A thread that overflows its stack has the SIGSEGV handler run, on its alternate stack, which
    // says so and exits with SIGSEGV's code: not the kernel killing the process with the signal,
    // the handler never run, as it did with no stack left to run it on.
    #[test]
    fn test_stack_overflow_runs_the_handler() {
        if std::env::var_os(FAULT).is_some_and(|fault| fault == "overflow") {
            fault_on_a_thread(|| {
                overflow(0);
            });
        }
        let output = run_alone("test_stack_overflow_runs_the_handler", "overflow");
        assert_eq!(
            output.status.code(),
            Some(FcExitCode::SIGSEGV as i32),
            "{output:?}"
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("] Shutting down VM after intercepting signal 11, code "),
            "{output:?}"
        );
        // cladefs: and says the thread overflowed its stack.
        #[cfg(feature = "cladefs")]
        {
            let line = fault_line(&output);
            assert!(
                line.ends_with(", in the guard below its stack: it overflowed its stack."),
                "{line}"
            );
        }
    }

    /// cladefs: the line of the handler's log that says where the fault was.
    #[cfg(feature = "cladefs")]
    fn fault_line(output: &Output) -> String {
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .lines()
            .find(|line| line.contains("] Thread fc_fault faulted at "))
            .unwrap_or_else(|| panic!("No fault logged: {output:?}"))
            .to_owned()
    }

    // cladefs: the SIGSEGV handler says where a thread faulted, and doesn't take it for an overflow
    // (TASK-137).
    #[cfg(feature = "cladefs")]
    #[test]
    fn test_fault_logs_its_address() {
        if std::env::var_os(FAULT).is_some_and(|fault| fault == "address") {
            fault_on_a_thread(|| {
                // SAFETY: The store faults, as the test wants, at an address nothing maps: it
                // writes nothing.
                unsafe { std::ptr::without_provenance_mut::<u8>(0x10).write_volatile(1) };
            });
        }
        let output = run_alone("test_fault_logs_its_address", "address");
        assert_eq!(
            output.status.code(),
            Some(FcExitCode::SIGSEGV as i32),
            "{output:?}"
        );
        let line = fault_line(&output);
        assert!(
            line.ends_with("] Thread fc_fault faulted at 0x10."),
            "{line}"
        );
    }

    /// A metric's group and name, as the metrics' JSON has them.
    type Metric = (&'static str, &'static str);

    /// The fatal signals the handlers exit for, raised by `raise`, which sends them, the codes
    /// they exit with, and the metric each writes, by its group and name: `SIGSYS` exits with
    /// `UnexpectedError`, sent, not a bad system call, before its metric is written.
    const FATAL: [(c_int, FcExitCode, Option<Metric>); 7] = [
        (SIGBUS, FcExitCode::SIGBUS, Some(("signals", "sigbus"))),
        (SIGSEGV, FcExitCode::SIGSEGV, Some(("signals", "sigsegv"))),
        (SIGILL, FcExitCode::SIGILL, Some(("signals", "sigill"))),
        (SIGSYS, FcExitCode::UnexpectedError, None),
        (SIGXFSZ, FcExitCode::SIGXFSZ, Some(("signals", "sigxfsz"))),
        (SIGXCPU, FcExitCode::SIGXCPU, Some(("signals", "sigxcpu"))),
        (SIGHUP, FcExitCode::SIGHUP, Some(("signals", "sighup"))),
    ];

    // Each fatal signal's handler, on a thread that holds the logger's lock, says so and exits
    // with the signal's code, taking no lock and allocating nothing, as a handler must: it
    // interrupts its thread anywhere, which may hold the logger's lock, or the allocator's. The
    // handlers logged through the logger, and waited for ever for its lock. Each writes its
    // signal's metric to the metrics' file, a line of its own.
    #[test]
    fn test_fatal_signals_take_no_lock() {
        if let Some(fault) = std::env::var_os(FAULT) {
            let fault = fault.to_str().unwrap().to_owned();
            if let Some(locked) = fault.strip_prefix("locked ") {
                let (signal, metrics) = locked.split_once(' ').unwrap();
                let signal: c_int = signal.parse().unwrap();
                let metrics_path = std::path::PathBuf::from(metrics);
                crate::vmm_config::metrics::init_metrics(
                    crate::vmm_config::metrics::MetricsConfig { metrics_path },
                )
                .unwrap();
                fault_on_a_thread(move || {
                    let _held = LOGGER.0.lock().unwrap();
                    forbid_allocation();
                    // SAFETY: Raises the signal on this thread, whose handler exits.
                    unsafe { libc::raise(signal) };
                });
            }
        }
        let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        for (signal, code, metric) in FATAL {
            let metrics = dir.as_path().join(format!("metrics-{signal}"));
            let output = run_alone(
                "test_fatal_signals_take_no_lock",
                &format!("locked {signal} {}", metrics.display()),
            );
            assert_eq!(
                (output.status.code(), output.status.signal()),
                (Some(code as i32), None),
                "signal {signal}: {output:?}"
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            let said = format!(
                " [anonymous-instance:fc_fault] Shutting down VM after intercepting signal {signal}, code "
            );
            assert!(stdout.contains(&said), "signal {signal}: {output:?}");
            let lines = std::fs::read_to_string(&metrics).unwrap();
            let written = match lines.lines().last() {
                Some(line) => {
                    let line: serde_json::Value = serde_json::from_str(line).unwrap();
                    let (group, name) = metric.expect("no metric written");
                    Some((group, name, line[group][name].as_u64()))
                }
                None => None,
            };
            assert_eq!(
                written,
                metric.map(|(group, name)| (group, name, Some(1))),
                "signal {signal}: metrics {lines:?}"
            );
        }
    }

    // A SIGPIPE raised by the logger's own write, its target a FIFO whose reader went, on the
    // thread that holds the logger's lock, is counted, and the write fails, which the logger
    // counts as a line missed: the handler took the logger's lock again, and waited for ever. Its
    // own line, written to the same FIFO, raises SIGPIPE again, which it takes for its own, not
    // counted. Once a reader opens the FIFO again, the handlers' lines reach it: a latch that
    // stopped them at the first EPIPE silenced them for good.
    #[test]
    fn test_sigpipe_from_the_loggers_write_takes_no_lock() {
        if std::env::var_os(FAULT).is_some_and(|fault| fault == "sigpipe") {
            LOGGER.init().unwrap();
            register_signal_handlers().unwrap();
            use std::os::unix::fs::OpenOptionsExt;
            let dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
            let fifo = dir.as_path().join("log");
            let path = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
            // SAFETY: Makes a FIFO at a path of the test's, checking the result.
            assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            let open_reader = || {
                std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(&fifo)
                    .unwrap()
            };
            let reader = open_reader();
            let target = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&fifo)
                .unwrap();
            signal_safe::set_log_target(&target).unwrap();
            LOGGER.0.lock().unwrap().target = Some(target);
            // The logger's target, a FIFO whose reader went.
            drop(reader);
            error_unrestricted!("A line to a FIFO whose reader went.");
            error_unrestricted!("Another.");
            assert_eq!(
                (
                    METRICS.signals.sigpipe.count(),
                    METRICS.logger.missed_log_count.count()
                ),
                (2, 2),
                "(SIGPIPEs, lines missed)"
            );
            // Its reader back, the handlers' lines reach it again.
            let mut reader = open_reader();
            let broke = log_from_signal_handler!("After its reader came back.");
            assert!(!broke);
            // All it holds, then EAGAIN, the FIFO's writer open still.
            let mut read = Vec::new();
            reader.read_to_end(&mut read).unwrap_err();
            let read = String::from_utf8_lossy(&read);
            assert!(
                read.ends_with("] After its reader came back.\n"),
                "{read:?}"
            );
            return;
        }
        let output = run_alone(
            "test_sigpipe_from_the_loggers_write_takes_no_lock",
            "sigpipe",
        );
        assert_eq!(output.status.code(), Some(0), "{output:?}");
    }
}
