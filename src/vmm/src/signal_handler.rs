// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::cell::{Cell, RefCell};
use std::ptr::null_mut;

use libc::{
    SIGBUS, SIGHUP, SIGILL, SIGPIPE, SIGSEGV, SIGSYS, SIGXCPU, SIGXFSZ, c_int, c_void, siginfo_t,
};
use vmm_sys_util::errno;

use crate::FcExitCode;
use crate::arch::host_page_size;
use crate::logger::{IncMetric, METRICS, StoreMetric, error, error_unrestricted};
use crate::utils::signal::SignalHandler;

// The offset of `si_syscall` (offending syscall identifier) within the siginfo structure
// expressed as an `(u)int*`.
// Offset `6` for an `i32` field means that the needed information is located at `6 * sizeof(i32)`.
// See /usr/include/linux/signal.h for the C struct definition.
// See https://github.com/rust-lang/libc/issues/716 for why the offset is different in Rust.
const SI_OFF_SYSCALL: isize = 6;

const SYS_SECCOMP_CODE: i32 = 1;

#[inline]
fn exit_with_code(exit_code: FcExitCode) {
    // Write the metrics before exiting.
    if let Err(err) = METRICS.write() {
        error_unrestricted!("Failed to write metrics while stopping: {}", err);
    }
    // SAFETY: Safe because we're terminating the process anyway.
    unsafe { libc::_exit(exit_code as i32) };
}

macro_rules! generate_handler {
    ($fn_name:ident ,$signal_name:ident, $exit_code:ident, $signal_metric:expr, $body:ident) => {
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

            error_unrestricted!(
                "Shutting down VM after intercepting signal {}, code {}.",
                si_signo,
                si_code
            );

            $body(si_code, info);

            match si_signo {
                $signal_name => exit_with_code(crate::FcExitCode::$exit_code),
                _ => exit_with_code(FcExitCode::UnexpectedError),
            };
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
    error_unrestricted!(
        "Shutting down VM after intercepting a bad syscall ({}).",
        syscall
    );
}

/// fxdax: says on which thread a fault was, where, and whether in the guard below the thread's
/// stack: a stack overflow (TASK-137).
fn log_fault(si_code: c_int, info: *mut siginfo_t) {
    let thread = THREAD.get();
    let name = thread.as_ref().map_or("<unknown>", ThreadInfo::name);
    // A signal sent, by `kill` or the like, rather than raised by a fault, has no address.
    if si_code <= 0 {
        error_unrestricted!("Thread {} was sent the signal: no fault.", name);
        return;
    }
    // SAFETY: Safe because `info` is the kernel's, for a fault, which carries its address.
    let addr = unsafe { (*info).si_addr() } as usize;
    if thread.is_some_and(|thread| thread.guard.0 <= addr && addr < thread.guard.1) {
        error_unrestricted!(
            "Thread {} faulted at {:#x}, in the guard below its stack: it overflowed its stack.",
            name,
            addr
        );
    } else {
        error_unrestricted!("Thread {} faulted at {:#x}.", name, addr);
    }
}

fn empty_fn(_si_code: c_int, _info: *mut siginfo_t) {}

generate_handler!(
    sigxfsz_handler,
    SIGXFSZ,
    SIGXFSZ,
    METRICS.signals.sigxfsz,
    empty_fn
);

generate_handler!(
    sigxcpu_handler,
    SIGXCPU,
    SIGXCPU,
    METRICS.signals.sigxcpu,
    empty_fn
);

generate_handler!(
    sigbus_handler,
    SIGBUS,
    SIGBUS,
    METRICS.signals.sigbus,
    log_fault
);

generate_handler!(
    sigsegv_handler,
    SIGSEGV,
    SIGSEGV,
    METRICS.signals.sigsegv,
    log_fault
);

generate_handler!(
    sigsys_handler,
    SIGSYS,
    BadSyscall,
    METRICS.seccomp.num_faults,
    log_sigsys_err
);

generate_handler!(
    sighup_handler,
    SIGHUP,
    SIGHUP,
    METRICS.signals.sighup,
    empty_fn
);
generate_handler!(
    sigill_handler,
    SIGILL,
    SIGILL,
    METRICS.signals.sigill,
    log_fault
);

#[inline(always)]
extern "C" fn sigpipe_handler(num: c_int, info: *mut siginfo_t, _unused: *mut c_void) {
    // Just record the metric and allow the process to continue, the EPIPE error needs
    // to be handled at caller level.

    // SAFETY: Safe because we're just reading some fields from a supposedly valid argument.
    let si_signo = unsafe { (*info).si_signo };
    // SAFETY: Safe because we're just reading some fields from a supposedly valid argument.
    let si_code = unsafe { (*info).si_code };

    if num != si_signo || num != SIGPIPE {
        error_unrestricted!("Received invalid signal {}, code {}.", si_signo, si_code);
        return;
    }

    METRICS.signals.sigpipe.inc();

    error_unrestricted!("Received signal {}, code {}.", si_signo, si_code);
}

/// fxdax: registers `handler` for `num` as `register_signal_handler` does, all signals blocked
/// while it runs, and to run on the thread's alternate signal stack ([`install_signal_stack`]):
/// a thread that overflowed its stack has none left to run it on, and the kernel, unable to
/// deliver the signal, kills the process with it, the handler never run (TASK-137).
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

/// fxdax: the size of each thread's alternate signal stack, besides its guard page: room for the
/// handlers, which log and write the metrics, and for the frame the kernel saves the registers in,
/// some kilobytes on hosts with large vector registers (`AT_MINSIGSTKSZ`); Rust's standard
/// library gives a thread `SIGSTKSZ`, 8 KiB, not enough for both. Only the pages a handler touches
/// are ever allocated.
const SIGNAL_STACK_SIZE: usize = 256 << 10;

/// fxdax: what the fatal signals' handlers say of the thread they interrupt, which they can't ask
/// for then: recorded as it starts, by [`install_signal_stack`].
#[derive(Debug, Clone, Copy)]
struct ThreadInfo {
    /// The thread's name, as much of it as fits, cut at a character's boundary.
    name: [u8; 32],
    name_len: usize,
    /// The addresses, from and up to, of the guard below the thread's stack, where it faults as it
    /// overflows. On the main thread, with musl, those below the stack as it was when recorded,
    /// which the kernel grows as it needs: an overflow there faults lower, and is not told.
    guard: (usize, usize),
}

impl ThreadInfo {
    fn current() -> Self {
        let mut name = [0; 32];
        let current = std::thread::current();
        let whole = current.name().unwrap_or("<unnamed>");
        let mut name_len = whole.len().min(name.len());
        while !whole.is_char_boundary(name_len) {
            name_len -= 1;
        }
        name[..name_len].copy_from_slice(&whole.as_bytes()[..name_len]);
        ThreadInfo {
            name,
            name_len,
            guard: stack_guard().unwrap_or((0, 0)),
        }
    }

    fn name(&self) -> &str {
        std::str::from_utf8(&self.name[..self.name_len]).unwrap_or("<unknown>")
    }
}

/// fxdax: the addresses, from and up to, of the guard below the calling thread's stack, found as
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

/// fxdax: an alternate signal stack, which unmaps it as it drops, at its thread's end, once not
/// the thread's any more.
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
        // flags are those Rust's standard library maps its threads' alternate signal stacks with,
        // which the VMM's seccomp filter allows.
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
    /// The calling thread, as [`install_signal_stack`] recorded it. It doesn't drop, so a signal's
    /// handler reads it with no more than a load: no destructor to register, nor lock to take.
    static THREAD: Cell<Option<ThreadInfo>> = const { Cell::new(None) };
    /// The calling thread's alternate signal stack, which [`install_signal_stack`] mapped.
    static SIGNAL_STACK: RefCell<Option<SignalStack>> = const { RefCell::new(None) };
}

/// fxdax: gives the calling thread an alternate stack, of 256 KiB below a guard page, for the
/// fatal signals' handlers [`register_signal_handlers`] registers to run on, and records what they
/// say of the thread: its name, and where its stack's guard is (TASK-137). Each thread that can
/// fault calls it as it starts, as Rust's standard library maps its own, and with the same calls:
/// before the thread installs a seccomp filter of its own, as the vCPUs' and the API's allow
/// neither its `mmap` nor its `mprotect`; the VMM's, which the threads started under it inherit,
/// does. If it can't, it says why, and the thread goes on with the alternate stack Rust's standard
/// library gave it: too small for the handlers, which overflow it, and the kernel kills the
/// process with the signal.
pub fn install_signal_stack() {
    THREAD.set(Some(ThreadInfo::current()));
    SIGNAL_STACK.with_borrow_mut(|installed| {
        if installed.is_some() {
            return;
        }
        match SignalStack::new().and_then(|stack| stack.install().map(|()| stack)) {
            Ok(stack) => *installed = Some(stack),
            Err(err) => error!("Failed to install the thread's alternate signal stack: {}", err),
        }
    });
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Output};

    use super::*;
    use crate::logger::LOGGER;

    /// Set, to the fault to make, in the process a test runs again for it alone, as the handler
    /// exits.
    const FAULT: &str = "FC_TEST_SIGNAL_HANDLER_FAULT";

    /// Runs the test `name` of this module again, in a process of its own, with `FAULT` set to
    /// `fault`.
    fn run_alone(name: &str, fault: &str) -> Output {
        let (_crate, module) = module_path!().split_once("::").unwrap();
        let test = format!("{module}::{name}");
        Command::new(std::env::current_exe().unwrap())
            .args([test.as_str(), "--exact", "--nocapture"])
            .env(FAULT, fault)
            .output()
            .unwrap()
    }

    /// In the process [`run_alone`] starts, registers the handlers and runs `fault` on a thread of
    /// its own, `fc_fault`, as Firecracker starts its threads, which the handler ends with the
    /// process.
    fn fault_on_a_thread(fault: fn()) -> ! {
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

    /// The line of the handler's log that says where the fault was.
    fn fault_line(output: &Output) -> String {
        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .lines()
            .find(|line| line.contains("] Thread fc_fault faulted at "))
            .unwrap_or_else(|| panic!("No fault logged: {output:?}"))
            .to_owned()
    }

    /// Recurses until the thread's stack overflows: each frame kept until the call it makes
    /// returns, which it never does, so no optimization makes the recursion a loop.
    #[allow(unconditional_recursion)]
    fn overflow(depth: u64) -> u64 {
        let frame = std::hint::black_box([depth; 64]);
        overflow(depth + 1) + std::hint::black_box(frame)[63]
    }

    // fxdax: a thread that overflows its stack has the SIGSEGV handler run, on its alternate
    // stack, which says so and exits with SIGSEGV's code: not the kernel killing the process with
    // the signal, the handler never run, as it did with no stack left to run it on (TASK-137).
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
        let line = fault_line(&output);
        assert!(
            line.ends_with(", in the guard below its stack: it overflowed its stack."),
            "{line}"
        );
    }

    // fxdax: the SIGSEGV handler says where a thread faulted, and doesn't take it for an overflow
    // (TASK-137).
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
        assert!(line.ends_with("] Thread fc_fault faulted at 0x10."), "{line}");
    }
}
