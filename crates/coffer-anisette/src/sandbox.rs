// Coffer: a native Linux client for Apple Passwords.
// Copyright (C) 2026  Hong Minhee
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Mandatory Linux resource and syscall confinement.
//!
//! The filter is installed after the request, libraries, and disposable state
//! directory have been opened, but before any proprietary instruction runs.
//! Network syscalls are absent from the allowlist and deterministically return
//! `EPERM`.  Linux Landlock denies filesystem access outside that disposable
//! directory.  Any failure to apply or verify a layer stops the helper.

use std::ffi::{CString, c_int};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::error::BridgeError;

const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

// These declarations follow Linux's public `linux/landlock.h` UAPI:
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/landlock.h
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
const LANDLOCK_ACCESS_FS_V1: u64 = LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_READ_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM;
const STATE_DIRECTORY_ACCESS: u64 = LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_READ_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_REFER
    | LANDLOCK_ACCESS_FS_TRUNCATE;

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

const _: () = assert!(size_of::<LandlockRulesetAttr>() == 8);
const _: () = assert!(size_of::<LandlockPathBeneathAttr>() == 16);

/// Arms the helper's parent-death signal before it reads or validates input.
#[allow(unsafe_code)]
pub(crate) fn arm_parent_death() -> Result<(), BridgeError> {
    // SAFETY: `getppid` has no pointer arguments, and `prctl` receives only the
    // documented scalar death-signal arguments.
    let parent = unsafe { libc::getppid() };
    // SAFETY: the call receives only the documented scalar death-signal
    // arguments and installs no user pointer.
    let armed = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) };
    if parent <= 1 || armed != 0 {
        return Err(BridgeError::SandboxUnavailable);
    }
    // Linux does not retroactively deliver the signal if the parent died just
    // before prctl.  Re-reading closes that race before any expensive work.
    // SAFETY: `getppid` has no pointer arguments or memory preconditions.
    let current_parent = unsafe { libc::getppid() };
    if current_parent == parent {
        Ok(())
    } else {
        Err(BridgeError::SandboxUnavailable)
    }
}

/// Applies every mandatory sandbox layer and returns the confined state root.
pub(crate) fn apply(state_directory: &Path) -> Result<OwnedFd, BridgeError> {
    close_inherited_descriptors()?;
    apply_limits()?;
    configure_process()?;
    apply_landlock(state_directory)?;
    let state = open_state_directory(state_directory)?;
    verify_filesystem_boundary(&state)?;
    install_seccomp(std::os::fd::AsRawFd::as_raw_fd(&state))?;
    verify_network_denied()?;
    verify_path_syscall_filter(state_directory, &state)?;
    verify_cross_process_syscalls_denied()?;
    Ok(state)
}

#[allow(unsafe_code)]
fn close_inherited_descriptors() -> Result<(), BridgeError> {
    // SAFETY: the helper protocol uses only stdin/stdout.  Closing every
    // descriptor from 3 upward prevents inherited sockets or secret-bearing
    // handles from crossing the proprietary execution boundary.
    let result = unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) };
    if result == 0 {
        Ok(())
    } else {
        Err(BridgeError::SandboxUnavailable)
    }
}

#[allow(unsafe_code)]
fn apply_limits() -> Result<(), BridgeError> {
    for (resource, current, maximum) in [
        (libc::RLIMIT_CORE, 0, 0),
        (libc::RLIMIT_FSIZE, 16 * 1024 * 1024, 16 * 1024 * 1024),
        (libc::RLIMIT_NOFILE, 32, 32),
        (libc::RLIMIT_NPROC, 1, 1),
        (libc::RLIMIT_CPU, 10, 10),
        (libc::RLIMIT_AS, 512 * 1024 * 1024, 512 * 1024 * 1024),
    ] {
        let limit = libc::rlimit {
            rlim_cur: current,
            rlim_max: maximum,
        };
        // SAFETY: `limit` is a live `rlimit`; every resource is a Linux
        // RLIMIT constant and the call only narrows this helper process.
        if unsafe { libc::setrlimit(resource, &limit) } != 0 {
            return Err(BridgeError::SandboxUnavailable);
        }
    }
    Ok(())
}

#[allow(unsafe_code)]
fn configure_process() -> Result<(), BridgeError> {
    // SAFETY: these prctl operations accept scalar arguments.  They disable
    // dumpability and irreversibly prevent privilege gain before Landlock and
    // the seccomp filter are installed.
    let results = unsafe {
        [
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0),
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
        ]
    };
    if results == [0; 2] {
        Ok(())
    } else {
        Err(BridgeError::SandboxUnavailable)
    }
}

#[allow(unsafe_code)]
fn apply_landlock(state_directory: &Path) -> Result<(), BridgeError> {
    // SAFETY: a null attribute with the VERSION flag is the kernel UAPI query.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<LandlockRulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi < 1 {
        return Err(BridgeError::SandboxUnavailable);
    }
    let mut handled = LANDLOCK_ACCESS_FS_V1;
    if abi >= 2 {
        handled |= LANDLOCK_ACCESS_FS_REFER;
    }
    if abi >= 3 {
        handled |= LANDLOCK_ACCESS_FS_TRUNCATE;
    }
    let ruleset_attr = LandlockRulesetAttr {
        handled_access_fs: handled,
    };
    // SAFETY: the pointer and exact UAPI structure size are valid for the call.
    let ruleset_raw = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::from_ref(&ruleset_attr),
            size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };
    let ruleset = owned_fd(ruleset_raw)?;
    let directory = CString::new(state_directory.as_os_str().as_bytes())
        .map_err(|_| BridgeError::SandboxUnavailable)?;
    // SAFETY: the bounded C string is live; O_PATH opens only a reference used
    // for the PATH_BENEATH rule and cannot read directory contents.
    let parent_raw = unsafe {
        libc::open(
            directory.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    let parent = owned_fd(parent_raw.into())?;
    let path_attr = LandlockPathBeneathAttr {
        allowed_access: STATE_DIRECTORY_ACCESS & handled,
        parent_fd: std::os::fd::AsRawFd::as_raw_fd(&parent),
    };
    // SAFETY: both owned descriptors and the exact UAPI rule structure remain
    // live for the calls. `no_new_privs` was irreversibly set first.
    let added = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            std::os::fd::AsRawFd::as_raw_fd(&ruleset),
            LANDLOCK_RULE_PATH_BENEATH,
            std::ptr::from_ref(&path_attr),
            0u32,
        )
    };
    // SAFETY: the ruleset descriptor is live and the second argument must be
    // zero in the current Landlock UAPI.
    let restricted = unsafe {
        libc::syscall(
            libc::SYS_landlock_restrict_self,
            std::os::fd::AsRawFd::as_raw_fd(&ruleset),
            0u32,
        )
    };
    if added != 0 || restricted != 0 {
        return Err(BridgeError::SandboxUnavailable);
    }
    Ok(())
}

#[allow(unsafe_code)]
fn open_state_directory(state_directory: &Path) -> Result<OwnedFd, BridgeError> {
    let directory = CString::new(state_directory.as_os_str().as_bytes())
        .map_err(|_| BridgeError::SandboxUnavailable)?;
    // SAFETY: the live C string names the already validated state root.  This
    // descriptor becomes the only pathname capability exposed after seccomp.
    let raw = unsafe {
        libc::open(
            directory.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    owned_fd(raw.into())
}

#[allow(unsafe_code)]
fn owned_fd(raw: libc::c_long) -> Result<OwnedFd, BridgeError> {
    let descriptor = i32::try_from(raw).map_err(|_| BridgeError::SandboxUnavailable)?;
    if descriptor < 0 {
        return Err(BridgeError::SandboxUnavailable);
    }
    // SAFETY: a successful open or ruleset syscall returned a fresh descriptor
    // whose sole ownership transfers to this RAII wrapper.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

#[allow(unsafe_code)]
fn install_seccomp(state_descriptor: libc::c_int) -> Result<(), BridgeError> {
    let mut filter =
        Vec::with_capacity(ALLOWED_SYSCALLS.len() * 2 + CONSTRAINED_PATH_SYSCALLS.len() * 5 + 6);
    // struct seccomp_data.arch is the u32 at offset 4.
    filter.push(stmt(BPF_LD | BPF_W | BPF_ABS, 4));
    filter.push(jump(BPF_JMP | BPF_JEQ | BPF_K, audit_arch(), 1, 0));
    filter.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    // struct seccomp_data.nr is the i32 at offset 0.
    filter.push(stmt(BPF_LD | BPF_W | BPF_ABS, 0));
    for syscall in ALLOWED_SYSCALLS {
        filter.push(jump(BPF_JMP | BPF_JEQ | BPF_K, *syscall as u32, 0, 1));
        filter.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    }
    for syscall in CONSTRAINED_PATH_SYSCALLS {
        // A mismatched syscall skips the complete argument-check block.  A
        // match may proceed only when args[0] is the pre-opened state dirfd.
        filter.push(jump(BPF_JMP | BPF_JEQ | BPF_K, *syscall as u32, 0, 4));
        filter.push(stmt(BPF_LD | BPF_W | BPF_ABS, 16));
        filter.push(jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            state_descriptor as u32,
            0,
            1,
        ));
        filter.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
        filter.push(stmt(
            BPF_RET | BPF_K,
            SECCOMP_RET_ERRNO | (libc::EPERM as u32),
        ));
    }
    filter.push(stmt(
        BPF_RET | BPF_K,
        SECCOMP_RET_ERRNO | (libc::EPERM as u32),
    ));
    let length = u16::try_from(filter.len()).map_err(|_| BridgeError::SandboxUnavailable)?;
    let program = libc::sock_fprog {
        len: length,
        filter: filter.as_mut_ptr(),
    };
    // SAFETY: `program` points to `filter`, which remains live for the call;
    // no_new_privs was set first, as Linux requires for unprivileged filters.
    let result = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            std::ptr::from_ref(&program),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(BridgeError::SandboxUnavailable)
    }
}

#[allow(unsafe_code)]
fn verify_network_denied() -> Result<(), BridgeError> {
    // SAFETY: this deliberately attempts to create an ordinary IPv4 socket.
    // The descriptor is closed if a broken filter unexpectedly permits it.
    let descriptor = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if descriptor >= 0 {
        // SAFETY: `descriptor` was returned by socket and is owned here.
        unsafe { libc::close(descriptor) };
        return Err(BridgeError::SandboxUnavailable);
    }
    // SAFETY: glibc's thread-local errno pointer is valid for this thread.
    let errno = unsafe { *libc::__errno_location() };
    if errno == libc::EPERM {
        Ok(())
    } else {
        Err(BridgeError::SandboxUnavailable)
    }
}

#[allow(unsafe_code)]
fn verify_path_syscall_filter(
    state_directory: &Path,
    state_descriptor: &OwnedFd,
) -> Result<(), BridgeError> {
    let absolute = CString::new(state_directory.as_os_str().as_bytes())
        .map_err(|_| BridgeError::SandboxUnavailable)?;
    // SAFETY: this deliberately presents AT_FDCWD to the constrained openat
    // rule.  The path is otherwise allowed by Landlock, so only the argument
    // filter can produce EPERM.
    let outside_capability = unsafe {
        libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            absolute.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
        )
    };
    // SAFETY: glibc's thread-local errno pointer is valid for this thread.
    if outside_capability >= 0 || unsafe { *libc::__errno_location() } != libc::EPERM {
        if outside_capability >= 0 {
            // SAFETY: a nonnegative result is an unexpectedly opened fd.
            unsafe { libc::close(outside_capability as c_int) };
        }
        return Err(BridgeError::SandboxUnavailable);
    }

    // SAFETY: this uses the one allowed directory descriptor and a static
    // relative path, proving the filter did not merely block all filesystem
    // access.
    let inside = unsafe {
        libc::openat(
            std::os::fd::AsRawFd::as_raw_fd(state_descriptor),
            c".".as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if inside < 0 {
        return Err(BridgeError::SandboxUnavailable);
    }
    // SAFETY: `inside` is uniquely owned by this verification call.
    if unsafe { libc::close(inside) } == 0 {
        Ok(())
    } else {
        Err(BridgeError::SandboxUnavailable)
    }
}

#[allow(unsafe_code)]
fn verify_cross_process_syscalls_denied() -> Result<(), BridgeError> {
    // Signal zero has no effect even if a broken filter permits the syscall.
    // SAFETY: `getppid` has no pointer arguments.
    let parent = unsafe { libc::getppid() };
    // SAFETY: scalar-only syscall used to verify that tgkill is absent.
    let signal = unsafe { libc::syscall(libc::SYS_tgkill, parent, parent, 0) };
    // SAFETY: glibc's thread-local errno pointer is valid for this thread.
    if signal != -1 || unsafe { *libc::__errno_location() } != libc::EPERM {
        return Err(BridgeError::SandboxUnavailable);
    }

    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // A null new-limit pointer makes this read-only if a broken filter permits
    // it. SAFETY: the output points to live uninitialized storage.
    let prlimit = unsafe {
        libc::syscall(
            libc::SYS_prlimit64,
            parent,
            libc::RLIMIT_NOFILE,
            std::ptr::null::<libc::rlimit>(),
            limit.as_mut_ptr(),
        )
    };
    // SAFETY: glibc's thread-local errno pointer is valid for this thread.
    if prlimit == -1 && unsafe { *libc::__errno_location() } == libc::EPERM {
        Ok(())
    } else {
        Err(BridgeError::SandboxUnavailable)
    }
}

#[allow(unsafe_code)]
fn verify_filesystem_boundary(state_directory: &OwnedFd) -> Result<(), BridgeError> {
    let outside = c"/";
    // SAFETY: the static C string is valid; Landlock must deny reading any
    // directory outside the sole PATH_BENEATH rule.
    let outside_fd = unsafe {
        libc::open(
            outside.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if outside_fd >= 0 {
        // SAFETY: the descriptor was unexpectedly opened and is owned here.
        unsafe { libc::close(outside_fd) };
        return Err(BridgeError::SandboxUnavailable);
    }
    // SAFETY: glibc's thread-local errno pointer is valid for this thread.
    if unsafe { *libc::__errno_location() } != libc::EACCES {
        return Err(BridgeError::SandboxUnavailable);
    }

    let probe = c"sandbox-probe";
    let directory = std::os::fd::AsRawFd::as_raw_fd(state_directory);
    // SAFETY: the static C string is live and is resolved only relative to the
    // owned disposable state root capability.
    let descriptor = unsafe {
        libc::openat(
            directory,
            probe.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR | libc::O_CLOEXEC,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(BridgeError::SandboxUnavailable);
    }
    // SAFETY: the descriptor is owned here; fchmodat exercises the same
    // descriptor-relative operation exported to Apple code.
    let chmod_status = unsafe { libc::fchmodat(directory, probe.as_ptr(), 0o600, 0) };
    // SAFETY: the descriptor was returned by the successful open above and is
    // still uniquely owned here.
    let close_status = unsafe { libc::close(descriptor) };
    // SAFETY: the bounded C string remains live and names only the probe file
    // under the disposable state directory.
    let unlink_status = unsafe { libc::unlinkat(directory, probe.as_ptr(), 0) };
    if chmod_status == 0 && close_status == 0 && unlink_status == 0 {
        Ok(())
    } else {
        Err(BridgeError::SandboxUnavailable)
    }
}

const fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

#[cfg(target_arch = "x86_64")]
const fn audit_arch() -> u32 {
    0xc000_003e
}

#[cfg(target_arch = "aarch64")]
const fn audit_arch() -> u32 {
    0xc000_00b7
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const fn audit_arch() -> u32 {
    0
}

#[cfg(target_arch = "x86_64")]
const ALLOWED_SYSCALLS: &[libc::c_long] = &[
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_close,
    libc::SYS_lseek,
    libc::SYS_mmap,
    libc::SYS_mprotect,
    libc::SYS_munmap,
    libc::SYS_brk,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_sigaltstack,
    libc::SYS_ioctl,
    libc::SYS_pread64,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_fcntl,
    libc::SYS_pipe2,
    libc::SYS_sched_yield,
    libc::SYS_mremap,
    libc::SYS_madvise,
    libc::SYS_nanosleep,
    libc::SYS_getpid,
    libc::SYS_gettid,
    libc::SYS_futex,
    libc::SYS_gettimeofday,
    libc::SYS_clock_gettime,
    libc::SYS_clock_nanosleep,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_getrandom,
    libc::SYS_fstat,
    libc::SYS_getdents64,
    libc::SYS_ftruncate,
    libc::SYS_umask,
    libc::SYS_arch_prctl,
    libc::SYS_set_tid_address,
    libc::SYS_set_robust_list,
    libc::SYS_rseq,
];

#[cfg(target_arch = "aarch64")]
const ALLOWED_SYSCALLS: &[libc::c_long] = &[
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_close,
    libc::SYS_lseek,
    libc::SYS_mmap,
    libc::SYS_mprotect,
    libc::SYS_munmap,
    libc::SYS_brk,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_sigaltstack,
    libc::SYS_ioctl,
    libc::SYS_pread64,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_fcntl,
    libc::SYS_sched_yield,
    libc::SYS_mremap,
    libc::SYS_madvise,
    libc::SYS_nanosleep,
    libc::SYS_getpid,
    libc::SYS_gettid,
    libc::SYS_futex,
    libc::SYS_gettimeofday,
    libc::SYS_clock_gettime,
    libc::SYS_clock_nanosleep,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_getrandom,
    libc::SYS_fstat,
    libc::SYS_getdents64,
    libc::SYS_ftruncate,
    libc::SYS_umask,
    libc::SYS_set_tid_address,
    libc::SYS_set_robust_list,
    libc::SYS_rseq,
];

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const CONSTRAINED_PATH_SYSCALLS: &[libc::c_long] = &[
    libc::SYS_openat,
    libc::SYS_newfstatat,
    libc::SYS_mkdirat,
    libc::SYS_fchmodat,
];

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const ALLOWED_SYSCALLS: &[libc::c_long] = &[];

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const CONSTRAINED_PATH_SYSCALLS: &[libc::c_long] = &[];
