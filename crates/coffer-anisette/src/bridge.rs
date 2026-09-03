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

//! In-helper loader, typed shims, and one-shot offline operation.
//!
//! Bionic ABI declarations and LP64 synchronization layouts are derived from
//! the public AOSP [`libc` headers](https://android.googlesource.com/platform/bionic/+/refs/heads/main/libc/include/).

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CString, c_char, c_int, c_uint, c_void};
use std::io::{self, Read};
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex};

use coffer_bootstrap::Architecture;
use elf_loader::image::{LoadedCore, SyntheticModule, SyntheticSymbol};
use elf_loader::{Loader, Relocator};
use zeroize::Zeroizing;

use crate::abi::{
    AdiDispose, AdiGetLoginCode, AdiLoadLibraryWithPath, AdiSetProvisioningPath, ImageKind, Import,
    MAX_LIBRARY_BYTES, validate,
};
use crate::error::BridgeError;
use crate::ipc::{self, Operation, Request, Response};

const DS_ID_SENTINEL: i64 = -2;
const MAX_C_STRING_BYTES: usize = 4 * 1024;
const MAX_ADI_OUTPUT_BYTES: usize = 1024 * 1024;
const CORE_HANDLE: usize = 0x434f_5245;

/// A non-secret classification of an Android property requested by Apple code.
///
/// The original property name is never retained, formatted, or sent to the
/// parent.  `Unknown` therefore reveals no arbitrary string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PropertyKey {
    /// `ro.product.model`.
    ProductModel,
    /// `ro.build.version.release`.
    AndroidRelease,
    /// `ro.build.version.sdk`.
    AndroidSdk,
    /// `ro.build.fingerprint`.
    BuildFingerprint,
    /// Any other property name.
    Unknown,
}

impl PropertyKey {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Self::ProductModel => 1,
            Self::AndroidRelease => 2,
            Self::AndroidSdk => 3,
            Self::BuildFingerprint => 4,
            Self::Unknown => u8::MAX,
        }
    }

    pub(crate) const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::ProductModel,
            2 => Self::AndroidRelease,
            3 => Self::AndroidSdk,
            4 => Self::BuildFingerprint,
            u8::MAX => Self::Unknown,
            _ => return None,
        })
    }
}

#[repr(C, align(16))]
struct StdioPlaceholder([u8; 456]);

static STDIO_PLACEHOLDER: StdioPlaceholder = StdioPlaceholder([0; 456]);
static CORE_CVU: AtomicUsize = AtomicUsize::new(0);
static CORE_VDF: AtomicUsize = AtomicUsize::new(0);
static CORE_REFS: AtomicUsize = AtomicUsize::new(0);
static LAST_ABORT_STUB: AtomicU32 = AtomicU32::new(u32::MAX);
static PROPERTY_QUERIES: Mutex<Vec<PropertyKey>> = Mutex::new(Vec::new());
static RWLOCKS: LazyLock<Mutex<BTreeMap<usize, Box<libc::pthread_rwlock_t>>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
static STATE_ROOT: Mutex<Option<StateRoot>> = Mutex::new(None);

struct StateRoot {
    path: Vec<u8>,
    descriptor: OwnedFd,
}

pub(crate) fn serve_one() -> Result<(), BridgeError> {
    let response = match crate::sandbox::arm_parent_death() {
        Ok(()) => match ipc::read_request(io::stdin().lock()) {
            Ok(request) => handle(request).unwrap_or_else(Response::Error),
            Err(error) => Response::Error(error),
        },
        Err(error) => Response::Error(error),
    };
    ipc::write_response(io::stdout().lock(), &response)
}

fn handle(request: Request) -> Result<Response, BridgeError> {
    let architecture = supported_architecture()?;
    match request.operation {
        Operation::SandboxProbe => {
            let state = checked_state_directory(&request.state_directory)?;
            crate::sandbox::apply(&state)?;
            Ok(Response::SandboxEnabled)
        }
        Operation::OfflineSmoke => offline_smoke(
            architecture,
            &request.library_root,
            &request.state_directory,
        ),
    }
}

fn supported_architecture() -> Result<Architecture, BridgeError> {
    let architecture = Architecture::host().map_err(|_| BridgeError::UnsupportedArchitecture)?;
    matches!(architecture, Architecture::X86_64 | Architecture::Aarch64)
        .then_some(architecture)
        .ok_or(BridgeError::UnsupportedArchitecture)
}

#[allow(unsafe_code)]
fn offline_smoke(
    architecture: Architecture,
    library_root: &Path,
    state_directory: &Path,
) -> Result<Response, BridgeError> {
    if !library_root.is_absolute() {
        return Err(BridgeError::InvalidPath);
    }
    let root = std::fs::canonicalize(library_root).map_err(|_| BridgeError::InvalidPath)?;
    let expected_directory = root.join("lib").join(architecture.android_abi());
    let library_directory =
        std::fs::canonicalize(&expected_directory).map_err(|_| BridgeError::InvalidPath)?;
    if library_directory != expected_directory || !library_directory.starts_with(&root) {
        return Err(BridgeError::InvalidPath);
    }
    let core_path = checked_library_path(&library_directory, "libCoreADI.so")?;
    let ssc_path = checked_library_path(&library_directory, "libstoreservicescore.so")?;
    let core_bytes = read_library(&core_path)?;
    let ssc_bytes = read_library(&ssc_path)?;
    let core_imports = validate(&core_bytes, architecture, ImageKind::CoreAdi)?;
    let ssc_imports = validate(&ssc_bytes, architecture, ImageKind::StoreServicesCore)?;

    reset_adapter_state();
    let bridge = bridge_module(core_imports.iter().chain(&ssc_imports))?;
    let core = relocate(&core_bytes, &bridge)?;
    publish_core_symbols(&core)?;
    let ssc = relocate(&ssc_bytes, &bridge)?;
    let entries = bind_adi_entries(&ssc)?;

    // The parent owns and cleans this disposable directory. It never points at
    // the XDG provisioning directory owned by a later slice.
    let state = checked_state_directory(state_directory)?;
    let library_directory = CString::new(library_directory.as_os_str().as_encoded_bytes())
        .map_err(|_| BridgeError::InvalidPath)?;
    let state_path =
        CString::new(state.as_os_str().as_encoded_bytes()).map_err(|_| BridgeError::InvalidPath)?;

    let state_descriptor = crate::sandbox::apply(&state)?;
    configure_state_root(&state, state_descriptor)?;
    // SAFETY: all three pointers were resolved from the policy-verified SSC
    // image with the MPL-declared prototypes.  C strings remain live across
    // each call.  The helper's seccomp and rlimits contain a bad ABI or abort.
    let loaded = unsafe { (entries.load_core_adi)(library_directory.as_ptr().cast()) };
    if loaded != 0 {
        return Err(BridgeError::CoreAdiLoadFailed);
    }
    // SAFETY: same verified image/prototype argument as above; `state_path`
    // names the live helper-owned disposable directory.
    let path_set = unsafe { (entries.set_provisioning_path)(state_path.as_ptr().cast()) };
    if path_set != 0 {
        return Err(BridgeError::ProvisioningPathFailed);
    }
    // SAFETY: the query takes only the documented sentinel integer and
    // returns an integer status; it produces no borrowed output.
    let provisioned = unsafe { (entries.get_login_code)(DS_ID_SENTINEL) } == 0;
    let properties = PROPERTY_QUERIES
        .lock()
        .map_err(|_| BridgeError::HelperFailed)?
        .clone();
    drop((ssc, core));
    Ok(Response::Smoke {
        provisioned,
        properties,
    })
}

fn checked_state_directory(state_directory: &Path) -> Result<PathBuf, BridgeError> {
    use std::os::unix::fs::PermissionsExt as _;

    if !state_directory.is_absolute() {
        return Err(BridgeError::InvalidPath);
    }
    let state = std::fs::canonicalize(state_directory).map_err(|_| BridgeError::InvalidPath)?;
    let metadata = std::fs::metadata(&state).map_err(|_| BridgeError::InvalidPath)?;
    let prefixed = state
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("coffer-anisette-state-"));
    let empty = std::fs::read_dir(&state)
        .map_err(|_| BridgeError::InvalidPath)?
        .next()
        .is_none();
    if state != state_directory
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o777 != 0o700
        || !prefixed
        || !empty
    {
        return Err(BridgeError::InvalidPath);
    }
    Ok(state)
}

fn checked_library_path(directory: &Path, basename: &str) -> Result<PathBuf, BridgeError> {
    let expected = directory.join(basename);
    let path = std::fs::canonicalize(&expected).map_err(|_| BridgeError::InvalidPath)?;
    if path != expected
        || path.parent() != Some(directory)
        || path.file_name().and_then(|n| n.to_str()) != Some(basename)
    {
        return Err(BridgeError::InvalidPath);
    }
    Ok(path)
}

fn read_library(path: &Path) -> Result<Vec<u8>, BridgeError> {
    let file = std::fs::File::open(path).map_err(|_| BridgeError::InvalidPath)?;
    let metadata = file.metadata().map_err(|_| BridgeError::InvalidPath)?;
    if !metadata.is_file() || metadata.len() > MAX_LIBRARY_BYTES as u64 {
        return Err(BridgeError::AbiMismatch);
    }
    let mut bytes =
        Vec::with_capacity(usize::try_from(metadata.len()).map_err(|_| BridgeError::AbiMismatch)?);
    file.take((MAX_LIBRARY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| BridgeError::InvalidPath)?;
    if bytes.len() > MAX_LIBRARY_BYTES {
        return Err(BridgeError::AbiMismatch);
    }
    Ok(bytes)
}

fn reset_adapter_state() {
    CORE_CVU.store(0, Ordering::SeqCst);
    CORE_VDF.store(0, Ordering::SeqCst);
    CORE_REFS.store(0, Ordering::SeqCst);
    LAST_ABORT_STUB.store(u32::MAX, Ordering::SeqCst);
    if let Ok(mut properties) = PROPERTY_QUERIES.lock() {
        properties.clear();
    }
    if let Ok(mut state) = STATE_ROOT.lock() {
        *state = None;
    }
}

fn relocate(bytes: &[u8], bridge: &SyntheticModule) -> Result<LoadedCore<()>, BridgeError> {
    let raw = Loader::new()
        .load_dylib(bytes)
        .map_err(|_| BridgeError::LoaderRejected)?;
    Relocator::new()
        .defer_init()
        .run(raw)
        .modules([bridge.clone()])
        .relocate()
        .map_err(|_| BridgeError::LoaderRejected)
}

#[allow(unsafe_code)]
fn publish_core_symbols(core: &LoadedCore<()>) -> Result<(), BridgeError> {
    // SAFETY: only addresses are materialized.  They are called later solely
    // through dlsym while `core` remains owned by `offline_smoke`.
    let cvu = unsafe { core.get::<unsafe extern "C" fn()>("cvu8io98wun") }
        .ok_or(BridgeError::MissingExport)?
        .into_raw() as usize;
    // SAFETY: same as for `cvu8io98wun`.
    let vdf = unsafe { core.get::<unsafe extern "C" fn()>("vdfut768ig") }
        .ok_or(BridgeError::MissingExport)?
        .into_raw() as usize;
    CORE_CVU.store(cvu, Ordering::SeqCst);
    CORE_VDF.store(vdf, Ordering::SeqCst);
    Ok(())
}

struct AdiEntries {
    load_core_adi: AdiLoadLibraryWithPath,
    set_provisioning_path: AdiSetProvisioningPath,
    get_login_code: AdiGetLoginCode,
}

#[allow(unsafe_code)]
fn bind_adi_entries(ssc: &LoadedCore<()>) -> Result<AdiEntries, BridgeError> {
    // SAFETY: the image passed the exact export-set policy and these types are
    // the MPL-2.0 SideStore declarations recorded in `abi`.
    let load_core_adi = *unsafe { ssc.get::<AdiLoadLibraryWithPath>("kq56gsgHG6") }
        .ok_or(BridgeError::MissingExport)?;
    // SAFETY: same policy and provenance as above.
    let set_provisioning_path = *unsafe { ssc.get::<AdiSetProvisioningPath>("nf92ngaK92") }
        .ok_or(BridgeError::MissingExport)?;
    // SAFETY: same policy and provenance as above.
    let get_login_code =
        *unsafe { ssc.get::<AdiGetLoginCode>("aslgmuibau") }.ok_or(BridgeError::MissingExport)?;
    Ok(AdiEntries {
        load_core_adi,
        set_provisioning_path,
        get_login_code,
    })
}

fn bridge_module<'a>(
    imports: impl Iterator<Item = &'a Import>,
) -> Result<SyntheticModule, BridgeError> {
    let real = real_shims();
    let stubs = stub_addresses();
    let mut seen = BTreeSet::new();
    let mut symbols = Vec::new();
    for import in imports {
        if !seen.insert((import.name.clone(), import.version.clone())) {
            continue;
        }
        let symbol = if import.name == "__sF" {
            SyntheticSymbol::object(
                import.name.clone(),
                std::ptr::from_ref(&STDIO_PLACEHOLDER).cast::<()>(),
                size_of::<StdioPlaceholder>(),
            )
        } else if let Some(address) = real.get(import.name.as_str()) {
            SyntheticSymbol::function(import.name.clone(), *address)
        } else {
            let index = symbols.len();
            let address = stubs.get(index).ok_or(BridgeError::AbiMismatch)?;
            SyntheticSymbol::function(import.name.clone(), *address)
        };
        symbols.push(match &import.version {
            Some(version) => symbol.with_version(version.clone(), true),
            None => symbol,
        });
    }
    Ok(SyntheticModule::new("__coffer_bionic_bridge", symbols))
}

fn real_shims() -> BTreeMap<&'static str, *const ()> {
    let mut shims = BTreeMap::from([
        ("malloc", libc::malloc as *const ()),
        ("free", libc::free as *const ()),
        ("calloc", libc::calloc as *const ()),
        ("realloc", libc::realloc as *const ()),
        ("memcpy", libc::memcpy as *const ()),
        ("memmove", libc::memmove as *const ()),
        ("memset", libc::memset as *const ()),
        ("memcmp", libc::memcmp as *const ()),
        ("memchr", libc::memchr as *const ()),
        ("strlen", libc::strlen as *const ()),
        ("strncpy", libc::strncpy as *const ()),
        ("strcmp", libc::strcmp as *const ()),
        ("strncmp", libc::strncmp as *const ()),
        ("open", shim_open as *const ()),
        ("read", libc::read as *const ()),
        ("write", shim_write as *const ()),
        ("close", libc::close as *const ()),
        ("mkdir", shim_mkdir as *const ()),
        ("chmod", shim_chmod as *const ()),
        ("umask", libc::umask as *const ()),
        ("ftruncate", libc::ftruncate as *const ()),
        ("fstat", libc::fstat as *const ()),
        ("lstat", shim_lstat as *const ()),
        ("gettimeofday", libc::gettimeofday as *const ()),
        ("abort", shim_abort as *const ()),
    ]);
    shims.extend([
        ("__errno", shim_errno as *const ()),
        ("arc4random", shim_arc4random as *const ()),
        (
            "__system_property_get",
            shim_system_property_get as *const (),
        ),
        ("fprintf", shim_fprintf as *const ()),
        ("fwrite", shim_fwrite as *const ()),
        ("fflush", shim_fflush as *const ()),
        ("dlopen", shim_dlopen as *const ()),
        ("dlsym", shim_dlsym as *const ()),
        ("dlclose", shim_dlclose as *const ()),
        ("dl_iterate_phdr", shim_dl_iterate_phdr as *const ()),
        ("__cxa_atexit", shim_cxa_atexit as *const ()),
        ("__cxa_finalize", shim_cxa_finalize as *const ()),
        ("pthread_once", shim_pthread_once as *const ()),
        ("pthread_rwlock_init", shim_rwlock_init as *const ()),
        ("pthread_rwlock_destroy", shim_rwlock_destroy as *const ()),
        ("pthread_rwlock_rdlock", shim_rwlock_rdlock as *const ()),
        ("pthread_rwlock_wrlock", shim_rwlock_wrlock as *const ()),
        ("pthread_rwlock_unlock", shim_rwlock_unlock as *const ()),
    ]);
    shims
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const BIONIC_PTHREAD_ONCE_SIZE: usize = 4;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const BIONIC_PTHREAD_RWLOCK_SIZE_LP64: usize = 14 * 4;
const BIONIC_PTHREAD_ALIGNMENT: usize = 4;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const _: () = assert!(size_of::<libc::pthread_once_t>() == BIONIC_PTHREAD_ONCE_SIZE);
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const _: () = assert!(size_of::<libc::pthread_rwlock_t>() == BIONIC_PTHREAD_RWLOCK_SIZE_LP64);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(size_of::<libc::stat>() == 144);
#[cfg(target_arch = "aarch64")]
const _: () = assert!(size_of::<libc::stat>() == 128);

#[cfg(target_arch = "x86_64")]
const _: () = {
    assert!(std::mem::offset_of!(libc::stat, st_ino) == 8);
    assert!(std::mem::offset_of!(libc::stat, st_mode) == 24);
    assert!(std::mem::offset_of!(libc::stat, st_size) == 48);
    assert!(std::mem::offset_of!(libc::stat, st_blocks) == 64);
};
#[cfg(target_arch = "aarch64")]
const _: () = {
    assert!(std::mem::offset_of!(libc::stat, st_ino) == 8);
    assert!(std::mem::offset_of!(libc::stat, st_mode) == 16);
    assert!(std::mem::offset_of!(libc::stat, st_size) == 48);
    assert!(std::mem::offset_of!(libc::stat, st_blocks) == 64);
};

#[allow(unsafe_code)]
extern "C" fn shim_errno() -> *mut c_int {
    // SAFETY: glibc exposes this thread-local accessor with the same result
    // type as Bionic's `__errno`.
    unsafe { libc::__errno_location() }
}

#[allow(unsafe_code)]
extern "C" fn shim_arc4random() -> c_uint {
    let mut bytes = [0u8; 4];
    // SAFETY: the live local has exactly the provided length.
    if unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), 0) } != 4 {
        // SAFETY: `_exit` cannot unwind across the FFI boundary.
        unsafe { libc::_exit(126) };
    }
    u32::from_ne_bytes(bytes)
}

#[allow(unsafe_code)]
extern "C" fn shim_system_property_get(name: *const c_char, value: *mut c_char) -> c_int {
    let key = bounded_c_string(name)
        .as_deref()
        .map(classify_property)
        .unwrap_or(PropertyKey::Unknown);
    if let Ok(mut properties) = PROPERTY_QUERIES.lock()
        && !properties.contains(&key)
        && properties.len() < 32
    {
        properties.push(key);
    }
    if !value.is_null() {
        // SAFETY: AOSP specifies a caller-owned `PROP_VALUE_MAX` buffer.  One
        // NUL byte is the smallest valid empty response.
        unsafe { value.write(0) };
    }
    0
}

fn classify_property(name: &[u8]) -> PropertyKey {
    match name {
        b"ro.product.model" => PropertyKey::ProductModel,
        b"ro.build.version.release" => PropertyKey::AndroidRelease,
        b"ro.build.version.sdk" => PropertyKey::AndroidSdk,
        b"ro.build.fingerprint" => PropertyKey::BuildFingerprint,
        _ => PropertyKey::Unknown,
    }
}

#[allow(unsafe_code)]
fn bounded_c_string(pointer: *const c_char) -> Option<Vec<u8>> {
    if pointer.is_null() {
        return None;
    }
    for length in 0..MAX_C_STRING_BYTES {
        // SAFETY: the caller supplied an FFI C string.  Reads are bounded; an
        // invalid pointer crashes only this sandboxed helper.
        if unsafe { pointer.add(length).read() } == 0 {
            // SAFETY: the same bounded scan established all bytes through the
            // terminator as readable for this invocation.
            return Some(unsafe { std::slice::from_raw_parts(pointer.cast(), length) }.to_vec());
        }
    }
    None
}

fn configure_state_root(path: &Path, descriptor: OwnedFd) -> Result<(), BridgeError> {
    let path = path.as_os_str().as_encoded_bytes();
    if path.contains(&0) {
        return Err(BridgeError::InvalidPath);
    }
    let mut state = STATE_ROOT.lock().map_err(|_| BridgeError::HelperFailed)?;
    *state = Some(StateRoot {
        path: path.to_vec(),
        descriptor,
    });
    Ok(())
}

fn relative_state_path(root: &[u8], requested: &[u8]) -> Option<CString> {
    let relative = if requested.starts_with(b"/") {
        if requested == root {
            b".".as_slice()
        } else if requested.get(..root.len()) == Some(root)
            && requested.get(root.len()) == Some(&b'/')
        {
            requested.get(root.len() + 1..)?
        } else {
            return None;
        }
    } else {
        requested
    };
    let mut normalized = Vec::new();
    for component in relative.split(|byte| *byte == b'/') {
        if component.is_empty() || component == b"." {
            continue;
        }
        if component == b".." {
            return None;
        }
        if !normalized.is_empty() {
            normalized.push(b'/');
        }
        normalized.extend_from_slice(component);
    }
    if normalized.is_empty() {
        normalized.push(b'.');
    }
    CString::new(normalized).ok()
}

fn state_path(requested: *const c_char) -> Option<(c_int, CString)> {
    let requested = bounded_c_string(requested)?;
    let state = STATE_ROOT.lock().ok()?;
    let state = state.as_ref()?;
    let relative = relative_state_path(&state.path, &requested)?;
    Some((state.descriptor.as_raw_fd(), relative))
}

#[allow(unsafe_code)]
fn reject_path() -> c_int {
    // SAFETY: glibc's thread-local errno pointer is valid for this thread.
    unsafe { *libc::__errno_location() = libc::EACCES };
    -1
}

#[allow(unsafe_code)]
unsafe extern "C" fn shim_open(path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
    let Some((directory, relative)) = state_path(path) else {
        return reject_path();
    };
    // SAFETY: `relative` is a live, NUL-terminated path constrained beneath
    // the pre-opened empty state root.  The third argument is consulted only
    // for creation flags, matching POSIX open's variadic ABI.
    unsafe { libc::openat(directory, relative.as_ptr(), flags, mode) }
}

#[allow(unsafe_code)]
unsafe extern "C" fn shim_mkdir(path: *const c_char, mode: libc::mode_t) -> c_int {
    let Some((directory, relative)) = state_path(path) else {
        return reject_path();
    };
    // SAFETY: the descriptor and normalized relative path are confined to the
    // disposable state root.
    unsafe { libc::mkdirat(directory, relative.as_ptr(), mode) }
}

#[allow(unsafe_code)]
unsafe extern "C" fn shim_chmod(path: *const c_char, mode: libc::mode_t) -> c_int {
    let Some((directory, relative)) = state_path(path) else {
        return reject_path();
    };
    // SAFETY: the descriptor and normalized relative path are confined to the
    // disposable state root, which starts empty and cannot create symlinks.
    unsafe { libc::fchmodat(directory, relative.as_ptr(), mode, 0) }
}

#[allow(unsafe_code)]
unsafe extern "C" fn shim_lstat(path: *const c_char, status: *mut libc::stat) -> c_int {
    let Some((directory, relative)) = state_path(path) else {
        return reject_path();
    };
    // SAFETY: the descriptor and normalized relative path are confined to the
    // disposable state root; the foreign caller owns `status`.
    unsafe {
        libc::fstatat(
            directory,
            relative.as_ptr(),
            status,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    }
}

extern "C" fn shim_fprintf(_stream: *mut c_void) -> c_int {
    -1
}

extern "C" fn shim_fwrite(
    _pointer: *const c_void,
    size: usize,
    count: usize,
    _stream: *mut c_void,
) -> usize {
    let _ = size;
    count
}

extern "C" fn shim_fflush(_stream: *mut c_void) -> c_int {
    0
}

#[allow(unsafe_code)]
extern "C" fn shim_write(descriptor: c_int, buffer: *const c_void, count: usize) -> isize {
    if matches!(descriptor, libc::STDOUT_FILENO | libc::STDERR_FILENO) {
        return isize::try_from(count).unwrap_or(isize::MAX);
    }
    // SAFETY: the proprietary caller owns a readable buffer of `count` bytes;
    // non-diagnostic file descriptors retain ordinary POSIX write behavior.
    unsafe { libc::write(descriptor, buffer, count) }
}

#[allow(unsafe_code)]
extern "C" fn shim_abort() -> ! {
    // SAFETY: `_exit` terminates without signaling another thread or unwinding
    // across the FFI boundary.
    unsafe { libc::_exit(134) }
}

#[allow(unsafe_code)]
extern "C" fn shim_dlopen(filename: *const c_char, _flags: c_int) -> *mut c_void {
    let Some(name) = bounded_c_string(filename) else {
        return std::ptr::null_mut();
    };
    let basename = name.rsplit(|byte| *byte == b'/').next().unwrap_or(&name);
    if basename == b"libCoreADI.so"
        && CORE_CVU.load(Ordering::SeqCst) != 0
        && CORE_VDF.load(Ordering::SeqCst) != 0
    {
        CORE_REFS.fetch_add(1, Ordering::SeqCst);
        CORE_HANDLE as *mut c_void
    } else {
        std::ptr::null_mut()
    }
}

#[allow(unsafe_code)]
extern "C" fn shim_dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void {
    if handle as usize != CORE_HANDLE || CORE_REFS.load(Ordering::SeqCst) == 0 {
        return std::ptr::null_mut();
    }
    let Some(name) = bounded_c_string(symbol) else {
        return std::ptr::null_mut();
    };
    match name.as_slice() {
        b"cvu8io98wun" => CORE_CVU.load(Ordering::SeqCst) as *mut c_void,
        b"vdfut768ig" => CORE_VDF.load(Ordering::SeqCst) as *mut c_void,
        _ => std::ptr::null_mut(),
    }
}

extern "C" fn shim_dlclose(handle: *mut c_void) -> c_int {
    if handle as usize != CORE_HANDLE {
        return -1;
    }
    CORE_REFS
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |refs| {
            refs.checked_sub(1)
        })
        .map_or(-1, |_| 0)
}

extern "C" fn shim_dl_iterate_phdr(_callback: *const c_void, _data: *mut c_void) -> c_int {
    // Unwinding through proprietary frames is unsupported.  Returning a
    // nonzero value makes libunwind stop instead of observing a false host
    // module list.
    -1
}

extern "C" fn shim_cxa_atexit(
    _function: unsafe extern "C" fn(*mut c_void),
    _argument: *mut c_void,
    _dso: *mut c_void,
) -> c_int {
    // The helper exits after one operation, and process exit releases every
    // mapping.  Running proprietary destructors would widen the call surface.
    0
}

extern "C" fn shim_cxa_finalize(_dso: *mut c_void) {}

#[allow(unsafe_code)]
extern "C" fn shim_pthread_once(
    control: *mut libc::pthread_once_t,
    init: extern "C" fn(),
) -> c_int {
    if !is_aligned(control) {
        return libc::EINVAL;
    }
    // SAFETY: AOSP Bionic and glibc use the same four-byte, four-aligned once
    // word; the guard rejects anything that fails the host alignment.
    unsafe { libc::pthread_once(control, init) }
}

fn is_aligned<T>(pointer: *const T) -> bool {
    !pointer.is_null() && (pointer as usize).is_multiple_of(align_of::<T>())
}

fn bionic_lock_key(lock: *mut libc::pthread_rwlock_t) -> Result<usize, c_int> {
    let address = lock as usize;
    if lock.is_null() || !address.is_multiple_of(BIONIC_PTHREAD_ALIGNMENT) {
        Err(libc::EINVAL)
    } else {
        Ok(address)
    }
}

#[allow(unsafe_code)]
extern "C" fn shim_rwlock_init(lock: *mut libc::pthread_rwlock_t) -> c_int {
    let Ok(key) = bionic_lock_key(lock) else {
        return libc::EINVAL;
    };
    let Ok(mut locks) = RWLOCKS.lock() else {
        return libc::EAGAIN;
    };
    if locks.contains_key(&key) {
        return libc::EBUSY;
    }
    let mut host = Box::new(std::mem::MaybeUninit::<libc::pthread_rwlock_t>::uninit());
    // SAFETY: the independent host allocation is properly aligned and live;
    // it is never overlaid on the four-aligned Bionic object.
    let status = unsafe { libc::pthread_rwlock_init(host.as_mut_ptr(), std::ptr::null()) };
    if status != 0 {
        return status;
    }
    // SAFETY: successful pthread initialization fully initialized the object.
    locks.insert(key, unsafe { host.assume_init() });
    0
}

#[allow(unsafe_code)]
extern "C" fn shim_rwlock_destroy(lock: *mut libc::pthread_rwlock_t) -> c_int {
    let Ok(key) = bionic_lock_key(lock) else {
        return libc::EINVAL;
    };
    let Ok(mut locks) = RWLOCKS.lock() else {
        return libc::EAGAIN;
    };
    let Some(mut host) = locks.remove(&key) else {
        return libc::EINVAL;
    };
    // SAFETY: the map uniquely owns an initialized host lock and removes it
    // before destruction, so no later lookup can begin using it.
    unsafe { libc::pthread_rwlock_destroy(host.as_mut()) }
}

macro_rules! rwlock_operation {
    ($name:ident, $operation:path) => {
        #[allow(unsafe_code)]
        extern "C" fn $name(lock: *mut libc::pthread_rwlock_t) -> c_int {
            let Ok(key) = bionic_lock_key(lock) else {
                return libc::EINVAL;
            };
            let host = {
                let Ok(locks) = RWLOCKS.lock() else {
                    return libc::EAGAIN;
                };
                let Some(host) = locks.get(&key) else {
                    return libc::EINVAL;
                };
                std::ptr::from_ref(host.as_ref()).cast_mut()
            };
            // SAFETY: the boxed host lock has a stable address while registered.
            // Concurrent destruction of a lock in use is already invalid POSIX
            // behavior and is outside the proprietary caller's valid states.
            unsafe { $operation(host) }
        }
    };
}

rwlock_operation!(shim_rwlock_rdlock, libc::pthread_rwlock_rdlock);
rwlock_operation!(shim_rwlock_wrlock, libc::pthread_rwlock_wrlock);
rwlock_operation!(shim_rwlock_unlock, libc::pthread_rwlock_unlock);

extern "C" fn abort_stub<const INDEX: usize>() -> ! {
    LAST_ABORT_STUB.store(INDEX as u32, Ordering::SeqCst);
    shim_abort()
}

fn stub_addresses() -> &'static [*const (); 512] {
    &STUB_ADDRESSES.0
}

struct StubAddresses([*const (); 512]);

// SAFETY: every pointer refers to immutable executable text with static
// lifetime; the table never dereferences or mutates through those pointers.
#[allow(unsafe_code)]
unsafe impl Sync for StubAddresses {}

static STUB_ADDRESSES: StubAddresses = StubAddresses([
    abort_stub::<0> as *const (),
    abort_stub::<1> as *const (),
    abort_stub::<2> as *const (),
    abort_stub::<3> as *const (),
    abort_stub::<4> as *const (),
    abort_stub::<5> as *const (),
    abort_stub::<6> as *const (),
    abort_stub::<7> as *const (),
    abort_stub::<8> as *const (),
    abort_stub::<9> as *const (),
    abort_stub::<10> as *const (),
    abort_stub::<11> as *const (),
    abort_stub::<12> as *const (),
    abort_stub::<13> as *const (),
    abort_stub::<14> as *const (),
    abort_stub::<15> as *const (),
    abort_stub::<16> as *const (),
    abort_stub::<17> as *const (),
    abort_stub::<18> as *const (),
    abort_stub::<19> as *const (),
    abort_stub::<20> as *const (),
    abort_stub::<21> as *const (),
    abort_stub::<22> as *const (),
    abort_stub::<23> as *const (),
    abort_stub::<24> as *const (),
    abort_stub::<25> as *const (),
    abort_stub::<26> as *const (),
    abort_stub::<27> as *const (),
    abort_stub::<28> as *const (),
    abort_stub::<29> as *const (),
    abort_stub::<30> as *const (),
    abort_stub::<31> as *const (),
    abort_stub::<32> as *const (),
    abort_stub::<33> as *const (),
    abort_stub::<34> as *const (),
    abort_stub::<35> as *const (),
    abort_stub::<36> as *const (),
    abort_stub::<37> as *const (),
    abort_stub::<38> as *const (),
    abort_stub::<39> as *const (),
    abort_stub::<40> as *const (),
    abort_stub::<41> as *const (),
    abort_stub::<42> as *const (),
    abort_stub::<43> as *const (),
    abort_stub::<44> as *const (),
    abort_stub::<45> as *const (),
    abort_stub::<46> as *const (),
    abort_stub::<47> as *const (),
    abort_stub::<48> as *const (),
    abort_stub::<49> as *const (),
    abort_stub::<50> as *const (),
    abort_stub::<51> as *const (),
    abort_stub::<52> as *const (),
    abort_stub::<53> as *const (),
    abort_stub::<54> as *const (),
    abort_stub::<55> as *const (),
    abort_stub::<56> as *const (),
    abort_stub::<57> as *const (),
    abort_stub::<58> as *const (),
    abort_stub::<59> as *const (),
    abort_stub::<60> as *const (),
    abort_stub::<61> as *const (),
    abort_stub::<62> as *const (),
    abort_stub::<63> as *const (),
    abort_stub::<64> as *const (),
    abort_stub::<65> as *const (),
    abort_stub::<66> as *const (),
    abort_stub::<67> as *const (),
    abort_stub::<68> as *const (),
    abort_stub::<69> as *const (),
    abort_stub::<70> as *const (),
    abort_stub::<71> as *const (),
    abort_stub::<72> as *const (),
    abort_stub::<73> as *const (),
    abort_stub::<74> as *const (),
    abort_stub::<75> as *const (),
    abort_stub::<76> as *const (),
    abort_stub::<77> as *const (),
    abort_stub::<78> as *const (),
    abort_stub::<79> as *const (),
    abort_stub::<80> as *const (),
    abort_stub::<81> as *const (),
    abort_stub::<82> as *const (),
    abort_stub::<83> as *const (),
    abort_stub::<84> as *const (),
    abort_stub::<85> as *const (),
    abort_stub::<86> as *const (),
    abort_stub::<87> as *const (),
    abort_stub::<88> as *const (),
    abort_stub::<89> as *const (),
    abort_stub::<90> as *const (),
    abort_stub::<91> as *const (),
    abort_stub::<92> as *const (),
    abort_stub::<93> as *const (),
    abort_stub::<94> as *const (),
    abort_stub::<95> as *const (),
    abort_stub::<96> as *const (),
    abort_stub::<97> as *const (),
    abort_stub::<98> as *const (),
    abort_stub::<99> as *const (),
    abort_stub::<100> as *const (),
    abort_stub::<101> as *const (),
    abort_stub::<102> as *const (),
    abort_stub::<103> as *const (),
    abort_stub::<104> as *const (),
    abort_stub::<105> as *const (),
    abort_stub::<106> as *const (),
    abort_stub::<107> as *const (),
    abort_stub::<108> as *const (),
    abort_stub::<109> as *const (),
    abort_stub::<110> as *const (),
    abort_stub::<111> as *const (),
    abort_stub::<112> as *const (),
    abort_stub::<113> as *const (),
    abort_stub::<114> as *const (),
    abort_stub::<115> as *const (),
    abort_stub::<116> as *const (),
    abort_stub::<117> as *const (),
    abort_stub::<118> as *const (),
    abort_stub::<119> as *const (),
    abort_stub::<120> as *const (),
    abort_stub::<121> as *const (),
    abort_stub::<122> as *const (),
    abort_stub::<123> as *const (),
    abort_stub::<124> as *const (),
    abort_stub::<125> as *const (),
    abort_stub::<126> as *const (),
    abort_stub::<127> as *const (),
    abort_stub::<128> as *const (),
    abort_stub::<129> as *const (),
    abort_stub::<130> as *const (),
    abort_stub::<131> as *const (),
    abort_stub::<132> as *const (),
    abort_stub::<133> as *const (),
    abort_stub::<134> as *const (),
    abort_stub::<135> as *const (),
    abort_stub::<136> as *const (),
    abort_stub::<137> as *const (),
    abort_stub::<138> as *const (),
    abort_stub::<139> as *const (),
    abort_stub::<140> as *const (),
    abort_stub::<141> as *const (),
    abort_stub::<142> as *const (),
    abort_stub::<143> as *const (),
    abort_stub::<144> as *const (),
    abort_stub::<145> as *const (),
    abort_stub::<146> as *const (),
    abort_stub::<147> as *const (),
    abort_stub::<148> as *const (),
    abort_stub::<149> as *const (),
    abort_stub::<150> as *const (),
    abort_stub::<151> as *const (),
    abort_stub::<152> as *const (),
    abort_stub::<153> as *const (),
    abort_stub::<154> as *const (),
    abort_stub::<155> as *const (),
    abort_stub::<156> as *const (),
    abort_stub::<157> as *const (),
    abort_stub::<158> as *const (),
    abort_stub::<159> as *const (),
    abort_stub::<160> as *const (),
    abort_stub::<161> as *const (),
    abort_stub::<162> as *const (),
    abort_stub::<163> as *const (),
    abort_stub::<164> as *const (),
    abort_stub::<165> as *const (),
    abort_stub::<166> as *const (),
    abort_stub::<167> as *const (),
    abort_stub::<168> as *const (),
    abort_stub::<169> as *const (),
    abort_stub::<170> as *const (),
    abort_stub::<171> as *const (),
    abort_stub::<172> as *const (),
    abort_stub::<173> as *const (),
    abort_stub::<174> as *const (),
    abort_stub::<175> as *const (),
    abort_stub::<176> as *const (),
    abort_stub::<177> as *const (),
    abort_stub::<178> as *const (),
    abort_stub::<179> as *const (),
    abort_stub::<180> as *const (),
    abort_stub::<181> as *const (),
    abort_stub::<182> as *const (),
    abort_stub::<183> as *const (),
    abort_stub::<184> as *const (),
    abort_stub::<185> as *const (),
    abort_stub::<186> as *const (),
    abort_stub::<187> as *const (),
    abort_stub::<188> as *const (),
    abort_stub::<189> as *const (),
    abort_stub::<190> as *const (),
    abort_stub::<191> as *const (),
    abort_stub::<192> as *const (),
    abort_stub::<193> as *const (),
    abort_stub::<194> as *const (),
    abort_stub::<195> as *const (),
    abort_stub::<196> as *const (),
    abort_stub::<197> as *const (),
    abort_stub::<198> as *const (),
    abort_stub::<199> as *const (),
    abort_stub::<200> as *const (),
    abort_stub::<201> as *const (),
    abort_stub::<202> as *const (),
    abort_stub::<203> as *const (),
    abort_stub::<204> as *const (),
    abort_stub::<205> as *const (),
    abort_stub::<206> as *const (),
    abort_stub::<207> as *const (),
    abort_stub::<208> as *const (),
    abort_stub::<209> as *const (),
    abort_stub::<210> as *const (),
    abort_stub::<211> as *const (),
    abort_stub::<212> as *const (),
    abort_stub::<213> as *const (),
    abort_stub::<214> as *const (),
    abort_stub::<215> as *const (),
    abort_stub::<216> as *const (),
    abort_stub::<217> as *const (),
    abort_stub::<218> as *const (),
    abort_stub::<219> as *const (),
    abort_stub::<220> as *const (),
    abort_stub::<221> as *const (),
    abort_stub::<222> as *const (),
    abort_stub::<223> as *const (),
    abort_stub::<224> as *const (),
    abort_stub::<225> as *const (),
    abort_stub::<226> as *const (),
    abort_stub::<227> as *const (),
    abort_stub::<228> as *const (),
    abort_stub::<229> as *const (),
    abort_stub::<230> as *const (),
    abort_stub::<231> as *const (),
    abort_stub::<232> as *const (),
    abort_stub::<233> as *const (),
    abort_stub::<234> as *const (),
    abort_stub::<235> as *const (),
    abort_stub::<236> as *const (),
    abort_stub::<237> as *const (),
    abort_stub::<238> as *const (),
    abort_stub::<239> as *const (),
    abort_stub::<240> as *const (),
    abort_stub::<241> as *const (),
    abort_stub::<242> as *const (),
    abort_stub::<243> as *const (),
    abort_stub::<244> as *const (),
    abort_stub::<245> as *const (),
    abort_stub::<246> as *const (),
    abort_stub::<247> as *const (),
    abort_stub::<248> as *const (),
    abort_stub::<249> as *const (),
    abort_stub::<250> as *const (),
    abort_stub::<251> as *const (),
    abort_stub::<252> as *const (),
    abort_stub::<253> as *const (),
    abort_stub::<254> as *const (),
    abort_stub::<255> as *const (),
    abort_stub::<256> as *const (),
    abort_stub::<257> as *const (),
    abort_stub::<258> as *const (),
    abort_stub::<259> as *const (),
    abort_stub::<260> as *const (),
    abort_stub::<261> as *const (),
    abort_stub::<262> as *const (),
    abort_stub::<263> as *const (),
    abort_stub::<264> as *const (),
    abort_stub::<265> as *const (),
    abort_stub::<266> as *const (),
    abort_stub::<267> as *const (),
    abort_stub::<268> as *const (),
    abort_stub::<269> as *const (),
    abort_stub::<270> as *const (),
    abort_stub::<271> as *const (),
    abort_stub::<272> as *const (),
    abort_stub::<273> as *const (),
    abort_stub::<274> as *const (),
    abort_stub::<275> as *const (),
    abort_stub::<276> as *const (),
    abort_stub::<277> as *const (),
    abort_stub::<278> as *const (),
    abort_stub::<279> as *const (),
    abort_stub::<280> as *const (),
    abort_stub::<281> as *const (),
    abort_stub::<282> as *const (),
    abort_stub::<283> as *const (),
    abort_stub::<284> as *const (),
    abort_stub::<285> as *const (),
    abort_stub::<286> as *const (),
    abort_stub::<287> as *const (),
    abort_stub::<288> as *const (),
    abort_stub::<289> as *const (),
    abort_stub::<290> as *const (),
    abort_stub::<291> as *const (),
    abort_stub::<292> as *const (),
    abort_stub::<293> as *const (),
    abort_stub::<294> as *const (),
    abort_stub::<295> as *const (),
    abort_stub::<296> as *const (),
    abort_stub::<297> as *const (),
    abort_stub::<298> as *const (),
    abort_stub::<299> as *const (),
    abort_stub::<300> as *const (),
    abort_stub::<301> as *const (),
    abort_stub::<302> as *const (),
    abort_stub::<303> as *const (),
    abort_stub::<304> as *const (),
    abort_stub::<305> as *const (),
    abort_stub::<306> as *const (),
    abort_stub::<307> as *const (),
    abort_stub::<308> as *const (),
    abort_stub::<309> as *const (),
    abort_stub::<310> as *const (),
    abort_stub::<311> as *const (),
    abort_stub::<312> as *const (),
    abort_stub::<313> as *const (),
    abort_stub::<314> as *const (),
    abort_stub::<315> as *const (),
    abort_stub::<316> as *const (),
    abort_stub::<317> as *const (),
    abort_stub::<318> as *const (),
    abort_stub::<319> as *const (),
    abort_stub::<320> as *const (),
    abort_stub::<321> as *const (),
    abort_stub::<322> as *const (),
    abort_stub::<323> as *const (),
    abort_stub::<324> as *const (),
    abort_stub::<325> as *const (),
    abort_stub::<326> as *const (),
    abort_stub::<327> as *const (),
    abort_stub::<328> as *const (),
    abort_stub::<329> as *const (),
    abort_stub::<330> as *const (),
    abort_stub::<331> as *const (),
    abort_stub::<332> as *const (),
    abort_stub::<333> as *const (),
    abort_stub::<334> as *const (),
    abort_stub::<335> as *const (),
    abort_stub::<336> as *const (),
    abort_stub::<337> as *const (),
    abort_stub::<338> as *const (),
    abort_stub::<339> as *const (),
    abort_stub::<340> as *const (),
    abort_stub::<341> as *const (),
    abort_stub::<342> as *const (),
    abort_stub::<343> as *const (),
    abort_stub::<344> as *const (),
    abort_stub::<345> as *const (),
    abort_stub::<346> as *const (),
    abort_stub::<347> as *const (),
    abort_stub::<348> as *const (),
    abort_stub::<349> as *const (),
    abort_stub::<350> as *const (),
    abort_stub::<351> as *const (),
    abort_stub::<352> as *const (),
    abort_stub::<353> as *const (),
    abort_stub::<354> as *const (),
    abort_stub::<355> as *const (),
    abort_stub::<356> as *const (),
    abort_stub::<357> as *const (),
    abort_stub::<358> as *const (),
    abort_stub::<359> as *const (),
    abort_stub::<360> as *const (),
    abort_stub::<361> as *const (),
    abort_stub::<362> as *const (),
    abort_stub::<363> as *const (),
    abort_stub::<364> as *const (),
    abort_stub::<365> as *const (),
    abort_stub::<366> as *const (),
    abort_stub::<367> as *const (),
    abort_stub::<368> as *const (),
    abort_stub::<369> as *const (),
    abort_stub::<370> as *const (),
    abort_stub::<371> as *const (),
    abort_stub::<372> as *const (),
    abort_stub::<373> as *const (),
    abort_stub::<374> as *const (),
    abort_stub::<375> as *const (),
    abort_stub::<376> as *const (),
    abort_stub::<377> as *const (),
    abort_stub::<378> as *const (),
    abort_stub::<379> as *const (),
    abort_stub::<380> as *const (),
    abort_stub::<381> as *const (),
    abort_stub::<382> as *const (),
    abort_stub::<383> as *const (),
    abort_stub::<384> as *const (),
    abort_stub::<385> as *const (),
    abort_stub::<386> as *const (),
    abort_stub::<387> as *const (),
    abort_stub::<388> as *const (),
    abort_stub::<389> as *const (),
    abort_stub::<390> as *const (),
    abort_stub::<391> as *const (),
    abort_stub::<392> as *const (),
    abort_stub::<393> as *const (),
    abort_stub::<394> as *const (),
    abort_stub::<395> as *const (),
    abort_stub::<396> as *const (),
    abort_stub::<397> as *const (),
    abort_stub::<398> as *const (),
    abort_stub::<399> as *const (),
    abort_stub::<400> as *const (),
    abort_stub::<401> as *const (),
    abort_stub::<402> as *const (),
    abort_stub::<403> as *const (),
    abort_stub::<404> as *const (),
    abort_stub::<405> as *const (),
    abort_stub::<406> as *const (),
    abort_stub::<407> as *const (),
    abort_stub::<408> as *const (),
    abort_stub::<409> as *const (),
    abort_stub::<410> as *const (),
    abort_stub::<411> as *const (),
    abort_stub::<412> as *const (),
    abort_stub::<413> as *const (),
    abort_stub::<414> as *const (),
    abort_stub::<415> as *const (),
    abort_stub::<416> as *const (),
    abort_stub::<417> as *const (),
    abort_stub::<418> as *const (),
    abort_stub::<419> as *const (),
    abort_stub::<420> as *const (),
    abort_stub::<421> as *const (),
    abort_stub::<422> as *const (),
    abort_stub::<423> as *const (),
    abort_stub::<424> as *const (),
    abort_stub::<425> as *const (),
    abort_stub::<426> as *const (),
    abort_stub::<427> as *const (),
    abort_stub::<428> as *const (),
    abort_stub::<429> as *const (),
    abort_stub::<430> as *const (),
    abort_stub::<431> as *const (),
    abort_stub::<432> as *const (),
    abort_stub::<433> as *const (),
    abort_stub::<434> as *const (),
    abort_stub::<435> as *const (),
    abort_stub::<436> as *const (),
    abort_stub::<437> as *const (),
    abort_stub::<438> as *const (),
    abort_stub::<439> as *const (),
    abort_stub::<440> as *const (),
    abort_stub::<441> as *const (),
    abort_stub::<442> as *const (),
    abort_stub::<443> as *const (),
    abort_stub::<444> as *const (),
    abort_stub::<445> as *const (),
    abort_stub::<446> as *const (),
    abort_stub::<447> as *const (),
    abort_stub::<448> as *const (),
    abort_stub::<449> as *const (),
    abort_stub::<450> as *const (),
    abort_stub::<451> as *const (),
    abort_stub::<452> as *const (),
    abort_stub::<453> as *const (),
    abort_stub::<454> as *const (),
    abort_stub::<455> as *const (),
    abort_stub::<456> as *const (),
    abort_stub::<457> as *const (),
    abort_stub::<458> as *const (),
    abort_stub::<459> as *const (),
    abort_stub::<460> as *const (),
    abort_stub::<461> as *const (),
    abort_stub::<462> as *const (),
    abort_stub::<463> as *const (),
    abort_stub::<464> as *const (),
    abort_stub::<465> as *const (),
    abort_stub::<466> as *const (),
    abort_stub::<467> as *const (),
    abort_stub::<468> as *const (),
    abort_stub::<469> as *const (),
    abort_stub::<470> as *const (),
    abort_stub::<471> as *const (),
    abort_stub::<472> as *const (),
    abort_stub::<473> as *const (),
    abort_stub::<474> as *const (),
    abort_stub::<475> as *const (),
    abort_stub::<476> as *const (),
    abort_stub::<477> as *const (),
    abort_stub::<478> as *const (),
    abort_stub::<479> as *const (),
    abort_stub::<480> as *const (),
    abort_stub::<481> as *const (),
    abort_stub::<482> as *const (),
    abort_stub::<483> as *const (),
    abort_stub::<484> as *const (),
    abort_stub::<485> as *const (),
    abort_stub::<486> as *const (),
    abort_stub::<487> as *const (),
    abort_stub::<488> as *const (),
    abort_stub::<489> as *const (),
    abort_stub::<490> as *const (),
    abort_stub::<491> as *const (),
    abort_stub::<492> as *const (),
    abort_stub::<493> as *const (),
    abort_stub::<494> as *const (),
    abort_stub::<495> as *const (),
    abort_stub::<496> as *const (),
    abort_stub::<497> as *const (),
    abort_stub::<498> as *const (),
    abort_stub::<499> as *const (),
    abort_stub::<500> as *const (),
    abort_stub::<501> as *const (),
    abort_stub::<502> as *const (),
    abort_stub::<503> as *const (),
    abort_stub::<504> as *const (),
    abort_stub::<505> as *const (),
    abort_stub::<506> as *const (),
    abort_stub::<507> as *const (),
    abort_stub::<508> as *const (),
    abort_stub::<509> as *const (),
    abort_stub::<510> as *const (),
    abort_stub::<511> as *const (),
]);

/// Owns one output allocation that must be released by ADI's disposer.
///
/// Rust never frees the foreign allocation directly.  Consuming the value
/// copies at most one mebibyte into zeroizing Rust storage and invokes the
/// matching ADI disposer exactly once, including on validation failure.
pub struct AdiOwnedBuffer {
    pointer: *const u8,
    length: usize,
    dispose: AdiDispose,
}

impl AdiOwnedBuffer {
    /// Takes ownership of a successful ADI output allocation.
    ///
    /// # Safety
    ///
    /// `pointer` must be null only when `length` is zero, otherwise it must be
    /// readable for `length` bytes.  `dispose` must be the disposer paired
    /// with that exact allocation, accept null for an empty allocation, and
    /// remain callable until this owner is consumed or dropped.
    #[allow(unsafe_code)]
    pub unsafe fn from_raw(pointer: *const u8, length: usize, dispose: AdiDispose) -> Self {
        Self {
            pointer,
            length,
            dispose,
        }
    }

    /// Copies the bounded bytes into zeroizing storage and disposes ADI data.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::HelperFailed`] when the pointer/length pair is
    /// invalid, exceeds the one-mebibyte bound, or ADI rejects disposal.
    #[allow(unsafe_code)]
    pub fn copy_and_dispose(mut self) -> Result<Zeroizing<Vec<u8>>, BridgeError> {
        if self.length > MAX_ADI_OUTPUT_BYTES || (self.length != 0 && self.pointer.is_null()) {
            return Err(BridgeError::HelperFailed);
        }
        // SAFETY: the ADI status succeeded, the pointer is non-null for a
        // nonempty length, and the length is bounded before creating a slice.
        let copied = Zeroizing::new(if self.length == 0 {
            Vec::new()
        } else {
            // SAFETY: the nonempty pointer and bounded length were checked.
            unsafe { std::slice::from_raw_parts(self.pointer, self.length) }.to_vec()
        });
        // SAFETY: ownership stays with ADI until exactly this call.  Rust never
        // attempts to free the foreign allocation.
        let pointer = self.pointer;
        self.pointer = std::ptr::null();
        // SAFETY: `from_raw` paired this pointer with its ADI disposer, and
        // clearing the field first prevents Drop from disposing it again.
        if unsafe { (self.dispose)(pointer) } != 0 {
            return Err(BridgeError::HelperFailed);
        }
        Ok(copied)
    }
}

#[allow(unsafe_code)]
impl Drop for AdiOwnedBuffer {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            // SAFETY: the owner has not been consumed; Drop is the exactly-once
            // fallback for an early return.
            let _ = unsafe { (self.dispose)(self.pointer) };
            self.pointer = std::ptr::null();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    #[cfg(target_arch = "x86_64")]
    use elf_loader::arch::x86_64::X86_64Arch;
    #[cfg(target_arch = "x86_64")]
    use elf_loader::elf::write::DsoBuilder;

    use super::*;

    #[test]
    fn property_names_are_classified_without_retaining_unknown_text() {
        assert_eq!(
            classify_property(b"ro.product.model"),
            PropertyKey::ProductModel
        );
        assert_eq!(
            classify_property(b"arbitrary-sensitive-looking"),
            PropertyKey::Unknown
        );
    }

    #[test]
    fn parent_owned_disposable_state_directory_is_accepted() {
        let state = tempfile::Builder::new()
            .prefix("coffer-anisette-state-")
            .tempdir()
            .expect("state directory");
        std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o700))
            .expect("restrict state directory");
        assert_eq!(
            checked_state_directory(state.path()).expect("valid state directory"),
            state.path()
        );
    }

    #[test]
    fn state_directory_must_be_private_and_empty() {
        let nonempty = tempfile::Builder::new()
            .prefix("coffer-anisette-state-")
            .tempdir()
            .expect("state directory");
        std::fs::set_permissions(nonempty.path(), std::fs::Permissions::from_mode(0o700))
            .expect("restrict state directory");
        std::fs::write(nonempty.path().join("unexpected"), b"x").expect("create entry");
        assert_eq!(
            checked_state_directory(nonempty.path()),
            Err(BridgeError::InvalidPath)
        );

        let public = tempfile::Builder::new()
            .prefix("coffer-anisette-state-")
            .tempdir()
            .expect("state directory");
        std::fs::set_permissions(public.path(), std::fs::Permissions::from_mode(0o755))
            .expect("set public mode");
        assert_eq!(
            checked_state_directory(public.path()),
            Err(BridgeError::InvalidPath)
        );
    }

    #[test]
    fn pathname_shims_accept_only_normalized_state_relative_paths() {
        let root = b"/tmp/coffer-anisette-state-test";
        assert_eq!(
            relative_state_path(root, b"/tmp/coffer-anisette-state-test/a/b")
                .expect("inside path")
                .as_bytes(),
            b"a/b"
        );
        assert_eq!(
            relative_state_path(root, b"./a//b")
                .expect("relative path")
                .as_bytes(),
            b"a/b"
        );
        assert!(relative_state_path(root, b"/tmp/outside").is_none());
        assert!(relative_state_path(root, b"../outside").is_none());
        assert!(relative_state_path(root, b"a/../../outside").is_none());
    }

    #[test]
    fn dlopen_dlsym_and_dlclose_are_allowlisted_and_refcounted() {
        reset_adapter_state();
        CORE_CVU.store(0x1110, Ordering::SeqCst);
        CORE_VDF.store(0x2220, Ordering::SeqCst);
        let allowed = CString::new("/verified/libCoreADI.so").expect("cstring");
        let denied = CString::new("libCoreFP.so").expect("cstring");
        let handle = shim_dlopen(allowed.as_ptr(), 1);
        assert_eq!(handle as usize, CORE_HANDLE);
        assert!(shim_dlopen(denied.as_ptr(), 1).is_null());
        let symbol = CString::new("cvu8io98wun").expect("cstring");
        assert_eq!(shim_dlsym(handle, symbol.as_ptr()) as usize, 0x1110);
        assert_eq!(shim_dlclose(handle), 0);
        assert_eq!(shim_dlclose(handle), -1);
    }

    #[test]
    fn rwlock_alignment_guard_never_forwards_unaligned_storage() {
        let mut storage = [0u8; 64];
        let unaligned = storage[1..].as_mut_ptr().cast::<libc::pthread_rwlock_t>();
        assert_eq!(shim_rwlock_init(unaligned), libc::EINVAL);
        let mut aligned = std::mem::MaybeUninit::<libc::pthread_rwlock_t>::uninit();
        let pointer = aligned.as_mut_ptr();
        assert_eq!(shim_rwlock_init(pointer), 0);
        assert_eq!(shim_rwlock_wrlock(pointer), 0);
        assert_eq!(shim_rwlock_unlock(pointer), 0);
        assert_eq!(shim_rwlock_destroy(pointer), 0);
    }

    #[test]
    fn four_aligned_bionic_lock_uses_independent_host_storage() {
        let mut storage = [0u32; 16];
        let base = storage.as_mut_ptr();
        let index =
            usize::from((base as usize).is_multiple_of(align_of::<libc::pthread_rwlock_t>()));
        let pointer = base.wrapping_add(index).cast::<libc::pthread_rwlock_t>();
        assert_eq!((pointer as usize) % BIONIC_PTHREAD_ALIGNMENT, 0);
        assert_ne!((pointer as usize) % align_of::<libc::pthread_rwlock_t>(), 0);
        assert_eq!(shim_rwlock_init(pointer), 0);
        assert_eq!(shim_rwlock_rdlock(pointer), 0);
        assert_eq!(shim_rwlock_unlock(pointer), 0);
        assert_eq!(shim_rwlock_destroy(pointer), 0);
    }

    static DISPOSE_CALLS: AtomicUsize = AtomicUsize::new(0);

    #[allow(unsafe_code)]
    unsafe extern "C" fn fake_dispose(pointer: *const u8) -> i32 {
        DISPOSE_CALLS.fetch_add(1, Ordering::SeqCst);
        // SAFETY: the test passes a pointer allocated by Box::into_raw with
        // this exact one-byte layout and transfers it here once.
        drop(unsafe { Box::from_raw(pointer.cast_mut()) });
        0
    }

    #[allow(unsafe_code)]
    unsafe extern "C" fn failing_dispose(pointer: *const u8) -> i32 {
        DISPOSE_CALLS.fetch_add(1, Ordering::SeqCst);
        // SAFETY: the test transfers the matching one-byte Box exactly once.
        drop(unsafe { Box::from_raw(pointer.cast_mut()) });
        -1
    }

    #[test]
    #[allow(unsafe_code)]
    fn adi_buffer_is_copied_zeroized_and_disposed_exactly_once() {
        DISPOSE_CALLS.store(0, Ordering::SeqCst);
        let pointer = Box::into_raw(Box::new(7u8));
        // SAFETY: the one-byte Box remains live and ownership is transferred
        // to the matching `fake_dispose` exactly once.
        let copied = unsafe { AdiOwnedBuffer::from_raw(pointer, 1, fake_dispose) }
            .copy_and_dispose()
            .expect("copy");
        assert_eq!(&*copied, &[7]);
        assert_eq!(DISPOSE_CALLS.load(Ordering::SeqCst), 1);
    }

    #[test]
    #[allow(unsafe_code)]
    fn adi_buffer_copy_is_zeroizing_before_a_failing_disposer_returns() {
        DISPOSE_CALLS.store(0, Ordering::SeqCst);
        let pointer = Box::into_raw(Box::new(9u8));
        // SAFETY: the one-byte Box remains live and ownership is transferred
        // to the matching `failing_dispose` exactly once.
        let error = unsafe { AdiOwnedBuffer::from_raw(pointer, 1, failing_dispose) }
            .copy_and_dispose()
            .expect_err("disposal failure");
        assert_eq!(error, BridgeError::HelperFailed);
        assert_eq!(DISPOSE_CALLS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn abort_stubs_have_deterministic_distinct_identities() {
        let stubs = stub_addresses();
        assert_eq!(stubs.len(), 512);
        assert_eq!(stubs.iter().copied().collect::<BTreeSet<_>>().len(), 512);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn synthetic_image_maps_with_initialization_deferred() {
        let image = DsoBuilder::<X86_64Arch>::new("deferred.so")
            .with_text(vec![0xc3])
            .build()
            .expect("build synthetic DSO");
        let bridge = SyntheticModule::new("__empty_bridge", Vec::<SyntheticSymbol>::new());
        let loaded = relocate(&image.bytes, &bridge).expect("map and relocate");
        assert!(!loaded.state().is_initialized());
    }

    #[test]
    #[ignore = "requires an explicit local support-library root; never runs in CI"]
    fn current_images_map_relocate_and_bind_without_initialization() {
        let root = PathBuf::from(
            std::env::var_os("COFFER_ANISETTE_LIBRARY_ROOT").expect("explicit library root"),
        );
        let architecture = Architecture::host().expect("supported host");
        let directory = root.join("lib").join(architecture.android_abi());
        let core_bytes = read_library(&directory.join("libCoreADI.so")).expect("read CoreADI");
        let ssc_bytes = read_library(&directory.join("libstoreservicescore.so"))
            .expect("read StoreServicesCore");
        let core_imports =
            validate(&core_bytes, architecture, ImageKind::CoreAdi).expect("CoreADI policy");
        let ssc_imports = validate(&ssc_bytes, architecture, ImageKind::StoreServicesCore)
            .expect("StoreServicesCore policy");
        let bridge = bridge_module(core_imports.iter().chain(&ssc_imports)).expect("bridge");
        let core = relocate(&core_bytes, &bridge).expect("relocate CoreADI");
        publish_core_symbols(&core).expect("bind CoreADI exports");
        let ssc = relocate(&ssc_bytes, &bridge).expect("relocate StoreServicesCore");
        let _entries = bind_adi_entries(&ssc).expect("bind typed ADI exports");
        assert!(!core.state().is_initialized());
        assert!(!ssc.state().is_initialized());
    }
}
