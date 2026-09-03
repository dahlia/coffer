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

//! Where bootstrap keeps things, and why each thing lives where it does.
//!
//! Three XDG base directories are involved, and the split between them is a
//! durability decision, not a tidiness one.
//!
//! # `XDG_DATA_HOME`: anisette provisioning state
//!
//! [`BootstrapPaths::provisioning_directory`] is the stable location for the
//! machine identity and provisioning material that local anisette generation
//! produces.  That material is not reproducible: it is bound to this
//! installation, it is created by talking to Apple, and losing it forces a
//! re-provision.  `XDG_DATA_HOME` is the only base directory the specification
//! describes as user data that must persist, so that is where it belongs.
//!
//! This crate **only reports that path**.  It never creates, writes, reads or
//! removes anything under it.  Library bootstrap and provisioning state are
//! deliberately different lifecycles: replacing the support libraries must not
//! be able to destroy an identity that cannot be regenerated offline.
//!
//! # `XDG_CACHE_HOME`: the support library payload
//!
//! [`BootstrapPaths::cache_root`] holds the extracted libraries, keyed by
//! architecture and content digest.  This payload *is* reproducible: it can be
//! downloaded again from Apple at any time, it contains nothing about the user,
//! and a cache cleaner deleting it costs bandwidth rather than access.  That is
//! exactly what `XDG_CACHE_HOME` is specified for.  Staging directories for
//! in-progress installs live here too, so that the final publish is a rename
//! within one filesystem.
//!
//! # `XDG_STATE_HOME`: which install is active
//!
//! [`BootstrapPaths::state_root`] holds two small files: the pointer to the
//! active installation and the cross-process bootstrap lock.  The pointer is
//! state that should survive a reboot but is neither user data nor a cache: if
//! the cache is wiped, the pointer is stale and bootstrap notices and re-runs.
//! Keeping it out of the cache is what lets Coffer tell "the payload was
//! cleaned up" apart from "nothing was ever installed", and keeping the lock
//! beside it means the lock file is not deleted by a cache cleaner while a
//! process holds it.

use core::fmt;
use std::env;
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use crate::arch::Architecture;

/// The directory name Coffer uses inside each XDG base directory.
const APPLICATION_DIRECTORY: &str = "coffer";

/// The subdirectory holding anisette provisioning state.
const PROVISIONING_DIRECTORY: &str = "anisette";

/// The subdirectory holding the Apple support libraries and their metadata.
const LIBRARY_DIRECTORY: &str = "apple-support-libraries";

/// The staging area for installs that have not been published yet.
const STAGING_DIRECTORY: &str = "staging";

/// The directory holding published installs, one subdirectory per install.
const VERSIONS_DIRECTORY: &str = "versions";

/// The file naming the active installation.
const ACTIVE_INSTALL_FILE: &str = "active.json";

/// The cross-process bootstrap lock.
const LOCK_FILE: &str = "bootstrap.lock";

/// The resolved filesystem locations bootstrap uses.
///
/// Construct one with [`BootstrapPaths::from_environment`] in production, or
/// with [`BootstrapPaths::rooted_at`] in tests, which places all three base
/// directories under a single temporary root so that a test never touches the
/// developer's real XDG directories.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapPaths {
    provisioning_directory: PathBuf,
    cache_root: PathBuf,
    state_root: PathBuf,
}

impl BootstrapPaths {
    /// Resolves the paths from the XDG environment.
    ///
    /// `XDG_DATA_HOME`, `XDG_CACHE_HOME` and `XDG_STATE_HOME` are honored when
    /// they hold an absolute path.  A relative value is ignored in favor of the
    /// specified default, as the XDG Base Directory Specification requires.
    ///
    /// # Errors
    ///
    /// Returns [`PathResolutionError::NoHomeDirectory`] when a default is
    /// needed and `HOME` is unset or empty.  Bootstrap has no sensible fallback
    /// in that case, and guessing one risks writing an installation somewhere
    /// the user cannot find or clean up.
    pub fn from_environment() -> Result<Self, PathResolutionError> {
        let data_home = base_directory("XDG_DATA_HOME", &[".local", "share"])?;
        let cache_home = base_directory("XDG_CACHE_HOME", &[".cache"])?;
        let state_home = base_directory("XDG_STATE_HOME", &[".local", "state"])?;
        Ok(Self::new(&data_home, &cache_home, &state_home))
    }

    /// Builds the paths from explicit XDG base directories.
    #[must_use]
    pub fn new(data_home: &Path, cache_home: &Path, state_home: &Path) -> Self {
        Self {
            provisioning_directory: data_home
                .join(APPLICATION_DIRECTORY)
                .join(PROVISIONING_DIRECTORY),
            cache_root: cache_home
                .join(APPLICATION_DIRECTORY)
                .join(LIBRARY_DIRECTORY),
            state_root: state_home
                .join(APPLICATION_DIRECTORY)
                .join(LIBRARY_DIRECTORY),
        }
    }

    /// Builds the paths with all three XDG base directories under `root`.
    ///
    /// Intended for tests and for sandboxed launches that supply their own
    /// root.  The subdirectory names match the XDG defaults so that a layout
    /// bug shows up here as well as in production.
    #[must_use]
    pub fn rooted_at(root: &Path) -> Self {
        Self::new(
            &root.join(".local").join("share"),
            &root.join(".cache"),
            &root.join(".local").join("state"),
        )
    }

    /// The durable location for anisette provisioning state.
    ///
    /// This crate never creates or removes this directory; it only reports
    /// where it is, so that the component that owns provisioning has one
    /// answer and library updates cannot disturb it.  See the module
    /// documentation for why it lives under `XDG_DATA_HOME`.
    #[must_use]
    pub fn provisioning_directory(&self) -> &Path {
        &self.provisioning_directory
    }

    /// The root of the redownloadable support library payload.
    #[must_use]
    pub fn cache_root(&self) -> &Path {
        &self.cache_root
    }

    /// The root of the small, durable bootstrap state.
    #[must_use]
    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    /// The staging area for installs that have not been published.
    ///
    /// On the same filesystem as [`BootstrapPaths::versions_root`], because
    /// publishing an install is a rename from one to the other.
    #[must_use]
    pub fn staging_root(&self) -> PathBuf {
        self.cache_root.join(STAGING_DIRECTORY)
    }

    /// The directory holding published installs.
    #[must_use]
    pub fn versions_root(&self) -> PathBuf {
        self.cache_root.join(VERSIONS_DIRECTORY)
    }

    /// The directory holding published installs for one architecture.
    #[must_use]
    pub fn architecture_root(&self, architecture: Architecture) -> PathBuf {
        self.versions_root().join(architecture.android_abi())
    }

    /// The directory a specific install is published to.
    #[must_use]
    pub fn install_directory(&self, architecture: Architecture, install_id: &str) -> PathBuf {
        self.architecture_root(architecture).join(install_id)
    }

    /// The file naming the active installation.
    #[must_use]
    pub fn active_install_file(&self) -> PathBuf {
        self.state_root.join(ACTIVE_INSTALL_FILE)
    }

    /// The cross-process bootstrap lock file.
    #[must_use]
    pub fn lock_file(&self) -> PathBuf {
        self.state_root.join(LOCK_FILE)
    }

    /// Checks that nothing irreplaceable sits where bootstrap deletes
    /// recursively.
    ///
    /// Bootstrap removes everything under [`BootstrapPaths::staging_root`] when
    /// it cleans up after an interrupted run, and it replaces whole install
    /// directories under [`BootstrapPaths::versions_root`].  Two things must
    /// therefore never live inside either of those: the anisette provisioning
    /// directory, whose contents cannot be regenerated offline, and the state
    /// root, which holds the lock that serializes bootstrap across processes
    /// and the pointer naming the active installation.  Symmetrically, nothing
    /// bootstrap manages may live inside the provisioning directory.
    ///
    /// Coffer refuses such a configuration outright rather than proceeding
    /// carefully within it, because no amount of care makes recursive deletion
    /// safe next to irreplaceable data.
    ///
    /// The comparison is made on *effective* paths: the longest existing
    /// ancestor of each location is resolved through symbolic links, and the
    /// remainder is normalized, so neither a `..` component nor a symlinked
    /// ancestor can hide a real containment from a purely lexical check.
    ///
    /// Sharing one XDG base directory between several of these is not by itself
    /// a violation; the subtrees still have to overlap.
    ///
    /// # Errors
    ///
    /// Returns [`LayoutViolation::ProvisioningOverlap`] when the provisioning
    /// directory overlaps something bootstrap manages, and
    /// [`LayoutViolation::StateInsideDeletedTree`] when the state root sits
    /// where bootstrap deletes recursively.
    pub fn check_separation(&self) -> Result<(), LayoutViolation> {
        let provisioning = effective_path(&self.provisioning_directory);
        let cache_root = effective_path(&self.cache_root);
        let state_root = effective_path(&self.state_root);
        let staging_root = effective_path(&self.staging_root());
        let versions_root = effective_path(&self.versions_root());

        // Nothing bootstrap manages may sit inside the provisioning directory,
        // and the provisioning directory may not sit inside a tree bootstrap
        // deletes recursively.
        for deleted in [&staging_root, &versions_root] {
            if provisioning.starts_with(deleted) {
                return Err(LayoutViolation::ProvisioningOverlap);
            }
        }
        // The deleted roots are listed here too, not just their parent: either
        // may itself be a symbolic link resolving into the provisioning
        // directory, in which case the cache root alone shows no overlap.
        for managed in [&cache_root, &state_root, &staging_root, &versions_root] {
            if managed.starts_with(&provisioning) {
                return Err(LayoutViolation::ProvisioningOverlap);
            }
        }

        for deleted in [&staging_root, &versions_root] {
            if state_root.starts_with(deleted) {
                return Err(LayoutViolation::StateInsideDeletedTree);
            }
        }
        Ok(())
    }
}

/// Resolves a path as far as the filesystem allows, then normalizes the rest.
///
/// [`std::fs::canonicalize`] fails on a path that does not exist yet, and every
/// path here may legitimately not exist on a first run.  So the longest
/// existing ancestor is canonicalized — which resolves symbolic links and `..`
/// in that part — and the components below it are appended with `.` dropped and
/// `..` popped lexically.
///
/// The result is not a guarantee: a component could be created, or replaced
/// with a symbolic link, after this returns.  It exists to make a containment
/// check see through the aliases that are actually present, and it is paired
/// with the refusal in `install::create_directory` to treat a symbolic link as
/// a bootstrap-owned directory at the moment it is used.
fn effective_path(path: &Path) -> PathBuf {
    let components: Vec<Component<'_>> = path.components().collect();

    // Longest existing prefix first, so as much of the path as possible is
    // resolved by the filesystem rather than lexically.  `Path::parent` cannot
    // drive this walk: it returns a path whose `file_name` is `None` once a
    // `..` component is reached.
    for split in (1..=components.len()).rev() {
        let prefix: PathBuf = components[..split].iter().collect();
        if let Ok(resolved) = prefix.canonicalize() {
            return extend_lexically(resolved, &components[split..]);
        }
    }
    extend_lexically(PathBuf::new(), &components)
}

/// Appends components to an already-resolved base, resolving `.` and `..`
/// lexically because there is no filesystem entry left to ask.
fn extend_lexically(mut base: PathBuf, components: &[Component<'_>]) -> PathBuf {
    for component in components {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                base.pop();
            }
            other => base.push(other.as_os_str()),
        }
    }
    base
}

/// A filesystem layout Coffer refuses to manage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LayoutViolation {
    /// The provisioning directory overlaps something bootstrap manages.
    ///
    /// See [`BootstrapPaths::check_separation`].
    ProvisioningOverlap,
    /// The state root sits inside a tree bootstrap deletes recursively.
    ///
    /// The state root holds the cross-process lock and the pointer naming the
    /// active installation.  Deleting it mid-run would unlink the lock another
    /// process is holding, letting a third process lock a different inode and
    /// defeating serialization.  See [`BootstrapPaths::check_separation`].
    StateInsideDeletedTree,
    /// A bootstrap-owned directory is a symbolic link.
    ///
    /// Bootstrap removes staging directories recursively, so a symbolic link
    /// standing in for one of its own directories would redirect that removal
    /// somewhere Coffer does not own.  Every bootstrap-owned directory must
    /// therefore be a real directory that Coffer created.
    SymbolicLink,
}

impl fmt::Display for LayoutViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LayoutViolation::ProvisioningOverlap => f.write_str(
                "the anisette provisioning directory overlaps a directory bootstrap manages",
            ),
            LayoutViolation::StateInsideDeletedTree => f.write_str(
                "the bootstrap state directory sits inside a directory bootstrap deletes",
            ),
            LayoutViolation::SymbolicLink => {
                f.write_str("a directory bootstrap manages is a symbolic link")
            }
        }
    }
}

impl std::error::Error for LayoutViolation {}

/// Resolves one XDG base directory from the process environment.
fn base_directory(variable: &str, default: &[&str]) -> Result<PathBuf, PathResolutionError> {
    resolve_base_directory(
        env::var_os(variable).as_deref(),
        env::var_os("HOME").as_deref(),
        default,
    )
}

/// The pure part of [`base_directory`], so the specification's rules can be
/// tested without mutating the process environment.
fn resolve_base_directory(
    override_value: Option<&OsStr>,
    home: Option<&OsStr>,
    default: &[&str],
) -> Result<PathBuf, PathResolutionError> {
    if let Some(value) = override_value {
        let path = Path::new(value);
        // The specification says a relative value is invalid and must be
        // ignored, not resolved against the working directory.
        if path.is_absolute() {
            return Ok(path.to_path_buf());
        }
    }
    let home = home
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .ok_or(PathResolutionError::NoHomeDirectory)?;
    Ok(default
        .iter()
        .fold(home, |path, segment| path.join(segment)))
}

/// Bootstrap could not work out where to keep its files.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PathResolutionError {
    /// An XDG base directory had to fall back to its default, but `HOME` is
    /// unset or empty.
    NoHomeDirectory,
}

impl fmt::Display for PathResolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathResolutionError::NoHomeDirectory => f.write_str(
                "cannot resolve the XDG base directories because HOME is unset or empty",
            ),
        }
    }
}

impl std::error::Error for PathResolutionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_provisioning_state_out_of_the_cache_and_the_state_directory() {
        let paths = BootstrapPaths::rooted_at(Path::new("/tmp/example"));
        let provisioning = paths.provisioning_directory();

        assert!(
            !provisioning.starts_with(paths.cache_root()),
            "provisioning state must not live under the cache root"
        );
        assert!(
            !provisioning.starts_with(paths.state_root()),
            "provisioning state must not live under the state root"
        );
        assert!(
            !paths.cache_root().starts_with(provisioning)
                && !paths.state_root().starts_with(provisioning),
            "no bootstrap-owned directory may live under the provisioning directory"
        );
    }

    #[test]
    fn places_each_kind_of_data_in_the_specified_base_directory() {
        let paths =
            BootstrapPaths::new(Path::new("/data"), Path::new("/cache"), Path::new("/state"));
        assert_eq!(
            paths.provisioning_directory(),
            Path::new("/data/coffer/anisette")
        );
        assert_eq!(
            paths.cache_root(),
            Path::new("/cache/coffer/apple-support-libraries")
        );
        assert_eq!(
            paths.state_root(),
            Path::new("/state/coffer/apple-support-libraries")
        );
        assert_eq!(
            paths.active_install_file(),
            Path::new("/state/coffer/apple-support-libraries/active.json")
        );
        assert_eq!(
            paths.lock_file(),
            Path::new("/state/coffer/apple-support-libraries/bootstrap.lock")
        );
    }

    #[test]
    fn the_staging_area_shares_a_filesystem_with_the_publish_target() {
        let paths = BootstrapPaths::rooted_at(Path::new("/tmp/example"));
        assert!(paths.staging_root().starts_with(paths.cache_root()));
        assert!(paths.versions_root().starts_with(paths.cache_root()));
    }

    #[test]
    fn separates_installs_by_architecture_and_install_id() {
        let paths =
            BootstrapPaths::new(Path::new("/data"), Path::new("/cache"), Path::new("/state"));
        assert_eq!(
            paths.install_directory(Architecture::X86_64, "abc123"),
            Path::new("/cache/coffer/apple-support-libraries/versions/x86_64/abc123")
        );
        assert_eq!(
            paths.install_directory(Architecture::Aarch64, "abc123"),
            Path::new("/cache/coffer/apple-support-libraries/versions/arm64-v8a/abc123")
        );
        assert_ne!(
            paths.install_directory(Architecture::X86_64, "abc123"),
            paths.install_directory(Architecture::Aarch64, "abc123")
        );
    }

    #[test]
    fn refuses_a_layout_where_bootstrap_would_recurse_into_provisioning_state() {
        // The provisioning directory inside the staging root, which
        // `clean_staging` empties.
        let paths = BootstrapPaths::new(
            Path::new("/cache/coffer/apple-support-libraries/staging"),
            Path::new("/cache"),
            Path::new("/state"),
        );
        assert_eq!(
            paths.check_separation(),
            Err(LayoutViolation::ProvisioningOverlap)
        );

        // The provisioning directory inside the versions root, whose install
        // directories are replaced wholesale.
        let paths = BootstrapPaths::new(
            Path::new("/cache/coffer/apple-support-libraries/versions"),
            Path::new("/cache"),
            Path::new("/state"),
        );
        assert_eq!(
            paths.check_separation(),
            Err(LayoutViolation::ProvisioningOverlap)
        );

        // The cache root inside the provisioning directory.
        let paths = BootstrapPaths::new(
            Path::new("/data"),
            Path::new("/data/coffer/anisette"),
            Path::new("/state"),
        );
        assert_eq!(
            paths.check_separation(),
            Err(LayoutViolation::ProvisioningOverlap)
        );

        // The state root inside the provisioning directory.
        let paths = BootstrapPaths::new(
            Path::new("/data"),
            Path::new("/cache"),
            Path::new("/data/coffer/anisette"),
        );
        assert_eq!(
            paths.check_separation(),
            Err(LayoutViolation::ProvisioningOverlap)
        );
    }

    #[test]
    fn refuses_a_layout_where_the_lock_and_pointer_would_be_deleted() {
        // The lock and the active pointer inside the staging root, which
        // `clean_staging` empties at the start of every run.
        let paths = BootstrapPaths::new(
            Path::new("/data"),
            Path::new("/cache"),
            Path::new("/cache/coffer/apple-support-libraries/staging"),
        );
        assert_eq!(
            paths.check_separation(),
            Err(LayoutViolation::StateInsideDeletedTree)
        );

        let paths = BootstrapPaths::new(
            Path::new("/data"),
            Path::new("/cache"),
            Path::new("/cache/coffer/apple-support-libraries/versions"),
        );
        assert_eq!(
            paths.check_separation(),
            Err(LayoutViolation::StateInsideDeletedTree)
        );
    }

    #[test]
    fn sees_through_a_relative_component_that_hides_a_real_overlap() {
        // Lexically `/cache/alias/../coffer/...` does not start with
        // `/cache/coffer/...`, but the effective location does.
        let paths = BootstrapPaths::new(
            Path::new("/cache/alias/../coffer/apple-support-libraries/staging"),
            Path::new("/cache"),
            Path::new("/state"),
        );
        assert_eq!(
            paths.check_separation(),
            Err(LayoutViolation::ProvisioningOverlap)
        );
    }

    #[test]
    fn sees_through_a_symbolic_link_that_hides_a_real_overlap() {
        let root = tempfile::tempdir().expect("temporary root");
        let real = root.path().canonicalize().expect("canonical root");
        let cache_home = real.join("cache");
        let staging = cache_home
            .join("coffer")
            .join("apple-support-libraries")
            .join("staging");
        std::fs::create_dir_all(&staging).expect("create staging");

        // `<root>/alias` points at the staging directory, so a data home under
        // it really does live where `clean_staging` deletes.
        let alias = real.join("alias");
        std::os::unix::fs::symlink(&staging, &alias).expect("symlink");

        let paths = BootstrapPaths::new(&alias.join("data"), &cache_home, &real.join("state"));
        assert_eq!(
            paths.check_separation(),
            Err(LayoutViolation::ProvisioningOverlap),
            "a symlinked ancestor must not hide the overlap"
        );
    }

    #[test]
    fn sees_a_deleted_root_that_is_itself_a_link_into_provisioning_state() {
        let root = tempfile::tempdir().expect("temporary root");
        let real = root.path().canonicalize().expect("canonical root");
        let data_home = real.join("data");
        let provisioning = data_home.join("coffer").join("anisette");
        let captured = provisioning.join("captured");
        std::fs::create_dir_all(&captured).expect("create provisioning");

        // The versions root is a symbolic link into the provisioning
        // directory.  The cache root itself shows no overlap; only the versions
        // root does.
        let cache_home = real.join("cache");
        let library_root = cache_home.join("coffer").join("apple-support-libraries");
        std::fs::create_dir_all(&library_root).expect("create library root");
        std::os::unix::fs::symlink(&captured, library_root.join("versions"))
            .expect("symlink versions root");

        let paths = BootstrapPaths::new(&data_home, &cache_home, &real.join("state"));
        assert_eq!(
            paths.check_separation(),
            Err(LayoutViolation::ProvisioningOverlap),
            "a deleted root linked into provisioning state must be refused"
        );
    }

    #[test]
    fn a_shared_base_directory_is_not_by_itself_an_overlap() {
        let root = tempfile::tempdir().expect("temporary root");
        BootstrapPaths::rooted_at(root.path())
            .check_separation()
            .expect("the default layout must be acceptable");
        BootstrapPaths::new(root.path(), root.path(), root.path())
            .check_separation()
            .expect("one base directory for all three must remain acceptable");
    }

    #[test]
    fn the_provisioning_path_is_stable_across_repeated_resolution() {
        let first = BootstrapPaths::rooted_at(Path::new("/tmp/example"));
        let second = BootstrapPaths::rooted_at(Path::new("/tmp/example"));
        assert_eq!(
            first.provisioning_directory(),
            second.provisioning_directory()
        );
        assert_eq!(first, second);
    }

    #[test]
    fn honors_an_absolute_xdg_override() {
        let resolved = resolve_base_directory(
            Some(OsStr::new("/xdg/data")),
            Some(OsStr::new("/home/example")),
            &[".local", "share"],
        )
        .expect("an absolute override needs no home directory");
        assert_eq!(resolved, Path::new("/xdg/data"));
    }

    #[test]
    fn ignores_a_relative_or_empty_xdg_override_in_favor_of_the_specified_default() {
        for override_value in ["relative/path", ""] {
            let resolved = resolve_base_directory(
                Some(OsStr::new(override_value)),
                Some(OsStr::new("/home/example")),
                &[".local", "state"],
            )
            .expect("the default applies");
            assert_eq!(resolved, Path::new("/home/example/.local/state"));
        }
    }

    #[test]
    fn fails_when_a_default_is_needed_but_home_is_unusable() {
        for home in [None, Some(OsStr::new(""))] {
            assert_eq!(
                resolve_base_directory(None, home, &[".cache"]),
                Err(PathResolutionError::NoHomeDirectory)
            );
        }
        // An absolute override means the default is never needed, so an
        // unusable home is not an error.
        assert_eq!(
            resolve_base_directory(Some(OsStr::new("/xdg/cache")), None, &[".cache"]),
            Ok(PathBuf::from("/xdg/cache"))
        );
    }
}
