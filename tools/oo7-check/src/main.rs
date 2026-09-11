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

//! Offline exhaustive provenance guard for the vendored oo7 crate.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Component, Path};
use std::process::Command;

use serde_json::Value;
use sha2::{Digest as _, Sha256};

const VENDOR_RELATIVE_PATH: &str = "crates/coffer-service/vendor/oo7-0.6.0";
const MANIFEST_RELATIVE_PATH: &str = "tools/oo7-0.6.0.json";
const PATCH_RELATIVE_PATH: &str = "tools/oo7-0.6.0.patch";
const MANIFEST_SHA256: &str = "b5b4156276864b648acd43bc1a5ef58b7097dd92ea74b11e416f1c77b7357e3f";
const PATCH_SHA256: &str = "14ba289bb7e5801118537a9fe9e976cfd75be219c1b7ba8d33e8a75d45d26b6a";
const PACKAGE_SHA256: &str = "78f2bfed90f1618b4b48dcad9307f25e14ae894e2949642c87c351601d62cebd";
const UPSTREAM_COMMIT: &str = "9070389f33bec2e47048384e2fdbd7aab64e0df7";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CheckError(&'static str);

impl fmt::Display for CheckError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for CheckError {}

fn main() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the checker remains under tools/oo7-check");
    if let Err(error) = run(repository) {
        eprintln!("oo7 vendor check failed: {error}");
        std::process::exit(1);
    }
}

fn run(repository: &Path) -> Result<(), CheckError> {
    let manifest_path = repository.join(MANIFEST_RELATIVE_PATH);
    let manifest_bytes = fs::read(&manifest_path)
        .map_err(|_| CheckError("the oo7 provenance manifest was absent"))?;
    verify_digest(
        &manifest_bytes,
        MANIFEST_SHA256,
        "the oo7 provenance manifest drifted",
    )?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| CheckError("the oo7 provenance manifest was invalid"))?;
    verify_metadata(&manifest)?;

    let expected = manifested_files(&manifest)?;
    let vendor = repository.join(VENDOR_RELATIVE_PATH);
    verify_manifested_tree(&vendor, &expected)?;
    verify_patch(repository, &vendor, &manifest)
}

fn verify_metadata(manifest: &Value) -> Result<(), CheckError> {
    let exact = [
        ("/schema", Value::from(1)),
        ("/vendor_path", Value::from(VENDOR_RELATIVE_PATH)),
        ("/package/name", Value::from("oo7")),
        ("/package/version", Value::from("0.6.0")),
        ("/package/source", Value::from("crates.io")),
        ("/package/archive_sha256", Value::from(PACKAGE_SHA256)),
        (
            "/package/repository",
            Value::from("https://github.com/linux-credentials/oo7"),
        ),
        ("/package/commit", Value::from(UPSTREAM_COMMIT)),
        ("/package/license", Value::from("MIT")),
        ("/patch/path", Value::from(PATCH_RELATIVE_PATH)),
        ("/patch/sha256", Value::from(PATCH_SHA256)),
    ];
    if exact
        .iter()
        .any(|(pointer, expected)| manifest.pointer(pointer) != Some(expected))
    {
        return Err(CheckError("the oo7 provenance metadata drifted"));
    }
    Ok(())
}

fn manifested_files(manifest: &Value) -> Result<BTreeMap<String, String>, CheckError> {
    let entries = manifest
        .get("files")
        .and_then(Value::as_array)
        .ok_or(CheckError("the oo7 file manifest was absent"))?;
    let mut files = BTreeMap::new();
    for entry in entries {
        let path = entry
            .get("path")
            .and_then(Value::as_str)
            .ok_or(CheckError("an oo7 manifest path was invalid"))?;
        let digest = entry
            .get("sha256")
            .and_then(Value::as_str)
            .ok_or(CheckError("an oo7 manifest digest was invalid"))?;
        if !safe_relative_path(path) || !valid_sha256(digest) {
            return Err(CheckError("an oo7 manifest entry was invalid"));
        }
        if files.insert(path.to_owned(), digest.to_owned()).is_some() {
            return Err(CheckError("an oo7 manifest path was duplicated"));
        }
    }
    if files.is_empty() {
        return Err(CheckError("the oo7 file manifest was empty"));
    }
    Ok(files)
}

fn safe_relative_path(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn valid_sha256(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn verify_manifested_tree(
    root: &Path,
    expected: &BTreeMap<String, String>,
) -> Result<(), CheckError> {
    let observed = relative_files(root)?;
    let expected_paths: BTreeSet<_> = expected.keys().cloned().collect();
    if observed != expected_paths {
        return Err(CheckError("the oo7 vendored file inventory drifted"));
    }
    for (relative, expected_digest) in expected {
        verify_file(
            &root.join(relative),
            expected_digest,
            "an oo7 vendored file drifted",
        )?;
    }
    Ok(())
}

fn relative_files(root: &Path) -> Result<BTreeSet<String>, CheckError> {
    let root_type = fs::symlink_metadata(root)
        .map_err(|_| CheckError("the oo7 vendor was absent"))?
        .file_type();
    if root_type.is_symlink() {
        return Err(CheckError("the oo7 vendor root may not be a symlink"));
    }
    if !root_type.is_dir() {
        return Err(CheckError("the oo7 vendor root was not a directory"));
    }
    let mut files = BTreeSet::new();
    collect_files(root, root, &mut files)?;
    Ok(files)
}

fn collect_files(
    root: &Path,
    directory: &Path,
    files: &mut BTreeSet<String>,
) -> Result<(), CheckError> {
    for entry in fs::read_dir(directory).map_err(|_| CheckError("the oo7 vendor was absent"))? {
        let entry = entry.map_err(|_| CheckError("the oo7 vendor could not be read"))?;
        let file_type = entry
            .file_type()
            .map_err(|_| CheckError("an oo7 vendor file type could not be read"))?;
        if file_type.is_symlink() {
            return Err(CheckError("the oo7 vendor may not contain symlinks"));
        }
        if file_type.is_dir() {
            collect_files(root, &entry.path(), files)?;
        } else if file_type.is_file() {
            let entry_path = entry.path();
            let relative = entry_path
                .strip_prefix(root)
                .map_err(|_| CheckError("an oo7 vendor path escaped its root"))?;
            let relative = relative
                .components()
                .map(|component| match component {
                    Component::Normal(name) => name
                        .to_str()
                        .ok_or(CheckError("an oo7 vendor path was not UTF-8")),
                    Component::Prefix(_)
                    | Component::RootDir
                    | Component::CurDir
                    | Component::ParentDir => {
                        Err(CheckError("an oo7 vendor path escaped its root"))
                    }
                })
                .collect::<Result<Vec<_>, _>>()?
                .join("/");
            files.insert(relative);
        } else {
            return Err(CheckError("the oo7 vendor contains a special file"));
        }
    }
    Ok(())
}

fn verify_patch(repository: &Path, vendor: &Path, manifest: &Value) -> Result<(), CheckError> {
    let patch = repository.join(PATCH_RELATIVE_PATH);
    verify_file(&patch, PATCH_SHA256, "the oo7 patch drifted")?;
    let modifications = manifest
        .pointer("/patch/modifications")
        .and_then(Value::as_array)
        .ok_or(CheckError("the oo7 patch records were absent"))?;
    if modifications.len() != 2 {
        return Err(CheckError("the oo7 patch records drifted"));
    }

    let reconstructed = tempfile::tempdir()
        .map_err(|_| CheckError("could not create an oo7 reconstruction directory"))?;
    let mut originals = BTreeMap::new();
    for modification in modifications {
        let relative = modification
            .get("path")
            .and_then(Value::as_str)
            .ok_or(CheckError("an oo7 patch path was invalid"))?;
        let upstream = modification
            .get("upstream_sha256")
            .and_then(Value::as_str)
            .ok_or(CheckError("an oo7 upstream digest was invalid"))?;
        let final_digest = modification
            .get("vendored_sha256")
            .and_then(Value::as_str)
            .ok_or(CheckError("an oo7 patched digest was invalid"))?;
        if !safe_relative_path(relative)
            || !valid_sha256(upstream)
            || !valid_sha256(final_digest)
            || originals.insert(relative, upstream).is_some()
        {
            return Err(CheckError("an oo7 patch record was invalid"));
        }
        let manifested = manifest
            .get("files")
            .and_then(Value::as_array)
            .and_then(|files| {
                files
                    .iter()
                    .find(|file| file.get("path").and_then(Value::as_str) == Some(relative))
            })
            .and_then(|file| file.get("sha256"))
            .and_then(Value::as_str);
        if manifested != Some(final_digest) {
            return Err(CheckError("an oo7 patched digest was inconsistent"));
        }
        let destination = reconstructed.path().join(relative);
        fs::create_dir_all(
            destination
                .parent()
                .ok_or(CheckError("an oo7 patch path had no parent"))?,
        )
        .map_err(|_| CheckError("could not prepare the oo7 reconstruction"))?;
        fs::copy(vendor.join(relative), destination)
            .map_err(|_| CheckError("could not stage a patched oo7 file"))?;
    }

    let initialized = Command::new("git")
        .args(["init", "--quiet"])
        .current_dir(reconstructed.path())
        .status()
        .map_err(|_| CheckError("could not initialize the oo7 reconstruction"))?;
    if !initialized.success() {
        return Err(CheckError("could not initialize the oo7 reconstruction"));
    }
    for arguments in [
        &["apply", "--unidiff-zero", "-R", "--check"][..],
        &["apply", "--unidiff-zero", "-R", "--whitespace=nowarn"][..],
    ] {
        let status = Command::new("git")
            .args(arguments)
            .arg(&patch)
            .current_dir(reconstructed.path())
            .status()
            .map_err(|_| CheckError("could not execute git apply for oo7"))?;
        if !status.success() {
            return Err(CheckError("the oo7 patch did not reconstruct upstream"));
        }
    }
    for (relative, upstream) in originals {
        verify_file(
            &reconstructed.path().join(relative),
            upstream,
            "an oo7 reconstructed upstream file drifted",
        )?;
    }
    Ok(())
}

fn verify_file(path: &Path, expected: &str, message: &'static str) -> Result<(), CheckError> {
    let bytes = fs::read(path).map_err(|_| CheckError(message))?;
    verify_digest(&bytes, expected, message)
}

fn verify_digest(bytes: &[u8], expected: &str, message: &'static str) -> Result<(), CheckError> {
    if sha256(bytes) == expected {
        Ok(())
    } else {
        Err(CheckError(message))
    }
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_manifest(root: &Path) -> BTreeMap<String, String> {
        let first = b"reviewed first file";
        let second = b"reviewed second file";
        fs::create_dir(root.join("nested")).expect("fixture directory");
        fs::write(root.join("first"), first).expect("first fixture");
        fs::write(root.join("nested/second"), second).expect("second fixture");
        BTreeMap::from([
            ("first".to_owned(), sha256(first)),
            ("nested/second".to_owned(), sha256(second)),
        ])
    }

    #[test]
    fn exhaustive_tree_check_rejects_changed_missing_and_additional_files() {
        let directory = tempfile::tempdir().expect("temporary vendor directory");
        let expected = fixture_manifest(directory.path());
        assert_eq!(verify_manifested_tree(directory.path(), &expected), Ok(()));

        fs::write(directory.path().join("first"), b"changed").expect("change fixture");
        assert_eq!(
            verify_manifested_tree(directory.path(), &expected),
            Err(CheckError("an oo7 vendored file drifted"))
        );
        fs::write(directory.path().join("first"), b"reviewed first file").expect("restore fixture");

        fs::remove_file(directory.path().join("nested/second")).expect("remove fixture");
        assert_eq!(
            verify_manifested_tree(directory.path(), &expected),
            Err(CheckError("the oo7 vendored file inventory drifted"))
        );
        fs::write(
            directory.path().join("nested/second"),
            b"reviewed second file",
        )
        .expect("restore fixture");

        fs::write(directory.path().join("additional"), b"unreviewed").expect("additional fixture");
        assert_eq!(
            verify_manifested_tree(directory.path(), &expected),
            Err(CheckError("the oo7 vendored file inventory drifted"))
        );
    }

    #[test]
    fn manifest_paths_and_digests_are_strict() {
        assert!(safe_relative_path("src/file.rs"));
        for path in ["", "/absolute", "../escape", "src/../escape"] {
            assert!(!safe_relative_path(path));
        }
        assert!(valid_sha256(&"a".repeat(64)));
        assert!(!valid_sha256(&"A".repeat(64)));
        assert!(!valid_sha256(&"a".repeat(63)));
    }

    #[cfg(unix)]
    #[test]
    fn exhaustive_tree_check_rejects_backslash_name_collision() {
        let directory = tempfile::tempdir().expect("temporary vendor directory");
        let expected = fixture_manifest(directory.path());
        fs::write(directory.path().join(r"nested\second"), b"unreviewed")
            .expect("backslash fixture");
        assert_eq!(
            verify_manifested_tree(directory.path(), &expected),
            Err(CheckError("the oo7 vendored file inventory drifted"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn exhaustive_tree_check_rejects_symlinked_vendor_root() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary directory");
        let vendor = directory.path().join("vendor");
        fs::create_dir(&vendor).expect("vendor fixture");
        let expected = fixture_manifest(&vendor);
        let link = directory.path().join("vendor-link");
        symlink(&vendor, &link).expect("vendor root symlink");
        assert_eq!(
            verify_manifested_tree(&link, &expected),
            Err(CheckError("the oo7 vendor root may not be a symlink"))
        );
    }
}
