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

//! Offline guard for the local-only anisette dependency and source boundary.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use quote::ToTokens as _;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

const UPSTREAM_REPOSITORY: &str = "https://github.com/SideStore/apple-private-apis";
const LICENSE_SHA256: &str = "1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5";
const UPSTREAM_METADATA_SHA256: &str =
    "b25aa331625af93d5d6aeb13af1e4538047338010c73ef39a0bce2f6831b6238";

const VENDORED_FILES: [&str; 6] = [
    "Cargo.toml",
    "LICENSE",
    "UPSTREAM.toml",
    "src/adi_proxy.rs",
    "src/anisette_headers_provider.rs",
    "src/lib.rs",
];

const FINAL_HASHES: [(&str, &str); 4] = [
    (
        "Cargo.toml",
        "1125b532c0a5a56f9c2a78b4d8b2f42c607d384a08c004e1e47b0075b48f35c3",
    ),
    (
        "src/lib.rs",
        "d78d24868413de5e91855dde866651eb3c94f4d0edb66d3516829d84f4fa690c",
    ),
    (
        "src/adi_proxy.rs",
        "54d49e82c895ab599b06f37b0029ce0852d8de7d68bd2413f7247257fecdc55e",
    ),
    (
        "src/anisette_headers_provider.rs",
        "2a223a214d7ae531dde984e84a6e9c857d6b41b066ef05197c4fb9c35b84fff9",
    ),
];

const PATCH_SHA256: &str = "e27436272e0dcb99255d1da7c00934ab50e1f33990ae62a504fbf20f73d62857";
const CRATES_IO_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";
const LOCAL_CLOSURE_PACKAGES: [&str; 22] = [
    "base64",
    "block-buffer",
    "cfg-if",
    "cmov",
    "const-oid",
    "cpufeatures",
    "crypto-common",
    "ctutils",
    "digest",
    "hybrid-array",
    "libc",
    "omnisette-local",
    "proc-macro2",
    "quote",
    "sha2",
    "syn",
    "thiserror",
    "thiserror-impl",
    "typenum",
    "unicode-ident",
    "zeroize",
    "zeroize_derive",
];

const ORIGINAL_HASHES: [(&str, &str); 4] = [
    (
        "Cargo.toml",
        "24b20eb7e8e7070b6c62adfadf56c8fbe1668ac91c23d2e7e466911e93e65833",
    ),
    (
        "src/lib.rs",
        "dc138772d9f680d48140b25c7e8097ef09ba3fc0aa1dcf91ee2cb8f444f87aa1",
    ),
    (
        "src/adi_proxy.rs",
        "0bf29dbc2488d210423db82f0454482bd681f7a5d8e7537c20666dfed1941b11",
    ),
    (
        "src/anisette_headers_provider.rs",
        "ac722a884cbc0134902960bf11eb044e256cff7f3b008430704090ba972dd149",
    ),
];

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
        .expect("the checker remains under tools/omnisette-check");
    if let Err(error) = run(repository) {
        eprintln!("omnisette local-only check failed: {error}");
        std::process::exit(1);
    }
}

fn run(repository: &Path) -> Result<(), CheckError> {
    let metadata = cargo_metadata(repository)?;
    verify_graph(&metadata)?;
    verify_source_boundary(repository)?;
    verify_provenance(repository)
}

fn cargo_metadata(repository: &Path) -> Result<Value, CheckError> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsStr::new("cargo").to_owned());
    let output = Command::new(cargo)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--all-features",
            "--offline",
        ])
        .current_dir(repository)
        .output()
        .map_err(|_| CheckError("could not execute cargo metadata"))?;
    if !output.status.success() {
        return Err(CheckError("cargo metadata --locked --all-features failed"));
    }
    serde_json::from_slice(&output.stdout).map_err(|_| CheckError("cargo metadata was invalid"))
}

fn verify_graph(metadata: &Value) -> Result<(), CheckError> {
    let packages = metadata
        .get("packages")
        .and_then(Value::as_array)
        .ok_or(CheckError("metadata packages were absent"))?;
    let nodes = metadata
        .pointer("/resolve/nodes")
        .and_then(Value::as_array)
        .ok_or(CheckError("metadata resolve graph was absent"))?;
    let workspace_root = metadata
        .get("workspace_root")
        .and_then(Value::as_str)
        .ok_or(CheckError("metadata workspace root was absent"))?;

    let mut names = BTreeMap::new();
    let mut manifests = BTreeMap::new();
    let mut sources = BTreeMap::new();
    let mut targets = BTreeMap::new();
    let mut declared_features = BTreeMap::new();
    for package in packages {
        let id = package
            .get("id")
            .and_then(Value::as_str)
            .ok_or(CheckError("a package ID was absent"))?;
        let name = package
            .get("name")
            .and_then(Value::as_str)
            .ok_or(CheckError("a package name was absent"))?;
        let features = package
            .get("features")
            .and_then(Value::as_object)
            .ok_or(CheckError("package features were absent"))?;
        let manifest = package
            .get("manifest_path")
            .and_then(Value::as_str)
            .ok_or(CheckError("a package manifest path was absent"))?;
        let package_targets = package
            .get("targets")
            .and_then(Value::as_array)
            .ok_or(CheckError("package targets were absent"))?
            .iter()
            .map(|target| {
                target
                    .get("src_path")
                    .and_then(Value::as_str)
                    .ok_or(CheckError("a target source path was absent"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        names.insert(id, name);
        manifests.insert(id, manifest);
        sources.insert(id, package.get("source").and_then(Value::as_str));
        targets.insert(id, package_targets);
        declared_features.insert(id, features.keys().map(String::as_str).collect::<Vec<_>>());
    }

    let coffer_id = workspace_package(
        &names,
        &manifests,
        &sources,
        &targets,
        workspace_root,
        "coffer-anisette",
        "crates/coffer-anisette/Cargo.toml",
    )?;
    let local_id = workspace_package(
        &names,
        &manifests,
        &sources,
        &targets,
        workspace_root,
        "omnisette-local",
        "crates/omnisette-local/Cargo.toml",
    )?;
    let roots = [coffer_id, local_id];
    let closure = dependency_closure(nodes, &roots)?;
    for id in &closure {
        let name = names
            .get(id.as_str())
            .ok_or(CheckError("resolved package was absent from metadata"))?;
        if forbidden_package(name) {
            return Err(CheckError(
                "a prohibited package entered the anisette closure",
            ));
        }
        if declared_features
            .get(id.as_str())
            .is_some_and(|features| features.iter().any(|feature| forbidden_feature(feature)))
        {
            return Err(CheckError(
                "a prohibited feature is declared in the anisette closure",
            ));
        }
    }

    let local_closure = dependency_closure(nodes, &[local_id])?;
    for id in &local_closure {
        let name = names
            .get(id.as_str())
            .ok_or(CheckError("resolved local package was absent"))?;
        if !LOCAL_CLOSURE_PACKAGES.contains(name) {
            return Err(CheckError(
                "an unreviewed package entered the omnisette-local closure",
            ));
        }
        if id != local_id && sources.get(id.as_str()).copied().flatten() != Some(CRATES_IO_SOURCE) {
            return Err(CheckError(
                "an omnisette-local dependency did not come from crates.io",
            ));
        }
    }

    if !declared_features
        .get(local_id)
        .is_some_and(|features| features.is_empty())
    {
        return Err(CheckError("omnisette-local must declare no features"));
    }
    let resolved_local = nodes
        .iter()
        .find(|node| node.get("id").and_then(Value::as_str) == Some(local_id))
        .ok_or(CheckError("omnisette-local resolve node was absent"))?;
    if !resolved_local
        .get("features")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        return Err(CheckError("omnisette-local resolved with features"));
    }

    let coffer_node = nodes
        .iter()
        .find(|node| node.get("id").and_then(Value::as_str) == Some(coffer_id))
        .ok_or(CheckError("coffer-anisette resolve node was absent"))?;
    let direct = dependency_ids(coffer_node)?;
    if !direct.contains(local_id) {
        return Err(CheckError(
            "coffer-anisette must directly depend on omnisette-local",
        ));
    }
    Ok(())
}

fn workspace_package<'a>(
    names: &BTreeMap<&'a str, &'a str>,
    manifests: &BTreeMap<&'a str, &'a str>,
    sources: &BTreeMap<&'a str, Option<&'a str>>,
    targets: &BTreeMap<&'a str, Vec<&'a str>>,
    workspace_root: &str,
    expected_name: &str,
    expected_relative_manifest: &str,
) -> Result<&'a str, CheckError> {
    let mut matching = names
        .iter()
        .filter_map(|(id, name)| (*name == expected_name).then_some(*id));
    let id = matching
        .next()
        .ok_or(CheckError("an anisette graph root was absent"))?;
    if matching.next().is_some() {
        return Err(CheckError("an anisette graph root was duplicated"));
    }
    let expected_manifest = Path::new(workspace_root).join(expected_relative_manifest);
    let expected_root = expected_manifest
        .parent()
        .ok_or(CheckError("an expected crate root was absent"))?;
    if sources.get(id).copied().flatten().is_some()
        || manifests
            .get(id)
            .is_none_or(|actual| Path::new(actual) != expected_manifest)
    {
        return Err(CheckError(
            "an anisette graph root was not the reviewed workspace path",
        ));
    }
    if targets.get(id).is_none_or(|package_targets| {
        package_targets.is_empty()
            || package_targets
                .iter()
                .any(|target| !Path::new(target).starts_with(expected_root))
    }) {
        return Err(CheckError(
            "an anisette target escaped its reviewed crate root",
        ));
    }
    Ok(id)
}

fn dependency_closure(nodes: &[Value], roots: &[&str]) -> Result<BTreeSet<String>, CheckError> {
    let mut adjacency = BTreeMap::new();
    for node in nodes {
        let id = node
            .get("id")
            .and_then(Value::as_str)
            .ok_or(CheckError("a resolve node ID was absent"))?;
        adjacency.insert(id, dependency_ids(node)?);
    }
    let mut closure = BTreeSet::new();
    let mut queue: VecDeque<_> = roots.iter().copied().collect();
    while let Some(id) = queue.pop_front() {
        if !closure.insert(id.to_owned()) {
            continue;
        }
        let dependencies = adjacency
            .get(id)
            .ok_or(CheckError("a root or dependency node was unresolved"))?;
        queue.extend(dependencies.iter().map(String::as_str));
    }
    Ok(closure)
}

fn dependency_ids(node: &Value) -> Result<BTreeSet<String>, CheckError> {
    node.get("deps")
        .and_then(Value::as_array)
        .ok_or(CheckError("resolve-node dependencies were absent"))?
        .iter()
        .map(|dependency| {
            dependency
                .get("pkg")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(CheckError("a dependency package ID was absent"))
        })
        .collect()
}

fn forbidden_package(name: &str) -> bool {
    [
        "reqwest",
        "android-loader",
        "sysv64",
        "remove-async-await",
        "tokio-tungstenite",
        "tungstenite",
    ]
    .contains(&name)
}

fn forbidden_feature(feature: &str) -> bool {
    let remote = ["remote", "anisette"].join("-");
    feature == remote || feature == format!("{remote}-v3")
}

fn verify_source_boundary(repository: &Path) -> Result<(), CheckError> {
    let vendor = repository.join("crates/omnisette-local");
    let observed = relative_files(&vendor)?;
    let expected: BTreeSet<_> = VENDORED_FILES.iter().map(ToString::to_string).collect();
    if observed != expected {
        return Err(CheckError("the vendored file inventory drifted"));
    }
    for root in [vendor, repository.join("crates/coffer-anisette")] {
        for path in recursive_source_files(&root)? {
            let bytes =
                fs::read(&path).map_err(|_| CheckError("a source file could not be read"))?;
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| CheckError("a source file was not UTF-8"))?;
            verify_source_text(&path, text)?;
        }
    }
    Ok(())
}

fn relative_files(root: &Path) -> Result<BTreeSet<String>, CheckError> {
    let mut files = BTreeSet::new();
    collect_files(root, root, &mut files)?;
    Ok(files)
}

fn collect_files(
    root: &Path,
    directory: &Path,
    files: &mut BTreeSet<String>,
) -> Result<(), CheckError> {
    for entry in fs::read_dir(directory).map_err(|_| CheckError("vendor directory was absent"))? {
        let entry = entry.map_err(|_| CheckError("vendor directory could not be read"))?;
        let file_type = entry
            .file_type()
            .map_err(|_| CheckError("vendor file type could not be read"))?;
        if file_type.is_symlink() {
            return Err(CheckError("the vendored crate may not contain symlinks"));
        }
        if file_type.is_dir() {
            collect_files(root, &entry.path(), files)?;
        } else if file_type.is_file() {
            let relative = entry
                .path()
                .strip_prefix(root)
                .map_err(|_| CheckError("vendor path escaped its root"))?
                .to_string_lossy()
                .replace('\\', "/");
            files.insert(relative);
        } else {
            return Err(CheckError("the vendored crate contains a special file"));
        }
    }
    Ok(())
}

fn recursive_source_files(root: &Path) -> Result<Vec<PathBuf>, CheckError> {
    let mut files = BTreeSet::new();
    collect_files(root, root, &mut files)?;
    Ok(files
        .into_iter()
        .filter(|path| path.ends_with(".rs") || path.ends_with("Cargo.toml"))
        .map(|path| root.join(path))
        .collect())
}

fn verify_source_text(path: &Path, text: &str) -> Result<(), CheckError> {
    if path.extension() == Some(OsStr::new("rs")) {
        let syntax = syn::parse_file(text).map_err(|_| CheckError("Rust source did not parse"))?;
        if token_stream_contains_indirection(syntax.into_token_stream()) {
            return Err(CheckError(
                "Rust source indirection is prohibited in the anisette boundary",
            ));
        }
    }
    let remote = ["remote", "anisette"].join("-");
    let prohibited_modules = [
        ["remote", "anisette", "v3"].join("_"),
        ["remote", "anisette"].join("_"),
        ["aos", "kit"].join("_"),
        ["store", "services", "core"].join("_"),
        ["posix", "macos"].join("_"),
        ["posix", "windows"].join("_"),
    ];
    let prohibited_hosts = [
        ["ani", "sidestore", "io"].join("."),
        ["ani", "f1sh", "me"].join("."),
    ];
    for line in text.lines() {
        let trimmed = line.trim_start();
        let comment =
            trimmed.starts_with("//") || (path.ends_with("Cargo.toml") && trimmed.starts_with('#'));
        if line.contains(&remote)
            || prohibited_hosts.iter().any(|host| line.contains(host))
            || (!comment
                && prohibited_modules
                    .iter()
                    .any(|module| line.contains(module)))
        {
            return Err(CheckError(
                "a prohibited module, feature, or hostname entered source",
            ));
        }
        if !line.contains("://") {
            continue;
        }
        let manifest_repository = path.ends_with("Cargo.toml")
            && trimmed == format!("repository = \"{UPSTREAM_REPOSITORY}\"");
        let allowed_comment = comment && comment_urls_are_allowlisted(line);
        let allowed_apple_endpoint = !comment && apple_endpoint_urls_are_allowlisted(path, line);
        if !manifest_repository && !allowed_comment && !allowed_apple_endpoint {
            return Err(CheckError("a remote-provider URL literal entered source"));
        }
    }
    Ok(())
}

fn apple_endpoint_urls_are_allowlisted(path: &Path, line: &str) -> bool {
    if !path.ends_with("crates/coffer-anisette/src/provision.rs") {
        return false;
    }
    let allowed = [
        "https://gsa.apple.com/grandslam/GsService2/lookup",
        "https://gsa.apple.com/grandslam/MidService/startMachineProvisioning",
        "https://gsa.apple.com/grandslam/MidService/finishMachineProvisioning",
        "http://www.apple.com/DTDs/PropertyList-1.0.dtd",
    ];
    let urls = urls_in_line(line);
    !urls.is_empty() && urls.iter().all(|url| allowed.contains(url))
}

fn urls_in_line(mut line: &str) -> Vec<&str> {
    let mut urls = Vec::new();
    while let Some(start) = line.find("://").and_then(|separator| {
        line[..separator]
            .char_indices()
            .rfind(|(_, character)| !character.is_ascii_alphabetic())
            .map_or(Some(0), |(start, character)| {
                Some(start + character.len_utf8())
            })
    }) {
        let candidate = &line[start..];
        let end = candidate
            .char_indices()
            .find_map(|(index, character)| {
                (character.is_whitespace()
                    || matches!(
                        character,
                        '\"' | '\'' | '<' | '>' | ')' | ']' | '}' | ';' | ','
                    )
                    || (character == '\\' && candidate.as_bytes().get(index + 1) == Some(&b'\"')))
                .then_some(index)
            })
            .unwrap_or(candidate.len());
        urls.push(&candidate[..end]);
        line = &candidate[end..];
    }
    urls
}

fn token_stream_contains_indirection(stream: TokenStream) -> bool {
    let tokens: Vec<_> = stream.into_iter().collect();
    for (index, token) in tokens.iter().enumerate() {
        match token {
            TokenTree::Group(group) => {
                if token_stream_contains_indirection(group.stream()) {
                    return true;
                }
            }
            TokenTree::Ident(ident)
                if ["include", "include_str", "include_bytes"]
                    .contains(&ident.to_string().trim_start_matches("r#"))
                    && matches!(tokens.get(index + 1), Some(TokenTree::Punct(punct)) if punct.as_char() == '!') =>
            {
                return true;
            }
            TokenTree::Punct(punct)
                if punct.as_char() == '#'
                    && matches!(tokens.get(index + 1), Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Bracket && attribute_contains_path(group.stream())) =>
            {
                return true;
            }
            TokenTree::Punct(_) | TokenTree::Ident(_) | TokenTree::Literal(_) => {}
        }
    }
    false
}

fn attribute_contains_path(stream: TokenStream) -> bool {
    let tokens: Vec<_> = stream.into_iter().collect();
    for (index, token) in tokens.iter().enumerate() {
        match token {
            TokenTree::Ident(ident)
                if ident.to_string().trim_start_matches("r#") == "path"
                    && matches!(tokens.get(index + 1), Some(TokenTree::Punct(punct)) if punct.as_char() == '=') =>
            {
                return true;
            }
            TokenTree::Group(group) if attribute_contains_path(group.stream()) => return true,
            TokenTree::Group(_)
            | TokenTree::Punct(_)
            | TokenTree::Ident(_)
            | TokenTree::Literal(_) => {}
        }
    }
    false
}

fn comment_urls_are_allowlisted(line: &str) -> bool {
    let allowed = [
        "https://mozilla.org/",
        "https://github.com/SideStore/apple-private-apis",
        "https://www.gnu.org/licenses/",
        "https://android.googlesource.com/",
        "https://git.kernel.org/",
    ];
    let urls: Vec<_> = line
        .split_whitespace()
        .filter_map(|word| {
            word.find("https://")
                .or_else(|| word.find("http://"))
                .map(|start| &word[start..])
        })
        .collect();
    !urls.is_empty()
        && urls
            .iter()
            .all(|url| allowed.iter().any(|prefix| url.starts_with(prefix)))
}

fn verify_provenance(repository: &Path) -> Result<(), CheckError> {
    let vendor = repository.join("crates/omnisette-local");
    verify_hash(&vendor.join("LICENSE"), LICENSE_SHA256)?;
    for (path, expected) in FINAL_HASHES {
        verify_hash(&vendor.join(path), expected)?;
    }
    let patch = repository.join("tools/omnisette-local.patch");
    let patch_bytes = fs::read(&patch).map_err(|_| CheckError("the checked patch was absent"))?;
    if !patch_bytes.starts_with(b"diff --git a/") {
        return Err(CheckError("the checked patch had an invalid preamble"));
    }
    verify_hash(&patch, PATCH_SHA256)?;
    verify_hash(&vendor.join("UPSTREAM.toml"), UPSTREAM_METADATA_SHA256)?;
    verify_patch_reconstruction(repository, &vendor)
}

fn verify_patch_reconstruction(repository: &Path, vendor: &Path) -> Result<(), CheckError> {
    let reconstructed = tempfile::tempdir()
        .map_err(|_| CheckError("could not create a reconstruction directory"))?;
    fs::create_dir(reconstructed.path().join("src"))
        .map_err(|_| CheckError("could not prepare the reconstruction directory"))?;
    let initialized = Command::new("git")
        .args(["init", "--quiet"])
        .current_dir(reconstructed.path())
        .status()
        .map_err(|_| CheckError("could not initialize the reconstruction directory"))?;
    if !initialized.success() {
        return Err(CheckError(
            "could not initialize the reconstruction directory",
        ));
    }
    for (relative, _) in FINAL_HASHES {
        fs::copy(vendor.join(relative), reconstructed.path().join(relative))
            .map_err(|_| CheckError("could not stage a final vendored file"))?;
    }
    let patch = repository.join("tools/omnisette-local.patch");
    for extra in [&["apply", "-R", "--check"][..], &["apply", "-R"][..]] {
        let status = Command::new("git")
            .args(extra)
            .arg(&patch)
            .current_dir(reconstructed.path())
            .status()
            .map_err(|_| CheckError("could not execute git apply"))?;
        if !status.success() {
            return Err(CheckError(
                "the checked patch did not reconstruct selected upstream files",
            ));
        }
    }
    for (relative, expected) in ORIGINAL_HASHES {
        verify_hash(&reconstructed.path().join(relative), expected)?;
    }
    Ok(())
}

fn verify_hash(path: &Path, expected: &str) -> Result<(), CheckError> {
    let bytes = fs::read(path).map_err(|_| CheckError("a provenance file was absent"))?;
    if sha256(&bytes) == expected {
        Ok(())
    } else {
        Err(CheckError("a provenance hash mismatched"))
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

    fn metadata_with_dependency(name: &str, feature: Option<&str>) -> Value {
        let features = feature.map_or_else(
            || serde_json::json!({}),
            |value| serde_json::json!({ value: [] }),
        );
        serde_json::json!({
            "workspace_root": "/reviewed",
            "packages": [
                {"id": "coffer", "name": "coffer-anisette", "features": {}, "manifest_path": "/reviewed/crates/coffer-anisette/Cargo.toml", "source": null, "targets": [{"src_path": "/reviewed/crates/coffer-anisette/src/lib.rs"}]},
                {"id": "local", "name": "omnisette-local", "features": {}, "manifest_path": "/reviewed/crates/omnisette-local/Cargo.toml", "source": null, "targets": [{"src_path": "/reviewed/crates/omnisette-local/src/lib.rs"}]},
                {"id": "dep", "name": name, "features": features, "manifest_path": "/registry/dep/Cargo.toml", "source": "registry+https://example.invalid/index", "targets": [{"src_path": "/registry/dep/src/lib.rs"}]}
            ],
            "resolve": {"nodes": [
                {"id": "coffer", "deps": [{"pkg": "local"}], "features": []},
                {"id": "local", "deps": [{"pkg": "dep"}], "features": []},
                {"id": "dep", "deps": [], "features": []}
            ]}
        })
    }

    fn metadata_without_dependency() -> Value {
        serde_json::json!({
            "workspace_root": "/reviewed",
            "packages": [
                {"id": "coffer", "name": "coffer-anisette", "features": {}, "manifest_path": "/reviewed/crates/coffer-anisette/Cargo.toml", "source": null, "targets": [{"src_path": "/reviewed/crates/coffer-anisette/src/lib.rs"}]},
                {"id": "local", "name": "omnisette-local", "features": {}, "manifest_path": "/reviewed/crates/omnisette-local/Cargo.toml", "source": null, "targets": [{"src_path": "/reviewed/crates/omnisette-local/src/lib.rs"}]}
            ],
            "resolve": {"nodes": [
                {"id": "coffer", "deps": [{"pkg": "local"}], "features": []},
                {"id": "local", "deps": [], "features": []}
            ]}
        })
    }

    #[test]
    fn metadata_accepts_the_reviewed_minimal_graph() {
        assert_eq!(verify_graph(&metadata_without_dependency()), Ok(()));
    }

    #[test]
    fn metadata_closure_rejects_each_prohibited_dependency() {
        for name in [
            "reqwest",
            "android-loader",
            "sysv64",
            "remove-async-await",
            "tokio-tungstenite",
            "tungstenite",
        ] {
            assert_eq!(
                verify_graph(&metadata_with_dependency(name, None)),
                Err(CheckError(
                    "a prohibited package entered the anisette closure"
                ))
            );
        }
    }

    #[test]
    fn metadata_closure_rejects_prohibited_features() {
        assert_eq!(
            verify_graph(&metadata_with_dependency(
                "safe-name",
                Some("remote-anisette")
            )),
            Err(CheckError(
                "a prohibited feature is declared in the anisette closure"
            ))
        );
    }

    #[test]
    fn metadata_local_closure_rejects_unreviewed_name_and_source() {
        assert_eq!(
            verify_graph(&metadata_with_dependency("safe-name", None)),
            Err(CheckError(
                "an unreviewed package entered the omnisette-local closure"
            ))
        );

        let mut metadata = metadata_with_dependency("sha2", None);
        assert_eq!(
            verify_graph(&metadata),
            Err(CheckError(
                "an omnisette-local dependency did not come from crates.io"
            ))
        );
        *metadata
            .pointer_mut("/packages/2/source")
            .expect("dependency source") = Value::String(CRATES_IO_SOURCE.to_owned());
        assert_eq!(verify_graph(&metadata), Ok(()));
    }

    #[test]
    fn metadata_rejects_an_unreviewed_same_name_graph_root() {
        let mut metadata = metadata_with_dependency("safe-name", None);
        let local = metadata
            .pointer_mut("/packages/1")
            .and_then(Value::as_object_mut)
            .expect("local package");
        local.insert(
            "manifest_path".to_owned(),
            Value::String("/registry/omnisette-local/Cargo.toml".to_owned()),
        );
        local.insert(
            "source".to_owned(),
            Value::String("registry+https://example.invalid/index".to_owned()),
        );
        assert_eq!(
            verify_graph(&metadata),
            Err(CheckError(
                "an anisette graph root was not the reviewed workspace path"
            ))
        );
    }

    #[test]
    fn metadata_rejects_target_and_build_script_path_escapes() {
        for target in ["/reviewed/provider.rs", "/reviewed/crates/build-script.rs"] {
            let mut metadata = metadata_with_dependency("safe-name", None);
            *metadata
                .pointer_mut("/packages/0/targets/0/src_path")
                .expect("coffer target path") = Value::String(target.to_owned());
            assert_eq!(
                verify_graph(&metadata),
                Err(CheckError(
                    "an anisette target escaped its reviewed crate root"
                ))
            );
        }
    }

    #[test]
    fn source_gate_rejects_module_feature_hostname_and_url_injections() {
        let path = Path::new("src/lib.rs");
        for injected in [
            "#[path = \"store_services_core.rs\"]\nmod provider;",
            "#[path = \"../../../tools/provider.rs\"]\nmod provider;",
            "#[path = \"opaque.data\"]\nmod provider;",
            "#[r#path = \"opaque.data\"]\nmod provider;",
            "include!(concat!(env!(\"OUT_DIR\"), \"/provider.rs\"));",
            "#[path /* token comment */ = \"provider.rs\"]\nmod provider;",
            "include /* token comment */ !(\"provider.rs\");",
            "std::include!(\"provider.rs\");",
            "::core::include!(\"provider.rs\");",
            "include_str!(\"provider.rs\");",
            "include_bytes!(\"provider.rs\");",
            "#[cfg_attr(all(), path = \"provider.rs\")]\nmod provider;",
            "#[cfg_attr(all(), r#path = \"provider.rs\")]\nmod provider;",
            "macro_rules! load { () => { include!(\"provider.rs\") } }",
        ] {
            assert_eq!(
                verify_source_text(path, injected),
                Err(CheckError(
                    "Rust source indirection is prohibited in the anisette boundary"
                ))
            );
        }
        for injected in [
            "mod remote_anisette;",
            "const FEATURE: &str = \"remote-anisette\";",
            "const HOST: &str = \"ani.sidestore.io\";",
        ] {
            assert_eq!(
                verify_source_text(path, injected),
                Err(CheckError(
                    "a prohibited module, feature, or hostname entered source"
                ))
            );
        }
        assert_eq!(
            verify_source_text(
                path,
                "const URL: &str = \"https://example.invalid/provider\";"
            ),
            Err(CheckError("a remote-provider URL literal entered source"))
        );
        let provisioning_path = Path::new("crates/coffer-anisette/src/provision.rs");
        for allowed in [
            "https://gsa.apple.com/grandslam/GsService2/lookup",
            "https://gsa.apple.com/grandslam/MidService/startMachineProvisioning",
            "https://gsa.apple.com/grandslam/MidService/finishMachineProvisioning",
            "http://www.apple.com/DTDs/PropertyList-1.0.dtd",
        ] {
            let source = format!("const URL: &str = \"{allowed}\";");
            assert!(verify_source_text(provisioning_path, &source).is_ok());
        }
        for injected in [
            "http://gsa.apple.com/grandslam/GsService2/lookup",
            "https://example.invalid/grandslam/GsService2/lookup",
            "https://gsa.apple.com.evil.invalid/grandslam/GsService2/lookup",
            "https://gsa.apple.com/grandslam/GsService2/lookup/extra",
            "https://gsa.apple.com/grandslam/GsService2/lookup?next=evil",
            "https://gsa.apple.com/grandslam/GsService2/midStartProvisioning",
            "https://gsa.apple.com/grandslam/GsService2/midFinishProvisioning",
            "https://www.apple.com/DTDs/PropertyList-1.0.dtd",
            "http://www.apple.com/DTDs/PropertyList-1.0.dtd?next=evil",
            "http://www.apple.com/DTDs/PropertyList-1.0.dtd/extra",
            r#"http://www.apple.com/DTDs/PropertyList-1.0.dtd\u{3f}next=evil"#,
        ] {
            let source = format!("const URL: &str = \"{injected}\";");
            assert_eq!(
                verify_source_text(provisioning_path, &source),
                Err(CheckError("a remote-provider URL literal entered source"))
            );
        }
        assert_eq!(
            verify_source_text(
                provisioning_path,
                "const URL: &str = \"arrow→https://example.invalid/provider\";"
            ),
            Err(CheckError("a remote-provider URL literal entered source"))
        );
        assert!(verify_source_text(path, "// https://mozilla.org/MPL/2.0/").is_ok());
        assert!(
            verify_source_text(
                path,
                "/// A doc comment containing `, path =` and `include!(`.\n\
                 fn example() {\n\
                     let value = \"include!(\";\n\
                     let path = \"value\";\n\
                     let _ = format!(\"{path}\", path = path);\n\
                 }"
            )
            .is_ok()
        );
    }

    #[test]
    fn inventory_comparison_detects_extra_and_missing_files() {
        let expected: BTreeSet<_> = VENDORED_FILES.iter().map(ToString::to_string).collect();
        let directory = tempfile::tempdir().expect("temporary vendor directory");
        fs::create_dir(directory.path().join("src")).expect("source directory");
        for relative in VENDORED_FILES {
            fs::write(directory.path().join(relative), b"fixture").expect("fixture file");
        }
        assert_eq!(
            relative_files(directory.path()).expect("inventory"),
            expected
        );

        fs::remove_file(directory.path().join("src/lib.rs")).expect("remove fixture");
        assert_ne!(
            relative_files(directory.path()).expect("missing inventory"),
            expected
        );
        fs::write(directory.path().join("src/lib.rs"), b"fixture").expect("restore fixture");
        fs::write(directory.path().join("src/unexpected.rs"), b"fixture").expect("extra fixture");
        assert_ne!(
            relative_files(directory.path()).expect("extra inventory"),
            expected
        );
    }

    #[test]
    fn upstream_and_final_hash_mismatches_are_distinct_records() {
        let original_hash = sha256(b"upstream bytes");
        let final_hash = sha256(b"modified bytes");
        assert_ne!(original_hash, final_hash);
        let directory = tempfile::tempdir().expect("temporary provenance directory");
        let file = directory.path().join("selected-file");
        fs::write(&file, b"upstream bytes").expect("upstream fixture");
        assert_eq!(verify_hash(&file, &original_hash), Ok(()));
        assert_eq!(
            verify_hash(&file, &final_hash),
            Err(CheckError("a provenance hash mismatched"))
        );
        fs::write(&file, b"modified bytes").expect("modified fixture");
        assert_eq!(verify_hash(&file, &final_hash), Ok(()));
        assert_eq!(
            verify_hash(&file, &original_hash),
            Err(CheckError("a provenance hash mismatched"))
        );
    }
}
