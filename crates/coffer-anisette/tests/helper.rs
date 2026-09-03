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

//! Process-level confinement tests for the dedicated helper.

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use coffer_anisette::HelperClient;
use coffer_bootstrap::Architecture;

#[test]
fn helper_refuses_to_run_without_verified_network_denial() {
    let client = HelperClient::new(
        env!("CARGO_BIN_EXE_coffer-anisette-helper"),
        Duration::from_secs(2),
    );
    client.probe_sandbox().expect("mandatory sandbox applies");
}

#[test]
fn offline_dispatch_rejects_empty_and_malformed_library_roots() {
    assert_eq!(invoke_offline(Path::new("")), error_response(2));

    let root = tempfile::tempdir().expect("library root");
    let architecture = Architecture::host().expect("supported test host");
    let directory = root.path().join("lib").join(architecture.android_abi());
    std::fs::create_dir_all(&directory).expect("library directory");
    std::fs::write(directory.join("libCoreADI.so"), b"not an ELF image").expect("core fixture");
    std::fs::write(
        directory.join("libstoreservicescore.so"),
        b"not an ELF image",
    )
    .expect("store-services fixture");
    assert_eq!(invoke_offline(root.path()), error_response(3));
}

fn invoke_offline(library_root: &Path) -> Vec<u8> {
    let state_directory = tempfile::Builder::new()
        .prefix("coffer-anisette-state-")
        .tempdir()
        .expect("state directory");
    std::fs::set_permissions(
        state_directory.path(),
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("restrict state directory");
    let state = std::fs::canonicalize(state_directory.path()).expect("canonical state directory");
    let library = library_root.as_os_str().as_encoded_bytes();
    let state_bytes = state.as_os_str().as_encoded_bytes();
    let payload_length = 4 + library.len() + state_bytes.len();
    let mut request = b"COFFADI\0\0\x01\x01\0".to_vec();
    request.extend_from_slice(
        &u32::try_from(payload_length)
            .expect("bounded test request")
            .to_be_bytes(),
    );
    request.extend_from_slice(
        &u16::try_from(library.len())
            .expect("bounded library path")
            .to_be_bytes(),
    );
    request.extend_from_slice(library);
    request.extend_from_slice(
        &u16::try_from(state_bytes.len())
            .expect("bounded state path")
            .to_be_bytes(),
    );
    request.extend_from_slice(state_bytes);

    let mut child = Command::new(env!("CARGO_BIN_EXE_coffer-anisette-helper"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("start helper");
    child
        .stdin
        .take()
        .expect("helper stdin")
        .write_all(&request)
        .expect("write request");
    let output = child.wait_with_output().expect("collect helper");
    assert!(output.status.success());
    output.stdout
}

fn error_response(code: u8) -> Vec<u8> {
    let mut response = b"COFFADI\0\0\x01\0".to_vec();
    response.push(code);
    response.extend_from_slice(&0u32.to_be_bytes());
    response
}
