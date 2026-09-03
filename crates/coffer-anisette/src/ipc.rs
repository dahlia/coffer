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

//! Byte-exact, bounded helper framing.

use std::io::{Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use crate::bridge::PropertyKey;
use crate::error::BridgeError;

const MAGIC: &[u8; 8] = b"COFFADI\0";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 16;
pub(crate) const MAX_FRAME_BYTES: usize = 16 * 1024;
const MAX_PATH_BYTES: usize = 4 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Operation {
    OfflineSmoke = 1,
    SandboxProbe = 2,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct Request {
    pub(crate) operation: Operation,
    pub(crate) library_root: PathBuf,
    pub(crate) state_directory: PathBuf,
}

impl core::fmt::Debug for Request {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Request")
            .field("operation", &self.operation)
            .field("library_root", &"<redacted-path>")
            .field("state_directory", &"<redacted-path>")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Response {
    Smoke {
        provisioned: bool,
        properties: Vec<PropertyKey>,
    },
    SandboxEnabled,
    Error(BridgeError),
}

pub(crate) fn write_request(mut writer: impl Write, request: &Request) -> Result<(), BridgeError> {
    let library = request.library_root.as_os_str().as_encoded_bytes();
    let state = request.state_directory.as_os_str().as_encoded_bytes();
    if library.len() > MAX_PATH_BYTES
        || state.len() > MAX_PATH_BYTES
        || library.contains(&0)
        || state.contains(&0)
    {
        return Err(BridgeError::InvalidMessage);
    }
    let library_len = u16::try_from(library.len()).map_err(|_| BridgeError::InvalidMessage)?;
    let state_len = u16::try_from(state.len()).map_err(|_| BridgeError::InvalidMessage)?;
    let payload_len = 4usize
        .checked_add(library.len())
        .and_then(|length| length.checked_add(state.len()))
        .ok_or(BridgeError::InvalidMessage)?;
    let payload_len = u32::try_from(payload_len).map_err(|_| BridgeError::InvalidMessage)?;
    write_header(&mut writer, request.operation as u8, 0, payload_len)?;
    writer
        .write_all(&library_len.to_be_bytes())
        .and_then(|()| writer.write_all(library))
        .and_then(|()| writer.write_all(&state_len.to_be_bytes()))
        .and_then(|()| writer.write_all(state))
        .map_err(|_| BridgeError::ProcessIo)
}

pub(crate) fn read_request(mut reader: impl Read) -> Result<Request, BridgeError> {
    let (kind, status, payload_len) = read_header(&mut reader)?;
    if status != 0 {
        return Err(BridgeError::InvalidMessage);
    }
    let operation = match kind {
        1 => Operation::OfflineSmoke,
        2 => Operation::SandboxProbe,
        _ => return Err(BridgeError::InvalidMessage),
    };
    let payload = read_payload(&mut reader, payload_len)?;
    if payload.len() < 4 {
        return Err(BridgeError::InvalidMessage);
    }
    let library_len = usize::from(u16::from_be_bytes([payload[0], payload[1]]));
    if library_len > MAX_PATH_BYTES || payload.len() < 4 + library_len {
        return Err(BridgeError::InvalidMessage);
    }
    let state_offset = 2 + library_len;
    let state_len = usize::from(u16::from_be_bytes([
        payload[state_offset],
        payload[state_offset + 1],
    ]));
    let state_start = state_offset + 2;
    if state_len > MAX_PATH_BYTES || payload.len() != state_start + state_len {
        return Err(BridgeError::InvalidMessage);
    }
    let library = &payload[2..state_offset];
    let state = &payload[state_start..];
    if library.contains(&0) || state.contains(&0) {
        return Err(BridgeError::InvalidMessage);
    }
    Ok(Request {
        operation,
        library_root: PathBuf::from(std::ffi::OsString::from_vec(library.to_vec())),
        state_directory: PathBuf::from(std::ffi::OsString::from_vec(state.to_vec())),
    })
}

pub(crate) fn write_response(
    mut writer: impl Write,
    response: &Response,
) -> Result<(), BridgeError> {
    match response {
        Response::Smoke {
            provisioned,
            properties,
        } => {
            let count = u8::try_from(properties.len()).map_err(|_| BridgeError::InvalidMessage)?;
            let mut payload = Vec::with_capacity(2 + properties.len());
            payload.push(u8::from(*provisioned));
            payload.push(count);
            payload.extend(properties.iter().map(|property| property.code()));
            let len = u32::try_from(payload.len()).map_err(|_| BridgeError::InvalidMessage)?;
            write_header(&mut writer, Operation::OfflineSmoke as u8, 0, len)?;
            writer
                .write_all(&payload)
                .map_err(|_| BridgeError::ProcessIo)
        }
        Response::SandboxEnabled => write_header(&mut writer, Operation::SandboxProbe as u8, 0, 0),
        Response::Error(error) => write_header(&mut writer, 0, error.code(), 0),
    }
}

pub(crate) fn read_response(mut reader: impl Read) -> Result<Response, BridgeError> {
    let (kind, status, payload_len) = read_header(&mut reader)?;
    let payload = read_payload(&mut reader, payload_len)?;
    if status != 0 {
        if kind != 0 || !payload.is_empty() {
            return Err(BridgeError::InvalidMessage);
        }
        return BridgeError::from_code(status)
            .map(Response::Error)
            .ok_or(BridgeError::InvalidMessage);
    }
    match kind {
        1 => {
            if payload.len() < 2 || payload.len() != 2 + usize::from(payload[1]) {
                return Err(BridgeError::InvalidMessage);
            }
            let mut properties = Vec::with_capacity(usize::from(payload[1]));
            for code in &payload[2..] {
                properties.push(PropertyKey::from_code(*code).ok_or(BridgeError::InvalidMessage)?);
            }
            Ok(Response::Smoke {
                provisioned: match payload[0] {
                    0 => false,
                    1 => true,
                    _ => return Err(BridgeError::InvalidMessage),
                },
                properties,
            })
        }
        2 if payload.is_empty() => Ok(Response::SandboxEnabled),
        _ => Err(BridgeError::InvalidMessage),
    }
}

fn write_header(
    writer: &mut impl Write,
    kind: u8,
    status: u8,
    payload_len: u32,
) -> Result<(), BridgeError> {
    let mut header = [0u8; HEADER_LEN];
    header[..8].copy_from_slice(MAGIC);
    header[8..10].copy_from_slice(&VERSION.to_be_bytes());
    header[10] = kind;
    header[11] = status;
    header[12..16].copy_from_slice(&payload_len.to_be_bytes());
    writer
        .write_all(&header)
        .map_err(|_| BridgeError::ProcessIo)
}

fn read_header(reader: &mut impl Read) -> Result<(u8, u8, usize), BridgeError> {
    let mut header = [0u8; HEADER_LEN];
    reader
        .read_exact(&mut header)
        .map_err(|_| BridgeError::InvalidMessage)?;
    if &header[..8] != MAGIC || u16::from_be_bytes([header[8], header[9]]) != VERSION {
        return Err(BridgeError::InvalidMessage);
    }
    let payload_len = u32::from_be_bytes(
        header[12..16]
            .try_into()
            .map_err(|_| BridgeError::InvalidMessage)?,
    ) as usize;
    if payload_len > MAX_FRAME_BYTES - HEADER_LEN {
        return Err(BridgeError::InvalidMessage);
    }
    Ok((header[10], header[11], payload_len))
}

fn read_payload(reader: &mut impl Read, payload_len: usize) -> Result<Vec<u8>, BridgeError> {
    let mut payload = vec![0u8; payload_len];
    reader
        .read_exact(&mut payload)
        .map_err(|_| BridgeError::InvalidMessage)?;
    let mut trailing = [0u8; 1];
    match reader.read(&mut trailing) {
        Ok(0) => Ok(payload),
        Ok(_) => Err(BridgeError::InvalidMessage),
        Err(_) => Err(BridgeError::InvalidMessage),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::os::unix::ffi::OsStringExt;

    use super::*;

    #[test]
    fn request_framing_is_byte_exact() {
        let request = Request {
            operation: Operation::OfflineSmoke,
            library_root: PathBuf::from("/tmp/lib"),
            state_directory: PathBuf::from("/tmp/state"),
        };
        let mut bytes = Vec::new();
        write_request(&mut bytes, &request).expect("encode request");
        assert_eq!(
            bytes,
            b"COFFADI\0\0\x01\x01\0\0\0\0\x16\0\x08/tmp/lib\0\x0a/tmp/state"
        );
        assert_eq!(read_request(Cursor::new(bytes)).expect("decode"), request);
    }

    #[test]
    fn request_framing_round_trips_non_utf8_linux_paths() {
        let request = Request {
            operation: Operation::OfflineSmoke,
            library_root: PathBuf::from(std::ffi::OsString::from_vec(
                b"/tmp/non-utf8-\xff".to_vec(),
            )),
            state_directory: PathBuf::from(std::ffi::OsString::from_vec(
                b"/tmp/state-\xfe".to_vec(),
            )),
        };
        let mut bytes = Vec::new();
        write_request(&mut bytes, &request).expect("encode request");
        assert_eq!(read_request(Cursor::new(bytes)).expect("decode"), request);
    }

    #[test]
    fn response_framing_is_byte_exact() {
        let response = Response::Smoke {
            provisioned: false,
            properties: vec![PropertyKey::ProductModel, PropertyKey::Unknown],
        };
        let mut bytes = Vec::new();
        write_response(&mut bytes, &response).expect("encode response");
        assert_eq!(bytes, b"COFFADI\0\0\x01\x01\0\0\0\0\x04\0\x02\x01\xff");
        assert_eq!(read_response(Cursor::new(bytes)).expect("decode"), response);
    }

    #[test]
    fn response_status_codes_and_payloads_fail_closed() {
        let mut unknown = b"COFFADI\0\0\x01\0\xff\0\0\0\0".to_vec();
        assert_eq!(unknown.len(), HEADER_LEN);
        assert_eq!(
            read_response(Cursor::new(&mut unknown)).expect_err("unknown status"),
            BridgeError::InvalidMessage
        );

        let mut status_payload = b"COFFADI\0\0\x01\0\x02\0\0\0\x01x".to_vec();
        assert_eq!(
            read_response(Cursor::new(&mut status_payload)).expect_err("status payload"),
            BridgeError::InvalidMessage
        );
    }

    #[test]
    fn malformed_truncated_trailing_and_oversized_frames_fail_closed() {
        let request = Request {
            operation: Operation::SandboxProbe,
            library_root: PathBuf::new(),
            state_directory: PathBuf::from("/tmp/state"),
        };
        let mut valid = Vec::new();
        write_request(&mut valid, &request).expect("encode");
        for end in 0..valid.len() {
            assert_eq!(
                read_request(Cursor::new(&valid[..end])).expect_err("truncated"),
                BridgeError::InvalidMessage
            );
        }
        let mut trailing = valid.clone();
        trailing.push(0);
        assert_eq!(
            read_request(Cursor::new(trailing)).expect_err("trailing"),
            BridgeError::InvalidMessage
        );
        let mut oversized = valid;
        oversized[12..16].copy_from_slice(&(MAX_FRAME_BYTES as u32).to_be_bytes());
        assert_eq!(
            read_request(Cursor::new(oversized)).expect_err("oversized"),
            BridgeError::InvalidMessage
        );
    }

    #[test]
    fn request_debug_redacts_paths() {
        let request = Request {
            operation: Operation::OfflineSmoke,
            library_root: PathBuf::from("/secret-looking-path"),
            state_directory: PathBuf::from("/another-secret-looking-path"),
        };
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("secret-looking"));
    }
}
