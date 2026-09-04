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

//! Versioned, byte-exact, bounded helper framing.

use std::io::{Read, Write};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::bridge::PropertyKey;
use crate::error::BridgeError;
use crate::types::MAX_SECRET_BYTES;

const MAGIC: &[u8; 8] = b"COFFADI\0";
const VERSION: u16 = 2;
const HEADER_LEN: usize = 16;
pub(crate) const MAX_FRAME_BYTES: usize = 2 * MAX_SECRET_BYTES + 16 * 1024;
const MAX_PATH_BYTES: usize = 4 * 1024;
const TRANSACTION_FINISH: u8 = 0x40;
const TRANSACTION_CANCEL: u8 = 0x41;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Operation {
    OfflineSmoke = 1,
    SandboxProbe = 2,
    SetAndroidId = 3,
    QueryProvisioned = 4,
    StartProvisioning = 5,
    RequestOtp = 6,
    Synchronize = 7,
    EraseProvisioning = 8,
    EndProvisioning = 9,
    DestroyProvisioning = 10,
}

impl Operation {
    fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::OfflineSmoke,
            2 => Self::SandboxProbe,
            3 => Self::SetAndroidId,
            4 => Self::QueryProvisioned,
            5 => Self::StartProvisioning,
            6 => Self::RequestOtp,
            7 => Self::Synchronize,
            8 => Self::EraseProvisioning,
            9 => Self::EndProvisioning,
            10 => Self::DestroyProvisioning,
            _ => return None,
        })
    }
}

pub(crate) struct Request {
    pub(crate) operation: Operation,
    pub(crate) library_root: PathBuf,
    pub(crate) provisioning_root: PathBuf,
    pub(crate) state_directory: PathBuf,
    pub(crate) ds_id: i64,
    pub(crate) android_id: Zeroizing<Vec<u8>>,
    pub(crate) secret: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for Request {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Request")
            .field("operation", &self.operation)
            .field("library_root", &"<redacted-path>")
            .field("provisioning_root", &"<redacted-path>")
            .field("state_directory", &"<redacted-path>")
            .field("ds_id", &"<redacted-identifier>")
            .field("android_id", &"<redacted>")
            .field("secret", &"<redacted>")
            .finish()
    }
}

pub(crate) enum Response {
    Smoke {
        provisioned: bool,
        properties: Vec<PropertyKey>,
    },
    SandboxEnabled,
    Unit(Operation),
    Provisioned(bool),
    SecretPair {
        operation: Operation,
        first: Zeroizing<Vec<u8>>,
        second: Zeroizing<Vec<u8>>,
    },
    ProvisioningStarted(Zeroizing<Vec<u8>>),
    Error(BridgeError),
}

impl core::fmt::Debug for Response {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Smoke {
                provisioned,
                properties,
            } => f
                .debug_struct("Smoke")
                .field("provisioned", provisioned)
                .field("properties", properties)
                .finish(),
            Self::SandboxEnabled => f.write_str("SandboxEnabled"),
            Self::Unit(operation) => f.debug_tuple("Unit").field(operation).finish(),
            Self::Provisioned(value) => f.debug_tuple("Provisioned").field(value).finish(),
            Self::SecretPair { operation, .. } => f
                .debug_struct("SecretPair")
                .field("operation", operation)
                .field("values", &"<redacted>")
                .finish(),
            Self::ProvisioningStarted(_) => f.write_str("ProvisioningStarted(<redacted>)"),
            Self::Error(error) => f.debug_tuple("Error").field(error).finish(),
        }
    }
}

pub(crate) enum TransactionCommand {
    Finish {
        ptm: Zeroizing<Vec<u8>>,
        tk: Zeroizing<Vec<u8>>,
    },
    Cancel,
}

impl core::fmt::Debug for TransactionCommand {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Finish { .. } => f.write_str("Finish(<redacted>)"),
            Self::Cancel => f.write_str("Cancel"),
        }
    }
}

pub(crate) fn write_request(mut writer: impl Write, request: &Request) -> Result<(), BridgeError> {
    let payload = encode_request_payload(request)?;
    write_frame(&mut writer, request.operation as u8, 0, &payload)
}

fn encode_request_payload(request: &Request) -> Result<Zeroizing<Vec<u8>>, BridgeError> {
    let mut payload = Zeroizing::new(Vec::with_capacity(request_payload_capacity(request)?));
    put_path(&mut payload, &request.library_root)?;
    put_path(&mut payload, &request.provisioning_root)?;
    put_path(&mut payload, &request.state_directory)?;
    payload.extend_from_slice(&request.ds_id.to_be_bytes());
    put_bytes_u8(&mut payload, &request.android_id, 16)?;
    put_bytes_u32(&mut payload, &request.secret, MAX_SECRET_BYTES)?;
    Ok(payload)
}

fn request_payload_capacity(request: &Request) -> Result<usize, BridgeError> {
    let mut capacity = 0usize;
    for path in [
        &request.library_root,
        &request.provisioning_root,
        &request.state_directory,
    ] {
        let bytes = path.as_os_str().as_bytes();
        if bytes.len() > MAX_PATH_BYTES || bytes.contains(&0) {
            return Err(BridgeError::InvalidMessage);
        }
        capacity = capacity
            .checked_add(2)
            .and_then(|value| value.checked_add(bytes.len()))
            .ok_or(BridgeError::InvalidMessage)?;
    }
    if request.android_id.len() > 16 || request.secret.len() > MAX_SECRET_BYTES {
        return Err(BridgeError::InvalidMessage);
    }
    capacity
        .checked_add(8)
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(request.android_id.len()))
        .and_then(|value| value.checked_add(4))
        .and_then(|value| value.checked_add(request.secret.len()))
        .ok_or(BridgeError::InvalidMessage)
}

#[cfg(test)]
pub(crate) fn read_request(mut reader: impl Read) -> Result<Request, BridgeError> {
    let request = read_request_frame(&mut reader)?;
    require_eof(&mut reader)?;
    Ok(request)
}

pub(crate) fn read_request_frame(reader: &mut impl Read) -> Result<Request, BridgeError> {
    let (kind, status, payload) = read_frame(reader)?;
    if status != 0 {
        return Err(BridgeError::InvalidMessage);
    }
    let operation = Operation::from_code(kind).ok_or(BridgeError::InvalidMessage)?;
    let mut cursor = Cursor::new(&payload);
    let library_root = cursor.path()?;
    let provisioning_root = cursor.path()?;
    let state_directory = cursor.path()?;
    let ds_id = i64::from_be_bytes(cursor.array()?);
    let android_id = Zeroizing::new(cursor.bytes_u8(16)?);
    let secret = Zeroizing::new(cursor.bytes_u32(MAX_SECRET_BYTES)?);
    cursor.finish()?;
    if matches!(
        operation,
        Operation::SetAndroidId
            | Operation::QueryProvisioned
            | Operation::StartProvisioning
            | Operation::RequestOtp
            | Operation::Synchronize
            | Operation::EraseProvisioning
    ) && android_id.len() != 16
    {
        return Err(BridgeError::InvalidMessage);
    }
    let unexpected_secret = matches!(
        operation,
        Operation::OfflineSmoke
            | Operation::SandboxProbe
            | Operation::SetAndroidId
            | Operation::QueryProvisioned
            | Operation::RequestOtp
            | Operation::EraseProvisioning
    ) && !secret.is_empty();
    let unexpected_android_id =
        matches!(operation, Operation::OfflineSmoke | Operation::SandboxProbe)
            && !android_id.is_empty();
    if unexpected_secret || unexpected_android_id {
        return Err(BridgeError::InvalidMessage);
    }
    Ok(Request {
        operation,
        library_root,
        provisioning_root,
        state_directory,
        ds_id,
        android_id,
        secret,
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
            let mut payload = Zeroizing::new(vec![u8::from(*provisioned), count]);
            payload.extend(properties.iter().map(|property| property.code()));
            write_frame(&mut writer, Operation::OfflineSmoke as u8, 0, &payload)
        }
        Response::SandboxEnabled => write_frame(&mut writer, Operation::SandboxProbe as u8, 0, &[]),
        Response::Unit(operation) => write_frame(&mut writer, *operation as u8, 0, &[]),
        Response::Provisioned(value) => write_frame(
            &mut writer,
            Operation::QueryProvisioned as u8,
            0,
            &[u8::from(*value)],
        ),
        Response::SecretPair {
            operation,
            first,
            second,
        } => {
            let capacity = encoded_pair_capacity(first, second)?;
            let mut payload = Zeroizing::new(Vec::with_capacity(capacity));
            put_bytes_u32(&mut payload, first, MAX_SECRET_BYTES)?;
            put_bytes_u32(&mut payload, second, MAX_SECRET_BYTES)?;
            write_frame(&mut writer, *operation as u8, 0, &payload)
        }
        Response::ProvisioningStarted(cpim) => {
            let capacity = encoded_secret_capacity(cpim)?;
            let mut payload = Zeroizing::new(Vec::with_capacity(capacity));
            put_bytes_u32(&mut payload, cpim, MAX_SECRET_BYTES)?;
            write_frame(&mut writer, Operation::StartProvisioning as u8, 0, &payload)
        }
        Response::Error(error) => write_frame(&mut writer, 0, error.code(), &[]),
    }
}

pub(crate) fn read_response(mut reader: impl Read) -> Result<Response, BridgeError> {
    let response = read_response_frame(&mut reader)?;
    require_eof(&mut reader)?;
    Ok(response)
}

pub(crate) fn read_response_frame(reader: &mut impl Read) -> Result<Response, BridgeError> {
    let (kind, status, payload) = read_frame(reader)?;
    if status != 0 {
        if kind != 0 || !payload.is_empty() {
            return Err(BridgeError::InvalidMessage);
        }
        return BridgeError::from_code(status)
            .map(Response::Error)
            .ok_or(BridgeError::InvalidMessage);
    }
    let operation = Operation::from_code(kind).ok_or(BridgeError::InvalidMessage)?;
    match operation {
        Operation::OfflineSmoke => {
            if payload.len() < 2 || payload.len() != 2 + usize::from(payload[1]) {
                return Err(BridgeError::InvalidMessage);
            }
            let properties = payload[2..]
                .iter()
                .map(|code| PropertyKey::from_code(*code).ok_or(BridgeError::InvalidMessage))
                .collect::<Result<_, _>>()?;
            Ok(Response::Smoke {
                provisioned: decode_bool(payload[0])?,
                properties,
            })
        }
        Operation::SandboxProbe if payload.is_empty() => Ok(Response::SandboxEnabled),
        Operation::SetAndroidId
        | Operation::EraseProvisioning
        | Operation::EndProvisioning
        | Operation::DestroyProvisioning
            if payload.is_empty() =>
        {
            Ok(Response::Unit(operation))
        }
        Operation::QueryProvisioned if payload.len() == 1 => {
            Ok(Response::Provisioned(decode_bool(payload[0])?))
        }
        Operation::StartProvisioning => {
            let mut cursor = Cursor::new(&payload);
            let cpim = Zeroizing::new(cursor.bytes_u32(MAX_SECRET_BYTES)?);
            cursor.finish()?;
            Ok(Response::ProvisioningStarted(cpim))
        }
        Operation::RequestOtp | Operation::Synchronize => {
            let mut cursor = Cursor::new(&payload);
            let first = Zeroizing::new(cursor.bytes_u32(MAX_SECRET_BYTES)?);
            let second = Zeroizing::new(cursor.bytes_u32(MAX_SECRET_BYTES)?);
            cursor.finish()?;
            Ok(Response::SecretPair {
                operation,
                first,
                second,
            })
        }
        _ => Err(BridgeError::InvalidMessage),
    }
}

pub(crate) fn write_transaction_command(
    mut writer: impl Write,
    command: &TransactionCommand,
) -> Result<(), BridgeError> {
    match command {
        TransactionCommand::Finish { ptm, tk } => {
            let capacity = encoded_pair_capacity(ptm, tk)?;
            let mut payload = Zeroizing::new(Vec::with_capacity(capacity));
            put_bytes_u32(&mut payload, ptm, MAX_SECRET_BYTES)?;
            put_bytes_u32(&mut payload, tk, MAX_SECRET_BYTES)?;
            write_frame(&mut writer, TRANSACTION_FINISH, 0, &payload)
        }
        TransactionCommand::Cancel => write_frame(&mut writer, TRANSACTION_CANCEL, 0, &[]),
    }
}

pub(crate) fn read_transaction_command(
    reader: &mut impl Read,
) -> Result<TransactionCommand, BridgeError> {
    let (kind, status, payload) = read_frame(reader)?;
    if status != 0 {
        return Err(BridgeError::InvalidMessage);
    }
    match kind {
        TRANSACTION_FINISH => {
            let mut cursor = Cursor::new(&payload);
            let ptm = Zeroizing::new(cursor.bytes_u32(MAX_SECRET_BYTES)?);
            let tk = Zeroizing::new(cursor.bytes_u32(MAX_SECRET_BYTES)?);
            cursor.finish()?;
            Ok(TransactionCommand::Finish { ptm, tk })
        }
        TRANSACTION_CANCEL if payload.is_empty() => Ok(TransactionCommand::Cancel),
        _ => Err(BridgeError::InvalidMessage),
    }
}

fn write_frame(
    writer: &mut impl Write,
    kind: u8,
    status: u8,
    payload: &[u8],
) -> Result<(), BridgeError> {
    if payload.len() > MAX_FRAME_BYTES - HEADER_LEN {
        return Err(BridgeError::InvalidMessage);
    }
    let mut header = [0u8; HEADER_LEN];
    header[..8].copy_from_slice(MAGIC);
    header[8..10].copy_from_slice(&VERSION.to_be_bytes());
    header[10] = kind;
    header[11] = status;
    header[12..16].copy_from_slice(
        &u32::try_from(payload.len())
            .map_err(|_| BridgeError::InvalidMessage)?
            .to_be_bytes(),
    );
    writer
        .write_all(&header)
        .and_then(|()| writer.write_all(payload))
        .map_err(|_| BridgeError::ProcessIo)
}

fn read_frame(reader: &mut impl Read) -> Result<(u8, u8, Zeroizing<Vec<u8>>), BridgeError> {
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
    let mut payload = Zeroizing::new(vec![0u8; payload_len]);
    reader
        .read_exact(&mut payload)
        .map_err(|_| BridgeError::InvalidMessage)?;
    Ok((header[10], header[11], payload))
}

pub(crate) fn require_eof(reader: &mut impl Read) -> Result<(), BridgeError> {
    let mut trailing = [0u8; 1];
    match reader.read(&mut trailing) {
        Ok(0) => Ok(()),
        _ => Err(BridgeError::InvalidMessage),
    }
}

fn put_path(output: &mut Vec<u8>, path: &Path) -> Result<(), BridgeError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() > MAX_PATH_BYTES || bytes.contains(&0) {
        return Err(BridgeError::InvalidMessage);
    }
    output.extend_from_slice(
        &u16::try_from(bytes.len())
            .map_err(|_| BridgeError::InvalidMessage)?
            .to_be_bytes(),
    );
    output.extend_from_slice(bytes);
    Ok(())
}

fn put_bytes_u8(output: &mut Vec<u8>, bytes: &[u8], maximum: usize) -> Result<(), BridgeError> {
    if bytes.len() > maximum {
        return Err(BridgeError::InvalidMessage);
    }
    output.push(u8::try_from(bytes.len()).map_err(|_| BridgeError::InvalidMessage)?);
    output.extend_from_slice(bytes);
    Ok(())
}

fn put_bytes_u32(output: &mut Vec<u8>, bytes: &[u8], maximum: usize) -> Result<(), BridgeError> {
    if bytes.len() > maximum {
        return Err(BridgeError::InvalidMessage);
    }
    output.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| BridgeError::InvalidMessage)?
            .to_be_bytes(),
    );
    output.extend_from_slice(bytes);
    Ok(())
}

fn encoded_secret_capacity(bytes: &[u8]) -> Result<usize, BridgeError> {
    if bytes.len() > MAX_SECRET_BYTES {
        return Err(BridgeError::InvalidMessage);
    }
    4usize
        .checked_add(bytes.len())
        .ok_or(BridgeError::InvalidMessage)
}

fn encoded_pair_capacity(first: &[u8], second: &[u8]) -> Result<usize, BridgeError> {
    encoded_secret_capacity(first)?
        .checked_add(encoded_secret_capacity(second)?)
        .ok_or(BridgeError::InvalidMessage)
}

fn decode_bool(value: u8) -> Result<bool, BridgeError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(BridgeError::InvalidMessage),
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], BridgeError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(BridgeError::InvalidMessage)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(BridgeError::InvalidMessage)?;
        self.offset = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], BridgeError> {
        self.take(N)?
            .try_into()
            .map_err(|_| BridgeError::InvalidMessage)
    }
    fn path(&mut self) -> Result<PathBuf, BridgeError> {
        let length = usize::from(u16::from_be_bytes(self.array()?));
        if length > MAX_PATH_BYTES {
            return Err(BridgeError::InvalidMessage);
        }
        let bytes = self.take(length)?;
        if bytes.contains(&0) {
            return Err(BridgeError::InvalidMessage);
        }
        Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec())))
    }
    fn bytes_u8(&mut self, maximum: usize) -> Result<Vec<u8>, BridgeError> {
        let length = usize::from(self.array::<1>()?[0]);
        if length > maximum {
            return Err(BridgeError::InvalidMessage);
        }
        Ok(self.take(length)?.to_vec())
    }
    fn bytes_u32(&mut self, maximum: usize) -> Result<Vec<u8>, BridgeError> {
        let length = u32::from_be_bytes(self.array()?) as usize;
        if length > maximum {
            return Err(BridgeError::InvalidMessage);
        }
        Ok(self.take(length)?.to_vec())
    }
    fn finish(self) -> Result<(), BridgeError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(BridgeError::InvalidMessage)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor as IoCursor;

    fn request(operation: Operation) -> Request {
        let carries_android_id =
            !matches!(operation, Operation::OfflineSmoke | Operation::SandboxProbe);
        let carries_secret = matches!(
            operation,
            Operation::StartProvisioning | Operation::Synchronize
        );
        Request {
            operation,
            library_root: PathBuf::from("/library"),
            provisioning_root: PathBuf::from("/data/coffer/anisette"),
            state_directory: PathBuf::from("/data/coffer/anisette/staging/.generation-a"),
            ds_id: -2,
            android_id: Zeroizing::new(if carries_android_id {
                b"01234567-89AB-CD".to_vec()
            } else {
                Vec::new()
            }),
            secret: Zeroizing::new(if carries_secret {
                b"input".to_vec()
            } else {
                Vec::new()
            }),
        }
    }

    #[test]
    fn every_public_operation_has_a_byte_exact_request_frame() {
        for (operation, code) in [
            (Operation::OfflineSmoke, 1),
            (Operation::SandboxProbe, 2),
            (Operation::SetAndroidId, 3),
            (Operation::QueryProvisioned, 4),
            (Operation::StartProvisioning, 5),
            (Operation::RequestOtp, 6),
            (Operation::Synchronize, 7),
            (Operation::EraseProvisioning, 8),
        ] {
            let request = request(operation);
            let mut encoded = Vec::new();
            write_request(&mut encoded, &request).expect("encode");
            let mut expected = b"COFFADI\0\0\x02".to_vec();
            expected.extend_from_slice(&[code, 0, 0, 0, 0, 0]);
            expected.extend_from_slice(b"\0\x08/library");
            expected.extend_from_slice(b"\0\x15/data/coffer/anisette");
            expected.extend_from_slice(b"\0\x2b/data/coffer/anisette/staging/.generation-a");
            expected.extend_from_slice(&(-2i64).to_be_bytes());
            expected.push(request.android_id.len() as u8);
            expected.extend_from_slice(&request.android_id);
            expected.extend_from_slice(&(request.secret.len() as u32).to_be_bytes());
            expected.extend_from_slice(&request.secret);
            let payload_length = u32::try_from(expected.len() - HEADER_LEN).expect("payload");
            expected[12..16].copy_from_slice(&payload_length.to_be_bytes());
            assert_eq!(encoded, expected);
            let decoded = read_request(IoCursor::new(encoded)).expect("decode");
            assert_eq!(decoded.operation, operation);
            assert_eq!(&*decoded.android_id, &*request.android_id);
            assert_eq!(&*decoded.secret, &*request.secret);
        }
    }

    #[test]
    fn request_payload_reserves_its_complete_size_before_copying_identifiers() {
        let mut request = request(Operation::StartProvisioning);
        request.secret = Zeroizing::new(vec![0x5a; MAX_SECRET_BYTES]);
        let expected = request_payload_capacity(&request).expect("capacity");
        let payload = encode_request_payload(&request).expect("payload");
        assert_eq!(payload.len(), expected);
        assert!(payload.capacity() >= expected);
    }

    #[test]
    fn finish_and_cancel_frames_are_byte_exact_and_redacted() {
        let finish = TransactionCommand::Finish {
            ptm: Zeroizing::new(b"ptm".to_vec()),
            tk: Zeroizing::new(b"tk".to_vec()),
        };
        let mut encoded = Vec::new();
        write_transaction_command(&mut encoded, &finish).expect("encode");
        assert_eq!(
            encoded,
            b"COFFADI\0\0\x02\x40\0\0\0\0\r\0\0\0\x03ptm\0\0\0\x02tk"
        );
        assert!(matches!(
            read_transaction_command(&mut IoCursor::new(encoded)).expect("decode"),
            TransactionCommand::Finish { .. }
        ));
        assert_eq!(format!("{finish:?}"), "Finish(<redacted>)");
        let mut cancel = Vec::new();
        write_transaction_command(&mut cancel, &TransactionCommand::Cancel).expect("cancel");
        assert_eq!(cancel, b"COFFADI\0\0\x02\x41\0\0\0\0\0");
    }

    #[test]
    fn malformed_truncated_trailing_unknown_and_oversized_frames_fail_closed() {
        let mut valid = Vec::new();
        write_request(&mut valid, &request(Operation::QueryProvisioned)).expect("encode");
        for end in 0..valid.len() {
            assert_eq!(
                read_request(IoCursor::new(&valid[..end])).expect_err("truncated"),
                BridgeError::InvalidMessage
            );
        }
        let mut trailing = valid.clone();
        trailing.push(0);
        assert_eq!(
            read_request(IoCursor::new(trailing)).expect_err("trailing"),
            BridgeError::InvalidMessage
        );
        let mut unknown = valid.clone();
        unknown[10] = 63;
        assert_eq!(
            read_request(IoCursor::new(unknown)).expect_err("unknown"),
            BridgeError::InvalidMessage
        );
        let mut oversized = valid;
        oversized[12..16].copy_from_slice(&(MAX_FRAME_BYTES as u32).to_be_bytes());
        assert_eq!(
            read_request(IoCursor::new(oversized)).expect_err("oversized"),
            BridgeError::InvalidMessage
        );

        let mut extraneous = request(Operation::QueryProvisioned);
        extraneous.secret = Zeroizing::new(b"unexpected".to_vec());
        let mut encoded = Vec::new();
        write_request(&mut encoded, &extraneous).expect("encode extraneous secret");
        assert_eq!(
            read_request(IoCursor::new(encoded)).expect_err("extraneous secret"),
            BridgeError::InvalidMessage
        );

        let mut extraneous = request(Operation::SandboxProbe);
        extraneous.android_id = Zeroizing::new(b"01234567-89AB-CD".to_vec());
        let mut encoded = Vec::new();
        write_request(&mut encoded, &extraneous).expect("encode extraneous identifier");
        assert_eq!(
            read_request(IoCursor::new(encoded)).expect_err("extraneous identifier"),
            BridgeError::InvalidMessage
        );
    }

    #[test]
    fn secret_response_debug_is_redacted() {
        let response = Response::SecretPair {
            operation: Operation::RequestOtp,
            first: Zeroizing::new(b"machine-secret".to_vec()),
            second: Zeroizing::new(b"otp-secret".to_vec()),
        };
        let rendered = format!("{response:?}");
        assert!(!rendered.contains("machine-secret") && !rendered.contains("otp-secret"));
    }
}
