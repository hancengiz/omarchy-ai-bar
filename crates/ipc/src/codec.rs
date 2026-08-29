//! A fail-closed, bounded newline-delimited JSON codec.

use std::io::{self, Write};
use std::marker::PhantomData;

use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

/// Maximum bytes in one wire record, including its terminating LF.
pub const MAX_JSON_LINE_BYTES: usize = 64 * 1024;
const MAX_JSON_PAYLOAD_BYTES: usize = MAX_JSON_LINE_BYTES - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum JsonLineError {
    #[error("JSON line exceeds the 64 KiB wire limit")]
    LineTooLong,
    #[error("JSON line is malformed or violates its message schema")]
    MalformedJson,
    #[error("JSON line must use one canonical LF terminator")]
    NonCanonicalNewline,
    #[error("JSON line was not terminated before EOF")]
    UnterminatedLine,
    #[error("more than one JSON record was supplied to a single-record decoder")]
    MultipleFrames,
    #[error("protocol message could not be serialized")]
    Serialization,
    #[error("decoder is poisoned after an earlier protocol violation")]
    Poisoned,
}

/// Encodes one compact JSON value followed by exactly one LF.
///
/// # Errors
///
/// Serialization failures and records whose JSON plus LF exceeds 64 KiB are
/// rejected. Error text never includes the serialized value.
pub fn encode_json_line<T>(message: &T) -> Result<Vec<u8>, JsonLineError>
where
    T: Serialize + ?Sized,
{
    let mut writer = CappedJsonBuffer::new();
    let serialization = serde_json::to_writer(&mut writer, message);
    if writer.exceeded {
        return Err(JsonLineError::LineTooLong);
    }
    if serialization.is_err() {
        return Err(JsonLineError::Serialization);
    }
    let mut encoded = writer.into_bytes();
    encoded.push(b'\n');
    Ok(encoded)
}

struct CappedJsonBuffer {
    bytes: Vec<u8>,
    exceeded: bool,
}

impl CappedJsonBuffer {
    const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            exceeded: false,
        }
    }

    fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

impl Write for CappedJsonBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|length| length > MAX_JSON_PAYLOAD_BYTES)
        {
            self.exceeded = true;
            return Err(io::Error::other("JSON record exceeded its fixed limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for CappedJsonBuffer {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

/// Decodes exactly one bounded, LF-terminated JSON record.
///
/// # Errors
///
/// Unterminated, CRLF, multi-record, malformed, and schema-invalid input is
/// rejected without returning the parser's potentially sensitive diagnostics.
pub fn decode_json_line<T>(frame: &[u8]) -> Result<T, JsonLineError>
where
    T: DeserializeOwned,
{
    if frame.len() > MAX_JSON_LINE_BYTES {
        return Err(JsonLineError::LineTooLong);
    }
    let Some(payload) = frame.strip_suffix(b"\n") else {
        return Err(JsonLineError::UnterminatedLine);
    };
    if payload.ends_with(b"\r") {
        return Err(JsonLineError::NonCanonicalNewline);
    }
    if payload.contains(&b'\n') {
        return Err(JsonLineError::MultipleFrames);
    }
    if payload.is_empty() {
        return Err(JsonLineError::MalformedJson);
    }
    serde_json::from_slice(payload).map_err(|_| JsonLineError::MalformedJson)
}

/// Incremental decoder for one connection and one message type.
///
/// A protocol violation permanently poisons the decoder. Callers should close
/// that connection rather than attempting to resynchronize after attacker-
/// controlled input.
#[derive(Debug, Clone)]
pub struct JsonLineDecoder<T> {
    buffer: Vec<u8>,
    poisoned: bool,
    message: PhantomData<fn() -> T>,
}

impl<T> Default for JsonLineDecoder<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> JsonLineDecoder<T> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buffer: Vec::new(),
            poisoned: false,
            message: PhantomData,
        }
    }

    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len()
    }

    fn reject<R>(&mut self, error: JsonLineError) -> Result<R, JsonLineError> {
        self.buffer.fill(0);
        self.buffer.clear();
        self.poisoned = true;
        Err(error)
    }

    /// Marks the input stream as finished.
    ///
    /// Empty EOF after a complete LF-terminated record is clean. Any buffered
    /// bytes are an unterminated record and poison the decoder.
    ///
    /// # Errors
    ///
    /// Returns [`JsonLineError::UnterminatedLine`] for a partial final record,
    /// or [`JsonLineError::Poisoned`] after an earlier violation.
    pub fn finish(&mut self) -> Result<(), JsonLineError> {
        if self.poisoned {
            return Err(JsonLineError::Poisoned);
        }
        if self.buffer.is_empty() {
            Ok(())
        } else {
            self.reject(JsonLineError::UnterminatedLine)
        }
    }
}

impl<T> JsonLineDecoder<T>
where
    T: DeserializeOwned,
{
    /// Adds a byte chunk and returns every complete message it contains.
    ///
    /// # Errors
    ///
    /// An oversized or invalid record poisons this decoder. A non-terminated
    /// buffer of exactly 64 KiB is already oversized because it still needs LF.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<T>, JsonLineError> {
        if self.poisoned {
            return Err(JsonLineError::Poisoned);
        }

        let mut messages = Vec::new();
        for &byte in chunk {
            self.buffer.push(byte);
            if self.buffer.len() > MAX_JSON_LINE_BYTES {
                return self.reject(JsonLineError::LineTooLong);
            }

            if byte == b'\n' {
                let frame = std::mem::take(&mut self.buffer);
                match decode_json_line(&frame) {
                    Ok(message) => messages.push(message),
                    Err(error) => return self.reject(error),
                }
            } else if self.buffer.len() == MAX_JSON_LINE_BYTES {
                return self.reject(JsonLineError::LineTooLong);
            }
        }
        Ok(messages)
    }
}

impl<T> Drop for JsonLineDecoder<T> {
    fn drop(&mut self) {
        self.buffer.fill(0);
    }
}
