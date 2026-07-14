//! Deterministic on-disk WIR exchanged with the private backend process.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_target::TargetIdentity;
use wrela_wir::{FORMAT_VERSION, Function, FunctionId, Module};

const MAGIC: &[u8; 8] = b"WRELWIR\0";

/// Serialize the stable portion of the current WIR contract.
pub fn encode(module: &Module) -> Result<Vec<u8>, EncodeError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    push_u32(&mut bytes, FORMAT_VERSION);
    push_string(&mut bytes, &module.name)?;
    push_string(&mut bytes, &module.target.0)?;
    push_u32(
        &mut bytes,
        module
            .functions
            .len()
            .try_into()
            .map_err(|_| EncodeError::LengthOverflow)?,
    );
    for function in &module.functions {
        push_u32(&mut bytes, function.id.0);
        push_string(&mut bytes, &function.name)?;
    }
    Ok(bytes)
}

/// Decode WIR while rejecting incompatible or malformed inputs.
pub fn decode(bytes: &[u8]) -> Result<Module, DecodeError> {
    let mut reader = Reader::new(bytes);
    if reader.take(MAGIC.len())? != MAGIC {
        return Err(DecodeError::InvalidMagic);
    }
    let version = reader.u32()?;
    if version != FORMAT_VERSION {
        return Err(DecodeError::UnsupportedVersion(version));
    }

    let name = reader.string()?;
    let target = TargetIdentity(reader.string()?);
    let function_count = reader.u32()?;
    let mut functions = Vec::with_capacity(function_count as usize);
    for _ in 0..function_count {
        functions.push(Function {
            id: FunctionId(reader.u32()?),
            name: reader.string()?,
        });
    }
    if !reader.is_empty() {
        return Err(DecodeError::TrailingBytes);
    }

    Ok(Module {
        name,
        target,
        functions,
    })
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), EncodeError> {
    push_u32(
        bytes,
        value
            .len()
            .try_into()
            .map_err(|_| EncodeError::LengthOverflow)?,
    );
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

/// WIR value cannot be represented by the current format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// A collection or string exceeds the format's 32-bit length field.
    LengthOverflow,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WIR value exceeds the codec length limit")
    }
}

impl std::error::Error for EncodeError {}

/// Malformed or incompatible serialized WIR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Input does not begin with the WIR magic bytes.
    InvalidMagic,
    /// Input uses a format version this compiler cannot consume.
    UnsupportedVersion(u32),
    /// Input ends before the declared value is complete.
    UnexpectedEnd,
    /// A WIR string is not valid UTF-8.
    InvalidUtf8,
    /// Bytes remain after the complete module.
    TrailingBytes,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => formatter.write_str("invalid WIR magic"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported WIR format version {version}")
            }
            Self::UnexpectedEnd => formatter.write_str("unexpected end of WIR input"),
            Self::InvalidUtf8 => formatter.write_str("invalid UTF-8 in WIR input"),
            Self::TrailingBytes => formatter.write_str("trailing bytes after WIR module"),
        }
    }
}

impl std::error::Error for DecodeError {}

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DecodeError> {
        if self.remaining.len() < length {
            return Err(DecodeError::UnexpectedEnd);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| DecodeError::UnexpectedEnd)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn string(&mut self) -> Result<String, DecodeError> {
        let length = self.u32()? as usize;
        let bytes = self.take(length)?;
        let value = std::str::from_utf8(bytes).map_err(|_| DecodeError::InvalidUtf8)?;
        Ok(value.to_owned())
    }

    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use wrela_target::TargetIdentity;
    use wrela_wir::{Function, FunctionId, Module};

    use super::{decode, encode};

    #[test]
    fn codec_round_trips_a_fixture_without_other_layers() {
        let module = Module {
            name: "codec-fixture".to_owned(),
            target: TargetIdentity("x86_64-uefi".to_owned()),
            functions: vec![Function {
                id: FunctionId(0),
                name: "entry".to_owned(),
            }],
        };

        let bytes = encode(&module).expect("encode fixture");
        assert_eq!(decode(&bytes), Ok(module));
    }
}
