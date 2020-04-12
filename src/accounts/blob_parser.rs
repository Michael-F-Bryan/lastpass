use crate::{
    accounts::Blob,
    keys::{DecryptionKey, PrivateKey},
};
use byteorder::{BigEndian, ByteOrder};
use std::{
    borrow::Cow,
    convert::TryInto,
    fmt::{self, Debug, Formatter},
    str::Utf8Error,
};

pub(crate) fn parse(
    raw: &[u8],
    _decryption_key: &DecryptionKey,
    _private_key: &PrivateKey,
) -> Result<Blob, BlobParseError> {
    let mut parser = Parser::new(raw);

    parser.parse()?;

    let version = parser.blob_version.ok_or(BlobParseError::MissingField {
        name: "blob_version",
    })?;

    Ok(Blob { version })
}

#[derive(Debug, thiserror::Error)]
pub enum BlobParseError {
    #[error("The \"{}\" chunk should contain a UTF-8 string", name)]
    ChunkShouldBeString {
        name: String,
        #[source]
        inner: Utf8Error,
    },
    #[error("Parsing didn't resolve the required field, {}", name)]
    MissingField { name: &'static str },
}

/// A parser that keeps track of data as it's parsed so we can collate it into
/// a [`Blob`] afterwards.
struct Parser<'a> {
    buffer: &'a [u8],
    blob_version: Option<u64>,
}

impl<'a> Parser<'a> {
    fn new(buffer: &'a [u8]) -> Self {
        Parser {
            buffer,
            blob_version: None,
        }
    }

    fn parse(&mut self) -> Result<(), BlobParseError> {
        while let Some(chunk) = self.next_chunk() {
            self.handle_chunk(chunk)?;
        }

        Ok(())
    }

    fn next_chunk(&mut self) -> Option<Chunk<'a>> {
        let (chunk, rest) = Chunk::parse(self.buffer)?;
        self.buffer = rest;
        Some(chunk)
    }

    fn handle_chunk(&mut self, chunk: Chunk<'_>) -> Result<(), BlobParseError> {
        match chunk.data_as_str() {
            Ok(data) if data.len() < 128 => {
                log::trace!("Handling {}: {:?}", chunk.name_as_str(), data)
            },
            _ => log::trace!(
                "Handling {} ({} bytes)",
                chunk.name_as_str(),
                chunk.data.len()
            ),
        }

        match chunk.name {
            // blob version
            b"LPAV" => {
                self.blob_version = chunk.data_as_str()?.parse().ok();
            },
            b"ACCT" => self.handle_account(chunk.data)?,
            // some sort of app field
            // b"ACFL" | b"ACOF" => unimplemented!(),
            // is local blob?
            // b"LOCL" => unimplemented!(),
            // share
            // b"SHAR" => unimplemented!(),
            // app info
            // b"AACT" => unimplemented!(),
            // app field
            // b"AACF" => unimplemented!(),
            // attachment
            // b"ATTA" => unimplemented!(),
            _ => {},
        }

        Ok(())
    }

    fn handle_account(
        &mut self,
        _account: &[u8],
    ) -> Result<(), BlobParseError> {
        unimplemented!()
    }
}

#[derive(Copy, Clone, PartialEq)]
struct Chunk<'a> {
    name: &'a [u8],
    data: &'a [u8],
}

impl<'a> Chunk<'a> {
    fn parse(buffer: &'a [u8]) -> Option<(Chunk<'a>, &'a [u8])> {
        if buffer.len() < 4 {
            return None;
        }

        let (name, buffer) = buffer.split_at(4);

        if buffer.len() < std::mem::size_of::<u32>() {
            return None;
        }

        let (num_bytes, buffer) = buffer.split_at(std::mem::size_of::<u32>());
        let num_bytes: usize =
            BigEndian::read_u32(num_bytes).try_into().unwrap();

        if num_bytes > buffer.len() {
            return None;
        }

        let (data, rest) = buffer.split_at(num_bytes);
        let chunk = Chunk { name, data };

        Some((chunk, rest))
    }

    fn name_as_str(&self) -> Cow<'a, str> { String::from_utf8_lossy(self.name) }

    fn data_as_str(&self) -> Result<&'a str, BlobParseError> {
        std::str::from_utf8(self.data).map_err(|e| {
            BlobParseError::ChunkShouldBeString {
                name: self.name_as_str().into_owned(),
                inner: e,
            }
        })
    }
}

impl<'a> Debug for Chunk<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_struct("Chunk");

        match std::str::from_utf8(self.name) {
            Ok(name) => f.field("name", &name),
            Err(_) => f.field("name", &self.name),
        };
        match std::str::from_utf8(self.data) {
            Ok(data) => f.field("data", &data),
            Err(_) => f.field("data", &self.data),
        };

        f.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::WriteBytesExt;
    use std::io::Write;

    const LPAV_CHUNK: &[u8] = &[
        0x4C, 0x50, 0x41, 0x56, 0x00, 0x00, 0x00, 0x03, 0x31, 0x39, 0x38,
    ];

    #[test]
    fn parse_single_chunk() {
        let should_be = Chunk {
            name: b"LPAV",
            data: b"198",
        };

        let (chunk, rest) = Chunk::parse(LPAV_CHUNK).unwrap();

        assert_eq!(chunk, should_be);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_several_known_chunks() {
        let chunks = &[Chunk {
            name: b"LPAV",
            data: b"198",
        }];
        let mut buffer = Vec::new();
        for chunk in chunks {
            buffer.write_all(chunk.name).unwrap();
            buffer
                .write_u32::<BigEndian>(chunk.data.len() as u32)
                .unwrap();
            buffer.write_all(chunk.data).unwrap();
        }
        let mut parser = Parser::new(&buffer);

        parser.parse().unwrap();

        assert_eq!(parser.blob_version, Some(198));
    }
}
