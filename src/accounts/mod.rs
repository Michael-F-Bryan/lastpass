//! Account management.

use crate::keys::{DecryptionKey, PrivateKey};
use byteorder::{BigEndian, ByteOrder};
use std::{
    convert::TryInto,
    fmt::{self, Debug, Formatter},
};

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum BlobParseError {}

#[derive(Debug, Clone, PartialEq)]
pub struct Blob {}

impl Blob {
    pub fn parse(
        raw: &[u8],
        _decryption_key: &DecryptionKey,
        _private_key: &PrivateKey,
    ) -> Result<Blob, BlobParseError> {
        let mut parser = Parser { buffer: raw };

        while let Some(chunk) = parser.next_chunk() {
            match chunk.name {
                // blob version
                b"LPAV" => unimplemented!(),
                // an account
                b"ACCT" => unimplemented!(),
                // some sort of app field
                b"ACFL" | b"ACOF" => unimplemented!(),
                // is local blob?
                b"LOCL" => unimplemented!(),
                // share
                b"SHAR" => unimplemented!(),
                // app info
                b"AACT" => unimplemented!(),
                // app field
                b"AACF" => unimplemented!(),
                // attachment
                b"ATTA" => unimplemented!(),
                _ => unimplemented!(),
            }
        }

        unimplemented!()
    }
}

struct Parser<'a> {
    buffer: &'a [u8],
}

impl<'a> Parser<'a> {
    fn next_chunk(&mut self) -> Option<Chunk<'a>> {
        let (chunk, rest) = Chunk::parse(self.buffer)?;
        self.buffer = rest;
        Some(chunk)
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

    #[test]
    fn parse_chunk() {
        let raw = &[
            0x4C, 0x50, 0x41, 0x56, 0x00, 0x00, 0x00, 0x03, 0x31, 0x39, 0x38,
        ];
        let should_be = Chunk {
            name: b"LPAV",
            data: b"198",
        };

        let (chunk, rest) = Chunk::parse(raw).unwrap();

        assert_eq!(chunk, should_be);
        assert!(rest.is_empty());
    }
}
