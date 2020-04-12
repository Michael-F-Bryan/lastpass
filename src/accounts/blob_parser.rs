use crate::{
    accounts::{Account, Attachment, Blob},
    keys::{DecryptionError, DecryptionKey},
};
use byteorder::{BigEndian, ByteOrder};
use std::{
    borrow::Cow,
    convert::TryInto,
    error::Error,
    fmt::{self, Debug, Formatter},
    str::{FromStr, Utf8Error},
};

pub(crate) fn parse(
    raw: &[u8],
    decryption_key: &DecryptionKey,
) -> Result<Blob, BlobParseError> {
    let mut parser = Parser::new(raw);

    parser.parse(decryption_key)?;

    let Parser {
        blob_version,
        accounts,
        ..
    } = parser;
    let version = unwrap_or_missing_field(blob_version, "blob_version")?;

    Ok(Blob { version, accounts })
}

fn unwrap_or_missing_field<T>(
    item: Option<T>,
    name: &'static str,
) -> Result<T, BlobParseError> {
    item.ok_or(BlobParseError::MissingField { name })
}

#[derive(Debug, thiserror::Error)]
pub enum BlobParseError {
    #[error("The \"{}\" chunk should contain a UTF-8 string", name)]
    ChunkShouldBeString {
        name: String,
        #[source]
        inner: Utf8Error,
    },
    #[error("Parsing didn't find, {}", name)]
    MissingField { name: &'static str },
    #[error("Reached the end of input while looking for {}", expected_field)]
    UnexpectedEOF { expected_field: &'static str },
    #[error("Unable to decrypt {}", field)]
    UnableToDecrypt {
        field: &'static str,
        #[source]
        inner: DecryptionError,
    },
    #[error("Parsing the {} field failed", field)]
    BadParse {
        field: &'static str,
        #[source]
        inner: Box<dyn Error + Send + Sync + 'static>,
    },
}

/// A parser that keeps track of data as it's parsed so we can collate it into
/// a [`Blob`] afterwards.
struct Parser<'a> {
    buffer: &'a [u8],
    blob_version: Option<u64>,
    accounts: Vec<Account>,
}

impl<'a> Parser<'a> {
    fn new(buffer: &'a [u8]) -> Self {
        Parser {
            buffer,
            blob_version: None,
            accounts: Vec::new(),
        }
    }

    fn parse(
        &mut self,
        decryption_key: &DecryptionKey,
    ) -> Result<(), BlobParseError> {
        while let Some(chunk) = self.next_chunk() {
            self.handle_chunk(chunk, decryption_key)?;
        }

        Ok(())
    }

    fn next_chunk(&mut self) -> Option<Chunk<'a>> {
        let (chunk, rest) = Chunk::parse(self.buffer)?;
        self.buffer = rest;
        Some(chunk)
    }

    fn handle_chunk(
        &mut self,
        chunk: Chunk<'_>,
        decryption_key: &DecryptionKey,
    ) -> Result<(), BlobParseError> {
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
            b"ACCT" => self.handle_account(chunk.data, decryption_key)?,
            b"ATTA" => self.handle_attachment(chunk.data)?,
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
            _ => {},
        }

        Ok(())
    }

    fn handle_account(
        &mut self,
        buffer: &[u8],
        decryption_key: &DecryptionKey,
    ) -> Result<(), BlobParseError> {
        self.accounts.push(parse_account(buffer, decryption_key)?);

        Ok(())
    }

    fn handle_attachment(
        &mut self,
        buffer: &[u8],
    ) -> Result<(), BlobParseError> {
        let attachment = parse_attachment(buffer)?;

        match self
            .accounts
            .iter_mut()
            .find(|account| account.id == attachment.parent)
        {
            Some(parent) => {
                parent.attachments.push(attachment);
            },
            None => unimplemented!(),
        }

        Ok(())
    }
}

pub(crate) fn parse_attachment(
    buffer: &[u8],
) -> Result<Attachment, BlobParseError> {
    let (id, buffer) = read_parsed(buffer, "attachment.id")?;
    let (parent, buffer) = read_parsed(buffer, "attachment.parent")?;
    let (mime_type, buffer) = read_str_item(buffer, "attachment.mimetype")?;
    let (storage_key, buffer) = read_str_item(buffer, "attachment.storagekey")?;
    let (size, buffer) = read_parsed(buffer, "attachment.size")?;
    let (filename, buffer) = read_str_item(buffer, "attachment.filename")?;

    let _ = buffer;

    Ok(Attachment {
        id,
        parent,
        mime_type: mime_type.to_string(),
        storage_key: storage_key.to_string(),
        size,
        filename: filename.to_string(),
    })
}

pub(crate) fn parse_account(
    buffer: &[u8],
    decryption_key: &DecryptionKey,
) -> Result<Account, BlobParseError> {
    let (id, buffer) = read_parsed(buffer, "account.id")?;
    let (name, buffer) =
        read_encrypted(buffer, "account.name", decryption_key)?;
    let (group, buffer) =
        read_encrypted(buffer, "account.group", decryption_key)?;
    let (url, buffer) = read_hex(buffer, "account.url")?;
    let (note, buffer) =
        read_encrypted(buffer, "account.note", &decryption_key)?;
    let (fav, buffer) = read_bool(buffer, "account.fav")?;
    let buffer = skip(buffer, "account.sharedfromaid")?;
    let (username, buffer) =
        read_encrypted(buffer, "account.username", decryption_key)?;
    let (password, buffer) =
        read_encrypted(buffer, "account.password", decryption_key)?;
    let (password_protected, buffer) = read_bool(buffer, "account.pwprotect")?;
    let buffer = skip(buffer, "account.genpw")?;
    let buffer = skip(buffer, "account.sn")?;
    let (last_touch, buffer) = read_str_item(buffer, "account.last_touch")?;
    let buffer = skip(buffer, "account.autologin")?;
    let buffer = skip(buffer, "account.never_autofill")?;
    let buffer = skip(buffer, "account.realm_data")?;
    let buffer = skip(buffer, "account.fiid")?;
    let buffer = skip(buffer, "account.custom_js")?;
    let buffer = skip(buffer, "account.submit_id")?;
    let buffer = skip(buffer, "account.captcha_id")?;
    let buffer = skip(buffer, "account.urid")?;
    let buffer = skip(buffer, "account.basic_auth")?;
    let buffer = skip(buffer, "account.method")?;
    let buffer = skip(buffer, "account.action")?;
    let buffer = skip(buffer, "account.groupid")?;
    let buffer = skip(buffer, "account.deleted")?;
    let (attachkey_encrypted, buffer) =
        read_str_item(buffer, "account.attachkey_encrypted")?;
    let (attachment_present, buffer) =
        read_bool(buffer, "account.attachpresent")?;
    let buffer = skip(buffer, "account.individualshare")?;
    let (note_type, buffer) = read_str_item(buffer, "account.notetype")?;
    let buffer = skip(buffer, "account.noalert")?;
    let (last_modified_gmt, buffer) =
        read_str_item(buffer, "account.last_modified_gmt")?;
    let buffer = skip(buffer, "account.hasbeenshared")?;
    let buffer = skip(buffer, "account.last_pwchange_gmt")?;
    let buffer = skip(buffer, "account.created_gmt")?;
    let buffer = skip(buffer, "account.vulnerable")?;

    let _ = buffer;

    Ok(Account {
        id,
        name,
        username,
        password,
        password_protected,
        note: note.to_string(),
        note_type: note_type.to_string(),
        last_touch: last_touch.to_string(),
        attachment_key: attachkey_encrypted.to_string(),
        attachment_present,
        favourite: fav,
        group,
        last_modified: last_modified_gmt.to_string(),
        url,
        attachments: Vec::new(),
    })
}

fn skip<'a>(
    buffer: &'a [u8],
    field: &'static str,
) -> Result<&'a [u8], BlobParseError> {
    let (_, buffer) = read_item(buffer, field)?;

    Ok(buffer)
}

fn read_encrypted<'a>(
    buffer: &'a [u8],
    field: &'static str,
    decryption_key: &DecryptionKey,
) -> Result<(String, &'a [u8]), BlobParseError> {
    let (ciphertext, buffer) = read_item(buffer, field)?;

    let decrypted = decryption_key
        .decrypt(ciphertext)
        .map_err(|e| BlobParseError::UnableToDecrypt { field, inner: e })?;

    let decrypted =
        String::from_utf8(decrypted).map_err(|e| BlobParseError::BadParse {
            field,
            inner: Box::new(e),
        })?;

    Ok((decrypted, buffer))
}

fn read_bool<'a>(
    buffer: &'a [u8],
    field: &'static str,
) -> Result<(bool, &'a [u8]), BlobParseError> {
    let (raw, buffer) = read_str_item(buffer, field)?;

    Ok((raw == "1", buffer))
}

fn read_parsed<'a, T>(
    buffer: &'a [u8],
    field: &'static str,
) -> Result<(T, &'a [u8]), BlobParseError>
where
    T: FromStr,
    T::Err: Error + Send + Sync + 'static,
{
    let (raw, buffer) = read_str_item(buffer, field)?;

    let parsed = T::from_str(raw).map_err(|e| BlobParseError::BadParse {
        field,
        inner: Box::new(e),
    })?;

    Ok((parsed, buffer))
}

/// Read a hex-encoded string.
fn read_hex<'a>(
    buffer: &'a [u8],
    field: &'static str,
) -> Result<(String, &'a [u8]), BlobParseError> {
    let (raw, buffer) = read_str_item(buffer, field)?;
    let hex = hex::decode(raw).map_err(|e| BlobParseError::BadParse {
        field,
        inner: Box::new(e),
    })?;

    let value =
        String::from_utf8(hex).map_err(|e| BlobParseError::BadParse {
            field,
            inner: Box::new(e),
        })?;

    Ok((value, buffer))
}

/// Read the next item, interpreting it as a UTF-8 string.
fn read_str_item<'a>(
    buffer: &'a [u8],
    field: &'static str,
) -> Result<(&'a str, &'a [u8]), BlobParseError> {
    let (item, buffer) = read_item(buffer, field)?;

    let item =
        std::str::from_utf8(item).map_err(|e| BlobParseError::BadParse {
            field,
            inner: Box::new(e),
        })?;

    Ok((item, buffer))
}

/// Splits a length-prefixed sequence off bytes off the front of a buffer.
fn read_item<'a>(
    buffer: &'a [u8],
    field: &'static str,
) -> Result<(&'a [u8], &'a [u8]), BlobParseError> {
    if buffer.len() < std::mem::size_of::<u32>() {
        return Err(BlobParseError::UnexpectedEOF {
            expected_field: field,
        });
    }

    let (field_length, buffer) = buffer.split_at(std::mem::size_of::<u32>());
    let field_length: usize =
        BigEndian::read_u32(field_length).try_into().unwrap();

    if buffer.len() < field_length {
        return Err(BlobParseError::UnexpectedEOF {
            expected_field: field,
        });
    }

    Ok(buffer.split_at(field_length))
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
    use crate::Id;
    use byteorder::WriteBytesExt;
    use std::io::Write;

    const LPAV_CHUNK: &[u8] = &[
        0x4C, 0x50, 0x41, 0x56, 0x00, 0x00, 0x00, 0x03, 0x31, 0x39, 0x38,
    ];

    fn decryption_key() -> DecryptionKey {
        // this is the decryption key used for the `blob_from_dummy_account.bin`
        // blob. Having it in git isn't really a security problem because that's
        // a dummy account, and the password has since been changed.
        let raw =
            "08c9bb2d9b48b39efb774e3fef32a38cb0d46c5c6c75f7f9d65259bfd374e120";
        let mut buffer = [0; DecryptionKey::LEN];
        hex::decode_to_slice(raw, &mut buffer).unwrap();

        DecryptionKey::from_raw(buffer)
    }

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
        let decryption_key = decryption_key();
        let mut parser = Parser::new(&buffer);

        parser.parse(&decryption_key).unwrap();

        assert_eq!(parser.blob_version, Some(198));
    }

    #[test]
    fn read_the_dummy_blob() {
        let raw = include_bytes!("blob_from_dummy_account.bin");
        let should_be = Blob {
            version: 12,
            accounts: vec![
                Account {
                    id: Id::from("5496230974130180673"),
                    name: String::from("Example password without folder"),
                    group: String::from(r"Some Folder\Nested"),
                    url: String::from("https://example.com/"),
                    note: String::new(),
                    note_type: String::new(),
                    favourite: false,
                    username: String::from("username"),
                    password: String::from("password"),
                    password_protected: false,
                    attachment_key: String::new(),
                    attachment_present: false,
                    last_touch: String::from("1586688785"),
                    last_modified: String::from("1586717585"),
                    attachments: Vec::new(),
                },
                Account {
                    id: Id::from("8852885818375729232"),
                    name: String::from("Another Password"),
                    group: String::new(),
                    url: String::from("https://google.com/"),
                    note: String::new(),
                    note_type: String::new(),
                    favourite: false,
                    username: String::from("user"),
                    password: String::from("My Super Secret Password!!1!"),
                    password_protected: false,
                    attachment_key: String::new(),
                    attachment_present: false,
                    last_touch: String::from("0"),
                    last_modified: String::from("1586717558"),
                    attachments: Vec::new(),
                },
                Account {
                    id: Id::from("8994685833508535250"),
                    name: String::new(),
                    group: String::from("Some Folder"),
                    url: String::from("http://group"),
                    note: String::new(),
                    note_type: String::new(),
                    favourite: false,
                    username: String::new(),
                    password: String::new(),
                    password_protected: false,
                    attachment_key: String::new(),
                    attachment_present: false,
                    last_touch: String::from("0"),
                    last_modified: String::from("1586717569"),
                    attachments: Vec::new(),
                },
                Account {
                    id: Id::from("7483661148987913660"),
                    name: String::new(),
                    group: String::from(r"Some Folder\Nested"),
                    url: String::from("http://group"),
                    note: String::new(),
                    note_type: String::new(),
                    favourite: false,
                    username: String::new(),
                    password: String::new(),
                    password_protected: false,
                    attachment_key: String::new(),
                    attachment_present: false,
                    last_touch: String::from("0"),
                    last_modified: String::from("1586717578"),
                    attachments: Vec::new(),
                },
                Account {
                    id: Id::from("5211400216940069976"),
                    name: String::from("My Address"),
                    group: String::from("Some Folder"),
                    url: String::from("http://sn"),
                    note: String::from("NoteType:Address\nLanguage:en-US\nTitle:mr\nFirst Name:Joseph\nMiddle Name:\nLast Name:Bloggs\nUsername:JoeBloggs\nGender:m\nBirthday:October,2,2003\nCompany:Acme Corporation\nAddress 1:address 1\nAddress 2:somewhere else\nAddress 3:hmm\nCity / Town:Springfield\nCounty:\nState:Western Australia\nZip / Postal Code:\nCountry:AU\nTimezone:\nEmail Address:joe.bloggs@gmail.com\nPhone:\nEvening Phone:\nMobile Phone:\nFax:\nNotes:Super secret non-existent address"),
                    note_type: String::from("Address"),
                    favourite: false,
                    username: String::new(),
                    password: String::new(),
                    password_protected: false,
                    attachment_key: String::new(),
                    attachment_present: false,
                    last_touch: String::from("0"),
                    last_modified: String::from("1586717700"),
                    attachments: Vec::new(),
                },
                Account {
                    id: Id::from("533903346832032070"),
                    name: String::from("My Secure Note"),
                    group: String::new(),
                    url: String::from("http://sn"),
                    note: String::from("This is a super secure note."),
                    note_type: String::from("Generic"),
                    favourite: false,
                    username: String::new(),
                    password: String::new(),
                    password_protected: false,
                    attachment_key: String::from("!MOeCidDT4GAmmh8eoMWyRA==|BWdjMSoIvClMRyWrDdIlz38tZiU3O1nmcbg95PRXCT4zKLTTG4s0OD9v/cO2L2pWnAkl4oaVPSIb8OuFhk1KaL77qBbrkAH03lWY/wIModA="),
                    attachment_present: true,
                    last_touch: String::from("0"),
                    last_modified: String::from("1586717786"),
                    attachments: vec![
                        Attachment {
                            id: Id::from("533903346832032070-27282"),
                            parent: Id::from("533903346832032070"),
                            mime_type: String::from("other:txt"),
                            storage_key: String::from("100000027282"),
                            size: 70,
                            filename: String::from("!zdLMAcQ9okxR3MFWNjoCaw==|B7NqfcNPX0IayFXNtxkqEw=="),
                        },
                    ],
                },
            ]
        };
        let decryption_key = decryption_key();

        let got = parse(raw, &decryption_key).unwrap();

        assert_eq!(got, should_be);
    }
}
