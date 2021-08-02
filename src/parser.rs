use crate::{
    keys::{DecryptionKey, PrivateKey},
    Account, App, Attachment, DecryptionError, Field, Share, Vault,
};
use byteorder::{BigEndian, ByteOrder};
use std::{
    borrow::Cow,
    convert::TryInto,
    error::Error,
    fmt::{self, Debug, Formatter},
    fs::File,
    io::Write,
    str::{FromStr, Utf8Error},
};
use url::Url;

pub(crate) fn parse(
    raw: &[u8],
    decryption_key: &DecryptionKey,
    private_key: &PrivateKey,
) -> Result<Vault, VaultParseError> {
    let mut parser = Parser::new();

    parser.parse(raw, decryption_key, private_key)?;

    let Parser {
        vault_version,
        accounts,
        local,
        ..
    } = parser;
    let version = unwrap_or_missing_field(vault_version, "vault_version")?;

    Ok(Vault {
        version,
        accounts,
        local,
    })
}

fn unwrap_or_missing_field<T>(
    item: Option<T>,
    name: &'static str,
) -> Result<T, VaultParseError> {
    item.ok_or(VaultParseError::MissingField { name })
}

/// Errors that can happen when parsing a [`Vault`] from raw bytes.
#[derive(Debug, thiserror::Error)]
pub enum VaultParseError {
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
/// a [`Vault`] afterwards.
#[derive(Debug, Default)]
struct Parser {
    vault_version: Option<u64>,
    accounts: Vec<Account>,
    shares: Vec<Share>,
    app: Option<App>,
    local: bool,
}

impl Parser {
    fn new() -> Self {
        Parser::default()
    }

    fn parse(
        &mut self,
        mut buffer: &[u8],
        decryption_key: &DecryptionKey,
        private_key: &PrivateKey,
    ) -> Result<(), VaultParseError> {
        while let Some((chunk, rest)) = Chunk::parse(buffer) {
            buffer = rest;
            self.handle_chunk(chunk, decryption_key, private_key)?;
        }

        Ok(())
    }

    fn handle_chunk(
        &mut self,
        chunk: Chunk<'_>,
        decryption_key: &DecryptionKey,
        private_key: &PrivateKey,
    ) -> Result<(), VaultParseError> {
        match chunk.data_as_str() {
            Ok(data) if data.len() < 128 => {
                log::trace!("Handling {}: {:?}", chunk.name_as_str(), data)
            }
            _ => log::trace!(
                "Handling {} ({} bytes)",
                chunk.name_as_str(),
                chunk.data.len()
            ),
        }

        match chunk.name {
            // vault version
            b"LPAV" => {
                self.vault_version = chunk.data_as_str()?.parse().ok();
            }
            b"ACCT" => self.handle_account(chunk.data, decryption_key)?,
            b"ATTA" => self.handle_attachment(chunk.data)?,
            b"LOCL" => self.local = true,
            b"SHAR" => self.handle_share(chunk.data, private_key)?,
            b"AACT" => self.handle_app(chunk.data, decryption_key)?,
            b"ACFL" | b"ACOF" => {
                self.handle_field(chunk.data, decryption_key)?
            }
            _ => {}
        }

        Ok(())
    }

    fn handle_account(
        &mut self,
        buffer: &[u8],
        decryption_key: &DecryptionKey,
    ) -> Result<(), VaultParseError> {
        self.accounts.push(parse_account(buffer, decryption_key)?);

        Ok(())
    }

    fn handle_attachment(
        &mut self,
        buffer: &[u8],
    ) -> Result<(), VaultParseError> {
        let attachment = parse_attachment(buffer)?;

        match self
            .accounts
            .iter_mut()
            .find(|account| account.id == attachment.parent)
        {
            Some(parent) => {
                parent.attachments.push(attachment);
            }
            None => unimplemented!(),
        }

        Ok(())
    }

    fn handle_field(
        &mut self,
        buffer: &[u8],
        decryption_key: &DecryptionKey,
    ) -> Result<(), VaultParseError> {
        let field = parse_account_field(buffer, decryption_key)?;

        // Fields from a chunck are added to the last created account,
        // and we push accounts to end of our accounts list
        match self.accounts.last_mut() {
            Some(account) => {
                account.fields.push(field);
            }
            // If no accounts have been added yet, we have error
            None => unimplemented!(),
        }

        Ok(())
    }

    fn handle_share(
        &mut self,
        buffer: &[u8],
        private_key: &PrivateKey,
    ) -> Result<(), VaultParseError> {
        let share = parse_share(buffer, private_key)?;
        self.shares.push(share);

        Ok(())
    }

    fn handle_app(
        &mut self,
        buffer: &[u8],
        decryption_key: &DecryptionKey,
    ) -> Result<(), VaultParseError> {
        self.app = Some(parse_app(buffer, decryption_key)?);

        Ok(())
    }
}

pub(crate) fn parse_app(
    buffer: &[u8],
    decryption_key: &DecryptionKey,
) -> Result<App, VaultParseError> {
    let (id, buffer) = read_parsed(buffer, "app.id")?;
    let (app_name, buffer) = read_hex_string(buffer, "app.appname")?;
    let (extra, buffer) = read_encrypted(buffer, "app.extra", decryption_key)?;
    let (name, buffer) = read_encrypted(buffer, "app.appname", decryption_key)?;
    let (group, buffer) = read_encrypted(buffer, "app.group", decryption_key)?;
    let (last_touch, buffer) = read_str_item(buffer, "app.last_touch")?;
    let buffer = skip(buffer, "app.fiid")?;
    let (password_protected, buffer) = read_bool(buffer, "app.pwprotect")?;
    let (favourite, buffer) = read_bool(buffer, "app.fav")?;
    let (window_title, buffer) = read_str_item(buffer, "app.wintitle")?;
    let (window_info, buffer) = read_str_item(buffer, "app.wininfo")?;
    let (exe_version, buffer) = read_str_item(buffer, "app.exeversion")?;
    let (autologin, buffer) = read_bool(buffer, "app.autologin")?;
    let (warn_version, buffer) = read_str_item(buffer, "app.warnversion")?;
    let (exe_hash, buffer) = read_str_item(buffer, "app.exehash")?;

    let _ = buffer;

    Ok(App {
        id,
        app_name,
        extra,
        name,
        group,
        last_touch: last_touch.to_string(),
        password_protected,
        favourite,
        window_title: window_title.to_string(),
        window_info: window_info.to_string(),
        exe_version: exe_version.to_string(),
        autologin,
        warn_version: warn_version.to_string(),
        exe_hash: exe_hash.to_string(),
    })
}

pub(crate) fn parse_share(
    buffer: &[u8],
    _private_key: &PrivateKey,
) -> Result<Share, VaultParseError> {
    // let (id, buffer) = read_parsed(buffer, "share.id")?;
    // let (key, buffer) = read_hex(buffer, "share")?;
    //
    // let _ = buffer;

    unimplemented!(
        "TODO: Implement this when I share a password with someone.\n\nBuffer: {:?}",
        buffer,
    )
}

pub(crate) fn parse_attachment(
    buffer: &[u8],
) -> Result<Attachment, VaultParseError> {
    let (id, buffer) = read_parsed(buffer, "attachment.id")?;
    let (parent, buffer) = read_parsed(buffer, "attachment.parent")?;
    let (mime_type, buffer) = read_str_item(buffer, "attachment.mimetype")?;
    let (storage_key, buffer) = read_str_item(buffer, "attachment.storagekey")?;
    let (size, buffer) = read_parsed(buffer, "attachment.size")?;
    let (encrypted_filename, buffer) =
        read_str_item(buffer, "attachment.filename")?;

    let _ = buffer;

    Ok(Attachment {
        id,
        parent,
        mime_type: mime_type.to_string(),
        storage_key: storage_key.to_string(),
        size,
        encrypted_filename: encrypted_filename.to_string(),
    })
}

pub(crate) fn parse_account_field(
    buffer: &[u8],
    decryption_key: &DecryptionKey,
) -> Result<Field, VaultParseError> {
    let (name, buffer) = read_parsed(buffer, "account.field.name")?;
    let (field_type, buffer) = read_str_item(buffer, "account.field.type")?;
    let (value, buffer) = match field_type {
        "email" | "tel" | "text" | "password" | "textarea" => {
            read_encrypted(buffer, "account.field.value", &decryption_key)?
        }
        _ => {
            let (str, buffer) = read_str_item(buffer, "account.field.value")?;
            (str.to_string(), buffer)
        }
    };
    let (checked, _buffer) = read_bool(buffer, "account.field.checked")?;

    Ok(Field {
        field_type: field_type.to_string(),
        name,
        value,
        checked,
    })
}

pub(crate) fn parse_account(
    buffer: &[u8],
    decryption_key: &DecryptionKey,
) -> Result<Account, VaultParseError> {
    let (id, buffer) = read_parsed(buffer, "account.id")?;
    let (name, buffer) =
        read_encrypted(buffer, "account.name", decryption_key)?;
    let (group, buffer) =
        read_encrypted(buffer, "account.group", decryption_key)?;
    let (url, buffer) = read_hex_string(buffer, "account.url")?;
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
        note,
        note_type: note_type.to_string(),
        last_touch: last_touch.to_string(),
        encrypted_attachment_key: attachkey_encrypted.to_string(),
        attachment_present,
        favourite: fav,
        group,
        last_modified: last_modified_gmt.to_string(),
        url: Url::parse(&url).map_err(|e| VaultParseError::BadParse {
            field: "account.url",
            inner: Box::new(e),
        })?,
        attachments: Vec::new(),
        fields: Vec::new(),
    })
}

fn skip<'a>(
    buffer: &'a [u8],
    field: &'static str,
) -> Result<&'a [u8], VaultParseError> {
    let (_, buffer) = read_item(buffer, field)?;

    Ok(buffer)
}

fn read_encrypted<'a>(
    buffer: &'a [u8],
    field: &'static str,
    decryption_key: &DecryptionKey,
) -> Result<(String, &'a [u8]), VaultParseError> {
    let (ciphertext, buffer) = read_item(buffer, field)?;

    let decrypted = decryption_key
        .decrypt(ciphertext)
        .map_err(|e| VaultParseError::UnableToDecrypt { field, inner: e })?;

    let decrypted = String::from_utf8(decrypted).map_err(|e| {
        VaultParseError::BadParse {
            field,
            inner: Box::new(e),
        }
    })?;

    Ok((decrypted, buffer))
}

fn read_bool<'a>(
    buffer: &'a [u8],
    field: &'static str,
) -> Result<(bool, &'a [u8]), VaultParseError> {
    let (raw, buffer) = read_str_item(buffer, field)?;

    Ok((raw == "1", buffer))
}

fn read_parsed<'a, T>(
    buffer: &'a [u8],
    field: &'static str,
) -> Result<(T, &'a [u8]), VaultParseError>
where
    T: FromStr,
    T::Err: Error + Send + Sync + 'static,
{
    let (raw, buffer) = read_str_item(buffer, field)?;

    let parsed = T::from_str(raw).map_err(|e| VaultParseError::BadParse {
        field,
        inner: Box::new(e),
    })?;

    Ok((parsed, buffer))
}

fn read_hex_string<'a>(
    buffer: &'a [u8],
    field: &'static str,
) -> Result<(String, &'a [u8]), VaultParseError> {
    let (hex, buffer) = read_hex(buffer, field)?;
    let value =
        String::from_utf8(hex).map_err(|e| VaultParseError::BadParse {
            field,
            inner: Box::new(e),
        })?;

    Ok((value, buffer))
}

/// Read a hex-encoded string.
fn read_hex<'a>(
    buffer: &'a [u8],
    field: &'static str,
) -> Result<(Vec<u8>, &'a [u8]), VaultParseError> {
    let (raw, buffer) = read_str_item(buffer, field)?;
    let hex = hex::decode(raw).map_err(|e| VaultParseError::BadParse {
        field,
        inner: Box::new(e),
    })?;

    Ok((hex, buffer))
}

/// Read the next item, interpreting it as a UTF-8 string.
fn read_str_item<'a>(
    buffer: &'a [u8],
    field: &'static str,
) -> Result<(&'a str, &'a [u8]), VaultParseError> {
    let (item, buffer) = read_item(buffer, field)?;

    let item =
        std::str::from_utf8(item).map_err(|e| VaultParseError::BadParse {
            field,
            inner: Box::new(e),
        })?;

    Ok((item, buffer))
}

/// Splits a length-prefixed sequence off bytes off the front of a buffer.
fn read_item<'a>(
    buffer: &'a [u8],
    field: &'static str,
) -> Result<(&'a [u8], &'a [u8]), VaultParseError> {
    if buffer.len() < std::mem::size_of::<u32>() {
        return Err(VaultParseError::UnexpectedEOF {
            expected_field: field,
        });
    }

    let (field_length, buffer) = buffer.split_at(std::mem::size_of::<u32>());
    let field_length: usize =
        BigEndian::read_u32(field_length).try_into().unwrap();

    if buffer.len() < field_length {
        return Err(VaultParseError::UnexpectedEOF {
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

    fn name_as_str(&self) -> Cow<'a, str> {
        String::from_utf8_lossy(self.name)
    }

    fn data_as_str(&self) -> Result<&'a str, VaultParseError> {
        std::str::from_utf8(self.data).map_err(|e| {
            VaultParseError::ChunkShouldBeString {
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

    const RAW_KEY_01: &str =
        "08c9bb2d9b48b39efb774e3fef32a38cb0d46c5c6c75f7f9d65259bfd374e120";

    const RAW_KEY_02: &str =
        "5440251a4ca70b772efba80ab4372e973ee00a8a2340f22b48f5efb569565d4b";

    fn keys(raw_key: &str) -> (DecryptionKey, PrivateKey) {
        // this is the decryption key used for the
        // `vault_from_dummy_account.bin` vault. Having it in git isn't
        // really a security concern because that's a dummy account and
        // the password has since been changed.
        let mut buffer = [0; DecryptionKey::LEN];
        hex::decode_to_slice(raw_key, &mut buffer).unwrap();
        let decryption_key = DecryptionKey::from_raw(buffer);

        let private_key = PrivateKey::new(Vec::new());

        (decryption_key, private_key)
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
        let (decryption_key, private_key) = keys(RAW_KEY_01);
        let mut parser = Parser::new();

        parser
            .parse(&buffer, &decryption_key, &private_key)
            .unwrap();

        assert_eq!(parser.vault_version, Some(198));
    }

    #[test]
    fn read_the_dummy_vault_without_fields() {
        let raw = include_bytes!("vault_from_dummy_account.bin");
        let should_be = Vault {
            version: 12,
            local: false,
            accounts: vec![
                Account {
                    id: Id::from("5496230974130180673"),
                    name: String::from("Example password without folder"),
                    group: String::from(r"Some Folder\Nested"),
                    url: Url::parse("https://example.com/").unwrap(),
                    note: String::new(),
                    note_type: String::new(),
                    favourite: false,
                    username: String::from("username"),
                    password: String::from("password"),
                    password_protected: false,
                    encrypted_attachment_key: String::new(),
                    attachment_present: false,
                    last_touch: String::from("1586688785"),
                    last_modified: String::from("1586717585"),
                    attachments: Vec::new(),
                    fields: Vec::new(),
                },
                Account {
                    id: Id::from("8852885818375729232"),
                    name: String::from("Another Password"),
                    group: String::new(),
                    url: Url::parse("https://google.com/").unwrap(),
                    note: String::new(),
                    note_type: String::new(),
                    favourite: false,
                    username: String::from("user"),
                    password: String::from("My Super Secret Password!!1!"),
                    password_protected: false,
                    encrypted_attachment_key: String::new(),
                    attachment_present: false,
                    last_touch: String::from("0"),
                    last_modified: String::from("1586717558"),
                    attachments: Vec::new(),
                    fields: Vec::new(),
                },
                Account {
                    id: Id::from("8994685833508535250"),
                    name: String::new(),
                    group: String::from("Some Folder"),
                    url: Url::parse("http://group").unwrap(),
                    note: String::new(),
                    note_type: String::new(),
                    favourite: false,
                    username: String::new(),
                    password: String::new(),
                    password_protected: false,
                    encrypted_attachment_key: String::new(),
                    attachment_present: false,
                    last_touch: String::from("0"),
                    last_modified: String::from("1586717569"),
                    attachments: Vec::new(),
                    fields: Vec::new(),
                },
                Account {
                    id: Id::from("7483661148987913660"),
                    name: String::new(),
                    group: String::from(r"Some Folder\Nested"),
                    url: Url::parse("http://group").unwrap(),
                    note: String::new(),
                    note_type: String::new(),
                    favourite: false,
                    username: String::new(),
                    password: String::new(),
                    password_protected: false,
                    encrypted_attachment_key: String::new(),
                    attachment_present: false,
                    last_touch: String::from("0"),
                    last_modified: String::from("1586717578"),
                    attachments: Vec::new(),
                    fields: Vec::new(),
                },
                Account {
                    id: Id::from("5211400216940069976"),
                    name: String::from("My Address"),
                    group: String::from("Some Folder"),
                    url: Url::parse("http://sn").unwrap(),
                    note: String::from("NoteType:Address\nLanguage:en-US\nTitle:mr\nFirst Name:Joseph\nMiddle Name:\nLast Name:Bloggs\nUsername:JoeBloggs\nGender:m\nBirthday:October,2,2003\nCompany:Acme Corporation\nAddress 1:address 1\nAddress 2:somewhere else\nAddress 3:hmm\nCity / Town:Springfield\nCounty:\nState:Western Australia\nZip / Postal Code:\nCountry:AU\nTimezone:\nEmail Address:joe.bloggs@gmail.com\nPhone:\nEvening Phone:\nMobile Phone:\nFax:\nNotes:Super secret non-existent address"),
                    note_type: String::from("Address"),
                    favourite: false,
                    username: String::new(),
                    password: String::new(),
                    password_protected: false,
                    encrypted_attachment_key: String::new(),
                    attachment_present: false,
                    last_touch: String::from("0"),
                    last_modified: String::from("1586717700"),
                    attachments: Vec::new(),
                    fields: Vec::new(),
                },
                Account {
                    id: Id::from("533903346832032070"),
                    name: String::from("My Secure Note"),
                    group: String::new(),
                    url: Url::parse("http://sn").unwrap(),
                    note: String::from("This is a super secure note."),
                    note_type: String::from("Generic"),
                    favourite: false,
                    username: String::new(),
                    password: String::new(),
                    password_protected: false,
                    encrypted_attachment_key: String::from("!MOeCidDT4GAmmh8eoMWyRA==|BWdjMSoIvClMRyWrDdIlz38tZiU3O1nmcbg95PRXCT4zKLTTG4s0OD9v/cO2L2pWnAkl4oaVPSIb8OuFhk1KaL77qBbrkAH03lWY/wIModA="),
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
                            encrypted_filename: String::from("!zdLMAcQ9okxR3MFWNjoCaw==|B7NqfcNPX0IayFXNtxkqEw=="),
                        },
                    ],
                    fields: Vec::new(),
                },
            ]
        };
        let (decryption_key, private_key) = keys(RAW_KEY_01);

        let got = parse(raw, &decryption_key, &private_key).unwrap();

        assert_eq!(got, should_be);
    }

    #[test]
    fn read_the_dummy_vault_with_fields() {
        let raw = include_bytes!("vault_from_dummy_account_2.bin");
        let should_be = Vault {
            version: 28,
            local: false,
            accounts: vec![
                Account {
                    id: Id::from("6034748985482010004"),
                    name: String::from("Some password with fields"),
                    group: String::new(),
                    // Lastpass assumes http if no scheme given
                    url: Url::parse("http://example.com").unwrap(),
                    note: String::from("Note here"),
                    note_type: String::new(),
                    favourite: false,
                    username: String::from("test.username"),
                    password: String::from("test.password"),
                    password_protected: false,
                    encrypted_attachment_key: String::new(),
                    attachment_present: false,
                    last_touch: String::from("1627824265"),
                    last_modified: String::from("1627824269"),
                    attachments: Vec::new(),
                    fields: vec![
                        Field {
                            name: String::from("new_field"),
                            field_type: String::from("text"),
                            checked: false,
                            value: String::from("text_new"),
                        },
                        Field {
                            name: String::from("Field1"),
                            field_type: String::from("text"),
                            checked: false,
                            value: String::from("Text Val"),
                        },
                        Field {
                            name: String::from("Field2"),
                            field_type: String::from("text"),
                            checked: false,
                            value: String::new(),
                        },
                        Field {
                            name: String::from("CheckedField"),
                            field_type: String::from("checkbox"),
                            checked: true,
                            value: String::new(),
                        },
                        Field {
                            name: String::from("PSWField"),
                            field_type: String::from("password"),
                            checked: false,
                            value: String::from("Password"),
                        },
                        Field {
                            name: String::from("SelectField"),
                            field_type: String::from("select-one"),
                            checked: false,
                            value: String::from("select1"),
                        },
                        Field {
                            name: String::from("BIG TEXT FIELD"),
                            field_type: String::from("text"),
                            checked: false,
                            value: String::from(
                                "test testtest test tes test set setes ",
                            ),
                        },
                        Field {
                            name: String::from("SelectField1"),
                            field_type: String::from("select-one"),
                            checked: false,
                            value: String::from("select2"),
                        },
                    ],
                },
                Account {
                    id: Id::from("206038515839830177"),
                    name: String::from("Psw After Fields"),
                    group: String::new(),
                    url: Url::parse("https://accounts.google.com/").unwrap(),
                    note: String::new(),
                    note_type: String::new(),
                    favourite: false,
                    username: String::from("uname"),
                    password: String::from("psw"),
                    password_protected: false,
                    encrypted_attachment_key: String::new(),
                    attachment_present: false,
                    last_touch: String::from("1627840045"),
                    last_modified: String::from("1627825645"),
                    attachments: Vec::new(),
                    fields: Vec::new(),
                },
            ],
        };

        let (decryption_key, private_key) = keys(RAW_KEY_02);

        let got = parse(raw, &decryption_key, &private_key).unwrap();

        assert_eq!(got, should_be);
    }
}
