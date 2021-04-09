use std::collections::HashMap;
use openssl::rsa::Rsa;
use openssl::pkey::Public;
use byteorder::{WriteBytesExt, LittleEndian, ReadBytesExt};
use std::io;
use std::fs::File;
use std::io::{BufReader, Read, Error};
use crate::utils::{compare_buffers, buffer_to_string, read_null_string};
use log::debug;
use crate::keyblock::ParseErrors::KeyfileParseError;

/// This file will be used to parse and provide a structure to represent a keyblock
///
/// Here is the keyblock format:
/// ```
/// keyblock = magic_number, flags, aes256, metadata, 64_number, { keyfile }, signature, [ crc ]
///
/// keyfile = flags, aes256, null_string, metadata, 64_number, { byte }
/// metadata = uid, null_string, null_string
///
/// aes256 = 256 * bit
/// magic_number = "banjo", 16 * bit
/// signature = 50 * bit
/// crc = 32 * bit
/// uid = "F" | "B", 8 * bit
///
/// null_string = ? ASCII characters ?, "\0"
/// 64_number = 64 * bit
/// flags = 64 * bit
/// byte = 8 * bit
/// bit = (0b0 | 0b1)
/// ```
///
/// Structure content:
///     - keyblock:
///         - magic number "banjo"
///         - 16 bits format specifier
///         - 64 bits feature/setting flags
///         - aes256 block secret, encrypted by the block password (if any) and by the root key
///         - 16 bits UID starting with "B"
///         - Name and description null terminated strings
///         - 64 bits number of keyfiles
///         - List of keyfiles
///         - RSA4096/SHA256 signature of the above content
///         - CRC checksum (if any)
///     - keyfile:
///         - 64 bits feature/setting flags
///         - aes256 key secret, encrypted by the key password (if any) and by the block secret
///         - 16 bits UID starting with "F"
///         - Null terminated key path
///         - Name and description null terminated strings
///         - 64 bits key length
///         - 8 bits aligned key content

/// Magic number starting every keyblock
const MAGIC_NUMBER: &[u8; 5] = b"banjo";
/// Version specifier used by this implementation
const FORMAT_SPECIFIER: u16 = 1;

pub(crate) const SECRET_SIZE: usize = 256;
pub(crate) const SIGNATURE_SIZE: usize = 50;

#[derive(Debug)]
pub struct KeyBlock {
    /// Reference to the root public key
    pub root_pubkey: Rsa<Public>,
    /// Format specifier
    pub format_specifier: u16,
    /// Set of option/setting flags for this block
    pub flags: u64,
    /// AES256 secret
    pub secret: Vec<u8>,
    /// Unique ID of this block
    pub uid: u16,
    /// Name of this block
    pub name: String,
    /// Description of this block
    pub description: String,
    /// Mapping of file locations to the keys inside this block
    pub keys: HashMap<String, KeyFile>,
    /// Block signature
    pub(crate) signature: Vec<u8>
}

#[derive(Debug)]
pub struct KeyFile {
    /// Set of option/setting flags for this key
    pub flags: u64,
    /// AES256 secret
    pub secret: Vec<u8>,
    /// Unique ID of this block
    pub uid: u16,
    /// Path to the key
    pub path: String,
    /// Name of this key
    pub name: String,
    /// Description of this key
    pub description: String,
    /// Length of the key
    pub length: u64,
    /// Encrypted key content
    pub content: Vec<u8>
}

/// Enumeration of the potential errors when parsing keyblocks
#[derive(Debug)]
pub enum ParseErrors {
    /// An error occurred when parsing a keyfile
    KeyfileParseError(u64, Box<ParseErrors>),
    /// An IO error occurred
    IOError(io::Error),
    /// EOL reached when expecting data
    UnexpectedEof,
    /// Magic number doesn't match `MAGIC_NUMBER`
    InvalidMagicNumber,
    /// We don't know how to parse this specifier
    UnknownFormatSpecifier
}

/// Convert IO errors to parse errors
impl From<io::Error> for ParseErrors {
    fn from(error: Error) -> Self {
        match error.kind() {
            io::ErrorKind::UnexpectedEof => ParseErrors::UnexpectedEof,
            _ => ParseErrors::IOError(error)
        }
    }
}

impl KeyBlock {
    /// Load a keyblock from disk and return it
    pub fn load(file: File, root_pubkey: Rsa<Public>) -> Result<KeyBlock, ParseErrors> {
        let mut reader = BufReader::new(file);

        // Check the validity of the magic number
        let mut magic_number_buffer = vec![0; MAGIC_NUMBER.len()];
        if reader.read(&mut magic_number_buffer)? < MAGIC_NUMBER.len() {
            return Err(ParseErrors::InvalidMagicNumber)
        }
        debug!("Magic number: {}", buffer_to_string(&magic_number_buffer));

        if !compare_buffers(&magic_number_buffer, &MAGIC_NUMBER.to_vec()) {
            return Err(ParseErrors::InvalidMagicNumber)
        }

        // Format specifier
        let format_specifier = reader.read_u16::<LittleEndian>()?;
        // Right now if the format specifier isn't `FORMAT_SPECIFIER` we return
        if format_specifier != FORMAT_SPECIFIER { return Err(ParseErrors::UnknownFormatSpecifier) }

        // Flags
        let flags = reader.read_u64::<LittleEndian>()?;

        // AES256 secret
        let mut secret: Vec<u8> = vec![0; SECRET_SIZE / 8];
        reader.read_exact(&mut secret)?;

        // UID
        let uid = reader.read_u16::<LittleEndian>()?;

        // Name and description
        let name = read_null_string(&mut reader);
        let description = read_null_string(&mut reader);

        // Keyfiles
        let keyfile_number = reader.read_u64::<LittleEndian>()?;
        let mut keys :HashMap<String, KeyFile> = HashMap::new();

        for i in 0..keyfile_number {
            debug!("Parsing key {}", i);
            let keyfile = KeyFile::load(&mut reader);

            match keyfile {
                Ok(key) => keys.insert(key.path.clone(), key),
                Err(error) => return Err(KeyfileParseError(i, Box::new(error)))
            };
        }

        // Signature
        let mut signature: Vec<u8> = vec![0; SIGNATURE_SIZE / 8];
        reader.read_exact(&mut signature)?;

        // TODO: Check signature

        Ok(KeyBlock {
            root_pubkey,
            format_specifier,
            flags,
            secret,
            uid,
            name,
            description,
            keys,
            signature
        })
    }

    /// Serialize this keyfile to a vector of bytes
    pub fn serialize(&self) -> Result<Vec<u8>, io::Error> {
        let mut buffer: Vec<u8> = Vec::new();

        // Magic number
        buffer.extend(MAGIC_NUMBER);

        // Version number
        buffer.write_u16::<LittleEndian>(FORMAT_SPECIFIER)?;

        // Flags
        buffer.write_u64::<LittleEndian>(self.flags)?;

        // AES256 secret
        buffer.extend(&self.secret);

        // UID
        buffer.write_u16::<LittleEndian>(self.uid)?;

        // Name and description
        buffer.extend(self.name.as_bytes());
        buffer.write_u8(0)?;
        buffer.extend(self.description.as_bytes());
        buffer.write_u8(0)?;

        // Number of keyfiles
        buffer.write_u64::<LittleEndian>(self.keys.len() as u64)?;

        // Keyfiles
        for keyfiles in self.keys.values() {
            buffer.extend(keyfiles.serialize()?);
        }

        // Signature
        buffer.extend(&self.signature);

        Ok(buffer)
    }
}

impl KeyFile {
    pub fn load(reader: &mut BufReader<File>) -> Result<KeyFile, ParseErrors> {
        // Flags
        let flags = reader.read_u64::<LittleEndian>()?;

        // AES256 secret
        let mut secret: Vec<u8> = vec![0; SECRET_SIZE / 8];
        reader.read_exact(&mut secret)?;

        // UID
        let uid = reader.read_u16::<LittleEndian>()?;

        // Path, name and description
        let path = read_null_string(reader);
        let name = read_null_string(reader);
        let description = read_null_string(reader);

        // Key length
        let length = reader.read_u64::<LittleEndian>()?;

        // Key content
        let mut content = vec![0; (length / 8) as usize];
        reader.read_exact(&mut content)?;

        Ok(KeyFile {
            flags,
            secret,
            uid,
            path,
            name,
            description,
            length,
            content
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, io::Error> {
        let mut buffer: Vec<u8> = Vec::new();

        // Flags
        buffer.write_u64::<LittleEndian>(self.flags)?;

        // AES256 secret
        buffer.extend(&self.secret);

        // UID
        buffer.write_u16::<LittleEndian>(self.uid)?;

        // Key path
        buffer.extend(self.path.as_bytes());
        buffer.write_u8(0)?;

        // Name and description
        buffer.extend(self.name.as_bytes());
        buffer.write_u8(0)?;
        buffer.extend(self.description.as_bytes());
        buffer.write_u8(0)?;

        // Key length
        buffer.write_u64::<LittleEndian>(self.length)?;

        // Key content
        buffer.extend(&self.content);

        Ok(buffer)
    }
}
