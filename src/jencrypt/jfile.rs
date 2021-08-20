use crate::encryption_package::EncryptionPackage;
use crate::io_err;
use aes::Aes128;
use jb_utils::extensions::io::EasyRead;
use ofb::cipher::{NewStreamCipher, SyncStreamCipher};
use ofb::Ofb;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::string::FromUtf8Error;

type HeaderData = (Vec<u8>, Vec<u8>, String);
type AesOfb = Ofb<Aes128>;

pub const PASSWORD_HASH_SIZE: usize = 88;
pub const SALT_SIZE: usize = 16;
pub const IV_SIZE: usize = 16;
pub const JFILE_HEADER_SIZE: usize = PASSWORD_HASH_SIZE + SALT_SIZE + IV_SIZE;
/// used to validate the string `"$scrypt"` within a encrypted file header.
const VALIDATION_LENGTH: usize = 7;
#[derive(Debug)]
pub enum HeaderParserError {
    InvalidPasswordHash(&'static str),
    IOError(std::io::Error),
}
impl fmt::Display for HeaderParserError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "1")
    }
}
impl std::error::Error for HeaderParserError {}

impl From<HeaderParserError> for std::io::Error {
    fn from(error: HeaderParserError) -> Self {
        match error {
            HeaderParserError::InvalidPasswordHash(err) => io_err!(err),
            HeaderParserError::IOError(err) => err,
        }
    }
}
impl From<std::io::Error> for HeaderParserError {
    fn from(error: std::io::Error) -> Self {
        Self::IOError(error)
    }
}
impl From<FromUtf8Error> for HeaderParserError {
    fn from(_err: FromUtf8Error) -> Self {
        /*Log Error here */
        HeaderParserError::InvalidPasswordHash(
            "The password hash within the requested file is invalid.",
        )
    }
}

fn check_if_file_exists<P: ?Sized + AsRef<Path>>(fname: &P) -> io::Result<()> {
    let is_file = std::fs::metadata(&fname)?.is_file();

    if !is_file {
        return Err(io_err!(
            ErrorKind::NotFound,
            format!(
                "The file '{}' does not exist!",
                fname.as_ref().to_str().unwrap()
            )
        ));
    }

    Ok(())
}
/// Makes an append-based file.
///
/// # Errors
/// * if `filename` is not a file in the file-system
/// * Any other IO error
pub fn make_file<P: ?Sized + AsRef<Path>>(fname: &P, reading: bool) -> io::Result<File> {
    if reading {
        check_if_file_exists(fname)?;
    }
    let writing = !reading;
    let file = OpenOptions::new()
        .read(reading)
        .write(writing)
        .create(writing)
        .append(true)
        .open(fname)?;
    Ok(file)
}

pub struct JFile {
    crypter: AesOfb,
    pub file: File,
    initialized: bool,
    iv: Vec<u8>,
    key_salt: Vec<u8>,
    password_hash: String,
}

/// Determines if the file contains the encryption header.
/// # WARNING
/// this method doesn't validate the salt and iv, it only promises to ensure
/// the header returns false  if the first 16 bytes are not utf8
/// and if the first 7 bytes wasn't tampered with.
pub fn file_contains_header<P: ?Sized + AsRef<Path>>(fname: &P) -> io::Result<bool> {
    let mut file = make_file(fname.as_ref(), true)?;

    let header = String::from_utf8(file.read_inplace(VALIDATION_LENGTH)?);
    Ok(header
        .map(|string| string.starts_with("$scrypt"))
        .unwrap_or(false))
}
/// Returns header-data from J-Encrypted file.
/// ## Header Requirements
///
/// * 16-bit IV
/// * 16-bit Salt
/// * 88 character hashed password
pub fn parse_header<P: ?Sized + AsRef<Path>>(fname: &P) -> Result<HeaderData, HeaderParserError> {
    let mut file = make_file(fname, true)?;

    let pass_hash = String::from_utf8(file.read_inplace(PASSWORD_HASH_SIZE)?)?;
    let iv = file.read_inplace(IV_SIZE)?;
    let key_salt = file.read_inplace(SALT_SIZE)?;

    Ok((iv, key_salt, pass_hash))
}
impl JFile {
    pub fn new(
        package: &EncryptionPackage,
        fname: impl AsRef<Path>,
        read: bool,
    ) -> io::Result<Self> {
        let crypter =
            AesOfb::new_var(&package.key, &package.iv).map_err(|e| io_err!(e.to_string()))?;

        Ok(JFile {
            crypter,
            file: make_file(fname.as_ref(), read)?,
            initialized: false,

            iv: package.iv.clone(),
            key_salt: package.key_salt.clone(),
            password_hash: package.password_hash.clone(),
        })
    }

    ///
    pub fn initialize_encryption(&mut self) -> io::Result<()> {
        self.initialized = true;
        self.write_header_data()
    }
    pub fn initialize_decryption(&mut self) -> io::Result<()> {
        self.initialized = true;
        self.file.seek(SeekFrom::Start(JFILE_HEADER_SIZE as u64))?;
        Ok(())
    }
    pub fn raw_write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.file.write_all(buf)?;
        Ok(())
    }

    fn apply_keystream(&mut self, buf: &mut [u8]) {
        self.crypter.apply_keystream(buf);
    }

    /// Initialize JFile with header data, (iv and salt), 32 bytes if not already initialized.
    /// Writes data to beginning of file.
    fn write_header_data(&mut self) -> io::Result<()> {
        if self.initialized {
            return Err(io_err!("Already wrote header!"));
        } else {
            self.initialized = true;
        }

        self.file.write_all(self.password_hash.as_bytes())?;
        self.file.write_all(&self.iv)?;
        self.file.write_all(&self.key_salt)?;

        Ok(())
    }

    fn make_temp_file(&self) {
        unimplemented!()
    }
    fn encrypt_as_file(&self) {
        unimplemented!()
    }

    fn clean_up_crypt() {
        unimplemented!()
    }

    pub fn encrypt(&mut self, to: impl Write) {
        unimplemented!()
    }
    pub fn decrypt(&mut self) {
        unimplemented!()
    }
}
impl Read for JFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let rb = self.file.read(buf)?;
        self.apply_keystream(&mut buf[..rb]);

        Ok(rb)
    }
}
impl Write for JFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut dat = buf.to_vec();
        self.apply_keystream(&mut dat);

        self.file.write(&dat)
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        let mut dat = buf.to_owned();
        self.apply_keystream(&mut dat);

        self.file.write_all(&dat)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn jfile_encrypt() {
        let package = EncryptionPackage::generate("Password123", None, None, None).unwrap();

        let mut jfile = JFile::new(&package, "test.txt", true).unwrap();

        //jfile.encrypt();
    }
}
