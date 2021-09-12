use crate::encryption_package::EncryptionPackage;
use crate::io_err;
use aes::Aes128;
use jb_utils::extensions::io::EasyRead;
use ofb::cipher::{NewStreamCipher, SyncStreamCipher};
use ofb::Ofb;
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::Path;

use std::fmt;
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

fn is_file<P: ?Sized + AsRef<Path>>(fname: &P) -> io::Result<()> {
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
/// Write all data from `input` to `output`.
///
/// Arguments:
/// * `input`: the read object
/// * `output`: the write object
///
fn pipe_io<I: EasyRead, O: Write>(input: &mut I, output: &mut O) -> io::Result<()> {
    let mut buf = vec![0; 8000];
    let mut r = 0;
    while input.e_read(&mut buf, &mut r)? > 0 {
        output.write_all(&buf[..r])?;
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
        is_file(fname)?;
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

pub struct JCrypter<F: Read + Write + Seek> {
    crypter: AesOfb,
    pub inner: F,
    initialized: bool,
    iv: Vec<u8>,
    key_salt: Vec<u8>,
    password_hash: String,
}

/// Determines if the reader contains the encryption header.
/// # WARNING
/// this method doesn't validate the salt and iv, it only promises to ensure
/// the header returns false  if the first 16 bytes are not utf8
/// and if the first 7 bytes wasn't tampered with.
pub fn contains_header<P: Read>(reader: &mut P) -> io::Result<bool> {
    let header = String::from_utf8(reader.read_inplace(VALIDATION_LENGTH)?);
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
pub fn parse_header(reader: &mut impl EasyRead) -> Result<HeaderData, HeaderParserError> {
    let pass_hash = String::from_utf8(reader.read_inplace(PASSWORD_HASH_SIZE)?)?;
    let iv = reader.read_inplace(IV_SIZE)?;
    let key_salt = reader.read_inplace(SALT_SIZE)?;

    Ok((iv, key_salt, pass_hash))
}
impl<F: Read + Write + Seek> JCrypter<F> {
    pub fn new(package: &EncryptionPackage, inner: F) -> io::Result<Self> {
        let crypter =
            AesOfb::new_var(&package.key, &package.iv).map_err(|e| io_err!(e.to_string()))?;

        Ok(JCrypter {
            crypter,
            inner,
            initialized: false,

            iv: package.iv.clone(),
            key_salt: package.key_salt.clone(),
            password_hash: package.password_hash.clone(),
        })
    }

    ///
    pub fn initialize_encryption(&mut self, to: &mut (impl Read + Write + Seek)) -> io::Result<()> {
        self.initialized = true;
        self.write_header_data(to)
    }
    pub fn initialize_decryption(&mut self) -> io::Result<()> {
        self.initialized = true;
        self.inner.seek(SeekFrom::Start(JFILE_HEADER_SIZE as u64))?;
        Ok(())
    }
    pub fn raw_write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.inner.write_all(buf)?;
        Ok(())
    }

    fn apply_keystream(&mut self, buf: &mut [u8]) {
        self.crypter.apply_keystream(buf);
    }

    /// Initialize JFile with header data, (iv and salt), 32 bytes if not already initialized.
    /// Writes data to beginning of file.
    fn write_header_data(&mut self, output: &mut (impl Read + Write + Seek)) -> io::Result<()> {
        output.write_all(self.password_hash.as_bytes())?;
        output.write_all(&self.iv)?;
        output.write_all(&self.key_salt)?;

        Ok(())
    }

    pub fn encrypt_to(&mut self, to: &mut (impl Write + Read + Seek)) -> io::Result<()> {
        self.initialize_encryption(to)?;

        pipe_io(self, to)
    }
    pub fn decrypt_to(&mut self, to: &mut (impl Write + Read + Seek)) -> io::Result<()> {
        self.initialize_decryption()?;

        pipe_io(self, to)
    }
}
impl<F: Read + Write + Seek> Read for JCrypter<F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let rb = self.inner.read(buf)?;
        self.apply_keystream(&mut buf[..rb]);

        Ok(rb)
    }
}
impl<F: Read + Write + Seek> Write for JCrypter<F> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut dat = buf.to_vec();
        self.apply_keystream(&mut dat);

        self.inner.write(&dat)
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        let mut dat = buf.to_owned();
        self.apply_keystream(&mut dat);

        self.inner.write_all(&dat)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jb_utils::structs::MemoryStream;
    const ENCRYPTED_DATA: &[u8] = &[
        36, 115, 99, 114, 121, 112, 116, 36, 108, 110, 61, 49, 53, 44, 114, 61, 56, 44, 112, 61,
        49, 36, 47, 115, 113, 103, 70, 49, 71, 101, 81, 70, 80, 111, 75, 74, 97, 82, 67, 80, 101,
        106, 52, 119, 36, 113, 121, 113, 104, 51, 84, 110, 74, 77, 57, 47, 47, 114, 70, 78, 104,
        103, 110, 87, 104, 88, 83, 117, 100, 69, 86, 102, 85, 104, 79, 112, 119, 111, 76, 102, 86,
        65, 119, 112, 75, 78, 75, 115, 82, 67, 135, 62, 228, 193, 124, 115, 56, 208, 209, 176, 83,
        95, 233, 0, 152, 100, 84, 196, 94, 55, 194, 90, 117, 243, 131, 55, 81, 27, 246, 248, 74,
        147, 253, 41, 76, 242, 99, 214, 78,
    ];
    const TEST_PASSWORD: &str = "Password123";
    const UNENCRYPTED_DATA: &[u8] = b"test 1234";

    #[test]
    fn jfile_encrypt() {
        let package = EncryptionPackage::generate(TEST_PASSWORD, None, None, None).unwrap();

        let test_stream = MemoryStream::new(UNENCRYPTED_DATA.to_vec().clone());
        let mut encrypter = JCrypter::new(&package, test_stream).unwrap();

        let mut output_test_stream = MemoryStream::default();

        encrypter
            .encrypt_to(&mut output_test_stream)
            .expect("Encrypt to failed");

        output_test_stream.seek(SeekFrom::Start(0)).unwrap();
        let encrypted_data = output_test_stream.data();

        // Validate if encrypted
        let (iv, salt, pass_hash) = parse_header(&mut output_test_stream).unwrap();

        assert_eq!(iv, package.iv);
        assert_eq!(salt, package.key_salt);
        assert_eq!(pass_hash, package.password_hash);
        assert!(&encrypted_data[JFILE_HEADER_SIZE..] != UNENCRYPTED_DATA);
    }
    #[test]
    fn jfile_decrypt() {
        let mut encrypted_data = MemoryStream::new(ENCRYPTED_DATA.to_vec());
        let package = EncryptionPackage::from_header(TEST_PASSWORD, &mut encrypted_data)
            .expect("failed to create encryption package");

        let mut test_output = MemoryStream::default();
        encrypted_data.seek(SeekFrom::Start(0));
        println!("{:?}", encrypted_data);
        let mut jcrypter =
            JCrypter::new(&package, encrypted_data).expect("Failed to create jcrypter");

        jcrypter
            .decrypt_to(&mut test_output)
            .expect("decrypt to failed");
        
        assert_eq!(test_output.data(), UNENCRYPTED_DATA);
    }
    #[test]
    fn test_encryption_package_from_header() {
        let mut test_file = MemoryStream::new(ENCRYPTED_DATA.to_vec());
        let package = EncryptionPackage::from_header(TEST_PASSWORD, &mut test_file);

        assert!(package.is_ok());
    }
}
