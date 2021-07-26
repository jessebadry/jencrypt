use crate::EncryptionPackage;
use aes::Aes128;
use jb_utils::extensions::io::EasyRead;

use crate::io_err;
use ofb::cipher::{NewStreamCipher, SyncStreamCipher};
use ofb::Ofb;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Error, ErrorKind, Read, Seek, SeekFrom, Write};
use std::string::FromUtf8Error;

type AesOfb = Ofb<Aes128>;

const PASSWORD_HASH_SIZE: usize = 88;
const SALT_SIZE: usize = 16;
const IV_SIZE: usize = 16;
const JFILE_HEADER_SIZE: usize = PASSWORD_HASH_SIZE + SALT_SIZE + IV_SIZE;

pub enum ParseError {
    InvalidPasswordHash(&'static str),
    IOError(std::io::Error),
}
impl From<FromUtf8Error> for ParseError {
    fn from(_err: FromUtf8Error) -> Self {
        /*Log Error here */
        ParseError::InvalidPasswordHash("The password hash within the requested file is invalid.")
    }
}
impl From<std::io::Error> for ParseError {
    fn from(err: std::io::Error) -> Self {
        ParseError::IOError(err)
    }
}

fn path_is_file(file_name: &str) -> io::Result<bool> {
    let result = std::fs::metadata(file_name)
        .map_err(|_| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("Provided path, '{}' is not found!", file_name),
            )
        })?
        .is_file();
    Ok(result)
}

pub fn make_file(filename: &str, reading: bool) -> io::Result<File> {
    if reading && !path_is_file(filename)? {
        return Err(io_err!(format!("The file '{}' does not exist!", filename)));
    }
    let writing = !reading;
    let file = OpenOptions::new()
        .read(reading)
        .write(writing)
        .create(writing)
        .append(true)
        .open(filename)?;
    Ok(file)
}

///Wrapper around  the seek function, simply converts the pos to the Seek equivalent value
/// and uses it to seek to that position in bytes
/// ->
/// Seek to an offset, in bytes, in a stream.
///
/// A seek beyond the end of a stream is allowed, but behavior is defined
/// by the implementation.
///
/// If the seek operation completed successfully,
/// this method returns the new position from the start of the stream.
/// That position can be used later with [`SeekFrom::Start`].
///
/// # Errors
///
/// Seeking to a negative offset is considered an error.
///
/// [`SeekFrom::Start`]: enum.SeekFrom.html#variant.Start
fn seek_to<T: Seek>(io_obj: &mut T, pos: u64) -> io::Result<u64> {
    io_obj.seek(SeekFrom::Start(pos))
}

pub struct JFile {
    crypter: AesOfb,
    file: File,
    ciphering: bool,
    started_encryption: bool,
    iv: Vec<u8>,
    key_salt: Vec<u8>,
}

impl JFile {
    pub fn new(package: &EncryptionPackage, fname: &str, read: bool) -> io::Result<Self> {
        let file = make_file(fname, read)?;

        let crypter =
            AesOfb::new_var(&package.key, &package.iv).map_err(|e| io_err!(e.to_string()))?;

        Ok(JFile {
            crypter,
            file,
            started_encryption: false,
            iv: package.iv.clone(),
            key_salt: package.key_salt.clone(),
            ciphering: true,
        })
    }

    ///
    pub fn initialize_decryption(&mut self) -> io::Result<&mut Self> {
        seek_to(&mut self.file, JFILE_HEADER_SIZE as u64)?;

        Ok(self)
    }

    ///Returns header-data from J-Encrypted file.
    pub fn parse_header(fname: &str) -> Result<(Vec<u8>, Vec<u8>, String), ParseError> {
        let mut file = make_file(fname, true)?;

        let pass_hash = String::from_utf8(file.read_inplace(PASSWORD_HASH_SIZE)?)?;
        let iv = file.read_inplace(IV_SIZE)?;
        let key_salt = file.read_inplace(SALT_SIZE)?;

        Ok((iv, key_salt, pass_hash))
    }
    pub fn raw_write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.file.write_all(buf)?;
        Ok(())
    }
    pub fn is_applying_cipher(&mut self, ciphering: bool) {
        self.ciphering = ciphering;
    }
    fn apply_keystream(&mut self, buf: &mut [u8]) {
        if self.ciphering {
            self.crypter.apply_keystream(buf);
        }
    }
    /// Initialize JFile with header data, (iv and salt), 32 bytes.
    /// Writes data to beginning of file.
    fn init_write(&mut self) -> io::Result<()> {
        if !self.started_encryption {
            self.file.write_all(&self.iv)?;
            self.file.write_all(&self.key_salt)?;
            self.started_encryption = true;
        }
        Ok(())
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
        self.init_write()?;

        let mut dat = buf.to_vec();
        self.apply_keystream(&mut dat);

        Ok(self.file.write(&dat)?)
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.init_write()?;
        let mut dat = buf.to_owned();
        self.apply_keystream(&mut dat);

        self.file.write_all(&dat)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()?;
        Ok(())
    }
}
