use crate::EncryptionPackage;
use aes::Aes128;
use jb_utils::extensions::io::EasyRead;

use crate::io_err;
use jencrypt::create_encryption_package;
use ofb::stream_cipher::{NewStreamCipher, SyncStreamCipher};
use ofb::Ofb;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Error, ErrorKind, Read, Seek, SeekFrom, Write};

type AesOfb = Ofb<Aes128>;

static JFILE_HEADER_SIZE: u64 = 32;

fn is_file(file_name: &str) -> bool {
    std::fs::metadata(file_name)
        .map_err(|_| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("Provided path, '{}' is not found!", file_name),
            )
        })
        .and_then(|meta| {
            if !meta.is_file() {
                Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Must provide a file to encrypt!",
                ))
            } else {
                Ok(())
            }
        })
        .is_ok()
}

fn file(filename: &str, reading: bool) -> io::Result<File> {
    if reading && !is_file(filename) {
        return Err(io_err!(format!("The file '{}' does not exist!", filename)));
    }
    let writing = !reading;
    let file = OpenOptions::new()
        .read(reading)
        .write(writing)
        .create(writing)
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
        let file = file(fname, read)?;

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

    pub fn is_decrypting(&mut self, is_decrypting: bool) -> io::Result<&mut Self> {
        if is_decrypting {
            println!("seeking to {}", JFILE_HEADER_SIZE);
            seek_to(&mut self.file, JFILE_HEADER_SIZE)?;
        }
        Ok(self)
    }
    //returns (iv:Vec<u8>, salt:Vec<u8>)
    pub fn get_iv_and_salt<T: Read>(file: &mut T) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let iv = file.read_inplace(16).map_err(|e| io_err!(e.to_string()))?;
        let key_salt = file.read_inplace(16).map_err(|e| io_err!(e.to_string()))?;
        Ok((iv, key_salt))
    }

    ///Returns header from J-Encrypted file.
    ///`get_iv_and_salt_from_file` returns an tuple `(iv:Vec<u8>, key_salt:Vec<u8>)`
    pub fn get_iv_and_salt_from_file(fname: &str) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let mut file = file(fname, true)?;
        let iv = file.read_inplace(16).map_err(|e| io_err!(e.to_string()))?;
        let key_salt = file.read_inplace(16).map_err(|e| io_err!(e.to_string()))?;
        Ok((iv, key_salt))
    }
    pub fn raw_write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.file.write_all(buf)?;
        Ok(())
    }
    pub fn is_applying_cipher(&mut self, ciphering: bool) {
        self.ciphering = ciphering;
    }
    fn apply_keystream(&mut self, buf: &mut [u8]) -> io::Result<()> {
        if self.ciphering {
            self.crypter.apply_keystream(buf);
        }
        Ok(())
    }
    fn init_write(&mut self) -> io::Result<()> {
        if !self.started_encryption {
            println!("Writing iv and salt.");
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
        self.apply_keystream(&mut buf[..rb])?;

        Ok(rb)
    }
}
impl Write for JFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.init_write()?;

        let mut dat = buf.to_vec();
        self.apply_keystream(&mut dat)?;

        Ok(self.file.write(&dat)?)
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.init_write()?;
        let mut data = buf.to_vec();
        self.apply_keystream(&mut data)?;
        self.file.write_all(&data)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()?;
        Ok(())
    }
}
