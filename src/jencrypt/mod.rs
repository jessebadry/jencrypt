extern crate readonly;

pub mod encryption_package;
pub mod j_file;
mod password_verification;
use self::password_verification::*;

use encryption_package::*;
use j_file::{make_file, JFile};
use jb_utils::extensions::io::EasyRead;
use std::fs::{remove_file, rename};
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};

//Iterator type for encrypting / decrypting a file
type CipherIterator<'a> = dyn Iterator<Item = io::Result<()>> + 'a;

const _DEBUG_MODE: bool = cfg!(debug_assertions);

use self::JEncryptError::*;
#[derive(Debug)]
pub enum JEncryptError {
    InvalidPassword(VerifyError),
    CouldNotHashUserPassword(scrypt::password_hash::HasherError),
    InvalidFileData(j_file::HeaderParserError),
    InvalidFileDataOther(String),
    IOError(io::Error),
}

impl From<EncryptionPackageError> for JEncryptError {
    fn from(err: EncryptionPackageError) -> Self {
        match err {
            EncryptionPackageError::HasherError(err) => Self::CouldNotHashUserPassword(err),
            EncryptionPackageError::InvalidParameter(err_name, details) => {
                Self::InvalidFileDataOther(format!(
                    "Param name: {}, details:\n {}",
                    err_name, details
                ))
            }
            EncryptionPackageError::IOErr(err) => Self::IOError(err),
        }
    }
}
impl From<io::Error> for JEncryptError {
    fn from(err: io::Error) -> Self {
        Self::IOError(err)
    }
}
/// The main cipher procedure using jencrypt.
///
/// JFile is the encryptor / decryptor.
///
/// # The Algorithm
/// *  Create a temporary file
/// *  Determine the file names for the normal file object and the JFile(encrypt/decryptor) object.
///     * if encrypting, use the user provided file name for the raw file, and a temporary file name for the JFile
///     * if decrypting, use the temporary name for the raw file, and the user-provided name for the JFile
/// *  Determine the input file and output files
///     * if encrypting, input from the raw file to the JFile
///     * if decrypting, initialize decryption on the JFile, then input from JFile and output to the raw file
/// *  Then remove the original file, rename the temporary file to the original file, finishing the encryption/decryption.
fn cipher_file<P: AsRef<Path>>(
    pack: &EncryptionPackage,
    fname: P,
    encrypting: bool,
) -> io::Result<()> {
    let fname = fname.as_ref();
    let mut temp_name = PathBuf::from(fname);
    temp_name.set_extension("tmp");
    let temp_name = temp_name.as_path();
    let reading = !encrypting;

    let (raw_file_name, jfile_name) = if encrypting {
        (fname, temp_name)
    } else {
        (temp_name, fname)
    };
    let normal_file = make_file(raw_file_name, !reading)?;

    let mut jfile = JFile::new(&pack, jfile_name, reading)?;

    if encrypting {
        pipe_io(normal_file, jfile)?;
    } else {
        jfile.initialize_decryption()?;
        pipe_io(jfile, normal_file)?;
    }

    remove_file(fname)?;
    rename(temp_name, fname)?;

    Ok(())
}

/// Write data from `input` to `output`.
///
/// Arguments:
/// * `input`: the file to be read from (expected as either `JFile` or `File`)
/// * `output`: the file to be write to (expected as either `JFile` or `File`)
///
fn pipe_io<T: EasyRead, E: Write>(mut input: T, mut output: E) -> io::Result<()> {
    let mut buf = vec![0; 8000];
    let mut r = 0;
    while input.e_read(&mut buf, &mut r)? > 0 {
        output.write_all(&buf[..r])?;
    }
    Ok(())
}

/// Return an iterator that ciphers each file with the parameters given.
///
/// ---
/// This function serves as the core implementation for ciphering files with JEncrypt.
/// ## Parameters
/// * `pack` - the encryption package which contains the needed data for ciphering.
/// * `fnames` - the file paths for the given files to be ciphered.
///
fn generate_cipher_iterator<'a, P: AsRef<Path>>(
    pack: EncryptionPackage,
    fnames: &'a [P],
    encrypting: bool,
) -> Box<CipherIterator<'a>> {
    Box::new(
        fnames
            .iter()
            .map(move |fname| cipher_file(&pack, fname.as_ref(), encrypting)),
    )
}
pub fn encrypt_files<'a, P: AsRef<Path>>(
    pswd: &str,
    fnames: &'a [P],
) -> Result<Box<CipherIterator<'a>>, JEncryptError> {
    let pack = EncryptionPackage::generate(pswd, None, None, None)?;

    Ok(generate_cipher_iterator(pack, fnames, true))
}
pub fn decrypt_files<'a, P: AsRef<Path>>(
    pswd: &str,
    fnames: &'a [P],
) -> Result<Box<CipherIterator<'a>>, JEncryptError> {
    let (iv, salt, pass_hash) = JFile::parse_header(fnames[0].as_ref()).map_err(InvalidFileData)?;

    verify_password(pswd, &pass_hash).map_err(InvalidPassword)?;

    let pack = EncryptionPackage::generate(pswd, Some(salt), Some(iv), Some(pass_hash))?;

    Ok(generate_cipher_iterator(pack, fnames, false))
}
#[cfg(test)]
mod tests {
    use super::*;

    const _TEST_FILE: &str = "jencrypt_test.txt";
    #[test]
    fn encrypt_files_is_ok_test() {
        let mut test_file = make_file(_TEST_FILE, false).unwrap();
        test_file.write_all(b"test").unwrap();

        assert!(encrypt_files("password123", &[_TEST_FILE]).is_ok());
    }
    #[test]
    fn encrypt_file_iter_works_test() {
        let mut test_file =
            make_file(_TEST_FILE, false).expect("Could not make test file in environment");
        test_file.write_all(b"test").unwrap();

        assert_eq!(
            encrypt_files("password123", &[_TEST_FILE]).unwrap().count(),
            1
        );
    }
}
