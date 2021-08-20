extern crate readonly;

pub mod encryption_package;
pub mod jfile;
mod password_verification;
use self::password_verification::*;
use encryption_package::*;
use jb_utils::extensions::io::EasyRead;
use jfile::{make_file, JFile};
use std::fs::{remove_file, rename};
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};

//Iterator type for encrypting / decrypting a file
type CipherIterator<'a> = dyn Iterator<Item = io::Result<()>> + 'a;
use self::JEncryptError::*;
#[derive(Debug)]
pub enum JEncryptError {
    InvalidPassword(VerifyError),
    CouldNotHashUserPassword(scrypt::password_hash::HasherError),
    InvalidFileData(jfile::HeaderParserError),
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

fn clean_up_temp(fname: &Path, temp_name: &Path) -> io::Result<()> {
    remove_file(fname)?;
    rename(temp_name, fname)?;

    Ok(())
}

/// The main cipher procedure using jencrypt.
///
/// JFile is the encryptor / decryptor.
///
/// # The Algorithm
/// *  Create a temporary file
/// *  Determine the input and output files for the ciphering algorithm.
///     * if encrypting, input is a `File` and output is a `JFile`
///     * if decrypting, input is a `JFile` and output is a `File`
/// *  Then remove the original file, rename the temporary file to the original file, finishing the encryption/decryption.
fn cipher_file<P: AsRef<Path>>(
    pack: &EncryptionPackage,
    fname: P,
    encrypting: bool,
) -> io::Result<()> {
    // Create temp file name
    let fname = PathBuf::from(fname.as_ref());
    let mut temp_name = fname.clone();
    temp_name.set_extension("tmp");


    // Determine which type of file is a temp file
    // if encrypting, the jfile is written to then renamed back to the original name
    // if decrypting, the standard file is written to from the jfile then renamed back to the original name
    let (file_name, jfile_name) = if encrypting {
        (&fname, &temp_name)
    } else {
        (&temp_name, &fname)
    };

    let reading = !encrypting;

    // Read from normal file if encrypting
    let mut normal_file = make_file(&file_name, encrypting)?;

    // Read if we are NOT encrypting (decrypting).
    let mut jfile = JFile::new(pack, &jfile_name, reading)?;

    let pip_io_result = if encrypting {
        jfile
            .initialize_encryption()
            .and(pipe_io(&mut normal_file, &mut jfile))
    } else {
        jfile
            .initialize_decryption()
            .and(pipe_io(&mut jfile, &mut normal_file))
    };

    pip_io_result.and(clean_up_temp(&fname, &temp_name))
}

/// Write data from `input` to `output`.
///
/// Arguments:
/// * `input`: the file to be read from (expected as either `JFile` or `File`)
/// * `output`: the file to be write to (expected as either `JFile` or `File`)
///
fn pipe_io<I: EasyRead, O: Write>(input: &mut I, output: &mut O) -> io::Result<()> {
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
    let (iv, salt, pass_hash) = jfile::parse_header(fnames[0].as_ref()).map_err(InvalidFileData)?;

    verify_password(pswd, &pass_hash).map_err(InvalidPassword)?;

    let pack = EncryptionPackage::generate(pswd, Some(salt), Some(iv), Some(pass_hash))?;

    Ok(generate_cipher_iterator(pack, fnames, false))
}
