extern crate readonly;

pub mod encryption_package;
pub mod j_file;
mod password_verification;

use self::password_verification::VerifyError::*;
use self::password_verification::*;

use encryption_package::*;
use j_file::{make_file, JFile};
use jb_utils::extensions::io::EasyRead;
use std::fs::{remove_file, rename};
use std::io;
use std::io::Write;

/// The main cipher procedure using JFile.
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
fn cipher_file(pack: &EncryptionPackage, fname: &str, encrypting: bool) -> io::Result<()> {
    let temp_name = format!("{}.temp", fname);
    let temp_name = temp_name.as_str();
    let reading = !encrypting;

    let (raw_file_name, jfile_name) = if encrypting {
        (fname, temp_name)
    } else {
        (temp_name, fname)
    };
    let normal_file = make_file(raw_file_name, !reading)?;

    let mut jfile = JFile::new(&pack, jfile_name, reading)?;

    if encrypting {
        impl_cipher(normal_file, jfile)?;
    } else {
        jfile.initialize_decryption()?;
        impl_cipher(jfile, normal_file)?;
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
fn impl_cipher<T: EasyRead, E: Write>(mut input: T, mut output: E) -> io::Result<()> {
    let mut buf = vec![0; 8000];
    let mut r = 0;
    while input.e_read(&mut buf, &mut r).unwrap_or(0) > 0 {
        output.write_all(&buf[..r])?;
    }
    Ok(())
}

pub fn encrypt_files(pswd: &str, fnames: &Vec<impl AsRef<str>>) -> io::Result<()> {
    let pack = EncryptionPackage::generate(pswd, None, None, None)?;
    for fname in fnames {
        if let Err(e) = cipher_file(&pack, fname.as_ref(), true) {
            println!("Error encrypting '{}', why: {}", fname.as_ref(), e);
        }
    }
    Ok(())
}
pub fn decrypt_files(pswd: &str, fnames: &Vec<impl AsRef<str>>) -> io::Result<()> {
    let (iv, salt, pass_hash) = JFile::parse_header(fnames[0].as_ref())?;
    verify_password(pswd, &pass_hash).unwrap_or_else(handle_verification_error);

    let pack = EncryptionPackage::generate(pswd, Some(salt), Some(iv), Some(pass_hash))?;

    for fname in fnames {
        if let Err(e) = cipher_file(&pack, fname.as_ref(), false) {
            println!("Error decrypting '{}', why: {}", fname.as_ref(), e);
        }
    }
    Ok(())
}

/// Prints a corresponding user message then aborts the application.
///
/// * Aborts(-1) on end of execution
fn handle_verification_error(err: VerifyError) {
    println!(
        "{}",
        match err {
            IncorrectHash(_err) => {
                /*Log error here */
                "Password hash is corrupt or missing from filename."
            }
            InvalidPassword(_err) => {
                /*Log error here */
                "The password you entered was incorrect!"
            }
        }
    );

    std::process::exit(-1);
}
