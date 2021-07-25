extern crate readonly;

pub mod j_file;
mod password_verification;

use self::password_verification::VerifyError::*;
use self::password_verification::*;
use crate::io_err;

use j_file::{make_file, JFile};
use jb_utils::extensions::io::EasyRead;
use rand::rngs::OsRng;
use rand::RngCore;
use scrypt::{scrypt, Params};
use std::fs::{remove_file, rename};
use std::io;
use std::io::Write;
use std::ptr::hash;

#[readonly::make]
pub struct EncryptionPackage {
    pub key: Vec<u8>,
    pub key_salt: Vec<u8>,
    pub iv: Vec<u8>,
    pub password_hash: String,
}

fn fill_random_secure(data: &mut [u8]) -> io::Result<()> {
    let mut r = OsRng::default();
    r.try_fill_bytes(data).map_err(|e| io_err!(e.to_string()))?;
    Ok(())
}

// fn secure_r_num() -> Result<u64> {
//     let mut r = OsRng::default();
//     Ok(r.next_u64())
// }

pub fn create_encryption_package(
    pass_str: &str,
    salt: Option<Vec<u8>>,
    iv: Option<Vec<u8>>,
) -> io::Result<EncryptionPackage> {

    if salt.as_ref().map(|salt| salt.len() != 16).unwrap_or(false)
        || iv.as_ref().map(|iv| iv.len() != 16).unwrap_or(false)
    {
        return Err(io_err!("salt or iv was not 16 bytes long!"));
    }

    let key_salt = salt.unwrap_or(make_random_16b()?);
    let iv = iv.unwrap_or(make_random_16b()?);

    let mut key = vec![0; 16];
    let params = Params::new(14, 8, 1).unwrap();
    scrypt(pass_str.as_bytes(), &key_salt, &params, &mut key)
        .map_err(|e| io_err!(e.to_string()))?;
        
    Ok(EncryptionPackage {
        key,
        iv,
        key_salt,

        password_hash: hash_password(pass_str)
            .map_err(|e| io_err!(e.to_string()))?
            .to_string(),
    })
}
fn make_random_16b() -> io::Result<Vec<u8>> {
    let mut salt = vec![0; 16];
    fill_random_secure(&mut salt)?;
    Ok(salt)
}

pub fn encrypt_file_p(encryption_pack: &EncryptionPackage, fname: &str) -> io::Result<()> {
    cipher_file(encryption_pack, fname, true)
}
pub fn decrypt_file_p(encryption_pack: &EncryptionPackage, fname: &str) -> io::Result<()> {
    cipher_file(encryption_pack, fname, false)
}
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

    // Do setup for decryption method if we are reading, reading in our case means decrypting.
    jfile.decryption_mode(reading)?;

    if encrypting {
        impl_cipher(normal_file, jfile)?;
    } else {
        impl_cipher(jfile, normal_file)?;
    }
    remove_file(fname)?;
    rename(temp_name, fname)?;

    Ok(())
}
/// Write data of `input` to `output`.
///
/// Arguments:
/// * `input`: the file to be read from (expected as either `JFile`, or `File`)
///
fn impl_cipher<T: EasyRead, E: Write>(mut input: T, mut output: E) -> io::Result<()> {
    let mut buf = vec![0; 8000];
    let mut r = 0;
    while input.e_read(&mut buf, &mut r).unwrap_or(0) > 0 {
        output.write(&mut buf[..r])?;
    }
    Ok(())
}
pub fn encrypt_file(pswd: &str, fname: &str) -> io::Result<()> {
    let pack = create_encryption_package(pswd, None, None)?;
    cipher_file(&pack, fname, true)
}
pub fn decrypt_file(pswd: &str, fname: &str) -> io::Result<()> {
    if let Err(e) = verify_password(pswd, "") {
        println!(
            "{}",
            match e {
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
    }
    let (iv, salt) = JFile::get_iv_and_salt_from_file(fname)?;
    let pack = create_encryption_package(pswd, Some(salt), Some(iv))?;
    cipher_file(&pack, fname, false)
}
