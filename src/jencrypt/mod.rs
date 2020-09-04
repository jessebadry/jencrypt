extern crate readonly;

pub mod j_file;
use crate::io_err;
use j_file::JFile;
use jb_utils::extensions::io::EasyRead;
use rand::rngs::OsRng;
use rand::RngCore;
use scrypt::{scrypt, ScryptParams};
use std::error;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::Write;

type Result<T, E = Box<dyn error::Error>> = std::result::Result<T, E>;
#[readonly::make]
pub struct EncryptionPackage {
    pub key: Vec<u8>,
    pub key_salt: Vec<u8>,
    pub iv: Vec<u8>,
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
    let salt = salt.unwrap_or(make_random_16b()?);
    let iv = iv.unwrap_or(make_random_16b()?);

    if salt.len() != 16 || iv.len() != 16 {
        return Err(io_err!("salt and iv must be 16 bytes long!"));
    }

    let mut password_cipher = vec![0; 16];
    let params = ScryptParams::new(14, 8, 1).unwrap();
    println!("running scrypt");
    scrypt(pass_str.as_bytes(), &salt, &params, &mut password_cipher)
        .map_err(|e| io_err!(e.to_string()))?;
    Ok(EncryptionPackage {
        key: password_cipher,
        iv: iv,
        key_salt: salt,
    })
}
fn make_random_16b() -> io::Result<Vec<u8>> {
    let mut salt = vec![0; 16];
    fill_random_secure(&mut salt)?;
    Ok(salt)
}
pub fn encrypt_file(pswd: &str, fname: &str) -> io::Result<()> {
    let pack = create_encryption_package(pswd, None, None)?;
    cipher_file(&pack, fname, true)
}

fn cipher_file(pack: &EncryptionPackage, fname: &str, encrypting: bool) -> io::Result<()> {
    let temp_name = format!("{}.temp", fname);
    let temp_name = temp_name.as_str();
    let reading = !encrypting;
    let (file_name, jfile_name) = if encrypting {
        (fname, temp_name)
    } else {
        (temp_name, fname)
    };
    let normal_file = OpenOptions::new()
        .create(reading)
        .read(encrypting)
        .write(!encrypting)
        .open(file_name)?;
    let mut jfile = JFile::new(&pack, jfile_name, reading)?;
    jfile.is_decrypting(reading)?;

    if encrypting {
        impl_cipher(normal_file, jfile)?;
    } else {
        impl_cipher(jfile, normal_file)?;
    }
    std::fs::remove_file(fname)?;
    std::fs::rename(temp_name, fname)?;
    Ok(())
}
fn impl_cipher<T: EasyRead, E: Write>(mut input: T, mut output: E) -> io::Result<()> {
    let mut buf = vec![0; 8000];
    let mut r = 0;
    while input.e_read(&mut buf, &mut r).unwrap_or(0) > 0 {
        output.write_all(&mut buf[..r])?;
    }
    Ok(())
}

pub fn decrypt_file(pswd: &str, fname: &str) -> io::Result<()> {
    let (iv, salt) = JFile::get_iv_and_salt_from_file(fname)?;
    let pack = create_encryption_package(pswd, Some(salt), Some(iv))?;
    cipher_file(&pack, fname, false)
}
