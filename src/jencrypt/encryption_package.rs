use crate::io_err;
use j_file::{ParseError, IV_SIZE, PASSWORD_HASH_SIZE, SALT_SIZE};
use jencrypt::password_verification::hash_password;
use rand::rngs::OsRng;
use rand::RngCore;
use scrypt::{scrypt, Params};
use std::io;

impl From<ParseError> for std::io::Error {
    fn from(error: ParseError) -> Self {
        match error {
            ParseError::InvalidPasswordHash(err) => io_err!(err),
            ParseError::IOError(err) => err,
        }
    }
}

#[readonly::make]
pub struct EncryptionPackage {
    pub key: Vec<u8>,
    pub key_salt: Vec<u8>,
    pub iv: Vec<u8>,
    pub password_hash: String,
}

fn validate_encryption_package(
    salt: &Option<Vec<u8>>,
    iv: &Option<Vec<u8>>,
    pass_hash: &Option<String>,
) -> io::Result<()> {
    let checked_salt = salt.as_ref().map(|salt| salt.len() != SALT_SIZE);
    let checked_iv = iv.as_ref().map(|iv| iv.len() != IV_SIZE);
    let checked_password = pass_hash
        .as_ref()
        .map(|pass_hash| pass_hash.len() != PASSWORD_HASH_SIZE);

    if checked_salt.unwrap_or(false) || checked_iv.unwrap_or(false) {
        return Err(io_err!(format!(
            "Salt size must be {} and iv must be {} in length",
            SALT_SIZE, IV_SIZE
        )));
    } else if checked_password.unwrap_or(false) {
        return Err(io_err!("Invalid hash size!"));
    }

    Ok(())
}
fn fill_random_secure(data: &mut [u8]) -> io::Result<()> {
    let mut r = OsRng::default();
    r.try_fill_bytes(data).map_err(|e| io_err!(e.to_string()))?;
    Ok(())
}

fn make_random_16b() -> io::Result<Vec<u8>> {
    let mut salt = vec![0; 16];
    fill_random_secure(&mut salt)?;
    Ok(salt)
}

/// Creates the main parameters for a JFile encryption / decryption.
pub fn create_encryption_package(
    pass_str: &str,
    salt: Option<Vec<u8>>,
    iv: Option<Vec<u8>>,
    pass_hash: Option<String>,
) -> io::Result<EncryptionPackage> {
    validate_encryption_package(&salt, &iv, &pass_hash).unwrap_or_else(|error| {
        println!("{}", error);
        std::process::exit(-1);
    });

    let key_salt = salt.unwrap_or(make_random_16b()?);
    let iv = iv.unwrap_or(make_random_16b()?);
    let password_hash = pass_hash.unwrap_or(hash_password(pass_str).map_err(|e| io_err!(e))?);

    let mut key = vec![0; 16];
    let params = Params::new(14, 8, 1).unwrap();

    scrypt(pass_str.as_bytes(), &key_salt, &params, &mut key)
        .map_err(|e| io_err!(e.to_string()))?;

    Ok(EncryptionPackage {
        key,
        iv,
        key_salt,

        password_hash,
    })
}
