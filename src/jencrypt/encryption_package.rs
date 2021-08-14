use crate::io_err;

use jencrypt::password_verification::hash_password;
use rand::rngs::OsRng;
use rand::RngCore;
use scrypt::password_hash;
use scrypt::{scrypt, Params};
use std::io;

/// JFile
use j_file::{IV_SIZE, PASSWORD_HASH_SIZE, SALT_SIZE};

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
#[derive(Debug)]
pub enum EncryptionPackageError {
    HasherError(password_hash::HasherError),
    InvalidParameter(&'static str, String),
    IOErr(io::Error),
}
impl From<io::Error> for EncryptionPackageError {
    fn from(err: io::Error) -> Self {
        IOErr(err)
    }
}
use self::EncryptionPackageError::*;
#[readonly::make]
pub struct EncryptionPackage {
    pub key: Vec<u8>,
    pub key_salt: Vec<u8>,
    pub iv: Vec<u8>,
    pub password_hash: String,
}

/// Map the Option to a boolean.
pub fn validate_bool<U, F>(opt: &Option<U>, predicate: F) -> bool
where
    F: FnOnce(&U) -> bool,
{
    opt.as_ref().map(predicate).unwrap_or(false)
}
impl EncryptionPackage {
    /// Validate the iv, salt and password_hash length to each of their according specification.
    fn validate_params(
        salt: &Option<Vec<u8>>,
        iv: &Option<Vec<u8>>,
        pass_hash: &Option<String>,
    ) -> Result<(), EncryptionPackageError> {
        // Check if length is invalid while still being an option, then default to false if None
        let salt_is_invalid = validate_bool(salt, |salt| salt.len() != SALT_SIZE);
        let iv_is_invalid = validate_bool(&iv, |iv| iv.len() != IV_SIZE);
        let password_is_invalid = validate_bool(&pass_hash, |pass_hash| {
            pass_hash.len() != PASSWORD_HASH_SIZE
        });

        if salt_is_invalid || iv_is_invalid {
            Err(InvalidParameter(
                "Salt or IV has invalid length!",
                format!(
                    "Salt size must be {} and iv must be {} in length",
                    SALT_SIZE, IV_SIZE
                ),
            ))
        } else if password_is_invalid {
            Err(InvalidParameter(
                "Invalid hash length!",
                format!("Hash must be {} in length.", PASSWORD_HASH_SIZE),
            ))
        } else {
            Ok(())
        }
    }
    /// Create the main parameters for a JFile encryption / decryption.
    pub fn generate(
        pass_str: &str,
        salt: Option<Vec<u8>>,
        iv: Option<Vec<u8>>,
        pass_hash: Option<String>,
    ) -> Result<EncryptionPackage, EncryptionPackageError> {
        Self::validate_params(&salt, &iv, &pass_hash)?;
        let key_salt = salt.unwrap_or(make_random_16b()?);
        let iv = iv.unwrap_or(make_random_16b()?);

        let password_hash = pass_hash.unwrap_or(hash_password(pass_str).map_err(HasherError)?);
        let mut key = vec![0; 16];

        scrypt(pass_str.as_bytes(), &key_salt, &Params::default(), &mut key).expect("Scrypt Error");

        Ok(EncryptionPackage {
            key,
            iv,
            key_salt,
            password_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_option() {
        let some_10 = Some(10);
        let none_option1 = None::<i32>;
        let is_some_and_equals_10 = validate_bool(&some_10, |int_value| *int_value == 10);

        let is_some_and_equals_1 = validate_bool(&some_10, |int_value| *int_value == 1);

        let is_none = validate_bool(&none_option1, |imaginary_int| *imaginary_int == 1);

        assert!(is_some_and_equals_10);

        assert_eq!(is_some_and_equals_1, false);

        assert_eq!(is_none, false);
    }
}
