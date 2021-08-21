use crate::jfile::HeaderParserError;
use crate::{io_err, jfile};

use jb_utils::extensions::io::EasyRead;
use jencrypt::password_verification::hash_password;
use rand::rngs::OsRng;
use rand::RngCore;
use scrypt::password_hash;
use scrypt::{scrypt, Params};
use std::io;

trait OptionUtils<T> {
    /// Map a option to a boolean using the provided predicate,
    /// returns false on None value.
    fn map_to_bool<F>(&self, predicate: F) -> bool
    where
        F: FnOnce(&T) -> bool;
}
impl<T> OptionUtils<T> for Option<T> {
    fn map_to_bool<F>(&self, predicate: F) -> bool
    where
        F: FnOnce(&T) -> bool,
    {
        self.as_ref().map(predicate).unwrap_or(false)
    }
}
/// JFile
use jfile::{parse_header, IV_SIZE, PASSWORD_HASH_SIZE, SALT_SIZE};

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

impl EncryptionPackage {
    /// Validate the iv, salt and password_hash length to each of their according specification.
    fn validate_params(
        salt: &Option<Vec<u8>>,
        iv: &Option<Vec<u8>>,
        pass_hash: &Option<String>,
    ) -> Result<(), EncryptionPackageError> {
        // Check if length is invalid while still being an option, then default to false if None
        let salt_is_invalid = salt.map_to_bool(|salt| salt.len() != SALT_SIZE);
        let iv_is_invalid = iv.map_to_bool(|iv| iv.len() != IV_SIZE);
        let password_is_invalid =
            pass_hash.map_to_bool(|pass_hash| pass_hash.len() != PASSWORD_HASH_SIZE);

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

    pub fn from_header<P: EasyRead>(
        password: &str,
        reader: &mut P,
    ) -> Result<Self, HeaderParserError> {
        let (iv, salt, pass_hash) = jfile::parse_header(reader)?;

        Ok(Self::generate(
            password,
            Some(salt),
            Some(iv),
            Some(pass_hash),
        ).expect("Generate failed, bug in parser?"))
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
        let is_some_and_equals_10 = some_10.map_to_bool(|int_value| *int_value == 10);

        let is_some_and_equals_1 = some_10.map_to_bool(|int_value| *int_value == 1);

        let is_none = none_option1.map_to_bool(|imaginary_int| *imaginary_int == 1);

        assert!(is_some_and_equals_10);

        assert_eq!(is_some_and_equals_1, false);

        assert_eq!(is_none, false);
    }
}
