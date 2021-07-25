use scrypt::{
    password_hash::{
        HashError, HasherError, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
        VerifyError as ScryptVerifyError,
    },
    Scrypt,
};

use rand::rngs::OsRng;
pub enum VerifyError {
    IncorrectHash(HashError),
    InvalidPassword(ScryptVerifyError),
}

impl From<HashError> for VerifyError {
    fn from(err: HashError) -> Self {
        VerifyError::IncorrectHash(err)
    }
}
impl From<ScryptVerifyError> for VerifyError {
    fn from(err: ScryptVerifyError) -> Self {
        VerifyError::InvalidPassword(err)
    }
}

pub fn hash_password(password: &str) -> Result<String, HasherError> {
    let salt = SaltString::generate(OsRng);
    // Hash password to PHC string using scrypt
    let password_hash = Scrypt
        .hash_password_simple(password.as_bytes(), salt.as_ref())?
        .to_string();

    Ok(password_hash)
}

pub fn verify_password(
    target_password: impl AsRef<str>,
    hashed_password: &str,
) -> Result<(), VerifyError> {
    let hash = PasswordHash::new(hashed_password)?;
    Scrypt.verify_password(target_password.as_ref().as_bytes(), &hash)?;

    Ok(())
}
