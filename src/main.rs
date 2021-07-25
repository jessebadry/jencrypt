extern crate aes;
extern crate base64;
extern crate jb_utils;
extern crate ofb;
extern crate rand;
extern crate scrypt;
extern crate webbrowser;
mod jencrypt;
use jb_utils::io_err;
use jb_utils::jb_inputs::input;
pub use jencrypt::*;
use rand::rngs::OsRng;
use rand::RngCore;
use scrypt::{
  password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
  Scrypt,
};
use std::fmt::Debug;
use std::iter::Iterator;
use std::string::ParseError;

fn repeat_while_err<T, V: Debug>(mut value: impl FnMut() -> Result<T, V>) -> T {
  let mut val = value();
  while val.is_err() {
    val = value();
  }
  val.unwrap()
}
fn main() {
  let password = b"hunter42";
  let mut token = vec![0u8; repeat_while_err(|| input("Enter byte length").parse::<usize>())];
  OsRng.fill_bytes(&mut token);
  let salt = SaltString::generate(OsRng);
  // // Hash password to PHC string ($scrypt$...)
  let password_hash = Scrypt
    .hash_password_simple(password, salt.as_ref())
    .unwrap()
    .to_string();

  // Verify password against PHC string
  let parsed_hash = PasswordHash::new(&password_hash).unwrap();
  assert!(Scrypt.verify_password(password, &parsed_hash).is_ok());

  // let password = input("Enter password /> ");
  // let fname = input("Enter filename /> ");

  // let encrypting = input("Are you locking a file? y/n").to_lowercase().trim() == "y";

  // let lock_method = if encrypting {
  //   jencrypt::encrypt_file
  // } else {
  //   jencrypt::decrypt_file
  // };

  // let method_name = if encrypting { "locked" } else { "unlocked" };

  // if lock_method(&password, &fname).is_ok() {
  //   println!("Successfully {} '{}' ", method_name, fname);

  //   if !encrypting {
  //     webbrowser::open(&fname).unwrap_or_else(|e| panic!("Couldn't open '{}', why: {}", fname, e));
  //   }
  // }
  // input("");
}
