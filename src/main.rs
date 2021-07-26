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

fn repeat_while_err<T, V: Debug>(mut value: impl FnMut() -> Result<T, V>) -> T {
  let mut val = value();
  while val.is_err() {
    val = value();
  }
  val.unwrap()
}
fn main() {
  let password = input("Enter password /> ");
  let fname = input("Enter filename /> ");

  let encrypting = input("Are you locking a file? y/n").to_lowercase().trim() == "y";

  let lock_method = if encrypting {
    jencrypt::encrypt_file
  } else {
    jencrypt::decrypt_file
  };

  let method_name = if encrypting { "locked" } else { "unlocked" };

  if let Err(e) = lock_method(&password, &fname) {
    println!("{}", e);
  } else {
    println!("Successfully {} '{}' ", method_name, fname);

    if !encrypting {
      webbrowser::open(&fname).unwrap_or_else(|e| panic!("Couldn't open '{}', why: {}", fname, e));
    }
  }
  input("");
}
