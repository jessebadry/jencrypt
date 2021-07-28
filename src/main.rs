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
use std::io::{Error as IOError, ErrorKind};

pub use jencrypt::*;

use jencrypt::j_file::JFile;
use std::fmt::Debug;

#[derive(Debug)]
enum Error {
  IOErr(IOError),
  InvalidInput(String),
  Other(),
}
impl From<IOError> for Error {
  fn from(err: IOError) -> Error {
    let err = match err.kind() {
      ErrorKind::NotFound => Self::InvalidInput(err.to_string()),
      _ => Self::IOErr(err),
    };

   err
  }
}
fn repeat_while_err<T, V: Debug>(mut value: impl FnMut() -> Result<T, V>) -> T {
  let mut val = value();
  while val.is_err() {
    val = value();
  }
  val.unwrap()
}

fn main() -> Result<(), Error> {
  let password = input("Enter password /> ");
  let fname = input("Enter filename /> ");

  let encrypting = !JFile::file_contains_header(&fname)?;

  let crypt_method = if encrypting {
    jencrypt::encrypt_file
  } else {
    jencrypt::decrypt_file
  };

  let method_name = if encrypting { "locked" } else { "unlocked" };

  if let Err(e) = crypt_method(&password, &fname) {
    println!("{}", e);
  } else {
    println!("Successfully {} '{}' ", method_name, fname);

    if !encrypting {
      webbrowser::open(&fname).expect(&format!("Couldn't open '{}'", fname));
    }
  }
  Ok(())
}
