extern crate aes;
pub extern crate jb_utils;
extern crate ofb;
extern crate rand;
extern crate scrypt;
mod jencrypt;
use jb_utils::io_err;
pub use jencrypt::*;