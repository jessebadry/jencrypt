extern crate aes;
extern crate clap;
extern crate jb_utils;
extern crate ofb;
extern crate rand;
extern crate scrypt;
mod jencrypt;
use jb_utils::debug::PerformanceTimer;
use jb_utils::io_err;

pub use jencrypt::*;
fn main() {
  // let fname = input("Enter file to encrypt..");

  // let password = input("Enter password for file..");

  // let pack = derive_pass(&password, None)
  //   .unwrap_or_else(|e| exit!("Error from password : {}", e.to_string()));
  // let read = j_file::JFile::new(pack, &fname, true);
  // let matches = App::new("JEncrypt")
  //   .author("Jesse Badry. <jessebadry@gmail.com>")
  //   .about("Encrypt's files and files in directories. Defaults to encrypting")
  //   .help("Provide file with -f 'my_file.txt' then use --decrypting to indicate a decryption")
  //   .arg(
  //     Arg::with_name("file")
  //       .short("f")
  //       .long("file")
  //       .value_name("FILE")
  //       .takes_value(true)
  //       .help("File to be encrypted or decrypted")
  //       .required(true),
  //   )
  //   .arg(
  //     Arg::with_name("password")
  //       .short("p")
  //       .help("The password for the file")
  //       .value_name("TEXT")
  //       .required(true)
  //       .takes_value(true),
  //   )
  //   .arg(
  //     Arg::with_name("decrypting")
  //     .short("d")
  //       .help("Enables decryption instead of encryption")
  //       .takes_value(false),
  //   )
  //   .get_matches();
  {
    let timer = PerformanceTimer::new();
    jencrypt::encrypt_file("Jesse1234", "D:\\Programs\\Illegal Downloads\\mcd.zip")
      .unwrap_or_else(|e| println!("Could not  encrypt file! why: {}", e));
  }
}
