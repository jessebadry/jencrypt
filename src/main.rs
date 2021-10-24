extern crate jencrypt;


#[feature(cli)]
mod cli {
    use super::*;

    extern crate jb_utils;
    extern crate nfd;

    use self::jb_utils::jb_inputs::input;
    use self::nfd::Response;
    use jencrypt::JEncryptError;
    use std::error::Error as StdError;
    use std::{fmt, io};
    use std::process::exit;

    // type Result<T> = std::result::Result<T, JEncryptError>;

    trait CLILogger<T, E> {
        fn log(self, msg: String) -> T;
    }

    #[derive(Clone, Debug)]
    enum Error {
        BrokenHeaderFile,
    }

    impl fmt::Display for Error {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            let msg = match *self {
                Error::BrokenHeaderFile => "",
            };

            write!(formatter, "{}", msg)
        }
    }

    impl std::error::Error for Error {}

    impl<T, E> CLILogger<T, E> for std::result::Result<T, E>
        where
            E: StdError,
    {
        fn log(self, msg: String) -> T {
            self.unwrap_or_else(|e| {
                println!("{}, raw error: {}", msg, e);
                exit(-1)
            })
        }
    }

    fn handle_error(error: jencrypt::JEncryptError) -> String {
        match error {
            jencrypt::JEncryptError::IOError(err) => format!("{}", err),
            jencrypt::JEncryptError::InvalidPassword(err) => format!("{}", err),
            jencrypt::JEncryptError::InvalidFileData(err) => {
                format!("Invalid file!, raw err {:?}", err)
            }
            jencrypt::JEncryptError::CouldNotHashUserPassword(err) => {
                format!("Could not has entered password, reason: {}", err)
            }
            _ => unimplemented!(),
        }
    }

    fn user_select_files() -> Vec<String> {
        let result = nfd::open_file_multiple_dialog(None, None).expect("Error with file dialog");

        let files = match result {
            Response::Okay(file_path) => [file_path].to_vec(),
            Response::OkayMultiple(files) => files,
            Response::Cancel => std::process::exit(0),
        };

        files
    }

    fn process_crypt_results(cipher_results: impl Iterator<Item=io::Result<()>>) -> String {
        println!("Finished validating, attempting operation..");
        let error_count = cipher_results
            .filter(|file| {
                let is_err = file.is_err();

                if is_err {
                    println!("Error = {:?}", file);
                }

                is_err
            })
            .count();

        let message = if error_count > 0 {
            format!("{} file(s) could not be ciphered.", error_count)
        } else {
            "All files were succesfully ciphered".to_string()
        };

        format!("Finished operation, {}", message)
    }

    pub fn run() {
        let password = input("Enter password ");

        let files = user_select_files();

        let mut header_file =
            std::fs::File::open(&files[0]).log("Could not open header file!".to_string());

        let decrypting = jencrypt::jfile::contains_header(&mut header_file)
            .log("Couldn't read Document header!".into());
        // if no header and we are decrypting, this means this file is not encrypted.

        let crypt_method = if decrypting {
            println!("decrypting files.");
            jencrypt::decrypt_files
        } else {
            println!("encrypting files.");
            jencrypt::encrypt_files
        };

        println!("Deriving password...");
        let result_message = match crypt_method(&password, &files) {
            Ok(cipher_results) => process_crypt_results(cipher_results),
            Err(e) => handle_error(e),
        };
        println!("{}", result_message);
    }
}

fn main() {
    #[cfg(feature="cli")]
        cli::run();
}
