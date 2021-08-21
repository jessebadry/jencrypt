#[cfg(feature = "cli")]
mod cli {
    use super::*;
    extern crate jb_utils;
    extern crate nfd;
    use self::jb_utils::jb_inputs::input;
    use self::nfd::Response;
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
            Response::Cancel => std::process::exit(-1),
        };

        files
    }
    pub fn run() {
        let password = input("Enter password ");

        let files = user_select_files();

        println!("file 0 = {}", &files[0]);
        let decrypting = jencrypt::jfile::contains_header(
            &mut std::fs::File::open(&files[0]).unwrap_or_else(|err| {
                println!("Error opening '{}'", &files[0]);
                std::process::exit(-1)
            }),
        )
        .expect("Couldn't read Document header!");
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
            Ok(cipher_iterator) => {
                println!("Finished validating, attempting operation..");
                let error_count = cipher_iterator
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
            Err(e) => handle_error(e),
        };
        println!("{}", result_message);
    }
}

fn main() {
    #[cfg(feature = "cli")]
    cli::run();
}
