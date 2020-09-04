extern crate jencrypt;
use crate::j_file::JFile;
use crate::{exit, io_err};
use jb_utils::extensions::io::EasyRead;
use jb_utils::extensions::strings::StringExt;
use jencrypt::*;
use std::error;
use std::fs::{metadata, write, File, OpenOptions};
use std::io;
use std::io::{Read, Seek, SeekFrom, Write};
#[allow(dead_code)]
static PATH: &str = "tests/";
#[allow(dead_code)]
fn write_test_log(name: &str, content: &str) -> Result<(), String> {
    let file_path = format!("{}{}", PATH, name);
    std::fs::create_dir_all(PATH).map_err(|e| e.to_string())?;
    write(file_path, content).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod _inner {
    use super::*;

    static TXT_DIR: &str = "txt_dir_test";
    static ENCRYPTED_NAME: &str = "encrypt_file.txt.x";
    static DECRYPTED_NAME: &str = "encrypt_file.txt";
    type Result<T, E = Box<dyn error::Error>> = std::result::Result<T, E>;

    //For aes128
    #[test]
    fn derive_pass_test() -> Result<()> {
        let j_result = create_encryption_package("Admin1234", None, None)?;
        assert_eq!(j_result.key.len(), 16);
        //println!("pass bytes = {:?}", j_result.password);
        Ok(())
    }
    fn make_test_file(fname: &str, contents: &str) -> io::Result<()> {
        let meta = metadata(fname).unwrap_or_else(|_| {
            let file =
                File::create(fname).unwrap_or_else(|why| exit!("Could not make file, {}", -1, why));
            file.metadata().unwrap()
        });
        if meta.len() < 1000 {
            write(fname, contents)?;
        }
        Ok(())
    }

    fn p_exists(pname: &str) -> bool {
        metadata(pname).is_ok()
    }
    #[test]
    fn encrypt_file() -> io::Result<()> {
        let test_file = DECRYPTED_NAME;
        make_test_file(test_file, &"bruh\n".to_string().mul(100))?;

        //if making new key, do not provide salt, as if None, the derive_pass function will generate a safe salt.
        let pack = create_encryption_package("admin123", None, None)
            .map_err(|e| io_err!(e.to_string()))?;
        let output_file_name = format!("{}.x", test_file);
        let mut encrypted_file = JFile::new(&pack, &output_file_name, false)?;
        let mut input_file = OpenOptions::new().read(true).open(test_file)?;

        println!("Derived key = {:?}", pack.key);

        let mut buf = vec![0; 6000];
        let mut r = 0;
        while input_file.e_read(&mut buf, &mut r).unwrap_or(0) > 0 {
            //Each write call with encrypt the given buffer.
            encrypted_file.write_all(&buf[..r])?;
        }

        println!("{:?}\n salt= {:?}", pack.iv, pack.key_salt);
        let mut iv_and_salt = pack.iv.clone();
        let mut salt = pack.key_salt.clone();

        iv_and_salt.append(&mut salt);
        assert_eq!(
            std::fs::read(&output_file_name)?[..32].to_vec(),
            iv_and_salt
        );
        Ok(())
    }
    fn rand_string() -> String {
        "".into()
    }
    fn make_txt_files(dir: &str, name: &str, contents: Option<String>) -> io::Result<()> {
        let contents = contents.unwrap_or(rand_string());

        for i in 0..100 {
            let fname = format!("{}/{}_{}.txt", dir, name, i);
            std::fs::write(fname, &contents)?;
        }
        Ok(())
    }
    fn make_txt_dir() -> io::Result<()> {
        let is_making = if p_exists(TXT_DIR) {
            let entries = std::fs::read_dir(TXT_DIR)?;
            let files = entries.filter(|entry| {
                if let Ok(entry) = entry {
                    if let Ok(m) = entry.metadata() {
                        m.is_file()
                    } else {
                        false
                    }
                } else {
                    false
                }
            });

            files.count() < 100
        } else {
            std::fs::create_dir(TXT_DIR)?;
            true
        };
        if is_making {
            make_txt_files(TXT_DIR, "test_file", Some("bruh".into()))?;
        }
        Ok(())
    }
    #[test]
    fn encrypt_dir_t() -> io::Result<()> {
        make_txt_dir()?;
        let entries = std::fs::read_dir(TXT_DIR)?;
        let files = entries.filter(|entry| {
            if let Ok(entry) = entry {
                if let Ok(m) = entry.metadata() {
                    m.is_file()
                } else {
                    false
                }
            } else {
                false
            }
        });
        let pack = create_encryption_package("admin123", None, None)
            .map_err(|e| io_err!(e.to_string()))?;
        let mut buf = vec![0; 6000];
        let mut r = 0;

        for file in files {
            let file_path = file?.path();
            let fname = file_path.as_path().to_str().unwrap();
            let mut file = JFile::new(&pack, fname, true)?;
            let new_file_name = format!("{}.temp", fname);
            let mut new_file = File::create(&new_file_name)?;

            while file.e_read(&mut buf, &mut r).unwrap_or(0) > 0 {
                new_file.write_all(&mut buf[..r])?;
            }
            drop(file);
            drop(new_file);
            std::fs::remove_file(fname)?;
            let temp_index = new_file_name.find(".temp").unwrap_or(0);
            if temp_index == 0 {
                return Err(io_err!(format!(
                    "Could not find .temp extension in encrypted file! for file {}",
                    new_file_name
                )));
            }
            std::fs::rename(new_file_name.clone(), &new_file_name[..temp_index])?;
        }
        Ok(())
    }
    fn buffered_read(fname: &str, offset: u64, to: u64) -> io::Result<Vec<u8>> {
        let mut file = File::open(fname)?;
        let mut buf = vec![0; (to - offset) as usize];

        if offset > 0 {
            file.seek(SeekFrom::Start(offset))?;
        }
        let bytes_read = file.read(&mut buf)?;
        Ok(buf[..bytes_read].to_vec())
    }

    #[test]
    fn decrypt_file() -> io::Result<()> {
        let test_file = ENCRYPTED_NAME;
        let (iv, key_salt) = JFile::get_iv_and_salt_from_file(test_file)?;
        assert_eq!(iv.len(), 16);
        assert_eq!(key_salt.len(), 16);

        let pack = create_encryption_package("admin123", Some(key_salt), Some(iv))
            .map_err(|e| io_err!(e.to_string()))?;

        let mut input_file = JFile::new(&pack, test_file, true)?;
        let input_file = input_file.is_decrypting(true)?;
        let mut output_file = File::create("dec.txt")?;

        let mut buf = vec![0; 6000];
        let mut r = 0;

        while input_file.e_read(&mut buf, &mut r).unwrap_or(0) > 0 {
            output_file.write_all(&mut buf[..r])?;
        }

        Ok(())
    }
    #[test]
    fn jencrypt_encrypt_file() -> io::Result<()> {
        let test_file = "jencrypt_test.txt";
        make_test_file(test_file, &"test\n".to_string().mul(100))?;
        jencrypt::encrypt_file("admin123", test_file)
    }
    #[test]
    fn jencrypt_decrypt_file() -> io::Result<()> {
        let test_file = "jencrypt_test.txt";
        jencrypt::decrypt_file("admin123", test_file)
    }
}
