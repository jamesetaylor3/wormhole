use wormhole::homebase;
use wormhole::starport;

fn main() {
    let mut args = std::env::args();

    let cmd = &args.nth(1).unwrap();

    match cmd.as_str() {
        "starport" => {
            println!("initializing starport! 🚀");
            starport::run();
        }

        "homebase" => {
            println!("initializing homebase! 🌎");
            homebase::run();
        }

        _ => println!("invalid command!"),
    }
}
