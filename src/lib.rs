#[macro_use]
extern crate log;

#[macro_export]
macro_rules! hexify {
    ($input:expr) => {
        $input
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    };
}

pub mod crypto;
pub mod homebase;
pub mod net;
pub mod starport;
