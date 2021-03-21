use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Payload {
    pub key: String,
    pub nonce: String,
    pub content: String,
}

pub mod client;
pub mod server;
