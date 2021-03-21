use std::convert::TryInto;
use std::str;

use hex::FromHex;

use crate::crypto::{self, SecretKey, SharedCipher};
use crate::hexify;
use crate::net::{client, Payload};

const NODE_URL: &str = "https://127.0.0.1:4433";
const NODE_PK: &str = "be252fccd79ae53d279f2d7c7e8acc3f5e9ce442711f6ae38bbf5cb72388185d";

pub fn run() {
    // will have a HTTP proxy listener
    // will be converter to a more general, SOCKS proxy
    // for now just sending a request

    let request = b"1\nduckduckgo.com\n80\nGET / HTTP/1.0\r\n\r\n";

    // only do one level of encryption right now

    let node_public = <[u8; 32]>::from_hex(NODE_PK).unwrap();

    let nonce = crypto::generate_nonce();
    let secret_key = SecretKey::generate();
    let public_key = secret_key.compute_public_key();

    // this assumes that we want to use a static_key for the lifetime of the proxy. we really dont. change this
    // we want to make a new ephemeral key for each request
    let cipher = SharedCipher::new(&secret_key, node_public);

    // encrypt the message
    let ciphertext = cipher.encrypt(nonce, request.to_vec());

    // pack up json...
    let body = Payload {
        key: hexify!(public_key.to_bytes()),
        nonce: hexify!(nonce),
        content: hexify!(ciphertext),
    };

    let body = serde_json::to_vec(&body).unwrap();

    // send it into the wormhole
    let res = client::send(NODE_URL, body);

    // extract the nonce and decrypt the response
    let (nonce, res) = res.split_at(12);
    let res = cipher.decrypt(nonce.try_into().unwrap(), res.to_vec());

    // present it to the user
    println!("{}", str::from_utf8(&res).unwrap());
}
