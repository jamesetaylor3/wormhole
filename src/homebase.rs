use std::str;
use hex::FromHex;

use crate::crypto::{self, SymmetricCipher};
use crate::hexify;
use crate::net::{client, Payload};

const NODE_URL: &'static str = "https://127.0.0.1:4433";
const NODE_PK: &'static str = "20b891cdf6f27dfb039301d74888b4f7bf46c6fc2bc2cc271bdd25e448f16a64";

pub fn run() {
    // will have a HTTP proxy listener
    // will be converter to a more general, SOCKS proxy
    // for now just sending a request

    let request = b"1\nduckduckgo.com\n80\nGET / HTTP/1.0\r\n\r\n";

    // only do one level of encryption right now

    let node_public = <[u8; 32]>::from_hex(NODE_PK).unwrap();

    let nonce = crypto::generate_nonce();

    // this assumes that we want to use a static_key for the lifetime of the proxy. we really dont. change this
    // we want to make a new ephemeral key for each request
    let cipher = SymmetricCipher::new(node_public, nonce);

    // encrypt the message
    let ciphertext = cipher.encrypt(request.to_vec());

    // pack up json...
    let body = Payload {
        key: hexify!(crypto::ECDH_PK.to_bytes()),
        nonce: hexify!(nonce),
        content: hexify!(ciphertext),
    };

    let body = serde_json::to_vec(&body).unwrap();

    // send it into the wormhole
    let res = client::send(NODE_URL, body);

    // decrypt the response
    let res = cipher.decrypt(res);

    // present it to the user
    println!("{}", str::from_utf8(&res).unwrap());
}
