use std::io::{Read, Write};
use std::net::TcpStream;
use std::str;

use hex::FromHex;
use nom::{
    bytes::complete::{tag, take, take_until},
    combinator::map_res,
    IResult,
};
use num_traits::PrimInt;

use crate::crypto::{self, SymmetricCipher};
use crate::hexify;
use crate::net::server;
use crate::net::Payload;

// will probably want to break up this module

pub fn run() {
    // broadcast the public key
    println!("{}", hexify!(crypto::ECDH_PK.to_bytes()));

    // will need to implement threading or async
    // will also need to remodel the token
    // it would be nice if the thing that read headers and body were more "connected". figure that out
    server::serve([127, 0, 0, 1], 4433, |payload: Payload| {
        // extract individual items
        let key = <[u8; 32]>::from_hex(payload.key).unwrap();
        let nonce = <[u8; 12]>::from_hex(payload.nonce).unwrap();
        let content = <Vec<u8>>::from_hex(payload.content).unwrap();

        // create a cipher from the key and nonce
        let cipher = SymmetricCipher::new(key, nonce);

        // decrypt the content
        let content_pt = cipher.decrypt(content);

        // parse the content and do the next action
        let response = FlightPlan::parse(&content_pt).unwrap().1.execute();

        // encrypt the response
        // TODO: make it so that we create a new nonce here
        let body_ct = cipher.encrypt(response);

        // return
        (200, body_ct)
    });
}

/// Where to go next next
#[derive(Debug)]
enum FlightPlan {
    Relay {
        hostname: Vec<u8>,
        port: u16,
        nonce: [u8; 12],
        body: Vec<u8>,
    },

    Terminal {
        hostname: Vec<u8>,
        port: u16,
        body: Vec<u8>,
    },
}

impl FlightPlan {
    fn parse(input: &[u8]) -> IResult<&str, Self> {
        // we should see if we can implement this function only using bytes no strings
        // also return a tuple is kinda silly for this function

        // TODO: from_utf8 should be lossy later
        let input = str::from_utf8(&input).unwrap();

        let (input, next_type) = take(1_usize)(input)?;
        let (input, _) = tag("\n")(input)?;

        let (input, hostname) = take_until("\n")(input)?;
        let (input, _) = tag("\n")(input)?;

        let (input, port) = map_res(take_until("\n"), from_decimal)(input)?;
        let (input, _) = tag("\n")(input)?;

        match next_type {
            // jumping to another relay
            "0" => (),

            // exiting the wormhole to a terminal
            "1" => {
                return Ok((
                    "",
                    Self::Terminal {
                        hostname: hostname.as_bytes().to_vec(),
                        port,
                        body: input.as_bytes().to_vec(),
                    },
                ));
            }

            // error: not a action code
            _ => (),
        }

        Ok((
            "",
            Self::Terminal {
                hostname: vec![],
                port: port,
                body: vec![],
            },
        ))
    }

    fn execute(&self) -> Vec<u8> {
        match self {
            Self::Relay { .. } => vec![],

            Self::Terminal {
                hostname,
                port,
                body,
            } => {
                // use TLS at some point for https
                // tcp_stream crate looks good for tls
                let url = format!("{}:{}", str::from_utf8(hostname).unwrap(), port);
                let mut stream = TcpStream::connect(url).unwrap();

                stream.write(&body).unwrap();
                let mut res = vec![0; 16 * 1024];
                stream.read(&mut res).unwrap();
                
                // trim the unccesary zeros.
                // this will fail if body buffer wasnt large enough
                let end_pos = res.iter().position(|&x| x == 0x0).unwrap();
                let res = Vec::from(res.split_at(end_pos).0);
                
                res
            }
        }
    }
}

fn from_decimal<T: PrimInt>(input: &str) -> Result<T, T::FromStrRadixErr> {
    T::from_str_radix(input, 10)
}
