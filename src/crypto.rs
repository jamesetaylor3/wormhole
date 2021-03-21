use aes_gcm::{
    aead::{
        generic_array::{typenum::U12, GenericArray},
        Aead, NewAead,
    },
    Aes256Gcm,
};
use lazy_static::lazy_static;
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

lazy_static! {
    static ref ECDH_SK: StaticSecret = StaticSecret::new(OsRng);
    pub static ref ECDH_PK: PublicKey = PublicKey::from(&*ECDH_SK);
}

pub struct SymmetricCipher {
    nonce: GenericArray<u8, U12>,
    cipher: Aes256Gcm,
}

impl SymmetricCipher {
    pub fn new(other_key: [u8; 32], nonce: [u8; 12]) -> Self {
        let other_key = PublicKey::from(other_key);

        let nonce = *GenericArray::from_slice(&nonce);

        let shared_key = ECDH_SK.diffie_hellman(&other_key).to_bytes();
        let shared_key = GenericArray::from_slice(&shared_key);

        let cipher = Aes256Gcm::new(&shared_key);

        SymmetricCipher { nonce, cipher }
    }

    pub fn encrypt(&self, pt: Vec<u8>) -> Vec<u8> {
        self.cipher.encrypt(&self.nonce, pt.as_ref()).unwrap()
    }

    pub fn decrypt(&self, ct: Vec<u8>) -> Vec<u8> {
        self.cipher.decrypt(&self.nonce, ct.as_ref()).unwrap()
    }
}

pub fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}
