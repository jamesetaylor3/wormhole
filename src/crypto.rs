use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, NewAead},
    Aes256Gcm,
};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

#[derive(Clone)]
pub struct SecretKey(StaticSecret);

impl SecretKey {
    pub fn generate() -> Self {
        Self(StaticSecret::new(OsRng))
    }

    pub fn compute_public_key(&self) -> PublicKey {
        PublicKey::from(&self.0)
    }

    pub fn diffie_hellman(&self, other: &PublicKey) -> SharedSecret {
        self.0.diffie_hellman(other)
    }
}

pub struct SharedCipher(Aes256Gcm);

impl SharedCipher {
    pub fn new(my_secret: &SecretKey, other_public: [u8; 32]) -> Self {
        let other_public = PublicKey::from(other_public);

        let shared_key = my_secret.diffie_hellman(&other_public).to_bytes();
        let shared_key = GenericArray::from_slice(&shared_key);

        let cipher = Aes256Gcm::new(&shared_key);

        SharedCipher(cipher)
    }

    pub fn encrypt(&self, nonce: [u8; 12], pt: Vec<u8>) -> Vec<u8> {
        let nonce = GenericArray::from_slice(&nonce);
        self.0.encrypt(nonce, pt.as_ref()).unwrap()
    }

    pub fn decrypt(&self, nonce: [u8; 12], ct: Vec<u8>) -> Vec<u8> {
        let nonce = GenericArray::from_slice(&nonce);
        self.0.decrypt(nonce, ct.as_ref()).unwrap()
    }
}

pub fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}
