use crate::keyblock::{KeyBlock, SECRET_SIZE, SIGNATURE_SIZE, KeyFile};
use openssl::rsa::Rsa;
use openssl::pkey::Public;
use rand::{thread_rng, Rng, RngCore};
use std::collections::HashMap;
use itertools::Itertools;


#[cfg(feature = "enable_debug")]
pub fn make_fake_rsa() -> Rsa<Public> {
    Rsa::public_key_from_pem(
        &*Rsa::generate(4096).unwrap().public_key_to_pem().unwrap()
    ).unwrap()
}


#[cfg(feature = "enable_debug")]
impl KeyBlock {
    pub fn make_fake() -> KeyBlock {
        let rsa = make_fake_rsa();
        let mut keys: HashMap<String, KeyFile> = HashMap::new();

        let mut secret: Vec<u8> = vec![0; SECRET_SIZE / 8];
        thread_rng().fill_bytes(secret.as_mut_slice());

        let key1 = KeyFile {
            flags: 6,
            secret,
            uid: (('K' as u16) << 8) + 52,
            path: "~/key1".to_string(),
            name: "key1".to_string(),
            description: "Fake key 1.".to_string(),
            length: 6 * 8,
            content: vec![1, 2, 3, 4, 5, 6]
        };
        keys.insert("~/key1".parse().unwrap(), key1);

        let mut secret: Vec<u8> = vec![0; SECRET_SIZE / 8];
        thread_rng().fill_bytes(secret.as_mut_slice());

        let key2 = KeyFile {
            flags: 4,
            secret,
            uid: (('K' as u16) << 8) + 45,
            path: "~/key2".to_string(),
            name: "key2".to_string(),
            description: "Fake key 2.".to_string(),
            length: 8 * 8,
            content: vec![8, 7, 6, 5, 4, 3, 2, 1]
        };
        keys.insert("~/key2".parse().unwrap(), key2);

        let mut secret: Vec<u8> = vec![0; SECRET_SIZE / 8];
        thread_rng().fill_bytes(secret.as_mut_slice());

        KeyBlock {
            root_pubkey: rsa,
            format_specifier: 0,
            flags: 0,
            secret,
            uid: (('B' as u16) << 8) + 89,
            name: "fake".to_string(),
            description: "This is a totally fake keyblock.".to_string(),
            keys,
            signature: vec![0; SIGNATURE_SIZE / 8]
        }
    }
}