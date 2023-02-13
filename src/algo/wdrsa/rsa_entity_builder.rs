#![allow(dead_code)]

use crate::algo::wdrsa::{RsaEntity, RuleRandBuilder};
use rsa::Pkcs1v15Encrypt;

pub struct RsaEntityBuilder {
    bit_size: usize,
    key: Vec<u8>,
    key_confuse_number: i64,
    // rng:RuleRand,
}

impl RsaEntityBuilder {
    pub fn new<Key>(key: Key) -> Self
    where
        Key: AsRef<[u8]>,
    {
        let key_confuse_number = rand::random();
        let key = Vec::from(key.as_ref());
        let bit_size = 2048;
        Self {
            bit_size,
            key,
            key_confuse_number,
        }
    }
    pub fn set_bit_size(mut self, bit_size: usize) -> Self {
        self.bit_size = bit_size;
        self
    }
    pub fn set_confuse_number(mut self, nb: i64) -> Self {
        self.key_confuse_number = nb;
        self
    }
    pub fn build_pkcs15(self) -> anyhow::Result<RsaEntity<Pkcs1v15Encrypt>> {
        let mut rand = RuleRandBuilder::new(self.key)
            .confuse_key_i64(self.key_confuse_number)
            .build();
        RsaEntity::new(&mut rand, self.bit_size, Pkcs1v15Encrypt)
    }
}
