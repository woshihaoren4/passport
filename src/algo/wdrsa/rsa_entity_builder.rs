use crypto::blockmodes::PkcsPadding;
use rsa::Pkcs1v15Encrypt;
use rsa::rand_core::CryptoRngCore;
use crate::algo::wdrsa::{RsaEntity, RuleRand, RuleRandBuilder};

pub struct RsaEntityBuilder{
    bit_size:usize,
    key:Vec<u8>,
    key_confuse_number: i64,
    // rng:RuleRand,
}

impl RsaEntityBuilder {
    pub fn new<Key>(key:Key, bit_size:usize)->Self
        where Vec<u8>:From<Key>
    {
        let key_confuse_number = 0;
        let key = Vec::from(key);
        Self{bit_size,key,key_confuse_number}
    }
    pub fn build_pkcs15(self)->anyhow::Result<RsaEntity<Pkcs1v15Encrypt>>{
        let mut rand = RuleRandBuilder::new(self.key).confuse_key_i64(self.key_confuse_number).build();
        RsaEntity::new(&mut rand,self.bit_size,Pkcs1v15Encrypt)
    }
}