use std::iter::repeat;
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use rand::{CryptoRng, Error, RngCore};


pub trait ConfuseRule:Send+Sync{
    fn confuse(&self,buf:&mut Vec<u8>);
}

pub struct RuleRand {
    key:Vec<u8>,
    confuse_rule:Box<dyn ConfuseRule>,
}

impl RuleRand {
    fn raw_new(buf:&Vec<u8>,confuse_rule:Box<dyn ConfuseRule>)->Self{
        let mut hasher = Sha1::new();
        hasher.input(buf.as_slice());
        let mut key:Vec<u8> = repeat(0).take((hasher.output_bits()+7)/8).collect();
        hasher.result(key.as_mut_slice());
        Self{key,confuse_rule}
    }
    pub fn new<Key>(key:Key)-> Self
        where Vec<u8>:From<Key>
    {
        RuleRandBuilder::new(key).build()
    }
    pub fn key(&self)->Vec<u8>{
        self.key.clone()
    }
    fn confuse(&mut self){
        self.confuse_rule.confuse(&mut self.key);
    }
}

impl CryptoRng for RuleRand{}
impl RngCore for RuleRand {
    fn next_u32(&mut self) -> u32 {
        self.confuse();
        u32::from_le_bytes([self.key[0],self.key[1],self.key[2],self.key[3]])
    }

    fn next_u64(&mut self) -> u64 {
        self.confuse();
        u64::from_le_bytes([self.key[0],self.key[1],self.key[2],self.key[3],self.key[4],self.key[5],self.key[6],self.key[7]])
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.confuse();
        let mut i = 0;
        let mut j = 0;
        while i < dest.len(){
            if j >= self.key.len(){
                j = 0;
            }
            dest[i]=self.key[j];
            i += 1;
            j += 1;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.confuse();
        self.fill_bytes(dest);Ok(())
    }
}

pub struct RuleRandBuilder {
    key:Vec<u8>,
    confuse_rule:Box<dyn ConfuseRule>
}

impl Default for RuleRandBuilder {
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        let mut key = Vec::with_capacity(1024);
        rng.fill_bytes(key.as_mut_slice());
        let confuse_rule = Box::new(ConfuseRuleDefault);
        Self{key,confuse_rule}
    }
}

impl RuleRandBuilder {
    pub fn new<Key>(key:Key)-> Self
    where Vec<u8>:From<Key>
    {
        let key = Vec::from(key);
        let confuse_rule = Box::new(ConfuseRuleDefault);
        Self{key,confuse_rule}
    }
    #[allow(dead_code)]
    pub fn reset(mut self,buf:Vec<u8>) -> Self{
        self.key = buf;self
    }
    #[allow(dead_code)]
    pub fn confuse_key(mut self,mut buf:Vec<u8>) -> Self{
        self.key.append(&mut buf);self
    }
    #[allow(dead_code)]
    pub fn confuse_key_i64(mut self,i:i64) -> Self{
        let mut buf = i.to_be_bytes().to_vec();
        self.key.append(&mut buf);self
    }
    #[allow(dead_code)]
    pub fn confuse_rule(mut self,rule:Box<dyn ConfuseRule>)->Self{
        self.confuse_rule = rule;self
    }
    pub fn build(self)-> RuleRand {
        RuleRand::raw_new(self.key.as_ref(),self.confuse_rule)
    }
}

pub struct ConfuseRuleDefault;

impl ConfuseRule for ConfuseRuleDefault{
    fn confuse(&self, buf: &mut Vec<u8>) {
        let mut list = vec![];
        let len = buf.len()-1;
        for (i,item) in buf.iter().enumerate(){
            let number = if i < len {
                *item as isize + buf[i+1] as isize + 1
            }else{
                *item as isize + buf[0] as isize + 1
            };
            let number = number % 256;
            list.push(number as u8);
        }
        let mut i = 0;
        while i < len {
            buf[i+1] = buf[i];
            buf[i] = list[len-i];
            i += 2;
        }
    }
}


#[cfg(test)]
mod test{
    use rsa::{RsaPrivateKey};
    use rsa::pkcs1::{EncodeRsaPublicKey, LineEnding};
    use crate::algo::wdrsa::rand::{ConfuseRule, ConfuseRuleDefault, RuleRandBuilder};

    #[test]
    fn test_rule_rand(){
        let mut buf = vec![1, 2, 3, 4, 5, 6,7];
        ConfuseRuleDefault.confuse(&mut buf);
        println!("{:?}",buf)
    }

    #[test]
    fn test_rule_rand_generate(){
        let mut rng = RuleRandBuilder::new("hello world").confuse_key_i64(123456).build();

        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let s = private_key.to_pkcs1_pem(LineEnding::default()).expect("generate pem bytes error");
        println!("{}",s);
    }
}