use ::rsa::rand_core::{CryptoRng, Error, RngCore};
use rand::rngs::ThreadRng;

mod wdrsa;

struct RsaRand{
    index:isize,
    rng:ThreadRng
}

impl RsaRand {
    pub fn new()->Self{
        let index = 0;
        let rng = rand::thread_rng();
        Self{index,rng}
    }
}

impl CryptoRng for RsaRand{}
impl RngCore for RsaRand {
    fn next_u32(&mut self) -> u32 {
        println!("next_u32");
        return 1
    }

    fn next_u64(&mut self) -> u64 {
        println!("next_u64");
        return 1
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        println!("[{}]fill_bytes=>{}",self.index,dest.len());
        self.rng.fill_bytes(dest);
        self.index += 1;
        // for (i,d) in dest.iter_mut().enumerate(){
        //     *d = i as u8;
        // }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        println!("try_fill_bytes");
        self.fill_bytes(dest);Ok(())
    }
}

#[cfg(test)]
mod test{
    use rsa::{RsaPrivateKey, RsaPublicKey, PublicKey, Pkcs1v15Encrypt};
    use crate::algo::RsaRand;

    #[test]
    pub fn test_private_key(){
        let mut rng = RsaRand::new();
        // let mut rng = rand::thread_rng();
        println!("start");
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

// Encrypt
        let data = b"hello world";
        let enc_data = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, &data[..]).expect("failed to encrypt");
        assert_ne!(&data[..], &enc_data[..]);

// Decrypt
        let dec_data = private_key.decrypt(Pkcs1v15Encrypt, &enc_data).expect("failed to decrypt");
        assert_eq!(&data[..], &dec_data[..]);
        println!("success");
    }
}