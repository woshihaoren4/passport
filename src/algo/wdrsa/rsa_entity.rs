use rsa::sha2::{Digest, Sha256,Sha384,Sha512};
use rand::RngCore;
use rsa::rand_core::CryptoRngCore;
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding, Signer, Verifier};

pub struct RsaEntity<T>{
    prk:RsaPrivateKey,
    puk:RsaPublicKey,
    ps:T,
    sign_verify_sha256:(SigningKey<Sha256>,VerifyingKey<Sha256>),
    sign_verify_sha384:(SigningKey<Sha384>,VerifyingKey<Sha384>),
    sign_verify_sha512:(SigningKey<Sha512>,VerifyingKey<Sha512>),
}

impl<P:PaddingScheme+Copy> RsaEntity<P> {
    pub fn new<R: CryptoRngCore + ?Sized>(rng:&mut R,bit_size: usize,ps:P)->anyhow::Result<Self>{
        let prk = RsaPrivateKey::new(rng,bit_size)?;
        let puk = prk.to_public_key();
        //初始化签名验证
        let sign_256 = SigningKey::<Sha256>::new_with_prefix(prk.clone());
        let verify_256 = sign_256.verifying_key();

        let sign_384 = SigningKey::<Sha384>::new_with_prefix(prk.clone());
        let verify_384 = sign_384.verifying_key();

        let sign_512 = SigningKey::<Sha512>::new_with_prefix(prk.clone());
        let verify_512 = sign_512.verifying_key();

        Ok(Self{prk,puk,ps,
            sign_verify_sha256:(sign_256,verify_256),
            sign_verify_sha384:(sign_384,verify_384),
            sign_verify_sha512:(sign_512,verify_512),
        })
    }
}

impl<P:PaddingScheme+Copy> RsaEntity<P> {
    pub fn public_key(&self)->RsaPublicKey{
        self.puk.clone()
    }
    //加密
    pub fn encrypt(&self,data: &[u8])->anyhow::Result<Vec<u8>>{
        let mut rng = rand::thread_rng();
        let result = self.puk.encrypt(&mut rng, self.ps, data)?;Ok(result)
    }
    //解密
    pub fn decrypt(&self,data: &[u8])->anyhow::Result<Vec<u8>>{
        let result = self.prk.decrypt(self.ps, data)?;Ok(result)
    }
    //签名 sha256
    pub fn sign_sha256(&self,data:&[u8])->anyhow::Result<Vec<u8>>{
        let mut rng = rand::thread_rng();
        let signature = self.sign_verify_sha256.0.sign_with_rng(&mut rng,data);
        let result:Vec<u8> = signature.to_vec();
        return Ok(result)
    }
    //验证
    pub fn verify_sha256(&self,data:&[u8],sign:&[u8])->anyhow::Result<()>{
        let sign = Signature::try_from(sign)?;
        self.sign_verify_sha256.1.verify(data,&sign)?;Ok(())
    }
}