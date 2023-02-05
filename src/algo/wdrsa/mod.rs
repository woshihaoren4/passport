mod rand;
mod rsa_entity;
mod rsa_entity_builder;

pub use rsa_entity::RsaEntity;
pub use self::rand::*;
pub use rsa_entity_builder::RsaEntityBuilder;


#[cfg(test)]
mod test{
    use rustc_serialize::hex::ToHex;
    use crate::algo::wdrsa::RsaEntityBuilder;
    #[test]
    fn encrypt_decrypt(){
        let entity = RsaEntityBuilder::new("hello world").build_pkcs15().expect("rsa 证书生成失败");

        let data = "test data";
        let cipher = entity.encrypt(data.as_bytes()).expect("rsa 加密失败");
        assert_ne!(cipher.as_slice(),data.as_bytes());

        let cleartext = entity.decrypt(cipher.as_slice()).expect("rsa 解密失败");
        assert_eq!(data.as_bytes(),cleartext,"加解密内容前后不一致");

        println!("success:{}",cipher.to_hex());
    }

    #[test]
    fn sign_verify(){
        let entity = RsaEntityBuilder::new("hello world").build_pkcs15().expect("rsa 证书生成失败");

        let data = "test data";
        let cipher = entity.sign_sha256(data.as_bytes()).expect("rsa 签名失败");
        assert_ne!(cipher.as_slice(),data.as_bytes());

        entity.verify_sha256(data.as_bytes(),cipher.as_slice()).expect("rsa 验证失败");

        println!("success:{}",cipher.len());
    }
}