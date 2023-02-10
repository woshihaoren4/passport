extern crate core;

mod algo;
mod app;
mod common;
mod define;
// mod libc;


pub use algo::*;
pub use app::PassportEntity;
pub use chrono::Utc;
pub use define::*;

#[cfg(test)]
mod test{
    use crate::{format_public_pem, init_passport, rsa_sha256_sign, rsa_sha156_verify};
    #[test]
    fn test_default_init_passport(){
        let key = "hello world".as_bytes();
        init_passport(key, 2048, "2022-01-02 00:00:00", "2023-01-02 00:00:00", 60 * 60 * 24 * 30).expect("passport entity init error");
        println!("success");
    }

    #[test]
    fn test_default_passport_show_public_pem(){
        let list = format_public_pem();
        for i in list.iter(){
            println!("==============> {} ===============================|",i.0);
            println!("{}",i.1);
        }
    }
    #[test]
    #[should_panic]
    fn test_default_passport_range_min(){
        rsa_sha256_sign("hello world".as_bytes(), 1).expect("< min timestamp");
    }
    #[test]
    #[should_panic]
    fn test_default_passport_range_max(){
        rsa_sha256_sign("hello world".as_bytes(), 5607792000).expect("> max timestamp");
    }

    #[test]
    fn test_default_passport_sign_verify(){
        let data = "hello world";
        let timestamp = 1866248975;
        let sign = rsa_sha256_sign(data.as_bytes(), timestamp).expect("sign error");
        rsa_sha156_verify(data.as_bytes(), sign.as_slice(), timestamp).expect("verify error");
        println!("test_default_passport_sign_verify  success");
    }
}