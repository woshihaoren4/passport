use crate::common::PFErr;
use crate::PassportEntity;
use chrono::{TimeZone, Utc};
use lazy_static::lazy_static;
use std::ops::DerefMut;
use std::sync::RwLock;
use std::time::Duration;

lazy_static! {
    static ref DEFAULT_PASSPORT: RwLock<PassportEntity> = {
        let start = Utc
            .datetime_from_str("2023-02-07 00:00:00", "%Y-%m-%d %H:%M:%S")
            .expect("default passport entity,start time generate error");
        let end = Utc
            .datetime_from_str("2123-02-07 00:00:00", "%Y-%m-%d %H:%M:%S")
            .expect("default passport entity,end time generate error");
        let interval = Duration::from_secs(60 * 60 * 24 * 30 * 12 * 10);
        let entity = PassportEntity::new("wd_passport_default_key", (start, end), interval, 1024)
            .expect("rsa certs build failed");
        RwLock::new(entity)
    };
}

pub fn init_passport(
    key: &[u8],
    bit_size: usize,
    start: &str,
    end: &str,
    interval: u64,
) -> anyhow::Result<()> {
    let start = Utc.datetime_from_str(start, "%Y-%m-%d %H:%M:%S")?;
    let end = Utc.datetime_from_str(end, "%Y-%m-%d %H:%M:%S")?;
    let interval = Duration::from_secs(interval);
    let entity = PassportEntity::new(key, (start, end), interval, bit_size)?;
    let mut wpp = match DEFAULT_PASSPORT.write() {
        Ok(o) => o,
        Err(e) => return anyhow::anyhow!("set DEFAULT_PASSPORT error:{}", e.to_string()).err(),
    };
    (*wpp.deref_mut()) = entity;
    Ok(())
}

pub fn rsa_sha256_encrypt(data: &[u8], timestamp_sec: i64) -> anyhow::Result<Vec<u8>>{
    let rpp = match DEFAULT_PASSPORT.read() {
        Ok(o) => o,
        Err(e) => {
            return anyhow::anyhow!("encrypt.read DEFAULT_PASSPORT error:{}", e.to_string()).err()
        }
    };
    rpp.encrypt(data, timestamp_sec)
}

pub fn rsa_sha256_decrypt(data: &[u8], timestamp_sec: i64) -> anyhow::Result<Vec<u8>>{
    let rpp = match DEFAULT_PASSPORT.read() {
        Ok(o) => o,
        Err(e) => {
            return anyhow::anyhow!("decrypt.read DEFAULT_PASSPORT error:{}", e.to_string()).err()
        }
    };
    rpp.decrypt(data, timestamp_sec)
}

pub fn rsa_sha256_sign(data: &[u8], timestamp_sec: i64) -> anyhow::Result<Vec<u8>> {
    let rpp = match DEFAULT_PASSPORT.read() {
        Ok(o) => o,
        Err(e) => {
            return anyhow::anyhow!("sign.read DEFAULT_PASSPORT error:{}", e.to_string()).err()
        }
    };
    rpp.sign_sha256(data, timestamp_sec)
}
pub fn rsa_sha156_verify(data: &[u8], sign: &[u8], timestamp_sec: i64) -> anyhow::Result<()> {
    let rpp = match DEFAULT_PASSPORT.read() {
        Ok(o) => o,
        Err(e) => {
            return anyhow::anyhow!("verify.read DEFAULT_PASSPORT error:{}", e.to_string()).err()
        }
    };
    rpp.verify_sha256(data, sign, timestamp_sec)
}
pub fn format_public_pem() -> Vec<(i64, String)> {
    let rpp = DEFAULT_PASSPORT
        .read()
        .expect("format_public_pem DEFAULT_PASSPORT error");
    rpp.to_public_pem()
}
