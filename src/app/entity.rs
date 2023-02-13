use crate::algo::{RsaEntity, RsaEntityBuilder};
use crate::common::*;
use chrono::{DateTime, TimeZone};
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::Pkcs1v15Encrypt;
use std::collections::HashMap;
use std::time::Duration;

pub struct PassportEntity {
    certs: HashMap<i64, RsaEntity<Pkcs1v15Encrypt>>,
    interval: i64,
}

impl PassportEntity {
    ///生成十年期，间隔30天的证书所需要的时间在30s内
    pub fn new<Key: AsRef<[u8]>, TZ: TimeZone>(
        key: Key,
        work_range_utc_sec: (DateTime<TZ>, DateTime<TZ>),
        upgrade_cycle: Duration,
        bit_size: usize,
    ) -> anyhow::Result<Self> {
        let interval = upgrade_cycle.as_secs() as i64;
        let list =
            PassportEntity::generate_rsa_entity(key, work_range_utc_sec, interval, bit_size)?;
        let mut certs = HashMap::new();
        for (index, et) in list.into_iter() {
            certs.insert(index, et);
        }
        Self { certs, interval }.ok()
    }

    pub(crate) fn generate_rsa_entity<Key: AsRef<[u8]>, TZ: TimeZone>(
        key: Key,
        work_range_utc_sec: (DateTime<TZ>, DateTime<TZ>),
        interval: i64,
        bit_size: usize,
    ) -> anyhow::Result<Vec<(i64, RsaEntity<Pkcs1v15Encrypt>)>> {
        let start = work_range_utc_sec.0.timestamp();
        let end = work_range_utc_sec.1.timestamp();
        let mut certs = vec![];
        for i in 0..i64::MAX {
            if i * interval + start > end + interval {
                break;
            }
            let mut cn = start + i * interval;
            cn -= cn % interval;
            let rsa_cert = RsaEntityBuilder::new(key.as_ref())
                .set_bit_size(bit_size)
                .set_confuse_number(cn)
                .build_pkcs15()?;
            certs.push((cn, rsa_cert));
        }
        certs.ok()
    }

    pub(crate) fn get_rsa_entity(&self, timestamp_sec: i64) -> Option<&RsaEntity<Pkcs1v15Encrypt>> {
        let ts = timestamp_sec - timestamp_sec % self.interval;
        self.certs.get(&ts)
    }
    pub fn sign_sha256<D: AsRef<[u8]>>(
        &self,
        data: D,
        timestamp_sec: i64,
    ) -> anyhow::Result<Vec<u8>> {
        let re = match self.get_rsa_entity(timestamp_sec) {
            Some(s) => s,
            None => {
                return anyhow::anyhow!("timestamp[{}] Out of scope of verification", timestamp_sec)
                    .err()
            }
        };
        re.sign_sha256(data.as_ref())
    }
    pub fn verify_sha256<D: AsRef<[u8]>>(
        &self,
        data: D,
        sign: D,
        timestamp_sec: i64,
    ) -> anyhow::Result<()> {
        let re = match self.get_rsa_entity(timestamp_sec) {
            Some(s) => s,
            None => {
                return anyhow::anyhow!("timestamp[{}] Out of scope of verification", timestamp_sec)
                    .err()
            }
        };
        re.verify_sha256(data.as_ref(), sign.as_ref())
    }
    pub fn to_public_pem(&self) -> Vec<(i64, String)> {
        let mut res = vec![];
        for (index, cert) in self.certs.iter() {
            res.push((
                *index,
                cert.public_key()
                    .to_pkcs1_pem(Default::default())
                    .expect("PassportEntity.to_public_pem error"),
            ))
        }
        res.sort_by(|a, b| a.0.cmp(&b.0));
        res
    }
    pub fn print_public_pem<Key: AsRef<[u8]>, TZ: TimeZone>(
        key: Key,
        work_range_utc_sec: (DateTime<TZ>, DateTime<TZ>),
        upgrade_cycle: Duration,
        bit_size: usize,
    ) -> anyhow::Result<Vec<(i64, String)>> {
        let interval = upgrade_cycle.as_secs() as i64;
        let list =
            PassportEntity::generate_rsa_entity(key, work_range_utc_sec, interval, bit_size)?;
        let mut certs = vec![];
        for (index, et) in list.into_iter() {
            let s = et
                .public_key()
                .to_pkcs1_pem(Default::default())
                .expect("print_public_pem：rsa certs format pem error");
            certs.push((index, s));
        }
        certs.ok()
    }
}

#[cfg(test)]
mod test {
    use super::PassportEntity;
    use crate::common::{Base64StdDecode, Base64StdEncode};
    use chrono::{TimeZone, Utc};
    use std::time::Duration;

    #[test]
    fn test_entity_new() {
        let start = Utc::now();
        // let end = DateTime::from_str("2023-11-28T00:00:00").expect("截止时间生成错误");
        let end = Utc
            .datetime_from_str("2033-02-06 00:00:00", "%Y-%m-%d %H:%M:%S")
            .expect("截止时间生成错误");
        let interval = Duration::from_secs(60 * 60 * 24 * 30);
        let start_generate = std::time::Instant::now();
        let _entity = PassportEntity::new("hello world", (start, end), interval, 2048)
            .expect("十年期证书生成失败");
        let end_generate = start_generate.elapsed();
        println!(
            "生成十年期，间隔30天的证书需要时间：{}",
            end_generate.as_secs()
        )
    }
    #[test]
    fn test_sign_verify() {
        let start = Utc::now();
        // let end = DateTime::from_str("2023-11-28T00:00:00").expect("截止时间生成错误");
        let end = Utc
            .datetime_from_str("2024-02-06 00:00:00", "%Y-%m-%d %H:%M:%S")
            .expect("截止时间生成错误");
        let interval = Duration::from_secs(60 * 60 * 24 * 30);
        let entity = PassportEntity::new("hello world", (start, end), interval, 1024)
            .expect("十年期证书生成失败");

        let data = "hello world";
        let sign_raw = entity.sign_sha256(data, 1678377600).expect("签名错误");
        let sign = (&sign_raw).base64().expect("base64 编码错误");
        println!("签名字符串 base64编码：len:{} --->{}", sign.len(), sign);
        let result = (&sign).try_decode_base64().expect("签名base64解码失败");
        assert_eq!(sign_raw, result, "base64 编解码前后的数据不一致");
        entity
            .verify_sha256(data.as_bytes(), result.as_slice(), 1678377600)
            .expect("rsa 签名验证失败");
        println!("success");
    }
}

// TSga1i6wbt6IXd7GiGJTGRyfSbpROjK4bFOiuk1zcpUPjxMlsS0EX28VRBsM16aP-WTsZD_catAAtUPX1jP6D1ZXd6-jrKU6fsfAgFfRQmJEhi1ftJlIqyLYQB8S33GJFh80ZnpYUjN4uAzNrC-PUA4RHT0i0Qej4TRSXRVa-cw
// cLD32gQg-fDZ6LfNqcDtCu-vX4glRmf-BZRfCvONMqkM8FlUbNMpRyJy-UJwdvVYvDHigTxcrz4UJBwwds72L_VaBBoASuotlM19DNVPoUxgEWhYGe-xpy1X06zek9-1a4ppMTQGXYx4v08iLQZl4yCGZSl6XyRL8mF9i7fi_0w
