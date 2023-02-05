use std::panic;
use ::base64::Engine;

pub trait Base64StdEncode{
    fn base64(self)->anyhow::Result<String>;
}

pub trait Base64StdDecode{
    fn try_decode_base64(self)->anyhow::Result<Vec<u8>>;
}

impl<T: AsRef<[u8]> + panic::UnwindSafe> Base64StdEncode for T {
    fn base64(self) -> anyhow::Result<String> {
        encode(self.as_ref())
    }
}

impl<T: AsRef<[u8]>> Base64StdDecode for T {
    fn try_decode_base64(self)->anyhow::Result<Vec<u8>> {
        decode(self.as_ref())
    }
}

pub fn encode<T: AsRef<[u8]> + panic::UnwindSafe>(data:T)->anyhow::Result<String>{
    let result = panic::catch_unwind(move||{
        ::base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
    });
    match result {
        Ok(o)=>Ok(o),
        Err(e)=> Err(anyhow::anyhow!("base64 encode panic:{:?}",e))
    }
}

pub fn decode<T: AsRef<[u8]>>(data:T)->anyhow::Result<Vec<u8>>{
    let buf = ::base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(data)?;Ok(buf)
}