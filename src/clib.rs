use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_longlong};
// use super::*;
#[no_mangle]
pub extern "C" fn sign(data: *const c_char, timestamp: c_longlong, sign: *mut c_char) -> c_int {
    unsafe {
        let data = CStr::from_ptr(data).to_bytes();
        let sign = CStr::from_ptr(sign).to_bytes();

        let result = match super::rsa_sha256_sign(data, timestamp) {
            Ok(o) => o,
            Err(e) => {
                println!("wd_passport error:{}", e);
                return -1;
            }
        };
        let len = result.len();
        let buf: &mut [u8] = &mut *(sign as *const [u8] as *mut [u8]);
        for (i, v) in result.iter().enumerate() {
            buf[i] = *v;
        }
        return len as c_int;
    }
}
#[no_mangle]
pub extern "C" fn verify(data: *const c_char, sign: *const c_char, timestamp: c_longlong) -> c_int {
    unsafe {
        let data = CStr::from_ptr(data).to_bytes();
        let sign = CStr::from_ptr(sign).to_bytes();

        if let Err(e) = super::rsa_sha156_verify(data, sign, timestamp) {
            println!("wd_passport verify error:{}", e);
            return -1;
        }
        return 0;
    }
}

#[no_mangle]
pub extern "C" fn encrypt(data: *const c_char, timestamp: c_longlong, ciphertext: *mut c_char) -> c_int {
    unsafe {
        let data = CStr::from_ptr(data).to_bytes();
        let ciphertext = CStr::from_ptr(ciphertext).to_bytes();

        let result = match super::rsa_sha256_encrypt(data, timestamp) {
            Ok(o) => o,
            Err(e) => {
                println!("wd_passport encrypt error:{}", e);
                return -1;
            }
        };
        let len = result.len();
        let buf: &mut [u8] = &mut *(ciphertext as *const [u8] as *mut [u8]);
        for (i, v) in result.iter().enumerate() {
            buf[i] = *v;
        }
        return len as c_int;
    }
}

#[no_mangle]
pub extern "C" fn decrypt(plaintext: *const c_char, data: *const c_char, timestamp: c_longlong) -> c_int {
    unsafe {
        let data = CStr::from_ptr(data).to_bytes();
        let plaintext = CStr::from_ptr(plaintext).to_bytes();

        let buf = match super::rsa_sha256_decrypt(plaintext,  timestamp) {
            Ok(o) => o,
            Err(e) => {
                println!("wd_passport encrypt error:{}",e);
                return -1;
            }
        };
        let len = buf.len();
        let data_len = data.len();
        let data: &mut [u8] = &mut *(data as *const [u8] as *mut [u8]);
        for i in 0..data_len{
            if i >= len {
                return len as c_int;
            }
            data[i] = buf[i]
        }
        return data_len as c_int;
    }
}
