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
                return 1;
            }
        };
        let buf: &mut [u8] = &mut *(sign as *const [u8] as *mut [u8]);
        for (i, v) in result.iter().enumerate() {
            buf[i] = *v;
        }
        return 0;
    }
}
#[no_mangle]
pub extern "C" fn verify(data: *const c_char, sign: *const c_char, timestamp: c_longlong) -> c_int {
    unsafe {
        let data = CStr::from_ptr(data).to_bytes();
        let sign = CStr::from_ptr(sign).to_bytes();

        if let Err(e) = super::rsa_sha156_verify(data, sign, timestamp) {
            println!("wd_passport verify error:{}", e);
            return 1;
        }
        return 0;
    }
}
