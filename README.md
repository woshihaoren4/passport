# passport
Issue and verify vouchers

## example

```rust
fn main() {
    let start = std::time::Instant::now();
    let result = call_dynamic().expect("运行出错");
    let use_time = start.elapsed();
    println!("success :{} 总用时：{}毫秒", result, use_time.as_millis());
}

fn call_dynamic() -> Result<u32, Box<dyn std::error::Error>> {
    unsafe {
        let start = std::time::Instant::now();
        let lib = libloading::Library::new("./src/libwd_passport.dylib")?;
        let sign_func: libloading::Symbol<
            unsafe extern "C" fn(
                data: *const c_char,
                timestamp: c_longlong,
                sign: *const c_char,
            ) -> c_int,
        > = lib.get(b"sign")?;
        let verify_func: libloading::Symbol<
            unsafe extern "C" fn(
                data: *const c_char,
                sign: *const c_char,
                timestamp: c_longlong,
            ) -> c_int,
        > = lib.get(b"verify")?;
        let use_time = start.elapsed();
        println!("启动用时：{}微秒", use_time.as_micros());

        let start = std::time::Instant::now();
        let data = CString::from_vec_unchecked(Vec::from("hello world"));
        let sign = CString::from_vec_unchecked(vec![1; 128]);
        let result = sign_func(data.as_ptr(), 1866248975, sign.as_ptr());
        assert_ne!(result,-1,"签名失败");
        let use_time = start.elapsed();
        println!("签名用时：{}微秒", use_time.as_micros());

        let start = std::time::Instant::now();
        let result = verify_func(data.as_ptr(), sign.as_ptr(), 1866248975);
        assert_ne!(result,-1,"验签失败");
        let use_time = start.elapsed();
        println!("验证用时：{}微秒", use_time.as_micros());

        return Ok(0);
    }
}

```