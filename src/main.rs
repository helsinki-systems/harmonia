use std::ffi::CStr;
use std::os::raw::c_char;

extern "C" {
    fn getStoreDir() -> *const c_char;
}

fn main() {
    let c_buf: *const c_char = unsafe { getStoreDir() };
    let c_str: &CStr = unsafe { CStr::from_ptr(c_buf) };
    let str: &str = c_str.to_str().unwrap();
    println!("{}", str);
}
