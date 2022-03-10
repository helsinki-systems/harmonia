use std::ffi::CStr;
use std::os::raw::c_char;

extern "C" {
    fn getBinDir() -> *const c_char;
    fn getStoreDir() -> *const c_char;
}

fn c_char_to_rust_str(c_buf: *const c_char) -> String {
    let c_str: &CStr = unsafe { CStr::from_ptr(c_buf) };
    let str: &str = c_str.to_str().unwrap();
    str.to_string()
}

pub fn get_bin_dir() -> String {
    c_char_to_rust_str(unsafe { getBinDir() })
}

pub fn get_store_dir() -> String {
    c_char_to_rust_str(unsafe { getStoreDir() })
}
