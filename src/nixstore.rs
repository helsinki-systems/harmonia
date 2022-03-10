#![allow(dead_code)]

use std::ffi::CStr;
use std::os::raw::{c_char, c_void};

extern "C" {
    fn nix_init();
    fn nix_set_verbosity(level: i32);
    fn nix_is_valid_path(path: *const c_char) -> bool;

    fn nix_get_bin_dir() -> *const c_char;
    fn nix_get_store_dir() -> *const c_char;

    fn free(ptr: *mut c_void);
}

fn c_char_to_rust_str(c_buf: *const c_char) -> Option<String> {
    if c_buf.is_null() {
        return None;
    }
    let c_str: &CStr = unsafe { CStr::from_ptr(c_buf) };
    let str: &str = c_str.to_str().unwrap();
    let ret = Some(str.to_string());
    unsafe { free(c_buf as *mut c_void) };
    ret
}

pub fn init() {
    unsafe { nix_init() }
}

pub fn set_verbosity(level: i32) {
    unsafe { nix_set_verbosity(level) }
}

pub fn is_valid_path<S: Into<String>>(path: S) -> Result<bool, std::ffi::NulError> {
    let c_path = std::ffi::CString::new(path.into())?;
    unsafe { Ok(nix_is_valid_path(c_path.as_ptr())) }
}

pub fn get_bin_dir() -> Option<String> {
    c_char_to_rust_str(unsafe { nix_get_bin_dir() })
}

pub fn get_store_dir() -> Option<String> {
    c_char_to_rust_str(unsafe { nix_get_store_dir() })
}
