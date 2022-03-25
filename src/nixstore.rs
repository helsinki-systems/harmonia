#![allow(dead_code)]

use std::ffi::CStr;
use std::os::raw::{c_char, c_ulong, c_void};

#[repr(C)]
struct NixStrArray {
    arr: *const c_char,
    size: usize,
}

#[repr(C)]
struct NixStrTuple {
    lhs: *const c_char,
    rhs: *const c_char,
}

#[repr(C)]
struct NixStrHash {
    arr: *mut NixStrTuple,
    size: usize,
}

#[repr(C)]
struct NixPathInfo {
    drv: *const c_char,
    narhash: *const c_char,
    time: c_ulong,
    size: usize,
    refs: NixStrArray,
    sigs: NixStrArray,
}

#[repr(C)]
struct NixDrv {
    outputs: NixStrHash,
    input_drvs: NixStrArray,
    input_srcs: NixStrArray,
    platform: *const c_char,
    builder: *const c_char,
    args: NixStrArray,
    env: NixStrHash,
}

extern "C" {
    fn nix_init();
    fn nix_set_verbosity(level: i32);
    fn nix_is_valid_path(path: *const c_char) -> bool;

    fn nix_query_path_info(path: *const c_char, base32: bool) -> *const NixPathInfo;

    fn nix_query_path_from_hash_part(hash_part: *const c_char) -> *const c_char;

    fn nix_derivation_from_path(drv_path: *const c_char) -> *const NixDrv;

    fn nix_get_bin_dir() -> *const c_char;
    fn nix_get_store_dir() -> *const c_char;

    fn free(ptr: *mut c_void);
}

fn c_char_to_str(c_buf: *const c_char) -> String {
    let c_str: &CStr = unsafe { CStr::from_ptr(c_buf) };
    let str: &str = c_str.to_str().unwrap();
    let ret = str.to_string();
    unsafe { free(c_buf as *mut c_void) };
    ret
}

fn c_char_to_option_str(c_buf: *const c_char) -> Option<String> {
    if c_buf.is_null() {
        return None;
    }
    Some(c_char_to_str(c_buf))
}

#[derive(Debug)]
pub struct PathInfo {
    pub drv: Option<String>,
    pub narhash: String,
    pub time: u64,
    pub size: usize,
    pub refs: Vec<String>,
    pub sigs: Vec<String>,
}

#[derive(Debug)]
pub struct Drv {
    pub outputs: std::collections::HashMap<String, Option<String>>,
    pub input_drvs: Vec<String>,
    pub input_srcs: Vec<String>,
    pub platform: String,
    pub builder: String,
    pub args: Vec<String>,
    pub env: std::collections::HashMap<String, String>,
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

pub fn query_path_info<S: Into<String>>(
    path: S,
    base32: bool,
) -> Result<PathInfo, std::ffi::NulError> {
    let c_path = std::ffi::CString::new(path.into())?;
    unsafe {
        let c_info = nix_query_path_info(c_path.as_ptr(), base32);
        //TODO(conni2461): Handle unhandled values. We are leaking otherwise
        Ok(PathInfo {
            drv: c_char_to_option_str((*c_info).drv),
            narhash: c_char_to_str((*c_info).narhash),
            time: (*c_info).time,
            size: (*c_info).size,
            refs: vec![],
            sigs: vec![],
        })
    }
}

pub fn query_path_from_hash_part<S: Into<String>>(hash_part: S) -> Option<String> {
    let c_hash_part = std::ffi::CString::new(hash_part.into()).unwrap();
    let res = c_char_to_str(unsafe { nix_query_path_from_hash_part(c_hash_part.as_ptr()) });
    if res.is_empty() {
        None
    } else {
        Some(res)
    }
}

pub fn derivation_from_path<S: Into<String>>(drv_path: S) -> Result<Drv, std::ffi::NulError> {
    let c_path = std::ffi::CString::new(drv_path.into())?;
    unsafe {
        let c_drv = nix_derivation_from_path(c_path.as_ptr());
        //TODO(conni2461): Handle unhandled values. We are leaking otherwise
        Ok(Drv {
            outputs: std::collections::HashMap::new(),
            input_drvs: vec![],
            input_srcs: vec![],
            platform: c_char_to_str((*c_drv).platform),
            builder: c_char_to_str((*c_drv).builder),
            args: vec![],
            env: std::collections::HashMap::new(),
        })
    }
}

pub fn get_bin_dir() -> Option<String> {
    c_char_to_option_str(unsafe { nix_get_bin_dir() })
}

pub fn get_store_dir() -> Option<String> {
    c_char_to_option_str(unsafe { nix_get_store_dir() })
}
