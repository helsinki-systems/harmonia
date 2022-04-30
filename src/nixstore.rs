#![allow(dead_code)]

//TODO(conni2461): FIND A WAY TO COPY LESS LUL

use std::collections::HashMap;
use std::ffi::CStr;
use std::os::raw::{c_char, c_uchar, c_ulong, c_void};
#[cfg(unix)]
use std::os::unix::io::RawFd;

#[repr(C)]
struct NixStrArray {
    arr: *const *const c_char,
    size: usize,
}

#[repr(C)]
struct NixStrTuple {
    lhs: *const c_char,
    rhs: *const c_char,
}

#[repr(C)]
struct NixStrHash {
    arr: *const *const NixStrTuple,
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
    ca: *const c_char,
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
    fn nix_set_verbosity(level: i32);
    fn nix_is_valid_path(path: *const c_char) -> bool;

    fn nix_export_path(path: *const c_char, buf: *mut c_uchar, size: usize);
    fn nix_export_path_to(paths: *const c_char, fd: i32);

    fn nix_query_path_info(path: *const c_char, base32: bool) -> *const NixPathInfo;

    fn nix_query_path_from_hash_part(hash_part: *const c_char) -> *const c_char;

    fn nix_convert_hash(algo: *const c_char, s: *const c_char, to_base_32: bool) -> *const c_char;
    fn nix_sign_string(secret_key: *const c_char, msg: *const c_char) -> *const c_char;

    fn nix_derivation_from_path(drv_path: *const c_char) -> *const NixDrv;

    fn nix_get_build_log(drv_path: *const c_char) -> *const c_char;
    fn nix_get_bin_dir() -> *const c_char;
    fn nix_get_store_dir() -> *const c_char;

    fn free(p: *mut c_void);
}

fn c_char_to_str(c_buf: *const c_char) -> Result<String, Box<dyn std::error::Error>> {
    let c_str: &CStr = unsafe { CStr::from_ptr(c_buf) };
    let str: &str = c_str.to_str()?;
    let ret = str.to_string();
    unsafe { free(c_buf as *mut _) };
    Ok(ret)
}

fn c_char_to_option_str(c_buf: *const c_char) -> Option<String> {
    if c_buf.is_null() {
        return None;
    }
    c_char_to_str(c_buf).ok()
}

fn c_string_array_to_str_vec(
    c_arr: &NixStrArray,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut res = Vec::with_capacity(c_arr.size);
    for i in 0..c_arr.size {
        unsafe { res.push(c_char_to_str(*(c_arr.arr.add(i)))?) };
    }
    unsafe { free(c_arr.arr as *mut _) };
    Ok(res)
}

fn c_string_hash_to_str_hashmap_opt(
    c_hashmap: &NixStrHash,
) -> Result<HashMap<String, Option<String>>, Box<dyn std::error::Error>> {
    let mut res = HashMap::with_capacity(c_hashmap.size);
    for i in 0..c_hashmap.size {
        unsafe {
            let tup = *(c_hashmap.arr.add(i));
            res.insert(c_char_to_str((*tup).lhs)?, c_char_to_option_str((*tup).rhs));
            free(tup as *mut _);
        }
    }
    unsafe { free(c_hashmap.arr as *mut _) };
    Ok(res)
}

fn c_string_hash_to_str_hashmap(
    c_hashmap: &NixStrHash,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut res = HashMap::with_capacity(c_hashmap.size);
    for i in 0..c_hashmap.size {
        unsafe {
            let tup = *(c_hashmap.arr.add(i));
            res.insert(c_char_to_str((*tup).lhs)?, c_char_to_str((*tup).rhs)?);
            free(tup as *mut _);
        }
    }
    unsafe { free(c_hashmap.arr as *mut _) };
    Ok(res)
}

#[derive(Debug)]
pub struct PathInfo {
    pub drv: Option<String>,
    pub narhash: String,
    pub time: u64,
    pub size: usize,
    pub refs: Vec<String>,
    pub sigs: Vec<String>,
    pub ca: Option<String>,
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

pub fn set_verbosity(level: i32) {
    unsafe { nix_set_verbosity(level) }
}

pub fn is_valid_path(path: &str) -> Result<bool, std::ffi::NulError> {
    let c_path = std::ffi::CString::new(path)?;
    unsafe { Ok(nix_is_valid_path(c_path.as_ptr())) }
}

pub fn query_path_info(path: &str, base32: bool) -> Result<PathInfo, Box<dyn std::error::Error>> {
    let c_path = std::ffi::CString::new(path)?;
    unsafe {
        let c_info = nix_query_path_info(c_path.as_ptr(), base32);
        let res = Ok(PathInfo {
            drv: c_char_to_option_str((*c_info).drv),
            narhash: c_char_to_str((*c_info).narhash)?,
            time: (*c_info).time,
            size: (*c_info).size,
            refs: c_string_array_to_str_vec(&(*c_info).refs)?,
            sigs: c_string_array_to_str_vec(&(*c_info).sigs)?,
            ca: c_char_to_option_str((*c_info).ca),
        });
        free(c_info as *mut _);
        res
    }
}

pub fn query_path_from_hash_part(hash_part: &str) -> Option<String> {
    let c_hash_part = match { std::ffi::CString::new(hash_part) } {
        Ok(v) => v,
        Err(_) => return None,
    };
    c_char_to_option_str(unsafe { nix_query_path_from_hash_part(c_hash_part.as_ptr()) })
}

pub fn convert_hash(algo: &str, s: &str, to_base_32: bool) -> Option<String> {
    let c_algo = match { std::ffi::CString::new(algo) } {
        Ok(v) => v,
        Err(_) => return None,
    };
    let c_s = match { std::ffi::CString::new(s) } {
        Ok(v) => v,
        Err(_) => return None,
    };
    c_char_to_option_str(unsafe { nix_convert_hash(c_algo.as_ptr(), c_s.as_ptr(), to_base_32) })
}

pub fn sign_string(secret_key: &str, msg: &str) -> Option<String> {
    let c_secret_key = match { std::ffi::CString::new(secret_key) } {
        Ok(v) => v,
        Err(_) => return None,
    };
    let c_msg = match { std::ffi::CString::new(msg) } {
        Ok(v) => v,
        Err(_) => return None,
    };
    c_char_to_option_str(unsafe { nix_sign_string(c_secret_key.as_ptr(), c_msg.as_ptr()) })
}

pub fn derivation_from_path(drv_path: &str) -> Result<Drv, Box<dyn std::error::Error>> {
    let c_path = std::ffi::CString::new(drv_path)?;
    unsafe {
        let c_drv = nix_derivation_from_path(c_path.as_ptr());
        let res = Ok(Drv {
            outputs: c_string_hash_to_str_hashmap_opt(&(*c_drv).outputs)?,
            input_drvs: c_string_array_to_str_vec(&(*c_drv).input_drvs)?,
            input_srcs: c_string_array_to_str_vec(&(*c_drv).input_srcs)?,
            platform: c_char_to_str((*c_drv).platform)?,
            builder: c_char_to_str((*c_drv).builder)?,
            args: c_string_array_to_str_vec(&(*c_drv).args)?,
            env: c_string_hash_to_str_hashmap(&(*c_drv).env)?,
        });
        free(c_drv as *mut _);
        res
    }
}

pub fn export_path(path: &str, size: usize) -> Option<Vec<u8>> {
    let c_path = match { std::ffi::CString::new(path) } {
        Ok(v) => v,
        Err(_) => return None,
    };

    let mut res: Vec<u8> = vec![0; size];
    unsafe { nix_export_path(c_path.as_ptr(), res.as_mut_ptr(), size) };
    Some(res)
}

pub fn export_path_to(path: &str, fd: RawFd) -> Option<()> {
    let c_path = match { std::ffi::CString::new(path) } {
        Ok(v) => v,
        Err(_) => return None,
    };
    unsafe { nix_export_path_to(c_path.as_ptr(), fd as i32) };

    Some(())
}

pub fn get_build_log(drv_path: &str) -> Option<String> {
    let c_path = match { std::ffi::CString::new(drv_path) } {
        Ok(v) => v,
        Err(_) => return None,
    };
    c_char_to_option_str(unsafe { nix_get_build_log(c_path.as_ptr()) })
}

pub fn get_bin_dir() -> Option<String> {
    c_char_to_option_str(unsafe { nix_get_bin_dir() })
}

pub fn get_store_dir() -> Option<String> {
    c_char_to_option_str(unsafe { nix_get_store_dir() })
}
