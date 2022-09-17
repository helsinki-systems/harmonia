#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(
    nonstandard_style,
    rust_2018_idioms,
    rustdoc::broken_intra_doc_links,
    rustdoc::private_intra_doc_links
)]
#![forbid(non_ascii_idents)]

#[cxx::bridge(namespace = "libnixstore")]
mod ffi {
    struct InternalPathInfo {
        drv: String,
        narhash: String,
        time: i64,
        size: usize,
        refs: Vec<String>,
        sigs: Vec<String>,
        ca: String,
    }

    struct InternalTuple {
        lhs: String,
        rhs: String,
    }

    struct InternalDrv {
        outputs: Vec<InternalTuple>,
        input_drvs: Vec<String>,
        input_srcs: Vec<String>,
        platform: String,
        builder: String,
        args: Vec<String>,
        env: Vec<InternalTuple>,
    }

    unsafe extern "C++" {
        include!("libnixstore/include/nix.h");

        // bindings that are also available in the perl bindings
        fn init();
        fn set_verbosity(level: i32);
        fn is_valid_path(path: &str) -> Result<bool>;
        fn query_references(path: &str) -> Result<Vec<String>>;
        fn query_path_hash(path: &str) -> Result<String>;
        fn query_deriver(path: &str) -> Result<String>;
        fn query_path_info(path: &str, base32: bool) -> Result<InternalPathInfo>;
        fn query_raw_realisation(output_id: &str) -> Result<String>;
        fn query_path_from_hash_part(hash_part: &str) -> Result<String>;
        fn compute_fs_closure(
            flip_direction: bool,
            include_outputs: bool,
            paths: Vec<&str>,
        ) -> Result<Vec<String>>;
        fn topo_sort_paths(paths: Vec<&str>) -> Result<Vec<String>>;
        fn follow_links_to_store_path(path: &str) -> Result<String>;
        fn export_paths(fd: i32, paths: Vec<&str>) -> Result<()>;
        fn import_paths(fd: i32, dont_check_signs: bool) -> Result<()>;
        fn hash_path(algo: &str, base32: bool, path: &str) -> Result<String>;
        fn hash_file(algo: &str, base32: bool, path: &str) -> Result<String>;
        fn hash_string(algo: &str, base32: bool, s: &str) -> Result<String>;
        fn convert_hash(algo: &str, s: &str, to_base_32: bool) -> Result<String>;
        fn sign_string(secret_key: &str, msg: &str) -> Result<String>;
        fn check_signature(public_key: &str, sig: &str, msg: &str) -> Result<bool>;
        fn add_to_store(src_path: &str, recursive: i32, algo: &str) -> Result<String>;
        fn make_fixed_output_path(
            recursive: bool,
            algo: &str,
            hash: &str,
            name: &str,
        ) -> Result<String>;
        fn derivation_from_path(drv_path: &str) -> Result<InternalDrv>;
        fn add_temp_root(store_path: &str) -> Result<()>;
        fn get_bin_dir() -> String;
        fn get_store_dir() -> String;

        // additional but useful for harmonia
        fn get_build_log(derivation_path: &str) -> Result<String>;
        fn get_nar_list(store_path: &str) -> Result<String>;
        fn dump_path(
            store_part: &str,
            callback: unsafe extern "C" fn(data: &[u8], user_data: usize) -> bool,
            user_data: usize,
        );
    }
}

fn string_to_opt(v: String) -> Option<String> {
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

pub struct PathInfo {
    pub drv: Option<String>,
    pub narhash: String,
    pub time: i64,
    pub size: usize,
    pub refs: Vec<String>,
    pub sigs: Vec<String>,
    pub ca: Option<String>,
}

pub struct Drv {
    pub outputs: std::collections::HashMap<String, Option<String>>,
    pub input_drvs: Vec<String>,
    pub input_srcs: Vec<String>,
    pub platform: String,
    pub builder: String,
    pub args: Vec<String>,
    pub env: std::collections::HashMap<String, String>,
}

#[inline]
/// Perform any necessary effectful operation to make the store up and running.
pub fn init() {
    ffi::init();
}

#[inline]
/// Set the loglevel.
pub fn set_verbosity(level: i32) {
    ffi::set_verbosity(level)
}

#[inline]
/// Check whether a path is valid.
pub fn is_valid_path(path: &str) -> bool {
    ffi::is_valid_path(path).unwrap_or(false)
}

#[inline]
/// Return references of a valid path. It is permitted to omit the name part of the store path.
pub fn query_references(path: &str) -> Result<Vec<String>, cxx::Exception> {
    ffi::query_references(path)
}

#[inline]
/// Return narhash of a valid path. It is permitted to omit the name part of the store path.
pub fn query_path_hash(path: &str) -> Result<String, cxx::Exception> {
    ffi::query_path_hash(path)
}

#[inline]
/// Return deriver of a valid path. It is permitted to omit the name part of the store path.
pub fn query_deriver(path: &str) -> Option<String> {
    match ffi::query_deriver(path) {
        Ok(v) => string_to_opt(v),
        Err(_) => None,
    }
}

#[inline]
/// Query information about a valid path. It is permitted to omit the name part of the store path.
pub fn query_path_info(path: &str, base32: bool) -> Result<PathInfo, cxx::Exception> {
    let res = ffi::query_path_info(path, base32)?;
    Ok(PathInfo {
        drv: string_to_opt(res.drv),
        narhash: res.narhash,
        time: res.time,
        size: res.size,
        refs: res.refs,
        sigs: res.sigs,
        ca: string_to_opt(res.ca),
    })
}

#[inline]
/// Query the information about a realisation
pub fn query_raw_realisation(output_id: &str) -> Option<String> {
    match ffi::query_raw_realisation(output_id) {
        Ok(v) => string_to_opt(v),
        Err(_) => None,
    }
}

#[inline]
/// Query the full store path given the hash part of a valid store path, or empty if the path
/// doesn't exist.
pub fn query_path_from_hash_part(hash_part: &str) -> Option<String> {
    match ffi::query_path_from_hash_part(hash_part) {
        Ok(v) => string_to_opt(v),
        Err(_) => None,
    }
}

#[inline]
/// Returns all store paths in the file system closure of `storePath`
///
/// That is, all paths than can be directly or indirectly reached from it. If `flip_direction` is
/// true, the set of paths that can reach `storePath` is returned; that is, the closures under the
/// `referrers` relation instead of the `references` relation is returned.
pub fn compute_fs_closure(
    flip_direction: bool,
    include_outputs: bool,
    paths: Vec<&str>,
) -> Result<Vec<String>, cxx::Exception> {
    ffi::compute_fs_closure(flip_direction, include_outputs, paths)
}

#[inline]
/// Sort a set of paths topologically under the references relation. If `p` refers to `q`, then `p`
/// precedes `q` in this list.
pub fn topo_sort_paths(paths: Vec<&str>) -> Result<Vec<String>, cxx::Exception> {
    ffi::topo_sort_paths(paths)
}

#[inline]
/// Follow symlinks until we end up with a path in the Nix store. Will transform the results to
/// store paths.
pub fn follow_links_to_store_path(path: &str) -> Result<String, cxx::Exception> {
    ffi::follow_links_to_store_path(path)
}

#[inline]
/// Export multiple paths in the format expected by `nix-store --import`.
pub fn export_paths(fd: i32, paths: Vec<&str>) -> Result<(), cxx::Exception> {
    ffi::export_paths(fd, paths)
}

#[inline]
/// Import a sequence of NAR dumps created by `export_paths()` into the Nix store. Optionally, the
/// contents of the NARs are preloaded into the specified FS accessor to speed up subsequent
/// access.
pub fn import_paths(fd: i32, dont_check_signs: bool) -> Result<(), cxx::Exception> {
    ffi::import_paths(fd, dont_check_signs)
}

#[inline]
/// Compute the hash of the given path. The hash is defined as (essentially)
/// `hashString(ht, dumpPath(path))`.
pub fn hash_path(algo: &str, base32: bool, path: &str) -> Result<String, cxx::Exception> {
    ffi::hash_path(algo, base32, path)
}

#[inline]
/// Compute the hash of the given file.
pub fn hash_file(algo: &str, base32: bool, path: &str) -> Result<String, cxx::Exception> {
    ffi::hash_file(algo, base32, path)
}

#[inline]
/// Compute the hash of the given string.
pub fn hash_string(algo: &str, base32: bool, s: &str) -> Result<String, cxx::Exception> {
    ffi::hash_string(algo, base32, s)
}

#[inline]
/// Parse the hash from a string representation in the format `[<type>:]<base16|base32|base64>` or
/// `<type>-<base64>` to a string representation of the hash, in `base-16`, `base-32`. The result
/// is not prefixed by the hash type.
pub fn convert_hash(algo: &str, s: &str, to_base_32: bool) -> Result<String, cxx::Exception> {
    ffi::convert_hash(algo, s, to_base_32)
}

#[inline]
/// Return a detached signature of the given string.
pub fn sign_string(secret_key: &str, msg: &str) -> Result<String, cxx::Exception> {
    ffi::sign_string(secret_key, msg)
}

#[inline]
/// Verify that `sig` is a valid signature for `msg`, using the signer's `public_key`.
pub fn check_signature(public_key: &str, sig: &str, msg: &str) -> Result<bool, cxx::Exception> {
    ffi::check_signature(public_key, sig, msg)
}

#[inline]
/// This is the preparatory part of `addToStore()`;
///
/// It computes the store path to which `src_path` is to be copied. Returns the store path.
pub fn add_to_store(src_path: &str, recursive: i32, algo: &str) -> Result<String, cxx::Exception> {
    ffi::add_to_store(src_path, recursive, algo)
}

#[inline]
pub fn make_fixed_output_path(
    recursive: bool,
    algo: &str,
    hash: &str,
    name: &str,
) -> Result<String, cxx::Exception> {
    ffi::make_fixed_output_path(recursive, algo, hash, name)
}

#[inline]
/// Read a derivation, after ensuring its existence through `ensurePath()`.
pub fn derivation_from_path(drv_path: &str) -> Result<Drv, cxx::Exception> {
    let res = ffi::derivation_from_path(drv_path)?;
    let mut outputs = std::collections::HashMap::new();
    for out in res.outputs {
        outputs.insert(out.lhs, string_to_opt(out.rhs));
    }

    let mut env = std::collections::HashMap::new();
    for v in res.env {
        env.insert(v.lhs, v.rhs);
    }

    Ok(Drv {
        outputs,
        input_drvs: res.input_drvs,
        input_srcs: res.input_srcs,
        platform: res.platform,
        builder: res.builder,
        args: res.args,
        env,
    })
}

#[inline]
/// Add a store path as a temporary root of the garbage collector. The root disappears as soon as
/// we exit.
pub fn add_temp_root(store_path: &str) -> Result<(), cxx::Exception> {
    ffi::add_temp_root(store_path)
}

#[inline]
/// Return the path to the directory where the main programs are stored.
pub fn get_bin_dir() -> String {
    ffi::get_bin_dir()
}

#[inline]
/// Returns the path to the directory where nix store sources and derived files.
pub fn get_store_dir() -> String {
    ffi::get_store_dir()
}

#[inline]
/// Return the build log of the specified store path, if available, or null otherwise.
pub fn get_build_log(derivation_path: &str) -> Option<String> {
    match ffi::get_build_log(derivation_path) {
        Ok(v) => string_to_opt(v),
        Err(_) => None,
    }
}

#[inline]
/// Return a JSON representation as String of the contents of a NAR (except file contents).
pub fn get_nar_list(store_path: &str) -> Result<String, cxx::Exception> {
    ffi::get_nar_list(store_path)
}

fn dump_path_trampoline<F>(data: &[u8], userdata: usize) -> bool
where
    F: FnMut(&[u8]) -> bool,
{
    let closure = unsafe { &mut *((userdata as *mut std::ffi::c_void) as *mut F) };
    closure(data)
}

#[inline]
/// Dump a store path in NAR format. The data is passed in chunks to callback
pub fn dump_path<F>(store_path: &str, callback: F)
where
    F: FnMut(&[u8]) -> bool,
{
    ffi::dump_path(
        store_path,
        dump_path_trampoline::<F>,
        &callback as *const _ as *const std::ffi::c_void as usize,
    );
}
