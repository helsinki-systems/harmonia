fn main() {
    println!("cargo:rerun-if-changed=lib/nix.cpp");

    cc::Build::new()
        .cpp(true)
        .flag("-std=c++17")
        .flag("-O2")
        .file("lib/nix.cpp")
        .compile("libnix.a");
    pkg_config::probe_library("nix-store").unwrap();
    pkg_config::probe_library("nix-store").unwrap();
}
