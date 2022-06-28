# libnixstore

Is a library that provides simple access to your local nix store, based on c++
bindings. It mimics the already available perl bindings but also adds bindings
on top, that might be useful.

Note: This project provides bindings, this makes the project automatically unsafe.

Supported nix version:
- nix 2.8
- nix 2.9

## Requirements

It is only available for systems that have the nix package manager installed.
To achieve this you should setup a simple shell.nix

```nix
with import <nixpkgs> { };
stdenv.mkDerivation {
  name = "xyz";
  nativeBuildInputs = [ rustc cargo gcc pkg-config ];
  buildInputs = [
    # required
    nixVersions.nix_2_9
    nlohmann_json
    libsodium
    boost

    # additional packages you might need
    rustfmt
    clippy
    # ...
  ];

  RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
}
```

## Example

```rust
fn main() {
    libnixstore::init();
    println!("{}", libnixstore::get_store_dir());
}
```
