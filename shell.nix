with import <nixpkgs> { };
stdenv.mkDerivation {
  name = "harmonia";
  nativeBuildInputs = [ rustc cargo gcc pkg-config ];
  buildInputs = [
    nix
    nlohmann_json
    libsodium
    boost
    rustfmt
    clippy
    cargo-watch
    cargo-edit
    cargo-outdated
    cargo-audit
    openssl
  ];

  RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
}
