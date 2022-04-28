with import <nixpkgs> { };
stdenv.mkDerivation {
  name = "harmonia";
  nativeBuildInputs = [ rustc cargo gcc pkg-config ];
  buildInputs = [
    nix_2_7
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

  # PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";
  RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";

  shellHook = ''
  '';
}
