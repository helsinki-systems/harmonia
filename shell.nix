with import <nixpkgs-unstable> { };
stdenv.mkDerivation {
  name = "bc";
  nativeBuildInputs = [ rustc cargo gcc pkg-config ];
  buildInputs = [
    nix
    nlohmann_json
    libsodium
    boost
    rustfmt
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
