with import <nixpkgs> { };
stdenv.mkDerivation {
  name = "bc";
  nativeBuildInputs = [ rustc cargo gcc pkg-config ];
  buildInputs = [
    unstable.nix
    unstable.nlohmann_json
    boost
    rustfmt
    cargo-watch
    cargo-edit
    openssl
  ];

  # PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";
  RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";

  shellHook = ''
  '';
}
