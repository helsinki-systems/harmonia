with import <nixpkgs> { };
stdenv.mkDerivation {
  name = "bc";
  nativeBuildInputs = [ rustc cargo gcc pkg-config ];
  buildInputs = [
    nix
    boost
    rustfmt
    cargo-watch
    cargo-edit
  ];

  RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";

  shellHook = ''
  '';
}
