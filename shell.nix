{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell {
  name = "harmonia";
  nativeBuildInputs = with pkgs; [ rustc cargo pkg-config ];
  buildInputs = with pkgs; [
    (if lib.versionAtLeast nix.version nixVersions.nix_2_12.version then nix else nixVersions.nix_2_12)
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

  # provide a dummy configuration for testing
  CONFIG_FILE = pkgs.writeText "config.toml" "";

  RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
}
