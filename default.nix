{ pkgs ? (import <nixpkgs> {}) }: with pkgs;

rustPlatform.buildRustPackage rec {
  name = "harmonia";
  src = nix-gitignore.gitignoreSource [ ] ./.;
  cargoLock.lockFile = ./Cargo.lock;

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [
    nixVersions.nix_2_9
    nlohmann_json
    libsodium
    boost
    openssl
  ];

  meta = with lib; {
    description = "Nix binary cache implemented in rust using libnix-store";
    homepage = https://github.com/helsinki-systems/harmonia;
    license = with licenses; [ mit ];
    maintainers = [ maintainers.conni2461 ];
    platforms = platforms.all;
  };
}
