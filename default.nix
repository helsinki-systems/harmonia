{ pkgs ? (import <nixpkgs> {}) }: with pkgs;

rustPlatform.buildRustPackage {
  name = "harmonia";
  src = nix-gitignore.gitignoreSource [ ] (lib.sources.sourceFilesBySuffices (lib.cleanSource ./.) [ ".rs" ".toml" ".lock" ".cpp" ".h" ".md" ]);
  cargoLock.lockFile = ./Cargo.lock;

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [
    nixVersions.nix_2_9
    nlohmann_json
    libsodium
    boost
    openssl
  ];

  dontCargoCheck = true;

  meta = with lib; {
    description = "Nix binary cache implemented in rust using libnix-store";
    homepage = "https://github.com/helsinki-systems/harmonia";
    license = with licenses; [ mit ];
    maintainers = [ maintainers.conni2461 ];
    platforms = platforms.all;
  };
}
