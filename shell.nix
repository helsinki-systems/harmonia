with import <nixpkgs> { };
stdenv.mkDerivation {
  name = "bc";
  nativeBuildInputs = [ pkg-config ];
  buildInputs = [
    nix
    boost
  ];

  shellHook = ''
    exec zsh
  '';
}
