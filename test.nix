{ nixpkgs }:

with builtins;

let
  system = "x86_64-linux";
  nixosPath = nixpkgs.path + "/nixos";
  makeTest = import (nixosPath + "/tests/make-test-python.nix");

  toTest = file: _: {
    name = replaceStrings [ ".nix" ] [ "" ] file;
    value = makeTest (import (./. + "/tests/${file}")) { };
  };

  tests = nixpkgs.lib.mapAttrs' toTest (builtins.readDir ./tests);
in
tests
