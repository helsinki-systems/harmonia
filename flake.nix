{
  description = "Nix binary cache implemented in rust using libnix-store";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";

  outputs = inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      perSystem = { config, pkgs, ... }: {
        packages.harmonia = pkgs.callPackage ./. {};
        packages.default = config.packages.harmonia;
        checks = import ./tests/default.nix {
          inherit pkgs;
          inherit (inputs) self;
        };
        devShells.default = pkgs.callPackage ./shell.nix {};
      };
      flake.nixosModules.harmonia = ./module.nix;
    };
}
