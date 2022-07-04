{ pkgs, ... }:

let
  helloCa = pkgs.hello.overrideAttrs (_: { __contentAddressed = true; });
  nixpkgs = pkgs.path;
in
{
  nodes = {
    harmonia = { config, pkgs, ... }:
      {
        imports = [ ../module.nix ];

        services.harmonia.enable = true;

        networking.firewall.allowedTCPPorts = [ 5000 ];
        environment.systemPackages = [ helloCa ];

        nix.extraOptions = ''
          experimental-features = nix-command ca-derivations
        '';
      };

    client01 = { config, pkgs, lib, ... }:
      {
        nix.binaryCaches = lib.mkForce [ "http://harmonia:5000" ];
        nix.extraOptions = ''
          experimental-features = nix-command ca-derivations
          require-sigs = false
        '';
      };
  };

  testScript = ''
    start_all()

    harmonia.wait_for_open_port(5000)

    client01.succeed("curl -fs http://harmonia:5000/version")
    client01.succeed("curl -fs http://harmonia:5000/nix-cache-info")

    # Instructions are from https://discourse.nixos.org/t/content-addressed-nix-call-for-testers/12881
    #client01.succeed("nix shell --trusted-public-keys ''' --substituters http://harmonia:5000/ ${helloCa} -c hello")
    client01.succeed("nix copy --impure --to file:///tmp/binary-cache --expr '(import ${nixpkgs} {}).hello.overrideAttrs (_: { __contentAddressed = true; })'")
    client01.succeed("nix store verify --sigs-needed 10000 ${helloCa}")
  '';
}
