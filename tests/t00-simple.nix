{ pkgs, ... }:

let
  testPkg = pkgs.writeShellScriptBin "simple00-test" ''
    echo hello world
  '';
in
{
  nodes = {
    harmonia = { config, pkgs, ... }:
      {
        imports = [ ../module.nix ];

        services.harmonia.enable = true;

        networking.firewall.allowedTCPPorts = [ 5000 ];
        environment.systemPackages = [ testPkg ];
      };

    client01 = { config, pkgs, lib, ... }:
      {
        nix.requireSignedBinaryCaches = false;
        nix.binaryCaches = lib.mkForce [ "http://harmonia:5000" ];
        nix.extraOptions = ''
          experimental-features = nix-command
        '';
      };
  };

  testScript = ''
    start_all()

    harmonia.wait_for_open_port(5000)

    client01.succeed("curl -f http://harmonia:5000/version")
    client01.succeed("curl -f http://harmonia:5000/nix-cache-info")

    client01.wait_until_succeeds("nix copy --from http://harmonia:5000/ ${testPkg}")
    client01.succeed("${testPkg}/bin/simple00-test")
  '';
}
