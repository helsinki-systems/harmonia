{ pkgs, ... }:

let
  testPkg = pkgs.writeShellScriptBin "varnish-test" ''
    echo hello world
  '';
in
{
  nodes = {
    harmonia = { config, pkgs, ... }:
      {
        imports = [ ../module.nix ];

        services.harmonia.enable = true;

        services.varnish = {
          enable = true;
          http_address = "0.0.0.0:80";
          config = ''
            vcl 4.0;
            backend harmonia {
              .host = "::1";
              .port = "5000";
            }
          '';
        };

        networking.firewall.allowedTCPPorts = [ 80 ];
        environment.systemPackages = [ testPkg ];
      };

    client01 = { config, pkgs, lib, ... }:
      {
        nix.requireSignedBinaryCaches = false;
        nix.binaryCaches = lib.mkForce [ "http://harmonia" ];
        nix.extraOptions = ''
          experimental-features = nix-command
        '';
      };
  };

  testScript = ''
    start_all()

    harmonia.wait_for_open_port(80)
    harmonia.wait_for_open_port(5000)

    client01.succeed("curl -f http://harmonia/version")
    client01.succeed("curl -f http://harmonia/nix-cache-info")

    client01.wait_until_succeeds("nix copy --from http://harmonia/ ${testPkg}")
    client01.succeed("${testPkg}/bin/varnish-test")
  '';
}
