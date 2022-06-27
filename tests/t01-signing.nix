{ pkgs, ... }:

let
  pgsqlPkg = pkgs.postgresql;

  copyScript = pkgs.writeShellScriptBin "copy-test" ''
    set -e
    PUBKEY=$(cat ${./cache.pk})
    nix copy \
      --option trusted-public-keys "$PUBKEY" \
      --from http://harmonia:5000 \
      --to /root/test-store \
      "$@"
  '';
in
{
  nodes = {
    harmonia = { config, pkgs, ... }:
      {
        imports = [ ../module.nix ];

        services.harmonia = {
          enable = true;
          settings = {
            sign_key_path = "${./cache.sk}";
          };
        };

        networking.firewall.allowedTCPPorts = [ 5000 ];
        environment.systemPackages = [ pgsqlPkg ];
      };

    client01 = { config, pkgs, lib, ... }:
      {
        environment.systemPackages = [ copyScript ];
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

    client01.wait_until_succeeds("${copyScript}/bin/copy-test ${pgsqlPkg}")
    client01.succeed("${pgsqlPkg}/bin/psql --version")
  '';
}
