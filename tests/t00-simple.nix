(import ./lib.nix)
({pkgs, ...} : {
  name = "t00-simple";

  nodes = {
    harmonia = { config, pkgs, ... }:
      {
        imports = [ ../module.nix ];

        services.harmonia.enable = true;

        networking.firewall.allowedTCPPorts = [ 5000 ];
        environment.systemPackages = [ pkgs.hello ];
      };

    client01 = { config, pkgs, lib, ... }:
      {
        nix.settings.require-sigs = false;
        nix.settings.substituters = lib.mkForce [ "http://harmonia:5000" ];
        nix.extraOptions = ''
          experimental-features = nix-command
        '';
      };
  };

  testScript = let
    hashPart = pkg: builtins.substring (builtins.stringLength builtins.storeDir + 1) 32 pkg.outPath;
  in ''
    import json
    start_all()

    client01.wait_until_succeeds("curl -f http://harmonia:5000/version")
    client01.succeed("curl -f http://harmonia:5000/nix-cache-info")

    client01.wait_until_succeeds("nix copy --from http://harmonia:5000/ ${pkgs.hello}")
    out = client01.wait_until_succeeds("curl http://harmonia:5000/${hashPart pkgs.hello}.ls")
    data = json.loads(out)
    print(out)
    assert data["version"] == 1, "version is not correct"
    assert data["root"]["entries"]["bin"]["type"] == "directory", "expect bin directory in listing"
    client01.succeed("${pkgs.hello}/bin/hello")
  '';
})
