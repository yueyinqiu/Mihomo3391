{ config, lib, pkgs, ... }:

let
  mihomo-config = pkgs.writeText "mihomo.yaml" ''
    log-level: debug
    mode: rule
    find-process-mode: always
    ipv6: false
    dns:
      enable: false
    tun:
      enable: true
      stack: system
      auto-route: true
      dns-hijack: []
      inet4-address: [198.20.0.1/30]
      iproute2-table-index: 2200
      iproute2-rule-index: 9000
    rules:
      - MATCH,DIRECT
  '';
in
{
  boot.kernelModules = [ "tun" ];
  boot.kernel.sysctl = {
    "net.ipv4.ip_forward" = 1;
    "net.ipv6.conf.all.forwarding" = 1;
  };

  environment.systemPackages = [ pkgs.python3 pkgs.iproute2 ];

  users.users.alice = {
    isNormalUser = true;
    uid = 1001;
    description = "test user";
  };

  systemd.services.mihomo = {
    wantedBy = [ "multi-user.target" ];
    after = [ "network.target" ];
    serviceConfig = {
      StateDirectory = "mihomo";
      ExecStart = "${pkgs.mihomo}/bin/mihomo -d /var/lib/mihomo -f /var/lib/mihomo/config.yaml";
      Restart = "on-failure";
      AmbientCapabilities = [ "CAP_NET_ADMIN" "CAP_NET_RAW" "CAP_NET_BIND_SERVICE" ];
    };
    preStart = ''
      install -m 644 ${mihomo-config} /var/lib/mihomo/config.yaml
    '';
  };
}