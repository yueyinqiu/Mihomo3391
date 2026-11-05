{ config, lib, pkgs, ... }:

let
  # 系统级 mihomo：一个 listeners/tun，按 UID(1001) 分流，直接 proxy 给用户 mihomo
  mihomo-system-config = pkgs.writeText "mihomo-system.yaml" ''
    log-level: debug
    mode: rule
    ipv6: false
    dns:
      enable: false
    listeners:
      - name: tun-alice
        type: tun
        device: tun-alice
        stack: gvisor
        auto-route: true
        strict-route: true
        dns-hijack: []
        inet4-address: [198.19.0.1/30]
        include-uid: [1001]
        iproute2-table-index: 2100
        iproute2-rule-index: 8000
        proxy: alice-upstream
    proxies:
      - name: alice-upstream
        type: socks5
        server: 127.0.0.1
        port: 1080
        udp: true
  '';

  # 用户 mihomo：以专用 uid(1002) 跑，mixed 入站 127.0.0.1:1080，DIRECT 出站
  mihomo-user-config = pkgs.writeText "mihomo-user.yaml" ''
    log-level: debug
    mode: global
    ipv6: false
    dns:
      enable: false
    mixed-port: 1080
    allow-lan: false
  '';
in
{
  boot.kernelModules = [ "tun" ];
  boot.kernel.sysctl = {
    "net.ipv4.ip_forward" = 1;
    "net.ipv6.conf.all.forwarding" = 1;
  };

  virtualisation.vlans = [ 1 ];

  networking.interfaces.eth1.ipv4.addresses = [
    { address = "192.168.50.1"; prefixLength = 24; }
  ];

  environment.systemPackages = [ pkgs.python3 pkgs.iproute2 pkgs.tcpdump ];

  users.users.alice = {
    isNormalUser = true;
    uid = 1001;
    description = "test user whose traffic is routed by UID";
  };
  users.users.alicesvc = {
    isSystemUser = true;
    uid = 1002;
    group = "alicesvc";
    shell = pkgs.bash;
    description = "dedicated uid for the per-user mihomo";
  };
  users.groups.alicesvc = { };

  systemd.services.mihomo-system = {
    wantedBy = [ "multi-user.target" ];
    after = [ "network.target" ];
    serviceConfig = {
      StateDirectory = "mihomo-system";
      ExecStart = "${pkgs.mihomo}/bin/mihomo -d /var/lib/mihomo-system -f /var/lib/mihomo-system/config.yaml";
      Restart = "on-failure";
      AmbientCapabilities = [ "CAP_NET_ADMIN" "CAP_NET_RAW" "CAP_NET_BIND_SERVICE" ];
    };
    preStart = ''
      install -m 644 ${mihomo-system-config} /var/lib/mihomo-system/config.yaml
    '';
  };

  systemd.services.mihomo-user = {
    wantedBy = [ "multi-user.target" ];
    after = [ "network.target" ];
    serviceConfig = {
      User = "alicesvc";
      Group = "alicesvc";
      StateDirectory = "mihomo-user";
      ExecStart = "${pkgs.mihomo}/bin/mihomo -d /var/lib/mihomo-user -f /var/lib/mihomo-user/config.yaml";
      Restart = "on-failure";
    };
    preStart = ''
      install -m 644 -o alicesvc -g alicesvc ${mihomo-user-config} /var/lib/mihomo-user/config.yaml
    '';
  };
}