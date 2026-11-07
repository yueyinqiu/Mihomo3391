{ config, lib, pkgs, ... }:

let
  # =====================================================================
  # 系统级 mihomo：每个用户一个 listeners/tun，include-uid 分流 + proxy 直连
  # （不查进程）。同时承担 fake-ip DNS，把真实域名下发给 per-user mihomo。
  # =====================================================================
  mihomo-system-config = pkgs.writeText "mihomo-system.yaml" ''
    log-level: debug
    mode: rule
    ipv6: false
    dns:
      enable: true
      enhanced-mode: fake-ip
      fake-ip-range: 198.18.0.1/16
      hosts:
        echo-alice.example.test: 192.168.50.2
        echo-bob.example.test: 192.168.50.2
      nameserver:
        - 1.1.1.1
    listeners:
      - name: tun-alice
        type: tun
        device: tun-alice
        stack: gvisor
        auto-route: true
        strict-route: true
        dns-hijack: [any:53]
        inet4-address: [198.19.0.1/30]
        include-uid: [1001]
        iproute2-table-index: 2100
        iproute2-rule-index: 8000
        proxy: alice-upstream
      - name: tun-bob
        type: tun
        device: tun-bob
        stack: gvisor
        auto-route: true
        strict-route: true
        dns-hijack: [any:53]
        inet4-address: [198.19.1.1/30]
        include-uid: [1002]
        iproute2-table-index: 2101
        # 注意：sing-tun 的 iproute2-rule-index 是"锚点"，一个 tun 实际占用约
        # N..N+3（并在 N+10 放 goto 目标）。两个 tun 的 rule-index 必须间隔足够大
        # 否则规则串互相覆盖（alice=8000 与 bob=8001 就会在 8001/8002/8003 冲突）。
        iproute2-rule-index: 8100
        proxy: bob-upstream
    proxies:
      - name: alice-upstream
        type: socks5
        server: 127.0.0.1
        port: 1080
        udp: true
      - name: bob-upstream
        type: socks5
        server: 127.0.0.1
        port: 1081
        udp: true
  '';

  # per-user mihomo：只放行自己的域名，其余 REJECT。用于强证明「域名下发」：
  # 只有收到 *域名*（而非 IP / fake-ip）才会命中 DOMAIN 规则走 DIRECT。
  mihomo-alice-config = pkgs.writeText "mihomo-alice.yaml" ''
    log-level: debug
    mode: rule
    ipv6: false
    dns:
      enable: true
      hosts:
        echo-alice.example.test: 192.168.50.2
      nameserver:
        - 192.168.50.2
    mixed-port: 1080
    allow-lan: false
    rules:
      - DOMAIN,echo-alice.example.test,DIRECT
      - MATCH,REJECT
  '';

  mihomo-bob-config = pkgs.writeText "mihomo-bob.yaml" ''
    log-level: debug
    mode: rule
    ipv6: false
    dns:
      enable: true
      hosts:
        echo-bob.example.test: 192.168.50.2
      nameserver:
        - 192.168.50.2
    mixed-port: 1081
    allow-lan: false
    rules:
      - DOMAIN,echo-bob.example.test,DIRECT
      - MATCH,REJECT
  '';
in
{
  # nsncd 默认代理所有 NSS 查询（含 hosts/DNS），导致 DNS 由 nscd 用户代发、uid 丢失，
  # uidrange 分流抓不到。用 nsncd 原生的 NSNCD_IGNORE_HOSTS=true 只关掉 hosts 代理，
  # 保留 passwd/group/systemd 动态数据源，应用自己发 DNS（uid 正确）。
  systemd.services.nscd.serviceConfig.Environment = [
    "NSNCD_HANDOFF_TIMEOUT=10"
    "NSNCD_IGNORE_HOSTS=true"
  ];

  boot.kernelModules = [ "tun" ];

  boot.kernel.sysctl = {
    "net.ipv4.ip_forward" = 1;
    "net.ipv6.conf.all.forwarding" = 1;
  };

  virtualisation.vlans = [ 1 ];

  networking.interfaces.eth1.ipv4.addresses = [
    { address = "192.168.50.1"; prefixLength = 24; }
  ];

  # 关键：让 alice/bob 的 DNS 查询目标指向一个"非本机"地址，从而走默认路由进 tun、
  # 被 dns-hijack 劫持（若指向 127.0.0.53 会走 local 表，永远不会进 tun）。
  networking.nameservers = [ "1.1.1.1" ];

  environment.systemPackages = [ pkgs.python3 pkgs.iproute2 pkgs.tcpdump ];

  users.users.alice = {
    isNormalUser = true;
    uid = 1001;
    description = "test user whose traffic is routed by UID";
  };
  users.users.bob = {
    isNormalUser = true;
    uid = 1002;
    description = "second test user";
  };
  users.users.alicesvc = {
    isSystemUser = true;
    uid = 1003;
    group = "alicesvc";
    shell = pkgs.bash;
    description = "dedicated uid for alice's per-user mihomo";
  };
  users.users.bobsvc = {
    isSystemUser = true;
    uid = 1004;
    group = "bobsvc";
    shell = pkgs.bash;
    description = "dedicated uid for bob's per-user mihomo";
  };
  users.groups.alicesvc = { };
  users.groups.bobsvc = { };

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

  systemd.services.mihomo-user-alice = {
    wantedBy = [ "multi-user.target" ];
    after = [ "network.target" ];
    serviceConfig = {
      User = "alicesvc";
      Group = "alicesvc";
      StateDirectory = "mihomo-user-alice";
      ExecStart = "${pkgs.mihomo}/bin/mihomo -d /var/lib/mihomo-user-alice -f /var/lib/mihomo-user-alice/config.yaml";
      Restart = "on-failure";
    };
    preStart = ''
      install -m 644 -o alicesvc -g alicesvc ${mihomo-alice-config} /var/lib/mihomo-user-alice/config.yaml
    '';
  };

  systemd.services.mihomo-user-bob = {
    wantedBy = [ "multi-user.target" ];
    after = [ "network.target" ];
    serviceConfig = {
      User = "bobsvc";
      Group = "bobsvc";
      StateDirectory = "mihomo-user-bob";
      ExecStart = "${pkgs.mihomo}/bin/mihomo -d /var/lib/mihomo-user-bob -f /var/lib/mihomo-user-bob/config.yaml";
      Restart = "on-failure";
    };
    preStart = ''
      install -m 644 -o bobsvc -g bobsvc ${mihomo-bob-config} /var/lib/mihomo-user-bob/config.yaml
    '';
  };
}