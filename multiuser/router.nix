{ config, lib, pkgs, ... }:

let
  yaml = pkgs.formats.yaml { };

  # 使用方自己按约定算（和 system 侧一致，不依赖 module 暴露任何东西）：
  #   socksPort = socksPortBase(7890) + seq（seq 默认 = uid）
  derivedUsers = lib.mapAttrsToList (name: u: {
    name = name;
    socksPort = 7890 + u.uid;
  }) (lib.filterAttrs (_: u: u.isNormalUser == true) config.users.users);

  # ---------------------------------------------------------------------
  # per-user 侧（真实里属于 home config，这里作为「使用方」定义）
  # ---------------------------------------------------------------------
  perUserMihomoConfig = u: yaml.generate "mihomo-${u.name}.yaml" {
    mode = "rule";
    log-level = "info";
    ipv6 = false;
    mixed-port = u.socksPort;   # host 直连，各 user 不同端口；出站用 interface-name 绑定出站网卡（不回环）
    allow-lan = false;
    interface-name = "eth1";
    dns = {
      enable = true;
      hosts = { "echo-${u.name}.example.test" = "192.168.50.2"; };
      nameserver = [ "192.168.50.2" ];
    };
    rules = [
      "DOMAIN,echo-${u.name}.example.test,DIRECT"
      "MATCH,REJECT"
    ];
  };
in
{
  imports = [ ./per-user-tun.nix ];

  # ---- 测试拓扑（非泛用） ----
  virtualisation.vlans = [ 1 ];

  networking.interfaces.eth1.ipv4.addresses = [
    { address = "192.168.50.1"; prefixLength = 24; }
  ];

  # 让 alice/bob 的 DNS 查询走默认路由进 tun、被 dns-hijack 劫持
  networking.nameservers = [ "1.1.1.1" ];

  environment.systemPackages = [ pkgs.python3 pkgs.iproute2 ];

  # ---- 测试用户 ----
  users.users = {
    alice = { isNormalUser = true; uid = 1001; description = "test user"; };
    bob   = { isNormalUser = true; uid = 1002; description = "test user"; };
  };

  # ---- 配置 per-user-tun module（仅 system 侧） ----
  per-user-tun = {
    enable = true;
  };

  # ---- per-user 侧（模拟 home config） ----
  systemd.services =
    lib.listToAttrs (map (u:
      lib.nameValuePair "user-tun-mihomo-${u.name}" {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig = {
          User = u.name;
          StateDirectory = "user-tun-mihomo-${u.name}";
          ExecStart = "${lib.getExe pkgs.mihomo} -d /var/lib/user-tun-mihomo-${u.name} -f ${perUserMihomoConfig u}";
          Restart = "on-failure";
        };
      }
    ) derivedUsers);
}