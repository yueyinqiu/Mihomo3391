{ config, lib, pkgs, ... }:

let
  yaml = pkgs.formats.yaml { };

  # 使用方自己按约定算（和 system 侧一致，不依赖 module 暴露任何东西）：
  #   netnsPath = /run/user-tun/netns/{name}（mihomo 进程要进的 netns 挂载点）
  #   mixed-port = 7890（每 ns 的 loopback 私有，统一端口）
  derivedUsers = lib.mapAttrsToList (name: u: {
    name = name;
    netnsPath = "/run/user-tun/netns/${name}";
  }) (lib.filterAttrs (_: u: u.isNormalUser == true) config.users.users);

  # ---------------------------------------------------------------------
  # per-user 侧（真实里属于 home config，这里作为「使用方」定义）
  # ---------------------------------------------------------------------
  perUserMihomoConfig = u: yaml.generate "mihomo-${u.name}.yaml" {
    mode = "rule";
    log-level = "info";
    ipv6 = false;
    mixed-port = 7890;   # 每 ns 私有统一端口；出站走 netns 默认路由（唯一 veth），无需 interface-name
    allow-lan = false;
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
        after = [ "user-tun-netns.service" ];
        requires = [ "user-tun-netns.service" ];
        serviceConfig = {
          User = u.name;
          StateDirectory = "user-tun-mihomo-${u.name}";
          NetworkNamespacePath = u.netnsPath;
          ExecStart = "${lib.getExe pkgs.mihomo} -d /var/lib/user-tun-mihomo-${u.name} -f ${perUserMihomoConfig u}";
          Restart = "on-failure";
        };
      }
    ) derivedUsers);
}