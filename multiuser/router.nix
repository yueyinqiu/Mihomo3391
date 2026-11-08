{ config, lib, pkgs, ... }:

let
  yaml = pkgs.formats.yaml { };

  # 使用方自己按约定算（和 system 侧一致，不依赖 module 暴露任何东西）：
  #   socketPath = /run/user-tun/{uid}/sock
  #   socksInPort = uid + 15884（= 16884 - 1000）
  derivedUsers = lib.mapAttrsToList (name: u: {
    name = name;
    uid = u.uid;
    socketPath = "/run/user-tun/${u.name}/sock";
    socksInPort = u.uid + 15884;
  }) (lib.filterAttrs (_: u: u.isNormalUser == true) config.users.users);

  # ---------------------------------------------------------------------
  # per-user 侧（真实里属于 home config，这里作为「使用方」定义）
  # ---------------------------------------------------------------------
  perUserGostConfig = u: yaml.generate "gost-${u.name}.yaml" {
    services = [
      {
        name = "user-${u.name}-in";
        addr = u.socketPath;
        handler = { type = "socks5"; chain = "to-mihomo"; };
        listener = { type = "unix"; };
      }
    ];
    chains = [
      {
        name = "to-mihomo";
        hops = [
          {
            name = "hop-0";
            nodes = [
              {
                name = "mihomo-socks-in";
                addr = "127.0.0.1:${toString u.socksInPort}";
                connector = { type = "socks5"; };
                dialer = { type = "tcp"; };
              }
            ];
          }
        ];
      }
    ];
  };

  perUserMihomoConfig = u: yaml.generate "mihomo-${u.name}.yaml" {
    mode = "rule";
    log-level = "debug";
    ipv6 = false;
    interface-name = "eth1";   # 出站绑接口（回环避免）
    mixed-port = u.socksInPort;
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

  environment.systemPackages = [ pkgs.python3 pkgs.iproute2 pkgs.tcpdump ];

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
    (lib.listToAttrs (map (u:
      lib.nameValuePair "user-tun-gost-${u.name}" {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig = {
          User = u.name;
          UMask = "0000";
          ExecStart = "${lib.getExe pkgs.gost} -C ${perUserGostConfig u}";
          Restart = "on-failure";
        };
      }
    ) derivedUsers))
    // (lib.listToAttrs (map (u:
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
    ) derivedUsers));
}