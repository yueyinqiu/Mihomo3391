{ config, lib, pkgs, ... }:

let
  yaml = pkgs.formats.yaml { };

  socketDirectory = "/run/user-tun";
  controllerGroup = "user-tun-controller";

  # 每个用户一份：应用 uid、per-user 服务 uid、gost 桥接端口、tun 参数。
  # 与 NixosErthane 的 user-tun + HomeAtErthane 的 gost.nix 结构对齐。
  users = [
    {
      name = "alice";
      uid = 1001;
      svcName = "alicesvc";
      svcUid = 1003;
      gostPort = 43007;      # system gost 的 TCP 监听端口（system mihomo 的 socks5 指向这）
      socksInPort = 16884;   # per-user mihomo 的 mixed 重入端口（per-user gost 的 tcp dial 指向这）
      tun = "tun-alice";
      table = 2100;
      inet4 = "198.19.1.1/30";
      peer = "198.19.1.2";
    }
    {
      name = "bob";
      uid = 1002;
      svcName = "bobsvc";
      svcUid = 1004;
      gostPort = 43008;
      socksInPort = 16885;
      tun = "tun-bob";
      table = 2101;
      inet4 = "198.19.2.1/30";
      peer = "198.19.2.2";
    }
  ];

  svcUidRange = "${toString (lib.foldl' lib.min 65535 (map (u: u.svcUid) users))}-${toString (lib.foldl' lib.max 0 (map (u: u.svcUid) users))}";

  dnsTable = 2000;
  othersTable = 2200;

  # =====================================================================
  # system mihomo：全局 DNS 劫持 tun + 每用户 tun（proxy 直连 gost 端口）+ 兜底 tun
  # =====================================================================
  mihomoSystemConfig = yaml.generate "mihomo-system.yaml" {
    mode = "rule";
    log-level = "debug";
    ipv6 = false;
    dns = {
      enable = true;
      enhanced-mode = "fake-ip";
      fake-ip-range = "198.18.0.1/16";
      hosts = {
        "echo-alice.example.test" = "192.168.50.2";
        "echo-bob.example.test" = "192.168.50.2";
      };
      nameserver = [ "1.1.1.1" ];
    };
    listeners =
      [
        {
          name = "tun-dns";
          type = "tun";
          device = "tun-dns";
          stack = "gvisor";
          auto-route = false;
          dns-hijack = [ "any:53" ];
          inet4-address = [ "198.19.0.1/30" ];
        }
      ]
      ++ map (u: {
        name = u.tun;
        type = "tun";
        device = u.tun;
        stack = "gvisor";
        auto-route = false;
        inet4-address = [ u.inet4 ];
        proxy = "user-${toString u.uid}";
      }) users
      ++ [
        {
          name = "tun-others";
          type = "tun";
          device = "tun-others";
          stack = "gvisor";
          auto-route = false;
          inet4-address = [ "198.19.3.1/30" ];
        }
      ];
    proxies = map (u: {
      name = "user-${toString u.uid}";
      type = "socks5";
      server = "127.0.0.1";
      port = u.gostPort;
    }) users;
    proxy-groups = [
      {
        name = "others";
        type = "select";
        proxies = [ "REJECT" "DIRECT" ] ++ (map (u: "user-${toString u.uid}") users);
      }
    ];
    rules = [ "MATCH,others" ];
  };

  # =====================================================================
  # system gost：每个用户一个 TCP listener，透传到对应 unix socket
  # =====================================================================
  gostSystemConfig = yaml.generate "gost-system.yaml" {
    services = map (u: {
      name = "user-${toString u.uid}";
      addr = "127.0.0.1:${toString u.gostPort}";
      handler = { type = "tcp"; chain = "to-${u.name}"; };
      listener = { type = "tcp"; };
    }) users;
    chains = map (u: {
      name = "to-${u.name}";
      hops = [
        {
          name = "hop-0";
          nodes = [
            {
              name = "user-sock";
              addr = "${socketDirectory}/${toString u.uid}/sock";
              connector = { type = "unix"; };
              dialer = { type = "unix"; };
            }
          ];
        }
      ];
    }) users;
  };

  # =====================================================================
  # per-user gost：监听自己的 unix socket，解析 socks5，喂回本用户 mihomo 重入点
  # =====================================================================
  perUserGostConfig = u: yaml.generate "gost-${u.name}.yaml" {
    services = [
      {
        name = "user-${toString u.uid}-in";
        addr = "${socketDirectory}/${toString u.uid}/sock";
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

  # =====================================================================
  # per-user mihomo：mixed 重入端口 + 只放行自己的域名（用于验证域名下发）
  # =====================================================================
  perUserMihomoConfig = u: yaml.generate "mihomo-${u.name}.yaml" {
    mode = "rule";
    log-level = "debug";
    ipv6 = false;
    dns = {
      enable = true;
      hosts = { "echo-${u.name}.example.test" = "192.168.50.2"; };
      nameserver = [ "192.168.50.2" ];
    };
    mixed-port = u.socksInPort;
    allow-lan = false;
    rules = [
      "DOMAIN,echo-${u.name}.example.test,DIRECT"
      "MATCH,REJECT"
    ];
  };

  # =====================================================================
  # 手写路由：声明式描述，交给 systemd oneshot 建立
  # =====================================================================
  routingRules =
    [ "pref 50 uidrange ${svcUidRange} lookup main"
      "pref 100 ipproto udp dport 53 lookup ${toString dnsTable}"
      "pref 100 ipproto tcp dport 53 lookup ${toString dnsTable}"
    ]
    ++ (lib.imap0 (i: u:
      "pref ${toString (1000 + i)} uidrange ${toString u.uid}-${toString u.uid} lookup ${toString u.table}"
    ) users)
    ++ [ "pref 32765 from all lookup ${toString othersTable}" ];

  routingRoutes =
    [ "default via 198.19.0.2 dev tun-dns table ${toString dnsTable}" ]
    ++ map (u: "default via ${u.peer} dev ${u.tun} table ${toString u.table}") users
    ++ [ "default via 198.19.3.2 dev tun-others table ${toString othersTable}" ];
in
{
  # DNS 按 53 全局劫持（tun-dns），不依赖 uid，保留默认 nsncd。

  boot.kernelModules = [ "tun" ];

  boot.kernel.sysctl = {
    "net.ipv4.ip_forward" = 1;
    "net.ipv6.conf.all.forwarding" = 1;
  };

  virtualisation.vlans = [ 1 ];

  networking.interfaces.eth1.ipv4.addresses = [
    { address = "192.168.50.1"; prefixLength = 24; }
  ];

  networking.nameservers = [ "1.1.1.1" ];

  environment.systemPackages = [ pkgs.python3 pkgs.iproute2 pkgs.tcpdump ];

  # 应用用户 + per-user 服务用户 + controllerGroup
  users.users = lib.listToAttrs (lib.flatten (map (u: [
    (lib.nameValuePair u.name {
      isNormalUser = true;
      uid = u.uid;
      description = "test user ${u.name}";
    })
    (lib.nameValuePair u.svcName {
      isSystemUser = true;
      uid = u.svcUid;
      group = u.svcName;
      shell = pkgs.bash;
      description = "dedicated uid for ${u.name}'s per-user mihomo";
    })
  ]) users));

  users.groups = (lib.listToAttrs (map (u: lib.nameValuePair u.svcName { }) users))
    // { ${controllerGroup} = { }; };

  # unix socket 目录：owner 是用户、group 是 controllerGroup（system gost 靠 group 访问）
  systemd.tmpfiles.rules =
    [ "d ${socketDirectory} 0755 root ${controllerGroup} -" ]
    ++ map (u: "d ${socketDirectory}/${toString u.uid} 0770 ${u.name} ${controllerGroup} -") users;

  systemd.services = lib.mkMerge [
    {
      mihomo-system = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig = {
          StateDirectory = "mihomo-system";
          ExecStart = "${pkgs.mihomo}/bin/mihomo -d /var/lib/mihomo-system -f /var/lib/mihomo-system/config.yaml";
          Restart = "on-failure";
          AmbientCapabilities = [ "CAP_NET_ADMIN" "CAP_NET_RAW" "CAP_NET_BIND_SERVICE" ];
        };
        preStart = ''
          install -m 644 ${mihomoSystemConfig} /var/lib/mihomo-system/config.yaml
        '';
      };

      # system gost：TCP -> unix socket
      user-tun-gost = {
        wantedBy = [ "multi-user.target" ];
        after = [ "mihomo-system.service" ];
        serviceConfig = {
          ExecStart = "${pkgs.gost}/bin/gost -C ${gostSystemConfig}";
          Restart = "on-failure";
          DynamicUser = true;
          SupplementaryGroups = [ controllerGroup ];
        };
      };

      # 声明式路由：Nix 列表 -> systemd oneshot -> ip 命令
      user-tun-route = {
        wantedBy = [ "multi-user.target" ];
        requires = [ "mihomo-system.service" ];
        after = [ "mihomo-system.service" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = ''
          for t in tun-dns ${lib.concatStringsSep " " (map (u: u.tun) users)} tun-others; do
            until ${pkgs.iproute2}/bin/ip link show $t >/dev/null 2>&1; do sleep 0.2; done
          done
          ${lib.concatMapStringsSep "\n" (r: "${pkgs.iproute2}/bin/ip rule add ${r}") routingRules}
          ${lib.concatMapStringsSep "\n" (r: "${pkgs.iproute2}/bin/ip route add ${r}") routingRoutes}
        '';
        preStop = ''
          ${lib.concatMapStringsSep "\n" (r: "${pkgs.iproute2}/bin/ip route del ${r}") (lib.reverseList routingRoutes)}
          ${lib.concatMapStringsSep "\n" (r: "${pkgs.iproute2}/bin/ip rule del ${r}") (lib.reverseList routingRules)}
        '';
      };
    }

    # per-user gost（每个用户一套）
    (lib.listToAttrs (map (u:
      lib.nameValuePair "gost-user-${u.name}" {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig = {
          User = u.name;
          UMask = "0000";
          ExecStart = "${pkgs.gost}/bin/gost -C ${perUserGostConfig u}";
          Restart = "on-failure";
        };
      }
    ) users))

    # per-user mihomo（每个用户一套）
    (lib.listToAttrs (map (u:
      lib.nameValuePair "mihomo-user-${u.name}" {
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" ];
        serviceConfig = {
          User = u.svcName;
          Group = u.svcName;
          StateDirectory = "mihomo-user-${u.name}";
          ExecStart = "${pkgs.mihomo}/bin/mihomo -d /var/lib/mihomo-user-${u.name} -f /var/lib/mihomo-user-${u.name}/config.yaml";
          Restart = "on-failure";
        };
        preStart = ''
          install -m 644 -o ${u.svcName} -g ${u.svcName} ${perUserMihomoConfig u} /var/lib/mihomo-user-${u.name}/config.yaml
        '';
      }
    ) users))
  ];
}