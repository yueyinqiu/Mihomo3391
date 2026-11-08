{ config, lib, pkgs, ... }:

let
  inherit (lib) mkOption mkEnableOption types mkIf;
  cfg = config.per-user-tun;
  yaml = pkgs.formats.yaml { };

  # IPv4 字符串 <-> 整数，用于「tunAddressBase + seq * addrStep」无限往上加
  ipToInt = ip:
    let ps = map lib.toInt (lib.splitString "." ip);
    in (lib.elemAt ps 0) * 16777216 + (lib.elemAt ps 1) * 65536 + (lib.elemAt ps 2) * 256 + (lib.elemAt ps 3);
  intToIp = n:
    let
      o1 = n / 16777216;
      o2 = (lib.mod n 16777216) / 65536;
      o3 = (lib.mod n 65536) / 256;
      o4 = lib.mod n 256;
    in "${toString o1}.${toString o2}.${toString o3}.${toString o4}";

  baseInt = ipToInt cfg.tunAddressBase;

  users =
    lib.mapAttrsToList (name: seq: let
      uid = config.users.users.${name}.uid;
    in {
      name = name;
      uid = uid;
      gostPort = seq + cfg.gostPortBase;
      tun = "${cfg.tunNamePrefix}${toString seq}";
      table = seq + cfg.tableBase;
      pref = seq + cfg.prefBase;
      inet4 = "${intToIp (baseInt + (seq + 2) * 4 + 1)}/30";
      peer = intToIp (baseInt + (seq + 2) * 4 + 2);
    }) cfg.userSeqs;

  # tun 设备名：统一 tunNamePrefix（默认 "ut-"），system 用词后缀、user 用数字后缀（seq 必为数字，天然不冲突）
  dnsTun = "${cfg.tunNamePrefix}dns";
  othersTun = "${cfg.tunNamePrefix}others";

  # 布局：dns = 第 0 个 /30，others = 第 1 个 /30，users 从第 2 个 /30 起（无末尾 magic）
  dnsTunInet4 = "${intToIp (baseInt + 1)}/30";
  dnsTunPeer = intToIp (baseInt + 2);
  othersTunAddr = baseInt + 4;
  othersTunInet4 = "${intToIp (othersTunAddr + 1)}/30";
  othersTunPeer = intToIp (othersTunAddr + 2);

  # =====================================================================
  # system mihomo：全局 53 劫持 tun + 每用户 tun（proxy 直连 gost）+ 兜底 tun
  # =====================================================================
  mihomoSystemConfig = yaml.generate "user-tun-mihomo.yaml" {
    mode = "rule";
    log-level = "info";
    ipv6 = false;
    dns = {
      enable = true;
      enhanced-mode = "fake-ip";
      fake-ip-range = cfg.fakeIpRange;
    };
    listeners =
      [
        {
          name = dnsTun;
          type = "tun";
          device = dnsTun;
          stack = "mips";
          auto-route = false;
          dns-hijack = [ "any:53" ];
          inet4-address = [ dnsTunInet4 ];
        }
      ]
      ++ map (u: {
        name = u.tun;
        type = "tun";
        device = u.tun;
        stack = "mips";
        auto-route = false;
        inet4-address = [ u.inet4 ];
        proxy = "user-${u.name}";
      }) users
      ++ [
        {
          name = othersTun;
          type = "tun";
          device = othersTun;
          stack = "mips";
          auto-route = false;
          inet4-address = [ othersTunInet4 ];
          proxy = "others";
        }
      ];
    proxies = map (u: {
      name = "user-${u.name}";
      type = "socks5";
      server = "127.0.0.1";
      port = u.gostPort;
    }) users
    ++ [
      {
        name = "others";
        type = "socks5";
        server = "127.0.0.1";
        port = cfg.othersGostPort;
      }
    ];
  };

  # =====================================================================
  # system gost：每个用户一个 TCP listener，透传到对应 unix socket
  # =====================================================================
  gostSystemConfig = yaml.generate "gost-system.yaml" {
    services = (map (u: {
      name = "user-${u.name}";
      addr = "127.0.0.1:${toString u.gostPort}";
      handler = { type = "tcp"; chain = "to-${u.name}"; };
      listener = { type = "tcp"; };
    }) users)
    ++ [
      {
        name = "others";
        addr = "127.0.0.1:${toString cfg.othersGostPort}";
        handler = { type = "tcp"; chain = "to-others"; };
        listener = { type = "tcp"; };
      }
    ];
    chains = (map (u: {
      name = "to-${u.name}";
      hops = [
        {
          name = "hop-0";
          nodes = [
            {
              name = "user-sock";
              addr = "${cfg.socketDirectory}/${u.name}/sock";
              connector = { type = "unix"; };
              dialer = { type = "unix"; };
            }
          ];
        }
      ];
    }) users)
    ++ [
      {
        name = "to-others";
        hops = [
          {
            name = "hop-0";
            nodes = [
              {
                name = "others-sock";
                addr = "${cfg.socketDirectory}/others/sock";
                connector = { type = "unix"; };
                dialer = { type = "unix"; };
              }
            ];
          }
        ];
      }
    ];
  };

  # =====================================================================
  # 手写路由（声明式描述，交给 systemd oneshot 建立）
  # =====================================================================
  routingRules =
    [ "pref 100 ipproto udp dport 53 lookup ${toString cfg.dnsTable}"
      "pref 100 ipproto tcp dport 53 lookup ${toString cfg.dnsTable}"
    ]
    ++ map (u:
      "pref ${toString u.pref} uidrange ${toString u.uid}-${toString u.uid} lookup ${toString u.table}"
    ) users
    ++ [ "pref 32765 from all lookup ${toString cfg.othersTable}" ];

  routingRoutes =
    [ "default via ${dnsTunPeer} dev ${dnsTun} table ${toString cfg.dnsTable}" ]
    ++ map (u: "default via ${u.peer} dev ${u.tun} table ${toString u.table}") users
    ++ [ "default via ${othersTunPeer} dev ${othersTun} table ${toString cfg.othersTable}" ];
in
{
  options.per-user-tun = {
    enable = mkEnableOption "per-user TUN 分流（系统级 mihomo + 两级 gost 桥接 + 手写路由）";

    # 每用户派生值的 base（全部写成「基准 - 1000」，最终值 = uid + base）
    gostPortBase = mkOption { type = types.int; default = 43007 - 1000; };
    # others（非普通用户）的 gost 端口，固定值，避开用户段
    othersGostPort = mkOption { type = types.int; default = 43000; };
    tableBase = mkOption { type = types.int; default = 2100 - 1000; };
    prefBase = mkOption { type = types.int; default = 1000 - 1000; };
    # normal user -> 序号（默认 = uid；地址那边会自行 +2 让出其前两组）
    userSeqs = mkOption {
      type = types.attrsOf types.int;
      default = lib.mapAttrs (_: u: u.uid) (lib.filterAttrs (_: u: u.isNormalUser == true) config.users.users);
    };
    # 隧道地址段起始（完整 IPv4，跨设备可配，避免与设备所在网络冲突）
    tunAddressBase = mkOption { type = types.str; default = "198.19.0.0"; };
    # per-user tun 名字前缀（拼 uid），总长需 < 15（IFNAMSIZ）
    tunNamePrefix = mkOption { type = types.str; default = "ut-"; };

    # tun 路由表号
    dnsTable = mkOption { type = types.int; default = 2000; };
    othersTable = mkOption { type = types.int; default = 2200; };

    # unix socket 目录 / controller 组
    socketDirectory = mkOption { type = types.str; default = "/run/user-tun"; };
    controllerGroup = mkOption { type = types.str; default = "user-tun-controller"; };

    # system mihomo 的 fake-ip DNS（域名由 fake-ip 反查后原样下发，真实解析交给下游 per-user mihomo）
    fakeIpRange = mkOption { type = types.str; default = "198.18.0.1/16"; };
  };

  config = mkIf cfg.enable {
    # boot.kernelModules = [ "tun" ];
    # boot.kernel.sysctl = {
    #   "net.ipv4.ip_forward" = 1;
    #   "net.ipv6.conf.all.forwarding" = 1;
    # };

    users.groups.${cfg.controllerGroup} = { };

    # unix socket 目录：owner 是用户、group 是 controllerGroup（gost 靠 group 访问）；
    # others/sock 目录 owner 是 root，由 controllerGroup 成员自行 listen 来接管 others 流量。
    systemd.tmpfiles.rules =
      [ "d ${cfg.socketDirectory} 0755 root ${cfg.controllerGroup} -"
        "d ${cfg.socketDirectory}/others 0770 root ${cfg.controllerGroup} -"
      ]
      ++ map (u: "d ${cfg.socketDirectory}/${u.name} 0770 ${u.name} ${cfg.controllerGroup} -") users;

    systemd.services = {
        user-tun-mihomo = {
          wantedBy = [ "multi-user.target" ];
          after = [ "network.target" ];
          serviceConfig = {
            DynamicUser = true;
            StateDirectory = "user-tun-mihomo";
            ExecStart = "${lib.getExe pkgs.mihomo} -d /var/lib/user-tun-mihomo -f ${mihomoSystemConfig}";
            Restart = "on-failure";
            AmbientCapabilities = [ "CAP_NET_ADMIN" ];
            # tun 需要访问 /dev/net/tun（host devtmpfs）并在 host 网络命名空间里操作
            PrivateDevices = false;
            PrivateUsers = false;
          };
        };

        # system gost：TCP -> unix socket
        user-tun-gost = {
          wantedBy = [ "multi-user.target" ];
          after = [ "user-tun-mihomo.service" ];
          serviceConfig = {
            ExecStart = "${lib.getExe pkgs.gost} -C ${gostSystemConfig}";
            Restart = "on-failure";
            DynamicUser = true;
            SupplementaryGroups = [ cfg.controllerGroup ];
          };
        };

        # 手写路由：Nix 列表 -> systemd oneshot -> ip 命令
        user-tun-route = {
          wantedBy = [ "multi-user.target" ];
          requires = [ "user-tun-mihomo.service" ];
          after = [ "user-tun-mihomo.service" ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            DynamicUser = true;
            AmbientCapabilities = [ "CAP_NET_ADMIN" ];
            Restart = "on-failure";
            RestartSec = 3;
          };
          script = ''
            ${lib.concatMapStringsSep "\n" (r: "${pkgs.iproute2}/bin/ip rule del ${r} 2>/dev/null || true\n            ${pkgs.iproute2}/bin/ip rule add ${r}") routingRules}
            ${lib.concatMapStringsSep "\n" (r: "${pkgs.iproute2}/bin/ip route replace ${r}") routingRoutes}
          '';
          preStop = ''
            ${lib.concatMapStringsSep "\n" (r: "${pkgs.iproute2}/bin/ip route del ${r} || true") (lib.reverseList routingRoutes)}
            ${lib.concatMapStringsSep "\n" (r: "${pkgs.iproute2}/bin/ip rule del ${r} || true") (lib.reverseList routingRules)}
          '';
        };
    };
  };
}