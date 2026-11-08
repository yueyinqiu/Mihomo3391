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
  vethBaseInt = ipToInt cfg.vethAddressBase;

  users =
    lib.mapAttrsToList (name: seq: let
      uid = config.users.users.${name}.uid;
    in {
      name = name;
      uid = uid;
      seq = seq;
      netnsName = "${cfg.netnsPrefix}${toString seq}";
      netnsPath = "/run/user-tun/netns/${name}";
      veth = "${cfg.vethPrefix}${toString seq}";
      vethPeer = "${cfg.vethPrefix}${toString seq}p";
      # veth 用 /31（点对点 2 地址，不浪费网络/广播）
      vethHost = intToIp (vethBaseInt + seq * 2);
      vethPeerAddr = intToIp (vethBaseInt + seq * 2 + 1);
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
  # system sing-box：全局 53 hijack tun + 每用户 tun（setns -> socks5 直连 per-user mihomo）
  # =====================================================================
  singBoxConfig = pkgs.writeText "user-tun-sing-box.json" (builtins.toJSON {
    log = { level = "info"; };
    dns = {
      servers = [
        { type = "local"; tag = "local"; }
        { type = "fakeip"; tag = "fakeip"; inet4_range = cfg.fakeIpRange; }
      ];
      rules = [
        { server = "fakeip"; }
      ];
      final = "local";
    };
    network_namespaces = map (u: {
      type = "default";
      tag = u.netnsName;
      path = u.netnsPath;
    }) users;
    inbounds =
      [
        {
          type = "tun";
          tag = dnsTun;
          interface_name = dnsTun;
          stack = "gvisor";
          address = [ dnsTunInet4 ];
        }
      ]
      ++ map (u: {
        type = "tun";
        tag = u.tun;
        interface_name = u.tun;
        stack = "gvisor";
        address = [ u.inet4 ];
      }) users
      ++ [
        {
          type = "tun";
          tag = othersTun;
          interface_name = othersTun;
          stack = "gvisor";
          address = [ othersTunInet4 ];
        }
      ];
    outbounds =
      map (u: {
        type = "socks";
        tag = "user-${u.name}";
        server = "127.0.0.1";
        server_port = 7890;
        version = "5";
        netns = u.netnsName;
      }) users
      # others：非 normal user 的兜底出口；当前 block（安全默认），真实环境由 consumer 定义同理的 others mihomo/netns
      ++ [
        {
          type = "block";
          tag = "others";
        }
      ];
    route = {
      rules =
        [ { port = [ 53 ]; action = "hijack-dns"; } ]
        ++ map (u: { inbound = [ u.tun ]; outbound = "user-${u.name}"; }) users
        ++ [ { inbound = [ othersTun ]; outbound = "others"; } ];
      final = "others";
    };
  });

  # =====================================================================
  # 手写路由（声明式描述，交给 systemd oneshot 建立）
  # =====================================================================
  routingRules =
    [ "pref 100 ipproto udp dport 53 lookup ${toString cfg.dnsTable}"
      "pref 100 ipproto tcp dport 53 lookup ${toString cfg.dnsTable}"
    ]
    # 回程：目标为各 veth 子网（/30）的包走 main 直连回 netns，不落入 others 兜底
    ++ map (u: "pref 40 to ${intToIp (vethBaseInt + u.seq * 2)}/31 lookup main") users
    # 回环避免：从各 veth 进来的流量直接走 main（不进 dport53/uidrange，避免回 tun）
    ++ map (u: "pref 50 iif ${u.veth} lookup main") users
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
    enable = mkEnableOption "per-user TUN 分流（系统级 mihomo + 多 netns + 手写路由）";

    tableBase = mkOption { type = types.int; default = 2100 - 1000; };
    prefBase = mkOption { type = types.int; default = 1000 - 1000; };
    # normal user -> 序号（默认 = uid；地址那边会自行 +2 让出其前两组）
    userSeqs = mkOption {
      type = types.attrsOf types.int;
      default = lib.mapAttrs (_: u: u.uid) (lib.filterAttrs (_: u: u.isNormalUser == true) config.users.users);
    };
    # 隧道地址段起始（完整 IPv4，跨设备可配，避免与设备所在网络冲突）
    tunAddressBase = mkOption { type = types.str; default = "198.19.0.0"; };
    # veth 子网起始（每 user 一个 /30，与 tun 段独立，互不干扰）
    vethAddressBase = mkOption { type = types.str; default = "100.64.0.0"; };
    # tun 设备名前缀（供 system 的 dns/others 与 user 的 seq 共用），拼出总长需 < 15（IFNAMSIZ）
    tunNamePrefix = mkOption { type = types.str; default = "ut-"; };
    # netns 名（ip netns add 的标识）前缀，避免和用户自己建的 netns 撞
    netnsPrefix = mkOption { type = types.str; default = "ut-"; };
    # veth 接口名前缀（host 端 {prefix}{seq}，netns 端 {prefix}{seq}p；与 tun 同为接口，用 utv- 区分）
    vethPrefix = mkOption { type = types.str; default = "utv-"; };

    # tun 路由表号
    dnsTable = mkOption { type = types.int; default = 2000; };
    othersTable = mkOption { type = types.int; default = 2200; };

    # veth 出站 MASQUERADE 到的物理接口（跨设备可配，对应真实的出站网卡）
    natInterface = mkOption { type = types.str; default = "eth1"; };

    # system sing-box 的 fake-ip 地址段；域名经 fake-ip 反查后原样下发（TCP/UDP 都传域名，单 ip 不分）
    fakeIpRange = mkOption { type = types.str; default = "198.18.0.1/16"; };
  };

  config = mkIf cfg.enable {
    # netns 方案：mihomo 流量从 veth 进 host 需转发（veth -> eth1），开 ip_forward
    boot.kernel.sysctl = {
      "net.ipv4.ip_forward" = 1;
    };

    # veth 的 host 端是我们手动配静态 IP，别让 dhcpcd 拿去 DHCP/IPv4LL 覆盖
    networking.dhcpcd.denyInterfaces = map (u: u.veth) users;
    # veth 子网对 target 不可见，出站时 MASQUERADE 成出站接口地址；networking.nat 会顺带配 forward
    networking.nat = {
      enable = true;
      internalInterfaces = map (u: u.veth) users;
      externalInterface = cfg.natInterface;
    };

    systemd.services = {
        # 每用户一个 root netns（sing-box setns 进去连 per-user mihomo，loopback 私有）
        user-tun-netns = {
          wantedBy = [ "multi-user.target" ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
          };
          script = ''
            mkdir -p /run/user-tun/netns
            ${lib.concatMapStringsSep "\n" (u: ''
              ${pkgs.iproute2}/bin/ip netns add ${u.netnsName} 2>/dev/null || true
              touch ${u.netnsPath}
              ${pkgs.util-linux}/bin/mount --bind /run/netns/${u.netnsName} ${u.netnsPath}
              ${pkgs.iproute2}/bin/ip link add ${u.veth} type veth peer name ${u.vethPeer} 2>/dev/null || true
              ${pkgs.iproute2}/bin/ip addr add ${u.vethHost}/31 dev ${u.veth} 2>/dev/null || true
              ${pkgs.iproute2}/bin/ip link set ${u.veth} up
              ${pkgs.iproute2}/bin/ip link set ${u.vethPeer} netns ${u.netnsName}
              ${pkgs.iproute2}/bin/ip netns exec ${u.netnsName} ${pkgs.iproute2}/bin/ip addr add ${u.vethPeerAddr}/31 dev ${u.vethPeer}
              ${pkgs.iproute2}/bin/ip netns exec ${u.netnsName} ${pkgs.iproute2}/bin/ip link set ${u.vethPeer} up
              ${pkgs.iproute2}/bin/ip netns exec ${u.netnsName} ${pkgs.iproute2}/bin/ip link set lo up
              ${pkgs.iproute2}/bin/ip netns exec ${u.netnsName} ${pkgs.iproute2}/bin/ip route add default via ${u.vethHost}
            '') users}
          '';
        };

        user-tun-singbox = {
          wantedBy = [ "multi-user.target" ];
          after = [ "network.target" "user-tun-netns.service" ];
          serviceConfig = {
            DynamicUser = true;
            ExecStart = "${pkgs.sing-box}/bin/sing-box run -c ${singBoxConfig}";
            Restart = "on-failure";
            # CAP_NET_ADMIN 建 tun；CAP_SYS_ADMIN 供 setns 进入各 user netns
            AmbientCapabilities = [ "CAP_NET_ADMIN" "CAP_SYS_ADMIN" ];
            # tun 需要访问 /dev/net/tun（host devtmpfs）并在 host 网络命名空间里操作
            PrivateDevices = false;
            PrivateUsers = false;
          };
        };

        # 手写路由：Nix 列表 -> systemd oneshot -> ip 命令
        user-tun-route = {
          wantedBy = [ "multi-user.target" ];
          requires = [ "user-tun-singbox.service" ];
          after = [ "user-tun-singbox.service" ];
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