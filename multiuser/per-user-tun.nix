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
      seq = seq;
      tun = "${cfg.tunNamePrefix}${toString seq}";
      # 每 user 一张表：tableBase + seq + 2（让出 dns=0、others=1 前两张；表号纯标识无顺序）
      table = cfg.tableBase + seq + 2;
      inet4 = "${intToIp (baseInt + (seq + 2) * 4 + 1)}/30";
      peer = intToIp (baseInt + (seq + 2) * 4 + 2);
      # per-user mihomo 的 socks 端口（host 直连，socksPortBase + seq；占用就占用）
      socksPort = cfg.socksPortBase + seq;
    }) cfg.userSeqs;

  # 路由表号统一从 tableBase 派生（表号无顺序语义，纯标识）：dns=0、others=1、user=seq+2
  dnsTable = cfg.tableBase;
  othersTable = cfg.tableBase + 1;

  # pref 按角色归并成 3 类：dns/user/others 各占一个 pref（user 全体共享）
  dnsPref = cfg.prefBase;
  userPref = cfg.prefBase + 1;
  othersPref = cfg.prefBase + 2;

  # 控制面：clash api 的 secret 文件目录 + 组（consumer 把需要控的用户加进这个组）
  controllerGroup = "user-tun-controller";
  controllerDirectory = "/run/user-tun/controller";
  controllerSecret = "${controllerDirectory}/secret";

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
    experimental = {
      clash_api = {
        external_controller = "127.0.0.1:${toString cfg.controllerPort}";
        secret = "@CLASH_SECRET@";
      };
    };
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
        server_port = u.socksPort;
        version = "5";
      }) users
      ++ [
        { type = "block"; tag = "block"; }
        {
          type = "selector";
          tag = "others";
          outbounds = map (u: "user-${u.name}") users ++ [ "block" ];
          default = "block";
        }
      ];
    route = {
      rules =
        [ { inbound = [ dnsTun ]; action = "hijack-dns"; } ]
        ++ map (u: { inbound = [ u.tun ]; outbound = "user-${u.name}"; }) users
        ++ [ { inbound = [ othersTun ]; outbound = "others"; } ];
      final = "others";
    };
  });

  # =====================================================================
  # 手写路由（声明式描述，交给 systemd oneshot 建立）
  # =====================================================================
  routingRules =
    [ "pref ${toString dnsPref} ipproto udp dport 53 lookup ${toString dnsTable}"
      "pref ${toString dnsPref} ipproto tcp dport 53 lookup ${toString dnsTable}"
    ]
    ++ map (u:
      "pref ${toString userPref} uidrange ${toString u.uid}-${toString u.uid} lookup ${toString u.table}"
    ) users
    ++ [ "pref ${toString othersPref} from all lookup ${toString othersTable}" ];

  routingRoutes =
    [ "default via ${dnsTunPeer} dev ${dnsTun} table ${toString dnsTable}" ]
    ++ map (u: "default via ${u.peer} dev ${u.tun} table ${toString u.table}") users
    ++ [ "default via ${othersTunPeer} dev ${othersTun} table ${toString othersTable}" ];
in
{
  options.per-user-tun = {
    enable = mkEnableOption "per-user TUN 分流（系统级 sing-box + 手写路由直连 per-user mihomo）";

    # 路由表号基准：dns=tableBase、others=tableBase+1、user=tableBase+seq+2
    tableBase = mkOption { type = types.int; default = 2000; };
    # pref 基准（dns=prefBase、user+1、others+2；避开 local 的 pref 0，撞了可整体平移）
    prefBase = mkOption { type = types.int; default = 100; };
    # normal user -> 序号（默认 = uid；地址那边会自行 +2 让出其前两组）
    userSeqs = mkOption {
      type = types.attrsOf types.int;
      default = lib.mapAttrs (_: u: u.uid) (lib.filterAttrs (_: u: u.isNormalUser == true) config.users.users);
    };
    # 隧道地址段起始（完整 IPv4，跨设备可配，避免与设备所在网络冲突）
    tunAddressBase = mkOption { type = types.str; default = "198.19.0.0"; };
    # per-user mihomo 的 socks 端口基准（user = base + seq；host 直连，占用就占用）
    socksPortBase = mkOption { type = types.int; default = 7890; };
    # tun 设备名前缀（供 system 的 dns/others 与 user 的 seq 共用），拼出总长需 < 15（IFNAMSIZ）
    tunNamePrefix = mkOption { type = types.str; default = "ut-"; };

    # system sing-box 的 fake-ip 地址段；域名经 fake-ip 反查后原样下发（TCP/UDP 都传域名，单 ip 不分）
    fakeIpRange = mkOption { type = types.str; default = "198.18.0.1/16"; };

    # clash api 监听的 host loopback 端口（sing-box clash api 只支持 TCP，secret 运行时随机生成）
    controllerPort = mkOption { type = types.int; default = 9090; };
  };

  config = mkIf cfg.enable {
    assertions = [{
      assertion = cfg.prefBase + 2 < 32766;
      message = "per-user-tun: prefBase 过大，others 兜底 rule 会越过 main(32766)";
    }];

    users.groups.${controllerGroup} = { };

    # clash api 的 secret 文件目录：controllerGroup 可读（secret 文件由 sing-box 的 ExecStartPre 生成）
    systemd.tmpfiles.rules = [
      "d ${controllerDirectory} 0750 root ${controllerGroup} -"
    ];

    systemd.services = {
        user-tun-singbox = {
          wantedBy = [ "multi-user.target" ];
          after = [ "network.target" "systemd-tmpfiles-setup.service" ];
          serviceConfig = {
            DynamicUser = true;
            # 运行时随机生成 clash secret：写组可读文件 + 注入 @CLASH_SECRET@ 占位符到 /run 的临时 config（不落 /nix/store）
            ExecStartPre = [ "!${pkgs.writeShellScript "user-tun-clash-secret" ''
              set -eu
              secret="$(${pkgs.openssl}/bin/openssl rand -hex 32)"
              printf '%s\n' "$secret" > ${controllerSecret}
              ${pkgs.coreutils}/bin/chown root:${controllerGroup} ${controllerSecret}
              ${pkgs.coreutils}/bin/chmod 640 ${controllerSecret}
              ${pkgs.gnused}/bin/sed "s|@CLASH_SECRET@|$secret|g" ${singBoxConfig} > /run/user-tun/sing-box.json
              ${pkgs.coreutils}/bin/chown root:${controllerGroup} /run/user-tun/sing-box.json
              ${pkgs.coreutils}/bin/chmod 640 /run/user-tun/sing-box.json
            ''}" ];
            ExecStart = "${pkgs.sing-box}/bin/sing-box run -c /run/user-tun/sing-box.json";
            Restart = "on-failure";
            # CAP_NET_ADMIN 建 tun
            AmbientCapabilities = [ "CAP_NET_ADMIN" ];
            # tun 需要访问 /dev/net/tun（host devtmpfs）并在 host 网络命名空间里操作
            PrivateDevices = false;
            PrivateUsers = false;
            # 读 ExecStartPre 生成 config（640 root:controllerGroup）需要 controllerGroup
            SupplementaryGroups = [ controllerGroup ];
            # ExecStartPre 要写 /run/user-tun（secret + 运行时 config），在 protect 下白名单放行
            ProtectSystem = "strict";
            ReadWritePaths = [ "/run/user-tun" ];
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

    # 供 controllerGroup 成员切换 others selector 的小工具（读 secret 文件 -> clash api）
    environment.systemPackages = [
      (pkgs.writeShellScriptBin "user-tun-select" ''
        set -eu
        name="$1"
        secret="$(${pkgs.coreutils}/bin/cat ${controllerSecret})"
        ${pkgs.curl}/bin/curl -sf -X PUT \
          -H "Authorization: Bearer $secret" \
          -d "{\"name\":\"$name\"}" \
          "http://127.0.0.1:${toString cfg.controllerPort}/proxies/others"
      '')
    ];
  };
}