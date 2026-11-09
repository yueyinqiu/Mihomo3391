{ config, lib, pkgs, ... }:

let
  inherit (lib) mkOption mkEnableOption types mkIf;
  cfg = config.single-tun;

  # 单用户：系统级 sing-box 纯 tun 转发（auto_route 自动路由，不按 uid 分流），
  # 所有流量 -> 一个 socks outbound -> 用户 mihomo（具体节点在 mihomo 里配）。
  singBoxConfig = pkgs.writeText "single-tun-sing-box.json" (builtins.toJSON {
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
    inbounds = [
      {
        type = "tun";
        tag = "tun";
        stack = "gvisor";
        address = [ cfg.tunAddress ];
        auto_route = true;
      }
    ];
    outbounds = [
      {
        type = "socks";
        tag = "mihomo";
        server = "127.0.0.1";
        server_port = cfg.socksPort;
        version = "5";
      }
    ];
    route = {
      rules = [
        { port = [ 53 ]; action = "hijack-dns"; }
      ];
      final = "mihomo";
    };
  });
in
{
  options.single-tun = {
    enable = mkEnableOption "单用户 tun 代理（系统级 sing-box 纯转发到用户 mihomo）";

    # 用户 mihomo 的 socks/mixed 端口（sing-box 直连它）
    socksPort = mkOption { type = types.int; default = 7890; };
    # tun 接口地址（单用户一个 tun，auto_route 会把其余流量自动路由进来）
    tunAddress = mkOption { type = types.str; default = "198.19.0.1/30"; };
    # fake-ip 地址段
    fakeIpRange = mkOption { type = types.str; default = "198.18.0.1/16"; };
  };

  config = mkIf cfg.enable {
    systemd.services.single-tun-singbox = {
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      serviceConfig = {
        DynamicUser = true;
        ExecStart = "${pkgs.sing-box}/bin/sing-box run -c ${singBoxConfig}";
        Restart = "on-failure";
        # CAP_NET_ADMIN 建 tun + auto_route 设置路由
        AmbientCapabilities = [ "CAP_NET_ADMIN" ];
        # tun 需要访问 /dev/net/tun（host devtmpfs）并在 host 网络命名空间里操作
        PrivateDevices = false;
        PrivateUsers = false;
      };
    };
  };
}