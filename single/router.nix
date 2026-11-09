{ config, lib, pkgs, ... }:

let
  yaml = pkgs.formats.yaml { };

  # 用户的 mihomo（真实里属于 home config，这里作为「使用方」定义）：
  #   具体节点/代理配置都在这；sing-box 只负责把它 traffics 转发过来。
  mihomoConfig = yaml.generate "mihomo-config.yaml" {
    mode = "rule";
    log-level = "info";
    ipv6 = true;
    mixed-port = 7890;      # = single-tun.socksPort，sing-box 直连这个端口
    allow-lan = false;
    interface-name = "eth1"; # 出站绑定 eth1，避免被 sing-box 的 tun 劫持回环
    dns = {
      enable = true;
      hosts = { "echo.example.test" = "192.168.50.2"; };
      nameserver = [ "192.168.50.2" ];
    };
    rules = [
      "DOMAIN,echo.example.test,DIRECT"
      "MATCH,REJECT"
    ];
  };
in
{
  imports = [ ./single-tun.nix ];

  # ---- 测试拓扑（非泛用） ----
  virtualisation.vlans = [ 1 ];

  networking.interfaces.eth1.ipv4.addresses = [
    { address = "192.168.50.1"; prefixLength = 24; }
  ];

  # 让 DNS 查询走默认路由进 tun、被 dns-hijack 劫持
  networking.nameservers = [ "1.1.1.1" ];

  environment.systemPackages = [ pkgs.python3 pkgs.iproute2 ];

  users.users.alice = { isNormalUser = true; uid = 1001; description = "test user"; };

  single-tun = {
    enable = true;
  };

  # 用户的 mihomo 服务（真实里是 home config / user 级 systemd）
  systemd.services.single-mihomo = {
    wantedBy = [ "multi-user.target" ];
    after = [ "network.target" ];
    serviceConfig = {
      User = "alice";
      StateDirectory = "single-mihomo";
      ExecStart = "${lib.getExe pkgs.mihomo} -d /var/lib/single-mihomo -f ${mihomoConfig}";
      Restart = "on-failure";
    };
  };
}