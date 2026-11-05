{
  description = "场景2：双栈 AF_INET6 socket 发 IPv4 包，mihomo UID 反查失败（process not found，bug 复现）";

  inputs = {
    nixpkgs.url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.zst";
  };

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      checks.${system}.dualstackBug = pkgs.testers.runNixOSTest {
        name = "mihomo-uid-dualstack-bug";
        nodes.machine = ./machine.nix;

        testScript = ''
          start_all()
          machine.wait_for_unit("multi-user.target")
          machine.wait_for_unit("mihomo.service")
          machine.wait_until_succeeds("ip link | grep -qE 'tun|Meta'", timeout=60)

          # B：双栈 IPv6 socket（AF_INET6，IPV6_V6ONLY=0 默认），发 UDP 到 IPv4-mapped 地址
          b = (
            "import socket,time\n"
            "s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)\n"
            "s.sendto(b'x',('::ffff:1.1.1.1',9999))\n"
            "print(s.getsockname())\n"
            "time.sleep(5)\n"
          )
          machine.succeed("cat > /tmp/b.py <<'PYEOF'\n" + b + "PYEOF\n")
          print("=== running AF_INET6 dual-stack script as alice (uid 1001) ===")
          print(machine.succeed("runuser -u alice -- python3 /tmp/b.py"))

          print("=== mihomo log (expect process not found) ===")
          print(machine.succeed("journalctl -u mihomo.service --no-pager | grep -iE 'uid|process' | tail -20"))

          # 断言：日志里出现 process not found（bug 复现）
          machine.succeed("journalctl -u mihomo.service --no-pager | grep 'process not found'")
          print("OK: dual-stack socket NOT resolved (process not found) -> bug reproduced")
        '';
      };
    };
}