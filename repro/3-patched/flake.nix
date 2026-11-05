{
  description = "场景3：应用 patch 后，双栈 AF_INET6 socket 也能被 UID 反查（bug 解决）";

  inputs = {
    nixpkgs.url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.zst";
  };

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      checks.${system}.default = pkgs.testers.runNixOSTest {
        name = "mihomo-uid-test";
        nodes.machine = ./machine.nix;

        testScript = ''
          start_all()
          machine.wait_for_unit("multi-user.target")
          machine.wait_for_unit("mihomo.service")
          machine.wait_until_succeeds("ip link | grep -qE 'tun|Meta'", timeout=60)

          # B：双栈 IPv6 socket（AF_INET6，IPV6_V6ONLY=0 默认），发 UDP 到 IPv4-mapped 地址
          script = (
            "import socket,time\n"
            "s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)\n"
            "s.sendto(b'x',('::ffff:1.1.1.1',9999))\n"
            "print(s.getsockname())\n"
            "time.sleep(5)\n"
          )
          machine.succeed("cat > /tmp/test.py <<'PYEOF'\n" + script + "PYEOF\n")
          print("=== running script as alice (uid 1001) ===")
          print(machine.succeed("runuser -u alice -- python3 /tmp/test.py"))

          print("=== mihomo log ===")
          print(machine.succeed("journalctl -u mihomo.service --no-pager | grep -iE 'uid|process' | tail -20"))

          machine.succeed("journalctl -u mihomo.service --no-pager | grep 'uid=1001'")
          machine.fail("journalctl -u mihomo.service --no-pager | grep 'process not found'")
        '';
      };
    };
}