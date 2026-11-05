{
  description = "场景1：正常情况（AF_INET 单栈 socket），mihomo UID 反查能拿到 uid（无 bug）";

  inputs = {
    nixpkgs.url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.zst";
  };

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      checks.${system}.normal = pkgs.testers.runNixOSTest {
        name = "mihomo-uid-normal-af-inet";
        nodes.machine = ./machine.nix;

        testScript = ''
          start_all()
          machine.wait_for_unit("multi-user.target")
          machine.wait_for_unit("mihomo.service")
          machine.wait_until_succeeds("ip link | grep -qE 'tun|Meta'", timeout=60)

          # A：普通 IPv4 socket（AF_INET），发 UDP 到 IPv4 地址
          a = (
            "import socket,time\n"
            "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
            "s.sendto(b'x',('1.1.1.1',9999))\n"
            "print(s.getsockname())\n"
            "time.sleep(5)\n"
          )
          machine.succeed("cat > /tmp/a.py <<'PYEOF'\n" + a + "PYEOF\n")
          print("=== running AF_INET script as alice (uid 1001) ===")
          print(machine.succeed("runuser -u alice -- python3 /tmp/a.py"))

          print("=== mihomo log (expect uid=1001) ===")
          print(machine.succeed("journalctl -u mihomo.service --no-pager | grep -iE 'uid|process' | tail -20"))

          # 断言：日志里能拿到 uid=1001（正常情况）
          machine.succeed("journalctl -u mihomo.service --no-pager | grep 'uid=1001'")
          print("OK: AF_INET socket resolved uid=1001 (no bug)")
        '';
      };
    };
}