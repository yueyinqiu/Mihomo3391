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
      checks.${system}.patched = pkgs.testers.runNixOSTest {
        name = "mihomo-uid-dualstack-patched";
        nodes.machine = ./machine.nix;

        testScript = ''
          start_all()
          machine.wait_for_unit("multi-user.target")
          machine.wait_for_unit("mihomo.service")
          machine.wait_until_succeeds("ip link | grep -qE 'tun|Meta'", timeout=60)

          # 同样跑双栈脚本，patch 修复后应能查到 uid
          b = (
            "import socket,time\n"
            "s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)\n"
            "s.sendto(b'x',('::ffff:1.1.1.1',9999))\n"
            "print(s.getsockname())\n"
            "time.sleep(5)\n"
          )
          machine.succeed("cat > /tmp/b.py <<'PYEOF'\n" + b + "PYEOF\n")
          print("=== running AF_INET6 dual-stack script with PATCHED mihomo ===")
          print(machine.succeed("runuser -u alice -- python3 /tmp/b.py"))

          print("=== mihomo log (expect uid=1001 now) ===")
          print(machine.succeed("journalctl -u mihomo.service --no-pager | grep -iE 'uid|process' | tail -20"))

          # 断言：patch 修复后，双栈 socket 也能查到 uid=1001
          machine.succeed("journalctl -u mihomo.service --no-pager | grep 'uid=1001'")
          print("OK: dual-stack socket resolved uid=1001 after patch -> bug fixed")
        '';
      };
    };
}