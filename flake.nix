{
  description = "mihomo per-user TUN test (MetaCubeX/mihomo discussions#3391)";

  inputs = {
    nixpkgs.url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.zst";
  };

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
      checks.${system} = {

        # ===================================================================
        # 每个用户一个 TUN —— 按 UID 分流 + proxy 直接转发（不查进程）
        # ===================================================================
        feasibility = pkgs.testers.runNixOSTest {
          name = "mihomo-per-user-tun-feasibility";
          nodes = {
            router = ./test/router.nix;
            target = ./test/target.nix;
          };

          testScript = ''
            start_all()
            router.wait_for_unit("multi-user.target")
            target.wait_for_unit("multi-user.target")
            target.wait_for_unit("echo-server.service")
            router.succeed("sleep 3")
            print("=== [diag] mihomo-user journal ===")
            print(router.succeed("journalctl -u mihomo-user.service -n 100 --no-pager || true"))
            print("=== [diag] mihomo-system journal ===")
            print(router.succeed("journalctl -u mihomo-system.service -n 100 --no-pager || true"))
            router.wait_for_unit("mihomo-user.service")
            router.wait_for_unit("mihomo-system.service")
            router.wait_until_succeeds("ip link show tun-alice >/dev/null 2>&1", timeout=60)

            print("=== ip rule (router) ===")
            print(router.succeed("ip rule show"))
            print("=== ip route table all v4 (router) ===")
            print(router.succeed("ip -4 route show table all"))
            print("=== ip addr (router) ===")
            print(router.succeed("ip addr"))
            print("=== system mihomo log ===")
            print(router.succeed("journalctl -u mihomo-system.service -n 60 --no-pager"))
            print("=== user mihomo log ===")
            print(router.succeed("journalctl -u mihomo-user.service -n 30 --no-pager"))

            echo = (
              "import socket\n"
              "HOST='192.168.50.2'; PORT=9999\n"
              "s=socket.create_connection((HOST,PORT),timeout=10)\n"
              "s.sendall(b'tcp-hello'); s.shutdown(socket.SHUT_WR)\n"
              "d=bytes()\n"
              "while True:\n"
              "    x=s.recv(4096)\n"
              "    if not x: break\n"
              "    d+=x\n"
              "assert d==b'tcp-hello', d\n"
              "print('TCP_OK')\n"
              "u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); u.settimeout(10)\n"
              "u.sendto(b'udp-hello',(HOST,PORT))\n"
              "data,_=u.recvfrom(4096)\n"
              "assert data==b'udp-hello', data\n"
              "print('UDP_OK')\n"
            )
            router.succeed("cat > /tmp/echotest.py <<'PYEOF'\n" + echo + "PYEOF\n")

            # 强制 include-uid 1001 的流量进 TUN（sing-tun 对直连子网默认走 main，
            # 这里模拟真实场景中目标走 default 路由、由 include-uid 拉进 TUN 的情况）
            router.succeed("ip rule add pref 7500 uidrange 1001-1001 lookup 2100")
            print("=== patched ip rule (alice 1001 forced into tun table) ===")
            print(router.succeed("ip rule show | grep -E '7500|8000|8010' || true"))

            print("=== alicesvc (uid 1002) echo direct (bypasses tun, sanity check) ===")
            out2 = router.succeed("runuser -u alicesvc -- python3 /tmp/echotest.py")
            print(out2)
            assert "TCP_OK" in out2 and "UDP_OK" in out2, out2

            print("=== alice (uid 1001) echo via tun -> proxy -> user mihomo -> target ===")
            router.succeed("tcpdump -ni tun-alice -l > /tmp/tun.log 2>&1 & tcpdump -ni lo port 1080 -l > /tmp/lo.log 2>&1 & sleep 1; echo tcpdump-started")
            out = ""
            try:
                out = router.succeed("runuser -u alice -- python3 /tmp/echotest.py")
                print(out)
            except Exception:
                router.succeed("sleep 1; pkill tcpdump || true")
                print("=== [diag] tcpdump tun-alice (SYN entering tun?) ===")
                print(router.succeed("cat /tmp/tun.log || echo 'empty'"))
                print("=== [diag] tcpdump lo:1080 (proxy connection?) ===")
                print(router.succeed("cat /tmp/lo.log || echo 'empty'"))
                print("=== [diag] mihomo-system journal ===")
                print(router.succeed("journalctl -u mihomo-system.service -n 150 --no-pager || true"))
                print("=== [diag] mihomo-user journal ===")
                print(router.succeed("journalctl -u mihomo-user.service -n 150 --no-pager || true"))
                raise
            assert "TCP_OK" in out, out
            assert "UDP_OK" in out, out

            # proxy 路径不应做 UID 反查，因此不应出现 could not get uid
            syslog = router.succeed("journalctl -u mihomo-system.service --no-pager")
            assert "could not get uid" not in syslog, "found 'could not get uid' in system mihomo log"

            # 强证明：停掉用户 mihomo，alice 的流量必须失败（说明它确实走了 proxy）
            router.succeed("systemctl stop mihomo-user.service")
            udpfail = (
              "import socket\n"
              "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(6)\n"
              "s.sendto(b'x',('192.168.50.2',9999))\n"
              "s.recvfrom(4096)\n"
            )
            router.succeed("cat > /tmp/udpfail.py <<'PYEOF'\n" + udpfail + "PYEOF\n")
            print("=== alice echo must FAIL without per-user mihomo (proves routed via proxy) ===")
            router.fail("runuser -u alice -- python3 /tmp/udpfail.py")
            print("OK: alice traffic routed through the per-user mihomo")
          '';
        };

        # ===================================================================
        # 复现双栈 socket 导致 UID 反查不到的问题
        # ===================================================================
        dualStack = pkgs.testers.runNixOSTest {
          name = "mihomo-dual-stack-uid";
          nodes = {
            machine = ./test/dualstack.nix;
          };

          testScript = ''
            start_all()
            machine.wait_for_unit("multi-user.target")
            machine.wait_for_unit("mihomo.service")

            print("=== [diag] ip link ===")
            print(machine.succeed("ip link"))
            print("=== [diag] mihomo journal ===")
            print(machine.succeed("journalctl -u mihomo.service -n 120 --no-pager"))

            machine.wait_until_succeeds("ip link | grep -qE 'tun|Meta'", timeout=60)

            print("=== ip rule ===")
            print(machine.succeed("ip rule show"))

            # A: AF_INET socket -> IPv4 packet, UID should be found
            a = (
              "import socket,time\n"
              "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
              "s.sendto(b'x',('1.1.1.1',9999))\n"
              "print(s.getsockname())\n"
              "time.sleep(5)\n"
            )
            machine.succeed("cat > /tmp/a.py <<'PYEOF'\n" + a + "PYEOF\n")
            print("=== running A (AF_INET) as alice ===")
            print(machine.succeed("runuser -u alice -- python3 /tmp/a.py"))

            # B: AF_INET6 dual-stack socket sending to IPv4-mapped address -> UID lookup fails
            b = (
              "import socket,time\n"
              "s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)\n"
              "s.sendto(b'x',('::ffff:1.1.1.1',9999))\n"
              "print(s.getsockname())\n"
              "time.sleep(5)\n"
            )
            machine.succeed("cat > /tmp/b.py <<'PYEOF'\n" + b + "PYEOF\n")
            print("=== running B (AF_INET6 dual-stack) as alice ===")
            print(machine.succeed("runuser -u alice -- python3 /tmp/b.py"))

            print("=== mihomo full log (find-process results) ===")
            print(machine.succeed("journalctl -u mihomo.service --no-pager"))

            print("=== grep: uid / process-not-found lines ===")
            print(machine.succeed("journalctl -u mihomo.service --no-pager | grep -iE 'uid|process' | tail -80"))
          '';
        };

      };
    };
}