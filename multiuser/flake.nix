{
  description = "多用户 per-user TUN（include-uid + proxy 直连，不查进程）+ fake-ip DNS + 域名下发验证";

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
        name = "mihomo-multiuser-tun-domain";
        nodes = {
          router = ./router.nix;
          target = ./target.nix;
        };

        testScript = ''
          start_all()
          router.wait_for_unit("multi-user.target")
          target.wait_for_unit("multi-user.target")
          target.wait_for_unit("echo-server.service")
          router.wait_for_unit("mihomo-system.service")
          router.wait_for_unit("mihomo-user-alice.service")
          router.wait_for_unit("mihomo-user-bob.service")
          router.wait_until_succeeds("ip link show tun-alice >/dev/null 2>&1", timeout=60)
          router.wait_until_succeeds("ip link show tun-bob >/dev/null 2>&1", timeout=60)

          print("=== [diag] ip rule (router) ===")
          print(router.succeed("ip rule show"))
          print("=== [diag] ip route table all (router) ===")
          print(router.succeed("ip -4 route show table all"))
          print("=== [diag] ip addr (router) ===")
          print(router.succeed("ip addr"))
          print("=== [diag] mihomo-system journal ===")
          print(router.succeed("journalctl -u mihomo-system.service -n 100 --no-pager || true"))

          # 关键发现：mihomo 的 include-uid auto-route 规则，对「本地进程发出」的包
          # （源地址已被内核解析成 eth0 的 IP，而非 0.0.0.0）匹配不到
          #   not iif lo lookup <table> / from 0.0.0.0 iif lo lookup <table>
          # 于是 include 的 uid 流量会落到 main 表、走 eth0，进不了 tun。
          # 与 feasibility 一致：手动补 ip rule，强制 uid 流量进各自 lookup table。

          echodns = (
            "import socket, sys\n"
            "host, port = sys.argv[1], int(sys.argv[2])\n"
            "ai = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "s.settimeout(10)\n"
            "s.connect(ai[0][4])\n"
            "s.sendall(b'domain-hello')\n"
            "s.shutdown(socket.SHUT_WR)\n"
            "data = bytes()\n"
            "while True:\n"
            "    x = s.recv(4096)\n"
            "    if not x: break\n"
            "    data += x\n"
            "assert data == b'domain-hello', data\n"
            "print('TCP_OK', host)\n"
          )
          router.succeed("cat > /tmp/echodns.py <<'PYEOF'\n" + echodns + "PYEOF\n")

          # 手动补 uid 分流规则（pref 7500/7501，优先级高于 sing-tun 自动生成的 8000+）
          router.succeed("ip rule add pref 7500 uidrange 1001-1001 lookup 2100")
          router.succeed("ip rule add pref 7501 uidrange 1002-1002 lookup 2101")
          print("=== [diag] patched ip rule (uidrange) ===")
          print(router.succeed("ip rule show | grep -E '7500|7501' || true"))

          print("=== [diag] /etc/resolv.conf ===")
          print(router.succeed("cat /etc/resolv.conf"))
          print("=== [diag] tcpdump DNS during alice getaddrinfo ===")
          router.succeed("tcpdump -ni any udp port 53 > /tmp/dns.log 2>&1 & sleep 1; runuser -u alice -- python3 /tmp/echodns.py echo-alice.example.test 9999 2>&1 || true; sleep 2; pkill tcpdump || true")
          print(router.succeed("cat /tmp/dns.log || echo '(empty)'"))

          # 正向 + 分流正确性。每个 per-user mihomo 只用 DOMAIN 精确规则放行自己的域名，
          # 其余 MATCH,REJECT。因此：
          #   1) 能连上 = 域名确实下发给 per-user（拿到 IP / fake-ip 都会命中 REJECT）
          #   2) alice 访问 bob 的域名必须失败 = 证明 include-uid 分流没串台
          print("=== alice -> echo-alice.example.test (expect TCP_OK) ===")
          print(router.succeed("runuser -u alice -- python3 /tmp/echodns.py echo-alice.example.test 9999"))
          print("=== alice -> echo-bob.example.test (expect FAIL) ===")
          router.fail("runuser -u alice -- python3 /tmp/echodns.py echo-bob.example.test 9999")
          print("=== bob -> echo-bob.example.test (expect TCP_OK) ===")
          print(router.succeed("runuser -u bob -- python3 /tmp/echodns.py echo-bob.example.test 9999"))
          print("=== bob -> echo-alice.example.test (expect FAIL) ===")
          router.fail("runuser -u bob -- python3 /tmp/echodns.py echo-alice.example.test 9999")

          print("=== per-user mihomo logs (域名应出现在 dial 行) ===")
          print(router.succeed("journalctl -u mihomo-user-alice.service -n 60 --no-pager || true"))
          print(router.succeed("journalctl -u mihomo-user-bob.service -n 60 --no-pager || true"))

          # proxy 路径不应做 UID 反查，因此系统 mihomo 日志不应出现 could not get uid
          syslog = router.succeed("journalctl -u mihomo-system.service --no-pager")
          assert "could not get uid" not in syslog, "found 'could not get uid' in system mihomo log"
        '';
      };
    };
}