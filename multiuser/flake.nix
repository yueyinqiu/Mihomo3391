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
          router.wait_for_unit("user-tun-mihomo.service")
          router.wait_for_unit("user-tun-mihomo-alice.service")
          router.wait_for_unit("user-tun-mihomo-bob.service")
          router.wait_for_unit("user-tun-gost.service")
          router.wait_for_unit("user-tun-gost-alice.service")
          router.wait_for_unit("user-tun-gost-bob.service")
          router.wait_until_succeeds("ip link show ut-dns >/dev/null 2>&1", timeout=60)
          router.wait_until_succeeds("ip link show ut-1001 >/dev/null 2>&1", timeout=60)
          router.wait_until_succeeds("ip link show ut-1002 >/dev/null 2>&1", timeout=60)
          router.wait_until_succeeds("ip link show ut-others >/dev/null 2>&1", timeout=60)

          print("=== [diag] ip rule (router) ===")
          print(router.succeed("ip rule show"))
          print("=== [diag] ip route table all (router) ===")
          print(router.succeed("ip -4 route show table all"))
          print("=== [diag] ip addr (router) ===")
          print(router.succeed("ip addr"))
          print("=== [diag] user-tun-mihomo journal ===")
          print(router.succeed("journalctl -u user-tun-mihomo.service -n 100 --no-pager || true"))

          # 路由完全手写（所有 tun 都是 auto-route: false）：
          #   DNS 按 dport 53 全局劫持进 ut-dns（不看 uid，nsncd 代理也无所谓）
          #   连接按 uid 分流进各 tun（proxy 直连，不查进程）
          #   非普通用户兜底进 ut-others（走 rules -> others）
          #   per-user 服务 uid 提前排除到 main（避免它们的 DNS/出站被劫持或回环）

          echodns = (
            "import socket, sys\n"
            "host, port = sys.argv[1], int(sys.argv[2])\n"
            "ai = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "s.settimeout(10)\n"
            "s.connect(ai[0][4])\n"
            "s.sendall(b'domain-hello')\n"
            "x = s.recv(4096)\n"
            "assert x == b'domain-hello', x\n"
            "print('TCP_OK', host)\n"
          )
          router.succeed("cat > /tmp/echodns.py <<'PYEOF'\n" + echodns + "PYEOF\n")

          # 直接测试 gost 链（绕过 mihomo tun）：socks5 -> system gost -> unix -> per-user gost -> mihomo
          gosttest = (
            "import socket, struct\n"
            "def c(s,h,p):\n"
            "    s.sendall(bytes([5,1,0]))\n"
            "    assert s.recv(2)==bytes([5,0]), 'greeting'\n"
            "    hb=h.encode()\n"
            "    s.sendall(bytes([5,1,0,3,len(hb)])+hb+struct.pack('>H',p))\n"
            "    r=s.recv(4); assert r[0]==5 and r[1]==0, ('connect', r)\n"
            "    a=r[3]\n"
            "    if a==1: s.recv(6)\n"
            "    elif a==3: s.recv(1+s.recv(1)[0]+2)\n"
            "    elif a==4: s.recv(18)\n"
            "s=socket.create_connection(('127.0.0.1',43008),timeout=10)\n"
            "c(s,'echo-alice.example.test',9999)\n"
            "s.sendall(b'domain-hello')\n"
            "x=s.recv(4096)\n"
            "print('GOST_TEST',x)\n"
            "assert x==b'domain-hello', x\n"
          )
          router.succeed("cat > /tmp/gosttest.py <<'PYEOF'\n" + gosttest + "PYEOF\n")
          print("=== direct gost bridge test (bypass tun) ===")
          print(router.succeed("python3 /tmp/gosttest.py"))

          # 路由由 systemd oneshot（user-tun-route）声明式建立，等它跑完即可
          router.wait_for_unit("user-tun-route.service")
          print("=== [diag] hand-written ip rule (from user-tun-route) ===")
          print(router.succeed("ip rule show"))
          print("=== [diag] hand-written ip route (tables) ===")
          print(router.succeed("ip -4 route show table 2000; ip -4 route show table 2101; ip -4 route show table 2102; ip -4 route show table 2200"))

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
          print(router.succeed("journalctl -u user-tun-mihomo-alice.service -n 60 --no-pager || true"))
          print(router.succeed("journalctl -u user-tun-mihomo-bob.service -n 60 --no-pager || true"))

          # proxy 路径不应做 UID 反查，因此系统 mihomo 日志不应出现 could not get uid
          syslog = router.succeed("journalctl -u user-tun-mihomo.service --no-pager")
          assert "could not get uid" not in syslog, "found 'could not get uid' in system mihomo log"
        '';
      };
    };
}