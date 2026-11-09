{
  description = "单用户 tun：系统级 sing-box 纯转发（auto_route）到用户 mihomo";

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
        name = "single-tun-domain";
        nodes = {
          router = ./router.nix;
          target = ./target.nix;
        };

        testScript = ''
          start_all()
          router.wait_for_unit("multi-user.target")
          target.wait_for_unit("multi-user.target")
          target.wait_for_unit("echo-server.service")
          router.wait_for_unit("single-mihomo.service")
          router.wait_for_unit("single-tun-singbox.service")

          print("=== [diag] ip rule (auto_route 生成的) ===")
          print(router.succeed("ip rule show"))
          print("=== [diag] ip route table all ===")
          print(router.succeed("ip -4 route show table all"))
          print("=== [diag] sing-box journal ===")
          print(router.succeed("journalctl -u single-tun-singbox.service -n 60 --no-pager || true"))

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

          udpecho = (
            "import socket, sys\n"
            "host, port = sys.argv[1], int(sys.argv[2])\n"
            "ai = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "s.settimeout(10)\n"
            "s.sendto(b'udp-hello', ai[0][4])\n"
            "x, _ = s.recvfrom(4096)\n"
            "assert x == b'udp-hello', x\n"
            "print('UDP_OK', host)\n"
          )
          router.succeed("cat > /tmp/udpecho.py <<'PYEOF'\n" + udpecho + "PYEOF\n")

          print("=== root -> echo.example.test TCP (expect TCP_OK，auto_route + 域名下发) ===")
          print(router.succeed("python3 /tmp/echodns.py echo.example.test 9999"))
          print("=== root -> echo.example.test UDP (expect UDP_OK) ===")
          print(router.succeed("python3 /tmp/udpecho.py echo.example.test 9999"))

          print("=== mihomo 日志（域名应出现在 dial 行） ===")
          print(router.succeed("journalctl -u single-mihomo.service -n 60 --no-pager || true"))
        '';
      };
    };
}