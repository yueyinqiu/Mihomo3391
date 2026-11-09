{ config, lib, pkgs, ... }:

let
  # UDP + TCP echo server, listens on 0.0.0.0:9999
  echo-server = pkgs.writeScript "echo-server.py" ''
    #!${pkgs.python3}/bin/python3
    import socket, threading

    HOST = "0.0.0.0"
    PORT = 9999

    def udp():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((HOST, PORT))
        while True:
            data, addr = s.recvfrom(65535)
            s.sendto(data, addr)

    def tcp():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(16)
        while True:
            c, addr = s.accept()
            def handle(conn):
                try:
                    while True:
                        d = conn.recv(65535)
                        if not d:
                            break
                        conn.sendall(d)
                except Exception:
                    pass
                finally:
                    conn.close()
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    threading.Thread(target=udp, daemon=True).start()
    tcp()
  '';
in
{
  virtualisation.vlans = [ 1 ];
  virtualisation.memorySize = 512;

  networking.interfaces.eth1.ipv4.addresses = [
    { address = "192.168.50.2"; prefixLength = 24; }
  ];

  networking.firewall.allowedTCPPorts = [ 9999 ];
  networking.firewall.allowedUDPPorts = [ 9999 53 ];

  # 提供 echo.example.test -> 192.168.50.2 的解析，供 mihomo 的 DIRECT 出站使用。
  services.dnsmasq = {
    enable = true;
    settings = {
      no-resolv = true;
      no-hosts = true;
      address = [ "/echo.example.test/192.168.50.2" ];
    };
  };

  environment.systemPackages = [ pkgs.python3 pkgs.iproute2 ];

  systemd.services.echo-server = {
    wantedBy = [ "multi-user.target" ];
    after = [ "network.target" ];
    serviceConfig = {
      ExecStart = "${pkgs.python3}/bin/python3 ${echo-server}";
      Restart = "always";
    };
  };
}