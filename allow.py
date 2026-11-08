import secrets
import socketserver
import subprocess
import sys
from http.server import BaseHTTPRequestHandler

command = " ".join(sys.argv[1:])
token = "/" + secrets.token_urlsafe(16)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != token:
            self.send_response(403)
            self.end_headers()
            return
        proc = subprocess.run(["sh", "-c", command],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        body = proc.stdout + f"\n--- exit {proc.returncode} ---\n".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

with Server(("127.0.0.1", 0), Handler) as srv:
    print(f"curl -s http://127.0.0.1:{srv.server_address[1]}{token}", flush=True)
    srv.serve_forever()