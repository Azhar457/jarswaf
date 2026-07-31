#!/usr/bin/env python3
"""jarsWAF Red Team — dummy backend echo server on 8080.
Logs every request to /tmp/redteam-backend.log so we can prove
whether a payload actually REACHED the backend (WAF bypass).
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import sys
import datetime

LOG = "/tmp/redteam-backend.log"


def log(msg):
    with open(LOG, "a") as f:
        f.write(f"{datetime.datetime.now().isoformat()} {msg}\n")


class Echo(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _handle(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        log(f"REQ {self.command} {self.path} UA={self.headers.get('User-Agent','')} BODY={body[:200]}")
        resp = json.dumps({
            "backend": "echo",
            "method": self.command,
            "path": self.path,
            "headers": {k: v for k, v in self.headers.items() if k.lower() in ("host", "content-type", "x-forwarded-for", "authorization", "cookie")},
            "body": body[:500],
        })
        data = resp.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_DELETE = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    print(f"Backend echo listening on :{port}")
    HTTPServer(("127.0.0.1", port), Echo).serve_forever()
