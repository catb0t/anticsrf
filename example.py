#!/usr/bin/env python3
from http.server  import BaseHTTPRequestHandler, HTTPServer
from json         import dumps
from socketserver import ThreadingMixIn
from urllib       import parse

import anticsrf

t = anticsrf.token_clerk(
    keysize=6,
    keyfunc=anticsrf.random_key,
    expire_after=1e7
)


class Server(BaseHTTPRequestHandler):
    def do_GET(self):
        po = parse.urlparse(self.path)
        qs = dict(parse.parse_qsl(po.query))

        if "action" not in qs:
            self.send_error(400)
            return

        self.send_response(200)
        self.end_headers()

        res = {}
        if qs["action"] == "new":
            res = t.register_new()
        elif qs["action"] == "valid":
            res = t.is_valid(qs["tok"])

        self.wfile.write(bytes(dumps(res), "utf-8"))

# action=new
# {"tok": "760d40", "exp": 1497098237605895.0, "iat": 1497098227605895}
# within t.expire_after microseconds
# action=valid&key=760d40
# {"exp": 1497098270397330.0, "reg": false, "old": false}
# more than t.expire_after microseconds later
# {"exp": 1497098270397330.0, "reg": false, "old": false}
# restart the server
# action=valid&key=760d40
# {"reg": false, "old": false, "exp": 0}


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""


if __name__ == "__main__":
    port = 9960
    server_address = ("", port)
    httpd = ThreadedHTTPServer(server_address, Server)

    print("Starting httpd on port {}...".format(port))

    httpd.serve_forever()
