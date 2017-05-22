#!/usr/bin/env python3
import anticsrf
from urllib import parse
from http.server import BaseHTTPRequestHandler, HTTPServer

t = anticsrf.token_clerk(keysize=2, keyfunc=anticsrf.keyfun_r)


class Server(BaseHTTPRequestHandler):
    def do_GET(self):
        po = parse.urlparse(self.path)
        qs = dict(parse.parse_qsl(po.query))
        self.send_response(200)
        self.end_headers()

        if not qs:
            return

        res = {}
        if qs["action"] == "new":
            res = t.register_new()
        elif qs["action"] == "valid":
            res = t.is_registered(qs["tok"])

        self.wfile.write(bytes(str(res), "utf-8"))

# action=new
# {'tok': 'ab', 'exp': 1495427365491373, 'iat': 1495423765491373},
# action=valid&key=ab
# {'old': False, 'reg': True, 'exp': 1495427365491373}


if __name__ == '__main__':
    port = 9960
    server_address = ("", port)
    httpd = HTTPServer(server_address, Server)

    print("Starting httpd on port {}...".format(port))

    httpd.serve_forever()
