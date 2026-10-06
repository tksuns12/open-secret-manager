"""The test site for scripts/test-mobile-chrome.sh: a sign-in page and then a
page that asks for a one-time code, over HTTPS on 127.0.0.1:8443 only, with
the certificate in the folder given; what each form sends is appended to
server.log there.

    python3 scripts/test-site.py <folder with site.crt and site.key>
"""
import http.server, ssl, sys, urllib.parse, os

here = sys.argv[1]
log = open(os.path.join(here, "server.log"), "a", buffering=1)

LOGIN = b"""<!doctype html><html><head><meta name=viewport content="width=device-width">
<title>Sign in</title></head><body style="font:18px sans-serif;margin:24px">
<h1>Sign in</h1>
<form method=post action=/login>
<p><label>Email or username<br><input name=username autocomplete=username style="font-size:20px;width:90%"></label></p>
<p><label>Password<br><input name=password type=password autocomplete=current-password style="font-size:20px;width:90%"></label></p>
<p><button type=submit style="font-size:20px">Sign in</button></p>
</form></body></html>"""

CODE = b"""<!doctype html><html><head><meta name=viewport content="width=device-width">
<title>Verify</title></head><body style="font:18px sans-serif;margin:24px">
<h1>Enter the code from your authenticator</h1>
<form method=post action=/code>
<p><input name=code autocomplete=one-time-code inputmode=numeric style="font-size:20px;width:60%"></p>
<p><button type=submit style="font-size:20px">Verify</button></p>
</form></body></html>"""

DONE = b"""<!doctype html><html><head><meta name=viewport content="width=device-width"><title>Signed in</title></head>
<body style="font:18px sans-serif;margin:24px"><h1>Signed in</h1></body></html>"""

class Handler(http.server.BaseHTTPRequestHandler):
    def page(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.page(CODE if self.path.startswith("/code") else LOGIN)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        value = lambda name: form.get(name, [""])[0]
        if self.path.startswith("/login"):
            log.write(f"LOGIN username={value('username')} password={value('password')}\n")
            self.page(CODE)
        else:
            log.write(f"CODE code={value('code')}\n")
            self.page(DONE)

    def log_message(self, *args):
        pass

server = http.server.ThreadingHTTPServer(("127.0.0.1", 8443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(os.path.join(here, "site.crt"), os.path.join(here, "site.key"))
server.socket = context.wrap_socket(server.socket, server_side=True)
print("serving https://login.osm.test:8443 on 127.0.0.1", flush=True)
server.serve_forever()
