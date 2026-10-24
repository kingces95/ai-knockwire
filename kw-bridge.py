#!/usr/bin/env python3
"""kw-bridge — knockwire's certwire app-layer sender.

kw-web stays a stdlib HTTP service; this companion holds knockwire's
domain-cert connection to the certwire router and speaks the
app layer (certwire_app) on its behalf:

  POST http://127.0.0.1:18770/deliver  {"to": <muse cert address>,
      "path": "/<guid>/<service...>", "method": "POST"}
      -> 200 {"status": <ack status>}  when the muse acked
      -> 502 {"status": null}          unbound / no ack (the caller
                                        spools to the mailbox, whose
                                        flusher retries through here)

The destination's router whitelist admits this service by its cert
domain (knockwire.net); the bridge in turn whitelists each muse
address it is asked to deliver to (acks travel back over the same
binding pair). The domain private key never leaves this host.
"""
import asyncio, json, os, sys, threading, http.server

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from certwire_client import CertwireClient
from certwire_app import AppClient
from cryptography.hazmat.primitives import serialization

CERT_FILE = os.environ.get('KW_BRIDGE_CERT', '/etc/knockwire/domain-cert.txt')
KEY_FILE = os.environ.get('KW_BRIDGE_KEY', '/etc/knockwire/provisor-ed25519')
URL = os.environ.get('KW_BRIDGE_URL', 'wss://certwire.net')
PORT = int(os.environ.get('KW_BRIDGE_PORT', '18770'))

CERT_TEXT = open(CERT_FILE).read()
_key = serialization.load_ssh_private_key(open(KEY_FILE, 'rb').read(),
                                          password=None)
import base64
sign = lambda data: base64.b64encode(_key.sign(data)).decode()


def log(msg):
    import time
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} "
          f"kw-bridge: {msg}", flush=True)


LOOP = None
CW = None
APP = None
DESTS = set()


async def amain():
    global CW, APP
    CW = CertwireClient(URL, CERT_TEXT, sign, log=log)
    APP = AppClient(CW, log=log)
    log('holding certwire connection')
    await CW.run()


def deliver(to, path, method):
    """Sync facade for the HTTP thread. Returns the ack status or
    None (unbound / timeout / not connected)."""
    async def _go():
        if to not in DESTS:
            DESTS.add(to)
            await CW.whitelist(sorted(DESTS))
        return await APP.post(to, path, method=method, timeout=12)
    fut = asyncio.run_coroutine_threadsafe(_go(), LOOP)
    try:
        return fut.result(timeout=15)
    except Exception as e:
        log(f'deliver {path} -> {to} failed: {e}')
        return None


class H(http.server.BaseHTTPRequestHandler):
    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == '/health':
            self._json(200, {'bound': CW.address if CW else None})
        else:
            self._json(404, {'error': 'not found'})

    def do_POST(self):
        if self.path != '/deliver':
            self._json(404, {'error': 'not found'})
            return
        try:
            ln = int(self.headers.get('Content-Length') or 0)
            req = json.loads(self.rfile.read(ln).decode() or '{}')
            to, path = req['to'], req['path']
            method = req.get('method') or 'POST'
        except Exception:
            self._json(400, {'error': 'bad request'})
            return
        status = deliver(to, path, method)
        if status is None:
            self._json(502, {'status': None})
        else:
            log(f'delivered {method} {path} -> {to}: ack {status}')
            self._json(200, {'status': status})

    def log_message(self, *a):
        pass


if __name__ == '__main__':
    LOOP = asyncio.new_event_loop()
    t = threading.Thread(target=LOOP.run_forever, daemon=True)
    t.start()
    asyncio.run_coroutine_threadsafe(amain(), LOOP)
    log(f'http on 127.0.0.1:{PORT}')
    http.server.ThreadingHTTPServer(('127.0.0.1', PORT), H).serve_forever()
