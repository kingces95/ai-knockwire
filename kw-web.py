import http.server, datetime, os, secrets, urllib.parse, urllib.request, json
import base64, hashlib, struct, threading, time, signal
from http.cookies import SimpleCookie
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CONFIG_PATH = '/etc/knockwire/meta.env'
GRAPH_VERSION = 'v23.0'
REDIRECT_URI = 'https://knockwire.ai/auth/meta/callback'

# ---------- guid registration (design: guid-hash-cert-design) ----------
# All knobs are env-overridable so the test harness can run the same
# code with short clocks and scratch paths.
STATE_PATH = os.environ.get('KW_STATE_PATH', '/var/lib/knockwire/state.json')
LOG_PATH = os.environ.get('KW_LOG_PATH', '/var/log/kw-test.log')
CERTMINT_BASE = os.environ.get('KW_CERTMINT_BASE', 'https://www.certmint.net')
PORT_POOL_START = int(os.environ.get('KW_PORT_START', '20000'))
PORT_POOL_END = int(os.environ.get('KW_PORT_END', '20999'))
LEASE_TTL_SECS = int(os.environ.get('KW_LEASE_TTL_SECS', str(24 * 3600)))
PORT_COLLECT_SECS = int(os.environ.get('KW_PORT_COLLECT_SECS', str(24 * 3600)))
CHALLENGE_TTL_SECS = int(os.environ.get('KW_CHALLENGE_TTL_SECS', '300'))
CULL_INTERVAL_SECS = int(os.environ.get('KW_CULL_INTERVAL_SECS', '60'))
TRUST_TTL_SECS = int(os.environ.get('KW_TRUST_TTL_SECS', '300'))
LISTEN_PORT = int(os.environ.get('KW_PORT', '18080'))

def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)

def ts(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')

def parse_ts(s):
    return datetime.datetime.strptime(s, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)

LOCK = threading.Lock()
def load_state():
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except Exception:
        return {'registrations': {}, 'challenges': {}, 'ports': {}}

def save_state(st):
    tmp = STATE_PATH + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(st, f)
    os.replace(tmp, STATE_PATH)

# ---------- certmint trust anchors (fetched, cached) ----------
TRUST = {'fetched': 0, 'mint_raw': None, 'revoked': set()}

def trust():
    """(mint public key raw bytes, revoked serial set) from certmint,
    cached for TRUST_TTL_SECS. Raises if never fetched successfully."""
    if time.time() - TRUST['fetched'] < TRUST_TTL_SECS and TRUST['mint_raw']:
        return TRUST['mint_raw'], TRUST['revoked']
    # A named UA: Cloudflare 403s urllib's default Python-urllib one.
    ua = {'User-Agent': 'knockwire/1.0'}
    with urllib.request.urlopen(urllib.request.Request(
            CERTMINT_BASE + '/pubkey', headers=ua), timeout=10) as r:
        pub = json.load(r)
    blob = base64.b64decode(pub['key'].split()[1])
    raw = blob[-32:]
    with urllib.request.urlopen(urllib.request.Request(
            CERTMINT_BASE + '/revoked', headers=ua), timeout=10) as r:
        revoked = {int(x) for x in r.read().decode().split()}
    TRUST.update(fetched=time.time(), mint_raw=raw, revoked=revoked)
    return raw, revoked

# ---------- cert / key helpers (same constructions as certmint) ----------
def parse_cert(text):
    lines = text.strip().split('\n')
    sig_line = lines[-1]
    if not sig_line.startswith('signature: '):
        raise ValueError('no signature line')
    body = ('\n'.join(lines[:-1]) + '\n').encode()
    fields = {}
    identities = []
    for ln in lines[:-1]:
        if ': ' in ln:
            k, v = ln.split(': ', 1)
            if k == 'identity':
                identities.append(v)
            else:
                fields[k] = v
    return fields, identities, body, sig_line.split(': ', 1)[1]

def parse_openssh_key(line):
    parts = line.strip().split()
    if len(parts) < 2 or parts[0] != 'ssh-ed25519':
        raise ValueError('not an ssh-ed25519 key')
    blob = base64.b64decode(parts[1])
    ln, = struct.unpack('>I', blob[:4])
    if blob[4:4 + ln] != b'ssh-ed25519':
        raise ValueError('bad blob')
    off = 4 + ln
    ln2, = struct.unpack('>I', blob[off:off + 4])
    raw = blob[off + 4:off + 4 + ln2]
    if len(raw) != 32:
        raise ValueError('bad key length')
    return blob, raw

def guid_hash_of(guid_bytes):
    return 'SHA256:' + base64.b64encode(hashlib.sha256(guid_bytes).digest()).decode().rstrip('=')

# ---------- ports: what is actually bound, not just registered ----------
def bound_ports():
    """Listening TCP ports in the pool range, read from the kernel
    tables — the ground truth for 'in use'."""
    out = set()
    for path in ('/proc/net/tcp', '/proc/net/tcp6'):
        try:
            lines = open(path).read().splitlines()[1:]
        except Exception:
            continue
        for ln in lines:
            f = ln.split()
            if f[3] == '0A':  # LISTEN
                port = int(f[1].rsplit(':', 1)[1], 16)
                if PORT_POOL_START <= port <= PORT_POOL_END:
                    out.add(port)
    return out

def kill_port(port):
    """SIGTERM whatever process holds the listener on `port` — the
    sshd session serving that forward. Cull teardown, step one."""
    inodes = set()
    for path in ('/proc/net/tcp', '/proc/net/tcp6'):
        try:
            lines = open(path).read().splitlines()[1:]
        except Exception:
            continue
        for ln in lines:
            f = ln.split()
            if f[3] == '0A' and int(f[1].rsplit(':', 1)[1], 16) == port:
                inodes.add(f[9])
    if not inodes:
        return
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        try:
            for fd in os.listdir(f'/proc/{pid}/fd'):
                try:
                    target = os.readlink(f'/proc/{pid}/fd/{fd}')
                except OSError:
                    continue
                if target.startswith('socket:[') and target[8:-1] in inodes:
                    os.kill(int(pid), signal.SIGTERM)
                    break
        except OSError:
            continue

def reaper():
    """Every CULL_INTERVAL_SECS: refresh last-bound sightings, and
    tear down expired leases IN REVERSE — kill the connection, then
    strip the registration."""
    while True:
        time.sleep(CULL_INTERVAL_SECS)
        try:
            bound = bound_ports()
            kills = []
            with LOCK:
                st = load_state()
                changed = False
                for h, reg in list(st['registrations'].items()):
                    port = reg['port']
                    if port in bound:
                        reg['last_bound'] = ts(now_utc())
                        st['ports'][str(port)] = {'last_used': ts(now_utc())}
                        changed = True
                    if parse_ts(reg['lease_expires']) < now_utc():
                        kills.append(port)
                        del st['registrations'][h]
                        changed = True
                if changed:
                    save_state(st)
            for port in kills:
                kill_port(port)
        except Exception:
            continue

def load_config():
    cfg = {}
    try:
        with open(CONFIG_PATH) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, v = line.split('=', 1)
                    cfg[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    return cfg

SESSIONS = {}  # session_token -> {'id':..., 'name':..., 'email':...}

CSS = "body{font-family:system-ui,sans-serif;margin:4rem auto;max-width:40rem;padding:0 1rem}h1{font-weight:600}p{color:#555}.btn{display:inline-block;background:#0081fb;color:#fff;padding:.7rem 1.4rem;border-radius:.5rem;text-decoration:none;font-weight:600}code{background:#f0f0f0;padding:.15rem .4rem;border-radius:.3rem}"

def page(title, inner):
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>{CSS}</style>
</head>
<body>
{inner}
</body>
</html>
""".encode()

class H(http.server.BaseHTTPRequestHandler):
    def _log(self):
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        src = self.headers.get('CF-Connecting-IP', self.client_address[0])
        ray = self.headers.get('CF-Ray', '-')
        host = self.headers.get('Host', '-')
        with open(LOG_PATH, 'a') as f:
            f.write(f'{ts} {self.command} {self.path} host={host} from {src} ray={ray}\n')
        return ts

    def _json(self, code, obj):
        self._send(code, json.dumps(obj).encode(), 'application/json')

    def _body_json(self):
        ln = int(self.headers.get('Content-Length') or 0)
        if ln <= 0 or ln > 65536:
            return {}
        try:
            return json.loads(self.rfile.read(ln).decode())
        except Exception:
            return {}

    # ---------- guid registration ----------
    def _register_challenge(self, qs):
        serial = (qs.get('serial') or [''])[0]
        if not serial.isdigit():
            self._json(400, {'error': 'serial required'})
            return
        nonce = secrets.token_urlsafe(32)
        with LOCK:
            st = load_state()
            st['challenges'][nonce] = {'serial': int(serial),
                                       'expires': ts(now_utc() + datetime.timedelta(seconds=CHALLENGE_TTL_SECS))}
            save_state(st)
        self._json(200, {'nonce': nonce,
                         'signing_string': f'knockwire-register-v1\n{serial}\n{nonce}'})

    def _register(self):
        req = self._body_json()
        cert_text = req.get('cert') or ''
        nonce = req.get('nonce') or ''
        sig_b64 = req.get('signature') or ''
        guid_hex = (req.get('guid') or '').strip().lower()
        try:
            mint_raw, revoked = trust()
        except Exception:
            self._json(502, {'error': 'certmint trust anchors unavailable'})
            return
        try:
            fields, identities, body, mint_sig = parse_cert(cert_text)
        except Exception:
            self._json(400, {'error': 'unparseable cert'})
            return
        try:
            Ed25519PublicKey.from_public_bytes(mint_raw).verify(base64.b64decode(mint_sig), body)
        except Exception:
            self._json(400, {'error': 'mint signature does not verify'})
            return
        guid_hash = fields.get('guid-hash')
        if not guid_hash:
            self._json(400, {'error': 'not a guid cert'})
            return
        serial = fields.get('serial', '')
        if not serial.isdigit():
            self._json(400, {'error': 'bad serial'})
            return
        if int(serial) in revoked:
            self._json(403, {'error': 'serial revoked'})
            return
        if parse_ts(fields['expires']) < now_utc():
            self._json(403, {'error': 'cert expired'})
            return
        try:
            guid_bytes = bytes.fromhex(guid_hex)
        except Exception:
            self._json(400, {'error': 'guid must be hex'})
            return
        if guid_hash_of(guid_bytes) != guid_hash:
            self._json(400, {'error': 'guid does not match cert'})
            return
        with LOCK:
            st = load_state()
            ch = st['challenges'].pop(nonce, None)
            if ch:
                save_state(st)
        if not ch or ch.get('serial') != int(serial) or parse_ts(ch['expires']) < now_utc():
            self._json(400, {'error': 'unknown or expired challenge'})
            return
        try:
            blob, raw = parse_openssh_key(fields['key'])
            Ed25519PublicKey.from_public_bytes(raw).verify(
                base64.b64decode(sig_b64),
                f'knockwire-register-v1\n{serial}\n{nonce}'.encode())
        except Exception:
            self._json(403, {'error': 'possession proof does not verify'})
            return
        # Allocate or renew, under the one lock.
        with LOCK:
            st = load_state()
            bound = bound_ports()
            lease_exp = ts(now_utc() + datetime.timedelta(seconds=LEASE_TTL_SECS))
            existing = st['registrations'].get(guid_hash)
            if existing:
                # Register while alive returns the same port — and a
                # lapsed lease re-adopts the port its connection may
                # still hold. Latest verified cert/key wins the record.
                port = existing['port']
                existing.update({'key': fields['key'],
                                 'key-fingerprint': fields['key-fingerprint'],
                                 'serial': int(serial),
                                 'lease_expires': lease_exp})
                st['ports'][str(port)] = {'last_used': ts(now_utc())}
                save_state(st)
                self._json(200, {'port': port, 'guid_hash': guid_hash,
                                 'lease_expires': lease_exp})
                return
            live_ports = {r['port'] for r in st['registrations'].values()
                          if parse_ts(r['lease_expires']) >= now_utc()}
            port = None
            for cand in range(PORT_POOL_START, PORT_POOL_END + 1):
                if cand in live_ports or cand in bound:
                    continue
                used = st['ports'].get(str(cand), {}).get('last_used')
                if used and parse_ts(used) + datetime.timedelta(seconds=PORT_COLLECT_SECS) > now_utc():
                    continue  # collected ports rest before reissue
                port = cand
                break
            if port is None:
                self._json(503, {'error': 'no ports available'})
                return
            st['registrations'][guid_hash] = {
                'port': port, 'key': fields['key'],
                'key-fingerprint': fields['key-fingerprint'],
                'serial': int(serial), 'lease_expires': lease_exp,
                'last_bound': None}
            st['ports'][str(port)] = {'last_used': ts(now_utc())}
            save_state(st)
        self._json(201, {'port': port, 'guid_hash': guid_hash,
                         'lease_expires': lease_exp})

    # ---------- knock relay: path only, everything else stripped ----------
    def _knock(self, guid_hex, rest):
        try:
            guid_hash = guid_hash_of(bytes.fromhex(guid_hex))
        except Exception:
            guid_hash = None
        port = None
        if guid_hash:
            with LOCK:
                st = load_state()
            reg = st['registrations'].get(guid_hash)
            if reg and parse_ts(reg['lease_expires']) >= now_utc():
                port = reg['port']
        if port is None:
            self._send(200, b'knockwire drop\n', 'text/plain')
            return
        # The delivered request is rebuilt from the path alone: no
        # body, no query, no fragment, no sender headers. Loopback is
        # never proxied.
        url = f'http://127.0.0.1:{port}{rest}'
        relay = urllib.request.Request(url, data=None, method=self.command)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(relay, timeout=5) as r:
                r.read()
            self._send(200, b'knockwire knock\n', 'text/plain')
        except Exception:
            self._send(200, b'knockwire drop\n', 'text/plain')

    def _send(self, code, body, ctype='text/html; charset=utf-8', extra=None):
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def _redirect(self, location, extra=None):
        self.send_response(302)
        self.send_header('Location', location)
        self.send_header('Content-Length', '0')
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()

    def _cookies(self):
        c = SimpleCookie()
        raw = self.headers.get('Cookie')
        if raw:
            c.load(raw)
        return {k: morsel.value for k, morsel in c.items()}

    def _session_user(self):
        tok = self._cookies().get('kw_session')
        return SESSIONS.get(tok) if tok else None

    def _route(self):
        ts = self._log()
        host = (self.headers.get('Host') or '').split(':')[0].lower()
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        # Agent API plane (any host): guid registration.
        if path == '/v1/register/challenge' and self.command == 'GET':
            self._register_challenge(urllib.parse.parse_qs(parsed.query))
            return
        if path == '/v1/register' and self.command == 'POST':
            self._register()
            return
        if host in ('push.knockwire.ai', 'push.knockwire.net'):
            # A knock is /<guid>/<service...>: deliver path-only, or
            # drop. Non-knock paths keep the doorbell stub.
            parts = path.split('/', 2)
            if len(parts) >= 2 and len(parts[1]) == 64 and \
                    all(c in '0123456789abcdef' for c in parts[1].lower()):
                rest = '/' + parts[2] if len(parts) > 2 and parts[2] else '/'
                self._knock(parts[1].lower(), rest)
                return
            self._send(200, f'knockwire hit {ts}\n'.encode(), 'text/plain')
            return
        cfg = load_config()
        app_id = cfg.get('META_APP_ID', '')
        app_secret = cfg.get('META_APP_SECRET', '')

        if path in ('/', '/index.html'):
            user = self._session_user()
            if user:
                email_line = f"<p>email: <code>{user.get('email') or '(not granted)'}</code></p>" if 'email' in user else ''
                name_line = f"<p>name: <code>{user.get('name') or '(unknown)'}</code></p>" if user.get('name') else ''
                inner = f"""<h1>knockwire</h1>
<p>You are signed in with Meta.</p>
<p>Your Meta ID: <code>{user['id']}</code></p>
{name_line}{email_line}
<p><a href="/logout">Sign out</a></p>"""
                self._send(200, page('knockwire', inner))
            elif app_id:
                inner = """<h1>knockwire</h1>
<p>Sign in to continue.</p>
<p><a class="btn" href="/auth/meta">Continue with Meta</a></p>"""
                self._send(200, page('knockwire', inner))
            else:
                inner = """<h1>knockwire</h1>
<p>Meta login is not configured yet.</p>"""
                self._send(200, page('knockwire', inner))
            return

        if path == '/auth/meta':
            if not app_id:
                self._send(503, page('knockwire', '<h1>knockwire</h1><p>Meta login is not configured yet.</p>'))
                return
            state = secrets.token_urlsafe(24)
            params = urllib.parse.urlencode({
                'client_id': app_id,
                'redirect_uri': REDIRECT_URI,
                'state': state,
                'response_type': 'code',
                'scope': 'public_profile',
            })
            cookie = f'kw_state={state}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600'
            self._redirect(f'https://www.facebook.com/{GRAPH_VERSION}/dialog/oauth?{params}',
                           [('Set-Cookie', cookie)])
            return

        if path == '/auth/meta/callback':
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if 'error' in qs:
                self._send(400, page('knockwire', f"<h1>knockwire</h1><p>Meta login was declined or failed: {qs.get('error_description', qs['error'])[0]}</p><p><a href=\"/\">Back</a></p>"))
                return
            code = (qs.get('code') or [''])[0]
            state = (qs.get('state') or [''])[0]
            if not code or not state or state != self._cookies().get('kw_state'):
                self._send(400, page('knockwire', '<h1>knockwire</h1><p>Invalid login callback (state check failed).</p><p><a href="/">Back</a></p>'))
                return
            try:
                token_params = urllib.parse.urlencode({
                    'client_id': app_id,
                    'client_secret': app_secret,
                    'redirect_uri': REDIRECT_URI,
                    'code': code,
                })
                with urllib.request.urlopen(f'https://graph.facebook.com/{GRAPH_VERSION}/oauth/access_token?{token_params}', timeout=15) as r:
                    token = json.load(r)['access_token']
                me_params = urllib.parse.urlencode({'fields': 'id,name', 'access_token': token})
                with urllib.request.urlopen(f'https://graph.facebook.com/{GRAPH_VERSION}/me?{me_params}', timeout=15) as r:
                    me = json.load(r)
            except Exception as e:
                self._send(502, page('knockwire', f'<h1>knockwire</h1><p>Could not complete Meta login: {type(e).__name__}</p><p><a href="/">Back</a></p>'))
                return
            tok = secrets.token_urlsafe(32)
            SESSIONS[tok] = {'id': me['id'], 'name': me.get('name')}
            cookie = f'kw_session={tok}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400'
            clear_state = 'kw_state=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'
            self._redirect('/', [('Set-Cookie', cookie), ('Set-Cookie', clear_state)])
            return

        if path == '/logout':
            tok = self._cookies().get('kw_session')
            if tok:
                SESSIONS.pop(tok, None)
            clear = 'kw_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'
            self._redirect('/', [('Set-Cookie', clear)])
            return

        self._send(404, b'not found\n', 'text/plain')

    do_GET = _route
    do_POST = _route
    do_HEAD = _route

threading.Thread(target=reaper, daemon=True).start()
http.server.ThreadingHTTPServer(('127.0.0.1', LISTEN_PORT), H).serve_forever()
