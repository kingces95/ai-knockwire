#!/usr/bin/env python3
"""knockwire muse-side client — stdlib + openssl + ssh CLI.

Usage:
  kw-client.py register   # register the held guid cert; print the port
  kw-client.py connect    # hold the long SSH connection (supervised loop)
  kw-client.py serve      # demux listener: record knocks (path only)
  kw-client.py show       # print the current registration

The guid + guid certs come from certmint's client storage
(~/.certmint/guid.txt, ~/.certmint/guid-certs/). Registering uses
the newest guid cert bound to the signing key (KW_KEY, default the
certmint key) — the same key material that then forms the SSH
connection, which is the point: one key, proven at registration,
enforced by sshd at connection.

Key formats: openssl signs with the PKCS#8 PEM happily, but ssh
cannot load that format ("invalid format") — and openssl cannot
sign with ssh's format either. So connect converts: the PKCS#8 key
is rewritten once into OpenSSH format at ~/.knockwire/ssh_key
(pure-stdlib conversion, same key material, fingerprint unchanged).
"""
import base64, hashlib, json, os, signal, struct, subprocess, sys, time
import datetime, http.server, urllib.parse

KW_BASE = os.environ.get('KW_BASE', 'https://knockwire.net')
KW_SSH_TARGET = os.environ.get('KW_SSH_TARGET', 'kw@knockwire.local')
KW_SSH_PORT = os.environ.get('KW_SSH_PORT', '')
DEMUX_PORT = int(os.environ.get('KW_DEMUX_PORT', '18765'))
CM_DIR = os.path.expanduser('~/.certmint')
CM_KEY = os.environ.get('KW_KEY', os.path.join(CM_DIR, 'id_ed25519.pem'))
SSH_KEY_FILE = os.path.expanduser('~/.knockwire/ssh_key')
GUID_FILE = os.path.join(CM_DIR, 'guid.txt')
GUID_DIR = os.path.join(CM_DIR, 'guid-certs')
KW_DIR = os.path.expanduser('~/.knockwire')
REG_FILE = os.path.join(KW_DIR, 'registration.json')
QUEUE_DIR = os.path.join(KW_DIR, 'queue')

def sh(*args, inp=None):
    r = subprocess.run(args, input=inp, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(f"{args[0]} failed: {r.stderr.decode()[:200]}")
    return r.stdout

def pubkey_of(pem):
    der = sh('openssl', 'pkey', '-in', pem, '-pubout', '-outform', 'DER')
    raw = der[-32:]
    blob = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + raw
    line = 'ssh-ed25519 ' + base64.b64encode(blob).decode()
    fp = 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')
    return line, fp

def sign_with(pem, msg_bytes):
    msg_f = os.path.join(KW_DIR, '.smsg')
    os.makedirs(KW_DIR, mode=0o700, exist_ok=True)
    open(msg_f, 'wb').write(msg_bytes)
    sig = sh('openssl', 'pkeyutl', '-sign', '-inkey', pem, '-rawin', '-in', msg_f)
    os.unlink(msg_f)
    return base64.b64encode(sig).decode()

def req(method, url, obj=None):
    args = ['curl', '-s', '-X', method, url,
            '-H', 'Content-Type: application/json', '-w', '\n%{http_code}']
    if obj is not None:
        args += ['-d', json.dumps(obj)]
    out = sh(*args).decode()
    body, _, code = out.rpartition('\n')
    try:
        parsed = json.loads(body) if body else {}
    except Exception:
        parsed = {}
    return int(code), parsed

def parse_cert(text):
    lines = text.strip().split('\n')
    fields = {}
    for ln in lines[:-1]:
        if ': ' in ln:
            k, v = ln.split(': ', 1)
            fields.setdefault(k, []).append(v)
    return fields

def my_guid_cert():
    _, my_fp = pubkey_of(CM_KEY)
    best = None
    if os.path.isdir(GUID_DIR):
        for name in os.listdir(GUID_DIR):
            if not name.endswith('.txt'):
                continue
            text = open(os.path.join(GUID_DIR, name)).read()
            fields = parse_cert(text)
            if fields['key-fingerprint'][0] == my_fp:
                serial = int(fields['serial'][0])
                if best is None or serial > best[0]:
                    best = (serial, text)
    return best

def _pkcs8_seed(pem_path):
    """The 32-byte Ed25519 seed out of an openssl PKCS#8 private key,
    via a minimal DER walk (openssl emits one fixed shape for
    ed25519: SEQ { INT, SEQ { OID 1.3.101.112 }, OCTET { OCTET } })."""
    der = sh('openssl', 'pkey', '-in', pem_path, '-outform', 'DER')
    pos = 0

    def take(n):
        nonlocal pos
        out = der[pos:pos + n]
        pos += n
        return out

    def tlv(tag):
        assert take(1)[0] == tag, 'unexpected DER'
        ln = take(1)[0]
        if ln & 0x80:
            n = ln & 0x7f
            ln = int.from_bytes(take(n), 'big')
        return take(ln)

    tlv(0x30)                    # outer SEQ (contents follow in stream)
    pos = 0
    take(2)                      # SEQ header
    tlv(0x02)                    # version INT
    alg = tlv(0x30)              # algorithm SEQ
    assert alg == bytes.fromhex('06032b6570'), 'not an ed25519 key'
    inner = tlv(0x04)            # privateKey OCTET STRING
    assert inner[0] == 0x04 and inner[1] == 32, 'unexpected key shape'
    return inner[2:]

def _ssh_str(b):
    return struct.pack('>I', len(b)) + b

def ssh_key_path():
    """An OpenSSH-format copy of the signing key, for ssh -i.
    Regenerated when missing or older than the source key."""
    if os.path.exists(SSH_KEY_FILE) and \
            os.path.getmtime(SSH_KEY_FILE) >= os.path.getmtime(CM_KEY):
        return SSH_KEY_FILE
    seed = _pkcs8_seed(CM_KEY)
    line, fp = pubkey_of(CM_KEY)
    blob = base64.b64decode(line.split()[1])
    raw = blob[-32:]
    check = int.from_bytes(os.urandom(4), 'big')
    block = struct.pack('>II', check, check)
    block += _ssh_str(b'ssh-ed25519') + _ssh_str(raw) + _ssh_str(seed + raw)
    block += _ssh_str(b'')
    pad = 8 - (len(block) % 8)
    block += bytes(range(1, pad + 1)) if pad else b''
    data = b'openssh-key-v1\x00'
    data += _ssh_str(b'none') + _ssh_str(b'none') + _ssh_str(b'')
    data += struct.pack('>I', 1) + _ssh_str(blob) + _ssh_str(block)
    os.makedirs(KW_DIR, mode=0o700, exist_ok=True)
    with open(SSH_KEY_FILE, 'w') as f:
        f.write('-----BEGIN OPENSSH PRIVATE KEY-----\n')
        f.write(base64.encodebytes(data).decode())
        f.write('-----END OPENSSH PRIVATE KEY-----\n')
    os.chmod(SSH_KEY_FILE, 0o600)
    return SSH_KEY_FILE

def my_certwire_address():
    """This muse's certwire address (issuer/serial of its id cert),
    advertised at registration so knockwire can deliver knocks as
    app-layer posts over certwire as well as via the tunnel port."""
    try:
        text = open(os.path.join(CM_DIR, 'cert.txt')).read()
        f = parse_cert(text)
        return f"{f['issuer'][0]}/{f['serial'][0]}"
    except Exception:
        return None

def do_register():
    guid = open(GUID_FILE).read().strip()
    found = my_guid_cert()
    assert found, 'no held guid cert bound to the certmint key'
    serial, cert = found
    code, ch = req('GET', f'{KW_BASE}/v1/register/challenge?serial={serial}')
    assert code == 200, f'challenge failed: {code} {ch}'
    sig = sign_with(CM_KEY, ch['signing_string'].encode())
    body = {'guid': guid, 'cert': cert,
            'nonce': ch['nonce'], 'signature': sig}
    cw_addr = my_certwire_address()
    if cw_addr:
        body['certwire'] = cw_addr
    code, obj = req('POST', f'{KW_BASE}/v1/register', body)
    assert code in (200, 201), f'register failed: {code} {obj}'
    os.makedirs(KW_DIR, mode=0o700, exist_ok=True)
    json.dump(obj, open(REG_FILE, 'w'))
    return obj

def cmd_register():
    obj = do_register()
    print('port:', obj['port'])
    print('lease expires:', obj['lease_expires'])

def _log(msg):
    ts = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    print(f'{ts} connect: {msg}', flush=True)

def _lease_stale(reg):
    """True when the registration is missing its port or its lease
    expires within the hour (the connect loop re-registers then;
    registering while a lease is alive returns the same port)."""
    if not reg or not reg.get('port'):
        return True
    try:
        exp = datetime.datetime.fromisoformat(
            reg['lease_expires'].replace('Z', '+00:00'))
    except Exception:
        return True
    return (exp - datetime.datetime.now(datetime.timezone.utc)
            < datetime.timedelta(hours=1))

def _sweep_orphan_ssh(port):
    """Kill any ssh already holding our exact forward. At supervisor
    start such a process can only be an orphan of a previous
    supervisor incarnation (or a wrong-transport dial): either way
    the new supervisor must start from a clean slate."""
    want = f'{port}:127.0.0.1:{DEMUX_PORT}'
    for pid in os.listdir('/proc'):
        if not pid.isdigit() or int(pid) == os.getpid():
            continue
        try:
            with open(f'/proc/{pid}/cmdline', 'rb') as f:
                argv = f.read().split(b'\0')
        except OSError:
            continue
        if argv and argv[0].endswith(b'ssh') and want.encode() in argv:
            _log(f'killing orphan ssh pid {pid} holding -R {want}')
            try:
                os.kill(int(pid), signal.SIGTERM)
            except OSError:
                pass

def cmd_connect():
    """Supervised connect: hold the SSH forward, and when ssh exits
    (the Cloudflare-proxied path severs tunnels at random ages —
    both ends log an abrupt EOF and nothing else notices), refresh
    the lease if it is near expiry and relaunch, with backoff.
    Before 2026-10-23 this exec'd ssh once and the forward stayed
    dead until the restart sentinel or the 12h lease check revived
    it; that discovery gap is what this loop closes."""
    try:
        reg = json.load(open(REG_FILE))
    except Exception:
        reg = None
    if _lease_stale(reg):
        try:
            reg = do_register()
            _log(f'registered: port {reg["port"]}, '
                 f'lease expires {reg["lease_expires"]}')
        except Exception as e:
            _log(f'register failed ({e}); continuing with on-file state')
            if reg is None:
                raise
    _sweep_orphan_ssh(reg['port'])

    child = {'proc': None}

    def _stop(signum, frame):
        if child['proc'] is not None:
            child['proc'].terminate()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    backoff = 5
    while True:
        try:
            reg = json.load(open(REG_FILE))
        except Exception:
            reg = None
        if _lease_stale(reg):
            try:
                reg = do_register()
                _log(f're-registered: port {reg["port"]}, '
                     f'lease expires {reg["lease_expires"]}')
            except Exception as e:
                _log(f're-register failed ({e}); relaunching on old state')
                if reg is None:
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 60)
                    continue
        port = reg['port']
        args = ['ssh', '-N', '-T',
                '-o', 'ExitOnForwardFailure=yes',
                '-o', 'ServerAliveInterval=30',
                '-o', 'ServerAliveCountMax=3',
                '-o', 'IdentitiesOnly=yes',
                '-i', ssh_key_path()]
        if KW_SSH_PORT:
            args += ['-p', KW_SSH_PORT]
        # No explicit bind address: sshd records the forward as
        # "localhost", which is what the authorized line's
        # permitlisten="localhost:<port>" matches.
        args += ['-R', f'{port}:127.0.0.1:{DEMUX_PORT}', KW_SSH_TARGET]
        _log('connecting: ' + ' '.join(args))
        started = time.time()
        child['proc'] = subprocess.Popen(args)
        rc = child['proc'].wait()
        child['proc'] = None
        lived = time.time() - started
        if lived >= 300:
            backoff = 5
        _log(f'ssh exited rc={rc} after {lived:.0f}s; '
             f'relaunching in {backoff}s')
        time.sleep(backoff)
        if lived < 300:
            backoff = min(backoff * 2, 60)

def cmd_serve():
    os.makedirs(QUEUE_DIR, mode=0o700, exist_ok=True)

    class Demux(http.server.BaseHTTPRequestHandler):
        def _knock(self):
            path = urllib.parse.urlparse(self.path).path
            # One queue subdirectory per service (the first path
            # segment): each channel's consumer claims only its own
            # service's knocks, so channels on one muse never race
            # for the same files.
            seg = path.strip('/').split('/')[0].lower()
            service = ''.join(c for c in seg if c.isalnum() or c == '-') or 'misc'
            qdir = os.path.join(QUEUE_DIR, service)
            os.makedirs(qdir, mode=0o700, exist_ok=True)
            name = f'{time.time():.3f}-{os.getpid()}.knock'
            with open(os.path.join(qdir, name), 'w') as f:
                f.write(f'{self.command} {path}\n')
            body = b'ok\n'
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(body)

        do_GET = _knock
        do_POST = _knock

        def log_message(self, *a):
            pass

    print(f'demux listening on 127.0.0.1:{DEMUX_PORT}, queue {QUEUE_DIR}', flush=True)
    http.server.ThreadingHTTPServer(('127.0.0.1', DEMUX_PORT), Demux).serve_forever()

def cmd_show():
    print(open(REG_FILE).read())

if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'show'
    {'register': cmd_register, 'connect': cmd_connect,
     'serve': cmd_serve, 'show': cmd_show}[cmd]()
