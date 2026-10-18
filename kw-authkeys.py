#!/usr/bin/env python3
"""knockwire AuthorizedKeysCommand helper.

sshd calls this for user `kw` on every connection attempt, with the
offered key's fingerprint (%f). It answers with the authorized line —
carrying the port restriction — only when a live registration binds
that fingerprint AND the cert serial behind it is not on certmint's
revoked list *right now*. That second check is the "revocation is
checked on connection" gate: a purely static authorized_keys file
cannot re-check anything, this can.

Revocation source: certmint /revoked, cached on disk with a TTL.
If the fetch fails, the cache is used however old it is — a
certmint outage must not strand every muse; freshness resumes with
the next successful fetch.
"""
import json, os, sys, time, urllib.request

STATE_PATH = os.environ.get('KW_STATE_PATH', '/var/lib/knockwire/state.json')
CERTMINT_BASE = os.environ.get('KW_CERTMINT_BASE', 'https://www.certmint.net')
REVOKED_CACHE = os.environ.get('KW_REVOKED_CACHE', '/var/lib/knockwire/revoked.cache')
REVOKED_TTL_SECS = int(os.environ.get('KW_REVOKED_TTL_SECS', '300'))


def revoked_serials():
    try:
        age = time.time() - os.path.getmtime(REVOKED_CACHE)
        if age < REVOKED_TTL_SECS:
            return {int(x) for x in open(REVOKED_CACHE).read().split()}
    except Exception:
        pass
    try:
        # A named UA: Cloudflare 403s urllib's default one.
        rq = urllib.request.Request(CERTMINT_BASE + '/revoked',
                                    headers={'User-Agent': 'knockwire/1.0'})
        with urllib.request.urlopen(rq, timeout=5) as r:
            text = r.read().decode()
        tmp = REVOKED_CACHE + '.tmp'
        with open(tmp, 'w') as f:
            f.write(text)
        os.replace(tmp, REVOKED_CACHE)
        return {int(x) for x in text.split()}
    except Exception:
        try:
            return {int(x) for x in open(REVOKED_CACHE).read().split()}
        except Exception:
            return set()


def main():
    if len(sys.argv) < 2:
        return
    offered_fp = sys.argv[1]
    try:
        st = json.load(open(STATE_PATH))
    except Exception:
        return
    now = time.time()
    for reg in st.get('registrations', {}).values():
        if reg.get('key-fingerprint') != offered_fp:
            continue
        lease = reg.get('lease_expires', '')
        # ISO Z strings compare lexicographically in the same format
        # the server writes; parse defensively instead:
        import datetime
        try:
            exp = datetime.datetime.strptime(lease, '%Y-%m-%dT%H:%M:%SZ').replace(
                tzinfo=datetime.timezone.utc).timestamp()
        except Exception:
            continue
        if exp < now:
            continue
        if reg.get('serial') in revoked_serials():
            continue
        port = reg['port']
        print(f'restrict,port-forwarding,permitlisten="localhost:{port}" {reg["key"]}')
        return


if __name__ == '__main__':
    main()
