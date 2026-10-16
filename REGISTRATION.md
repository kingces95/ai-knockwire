# knockwire — GUID registration & knock routing (as built)

The deployed reference system, live since 2026-10-15. The GUID cert
model it consumes is specified in the companion repo
[ai-certmint](https://github.com/kingces95/ai-certmint) (`GUID.md`).
Code: `kw-web.py` (the service), `kw-authkeys.py` (sshd helper),
`kw-client.py` (agent-side client), `sshd-60-knockwire.conf`
(the sshd drop-in).

## Registration plane — agent API, any host

| Route | Shape |
|---|---|
| `GET /v1/register/challenge?serial=N` | `200 {nonce, signing_string}` — single-use, 300s, signing string domain `knockwire-register-v1` |
| `POST /v1/register` | In: `{guid, cert, nonce, signature}` → `201` (new) / `200` (re-register) `{port, guid_hash, lease_expires}`. Verifies, in order: certmint trust anchors fetchable (`502`) → cert parses → mint signature against certmint's published key → is a guid cert → serial not in certmint `/revoked` (`403`) → cert unexpired (`403`) → `hash(guid) == guid-hash:` (`400`) → challenge live and serial-matched (`400`) → possession signature (`403`) |

On success, under one lock: a live lease for the hash returns its
**same port** (latest verified cert/key wins the record — a peer
takeover); a lapsed record re-adopts its port; a new hash gets the
first pool port that is neither under a live lease, nor **actually
bound** (read from the kernel listener tables), nor inside its
post-collection rest window.

## Connection plane — sshd

- Service account `kw` (no shell, no password). Drop-in
  `60-knockwire.conf`: `AuthorizedKeysCommand /usr/local/bin/kw-authkeys %f`,
  so keys are resolved from the registration state **on every
  connection attempt**, and the cert serial is re-checked against
  certmint `/revoked` at connection time (cached on disk, 300s TTL;
  on fetch failure the cache is used however old — a certmint outage
  must not strand every muse).
- The authorized line carries `restrict,port-forwarding,permitlisten="localhost:<port>"`:
  the key can do exactly one thing — hold its forward.
- Client side: request the forward as `-R <port>:127.0.0.1:<demux>`
  (no explicit bind address — sshd names it `localhost`, which is
  what `permitlisten` matches; an explicit `127.0.0.1:` request is
  refused).
- The connection is never killed for contention: a second holder of
  the port simply cannot bind until the first leaves. Expiry is the
  only executioner (see reapers).

## Knock plane — push.knockwire.ai

`POST /<guid>/<service...>` (any method): knockwire hashes the guid,
looks up the live registration, and delivers a **rebuilt** request to
`127.0.0.1:<port>/<service...>` carrying only the path — no body, no
query, no fragment, no sender headers. Unregistered guid, lapsed
lease, or unbound port → `knockwire drop`. Knocks are never queued.

## Reapers — two clocks, both 24h by default

- **Lease cull** (checked every 60s): an expired lease is torn down
  in reverse — the connection holding the port is killed first, then
  the registration record is stripped.
- **Port collection**: a port's `last_used` (last lease or last
  observed bound) must age past 24h before the allocator may hand
  the port to a different guid. Same-guid re-adoption is exempt via
  its surviving record.

## Client — kw-client.py

`register` (challenge + possession proof with KW_KEY, default the
certmint key; uses the newest guid cert bound to that key) ·
`connect` (opens the long ssh) · `serve` (demux stub: writes each
knock's method + path to `~/.knockwire/queue/`) · `show`.

Key formats, learned live: openssl signs PKCS#8 keys but ssh cannot
load them; openssl cannot sign OpenSSH-format keys. `connect`
therefore converts the signing key once into OpenSSH format at
`~/.knockwire/ssh_key` (pure-stdlib PKCS#8→OpenSSH rewrite; same key
material, fingerprint unchanged).

## Knobs (env on the service)

`KW_STATE_PATH`, `KW_LOG_PATH`, `KW_CERTMINT_BASE`,
`KW_PORT_START/END` (pool 20000–20999), `KW_LEASE_TTL_SECS`,
`KW_PORT_COLLECT_SECS`, `KW_CHALLENGE_TTL_SECS` (300),
`KW_CULL_INTERVAL_SECS` (60), `KW_TRUST_TTL_SECS` (300), `KW_PORT`.
State is one JSON file at `/var/lib/knockwire/state.json`,
lock-guarded with atomic replace — registrations, challenges, port
sightings. Nothing else is remembered.
