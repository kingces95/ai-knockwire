# ai-knockwire

**knockwire** is a doorbell for AI agents. Services hold webhooks;
agents hold keys. knockwire connects them without either side
learning anything it shouldn't:

- A webhook URL carries an unguessable **GUID** — an address, not a
  name. The GUID's ownership is certified by a **guid cert** from
  [certmint](https://github.com/kingces95/ai-certmint): the mint
  generates the GUID, signs its hash into peer certificates binding
  it to keys, and keeps nothing else. There is no registry.
- An agent **registers** `{guid, guid cert}` plus a possession proof
  with knockwire's REST API. knockwire verifies the cert against
  certmint's published key and revocation list, provisions a port,
  and authorizes the cert's key in sshd for exactly that port.
- The agent opens **one long SSH connection** and holds a reverse
  forward on its port. A webhook POST to `/<guid>/<service>` is
  delivered through it carrying **only the path** — body, query, and
  fragment are stripped at the door. A knock is a pointer: the agent
  pulls the truth from the service itself.
- Registrations are **leases** (24h). Two independent reapers cull
  expired leases (kill the connection, then strip the
  authorization) and rest freed ports before reissue. Registering
  while a lease is alive returns the same port. Knocks to
  unregistered addresses are dropped, never queued.

Full as-built documentation: [REGISTRATION.md](REGISTRATION.md) —
the registration API, the connection plane, the knock plane, the
reapers, and the client, with every knob and policy parameter.

## Files

- `kw-web.py` — the service (Python 3, stdlib HTTP server + the
  `cryptography` package for Ed25519 verification). Registration
  API, knock relay, reaper thread, and the human sign-in pages.
- `kw-authkeys.py` — the sshd `AuthorizedKeysCommand` helper: keys
  are resolved from the registration state at connection time and
  the cert serial is re-checked against certmint `/revoked` on
  every connection.
- `kw-client.py` — a reference agent-side client
  (register / connect / serve / show). Uses the system `openssl`
  CLI for signing; converts the signing key to OpenSSH format for
  ssh (same key material — the two ecosystems use different key
  file envelopes; see REGISTRATION.md).
- `sshd-60-knockwire.conf` — the sshd drop-in for the service
  account: command-resolved keys, forwarding only, no shell.

## Running a knockwire

The service expects, on the host:

- A reachable **certmint** (its `/pubkey` and `/revoked` are the
  trust anchors, fetched and cached). Set `KW_CERTMINT_BASE`.
- A service account `kw` and the sshd drop-in installed, so sshd
  accepts the agent connections and their single-port forwards.
- State (registrations, challenges, port sightings) is a single
  JSON file the service owns; port pool, lease and collection
  clocks, and paths are environment knobs documented in
  REGISTRATION.md.

Site values (hostnames, the certmint deployment to trust, provider
app credentials for the sign-in pages) are deployment config
supplied through the environment and config files — never literals
in the code.

## Status

Live and tested: a 21-case suite against a test mint (registration
positives and negatives, allocation, lease cull, port collection),
plus staged live probes of the sshd plane — authorization,
forward binding, path-only delivery, and revocation enforced at
connection time.
