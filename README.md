# FWArmy

**FWArmy** is an optional, self-hostable relay / rendezvous server for **WArmy**.
It matches online users and forwards **opaque encrypted envelopes** — it never stores
messages and cannot read their contents.

- No message storage: envelopes live in an in-memory queue with a 30-second TTL and disappear on restart.
- Opaque forwarding only: end-to-end encryption happens on the clients; the server only sees routing metadata.
- Per-credential access control with usage statistics and quotas.
- Multi-server "expand" networking: several FWArmy instances can forward for each other (multi-hop, loop-protected).
- **DHT discovery (default on)**: every instance runs a `warmy-dht/1` node (protocol-compatible with WArmy's
  sync-protocol) and publishes signed service and client-locator records — clients find relays and each other
  by fingerprint. DHT only handles *discovery*; message delivery still requires mutual credentials + TLS
  fingerprint pinning. Abuse hardening: datagram size cap, per-source rate limiting, bounded record store,
  signed records with sequence anti-rollback.
- **Self-describing relay credentials**: generated tokens embed the relay's address (host + port), so a
  client only needs "name + credential" — no separate host/port fields. Tokens can be revoked individually.
- **Session prompt messages ("addition")**: up to 1000 plain-text one-liners per library (≤120 bytes each,
  hard-clamped at input and on save), attached to relayed envelopes per credential in random / sequence /
  weighted modes — with a hash-chain audit trail and signed checkpoints.
- **Offline delivery contract**: when the recipient is offline the relay answers honestly with
  `200 {ok:false, error:'offline', offline:true}` — it never caches or re-delivers. Retry is entirely the
  sender's job (outbox + resend on "online"), and an `offline` result is **not** counted as a server
  failure. Clients may poll a relay's online table read-only via `POST /api/presence/batch` and
  `GET /api/lookup?did=`.
- Single-file binaries for Windows / macOS / Linux (Node SEA), plus a source mode that runs on Node ≥ 20.
- Local-only admin page (loopback, no login) with credentials, quotas, TLS, DHT, ports, reachability and updates.

---

## Install

Grab a release package from [Releases](https://github.com/Pondsi/FWArmy/releases) and either unpack it
anywhere (portable) or run the installer:

```powershell
# Windows (PowerShell)
.\install.ps1
```

```bash
# macOS / Linux
sh install.sh
```

The installer downloads the platform binary, installs shortcuts, and **preserves your `data/` directory**
across upgrades. On machines with application-control policies (e.g. Windows WDAC / Smart App Control
or macOS Gatekeeper) an unsigned binary may be blocked by the OS; that is an OS policy, not a server bug —
use a signed build or allow the app per your organization's rules.

## Quick start

```bash
# Start (source mode; or run the installed/portable FWArmy binary)
node server.mjs
# or
./start.sh          # start.bat on Windows
```

Then open the admin page (it opens automatically, or visit `http://127.0.0.1:8787/`):

1. The first start generates a self-signed TLS certificate and **does not** create any credential for you.
2. Click **Generate credential** on the admin page; the token is shown once — store it in your client.
3. Point WArmy (or any protocol-compatible client) at your server address + credential + TLS fingerprint.

Useful flags: `--port=8787` (fixed admin-entry port), `--host=0.0.0.0`, `--data=<dir>`, `--no-open`, `--quiet`.
Default ports are **fixed** (no auto-increment since v0.6.0): if a port is busy the server reports an
"error" state for it on the Ports page, where you can force-enable it (killing the occupying process)
or pick another port.

## Ports

FWArmy listens on **multiple business ports** by default:

- `8787` — admin entry (can be changed on the Ports page; the old port keeps listening as a plain
  business port afterwards, and the entry port can never be paused or removed),
- `59599` — relay credentials (WArmy clients),
- `58588` — expand credentials (inbound, "被扩网" — used by other FWArmy instances),
- DHT-UDP `443` / `62666` — discovery/bootstrap (see below).

The Ports page shows every port's state (listening / paused / error, TCP and UDP), which credentials
reference it, and lets you add / pause / resume / remove ports. Pausing a UDP port keeps its config
(resume restores it); at least one DHT UDP port must stay active. A credential is only usable while its
port is in the listening set.

## CLI

The same commands work on the single-file binary (`FWArmy …`) and via `node ctl.mjs …`:

```text
start [--open] [--port=8787] [--data=dir]   start the server detached
stop [--force]                              stop it (--force kills a hung process, honestly)
status | open | table | console             inspect / open admin page / live table
cred-new <name> …                           create a credential
cred-list | cred-update | cred-disable | cred-enable | cred-delete
stats | ip | update | version               usage stats, public IP probe, updates, version
```

## Configuration & security model

- **TLS**: self-signed certificate with **fingerprint pinning** by default (clients must pin the
  certificate fingerprint; verify it out-of-band before sending any token). Optionally use your own
  certificate (`user-cert` mode) or plain HTTP on loopback only.
- **Credentials**: only SHA-256 hashes are stored; quotas (per-minute / daily / monthly / yearly,
  requests and bytes) can be set globally and per credential. `0` means unlimited for daily/monthly/
  yearly/total quotas; per-minute limits must be greater than zero. A relay credential can carry an
  optional endpoint (host + port, default `59599`) for the client's reference.
- **Pause**: unchecking "accept new deliveries" rejects new relays with HTTP 503 while polling and
  lookups keep working.
- **Admin page**: bound to loopback with Host/Origin checks and no login — anyone who can run
  processes on the same machine can use it (documented worst case).
- **Expand networking**: outbound peers are pinned by fingerprint before any credential is sent;
  messages carry signed origins and unique IDs — the same message id passes at most twice per 24h
  (a third sighting is dropped and the message id itself is blacklisted, so relay rings never loop
  forever; no hop-count limit is used), plus route-based loop detection.
  Inbound ("被扩网") credentials are self-describing: `fwnexp_v2_<base64url{host,port,rand}>`. The
  address defaults to your probed public IP (shown in the header bar, refreshable) and can be edited;
  the port defaults to **58588** and must equal a port this server is actually listening on —
  otherwise the credential is hard-disabled (`401 credential-port-unavailable`) until the conflict is
  resolved. The peer only needs name + credential, no manual address (legacy tokens without an address
  are rejected with `400 legacy-token-not-supported`). Credentials can be managed (rename, rate/bytes
  limits, expiry) and are disabled while expired.
  Message identity is the `msgId` in the header — **content is never compared**: resends or retries
  with a fresh `msgId` always pass (clients should generate a new msgId per attempt). Requests without
  a `msgId` are rejected with HTTP 400 (`bad-msg-id`) and never enqueued.
  `msgId` is covered by the Ed25519 origin signature (canonical string), so a malicious or broken
  relay cannot rewrite it to bypass loop protection — tampering fails signature verification (403).
- **DHT (discovery layer, always on)**: `warmy-dht/1` node, signed service/locator records (Ed25519,
  AES-256-GCM, seq anti-rollback, ±10 min clock tolerance), anchor bootstrap with exponential backoff,
  and per-source rate limiting. DHT never authorizes delivery — forwarding always requires configured
  mutual credentials and pinned TLS fingerprints; unauthenticated relay requests are dropped (401) and
  rate-limited by source IP. The **advertised address is the business TCP port** (auto-inferred public
  IP, IPv6 preferred; manual host/domain allowed while it verifies as this instance, re-checked every
  5 minutes); the **bootstrap (guide) address** shown per entry is the same host × the UDP DHT ports.
  Default anchors are **`DHT.pondsi.com`** and **`DHT2.pondsi.com`** on UDP **443** and **62666**
  (aligned with WArmy; anchors need no credential — anonymous discovery; security comes from node
  Ed25519 signatures, group-key encryption and inbound rate limiting). The admin page lists the default
  anchors read-only (fixed, full `host:port`) and lets you add/remove **manual anchors** above them.
  External addresses are a managed list with per-entry health (active / error / paused) and
  edit / pause / delete; auto fallback = probed public IPv4 & IPv6 × the listening business port
  (up to 4 entries, IPv6 preferred), pausable only while another address is active, with a periodic
  self-check that re-enables all fallbacks when none is active.
  **Client locator records**: a client's `register` immediately publishes a signed locator record
  ("this client is currently at relay X"), refreshed every 10 minutes while online (≤200 per round,
  oldest first) and naturally expiring ~30 minutes after going offline — that is how a sender can tell
  the recipient is back online (poll the DHT by the recipient's did fingerprint, or query the relay's
  read-only presence endpoints above).
- **Offline results**: both `/api/relay` and `/api/expand/relay` answer `200 {ok:false, error:'offline',
  offline:true}` for an offline recipient (only `queue-full` is a 429). An `offline` result is the
  recipient's state, **not** a server failure — senders keep such messages in their outbox (saved,
  no failure counter) and resend when the recipient is detected online. See the failure-code table in
  the source docs for the full list.
- **Reachability**: NAT-PMP (RFC 6886) and STUN (RFC 5389) probes; port mapping mutates router state
  and requires explicit confirmation.

## Auto-update

Single-file binaries can self-update from GitHub Releases: the updater downloads the asset, checks
its SHA-256, stages it, restarts and health-checks the new process (product / version / data-directory
identity), and rolls back if the new process does not become healthy. Updates trust GitHub release
digests; there is no independent manifest signature yet.

## Build from source

Requires Node.js ≥ 20 (builds are made with Node 24) and network access for `npx`:

```bash
node build-sea.mjs                              # bundle + inject SEA -> dist/FWArmy(.exe)
node packaging/package.mjs --platform=win-x64   # verify version/BUILD-INFO/hash, then pack + SHA256SUMS
```

The packager refuses inconsistent version metadata or a stale binary, and never ships `data/`.

## Sponsors

FWArmy is free and open source — no paid tier, no locked features. If you would like to support the
project, see **[SPONSORS.md](SPONSORS.md)** for donation options (WeChat Pay / Alipay / PayPal) and
other ways to help.

## License

MIT — see [LICENSE](LICENSE). **Attribution to Pondsi is mandatory** (see the license text):
keep the credit reasonably visible in your README, docs, about screen, package metadata or source
headers.

---

Pondsi — thank you for using FWArmy.
