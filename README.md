# FWArmy

**FWArmy** is an optional, self-hostable relay / rendezvous server for **WArmy**.
It matches online users and forwards **opaque encrypted envelopes** — it never stores
messages and cannot read their contents.

- No message storage: envelopes live in an in-memory queue with a 30-second TTL and disappear on restart.
- Opaque forwarding only: end-to-end encryption happens on the clients; the server only sees routing metadata.
- Per-credential access control with usage statistics and quotas.
- Multi-server "expand" networking: several FWArmy instances can forward for each other (multi-hop, loop-protected).
- Single-file binaries for Windows / macOS / Linux (Node SEA), plus a source mode that runs on Node ≥ 20.
- Local-only admin page (loopback, no login) with credentials, quotas, TLS, reachability and updates.

Chinese documentation is available in [说明.md](说明.md).

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

Useful flags: `--port=8787` (fixed port; fails if busy), `--host=0.0.0.0`, `--data=<dir>`, `--no-open`, `--quiet`.
Default port auto-increments when busy; an explicit `--port` never does.

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
  yearly/total quotas; per-minute limits must be greater than zero.
- **Pause**: unchecking "accept new deliveries" rejects new relays with HTTP 503 while polling and
  lookups keep working.
- **Admin page**: bound to loopback with Host/Origin checks and no login — anyone who can run
  processes on the same machine can use it (documented worst case).
- **Expand networking**: outbound peers are pinned by fingerprint before any credential is sent;
  messages carry signed origins, unique IDs (24h window, max 2 forwards), and loop detection.
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

## License

MIT — see [LICENSE](LICENSE). **Attribution to Pondsi is mandatory** (see the license text):
keep the credit reasonably visible in your README, docs, about screen, package metadata or source
headers.

---

Pondsi — thank you for using FWArmy.
