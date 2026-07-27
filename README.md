# SSO Watcher

Real-time detection of SSO / auth-provider login flows on a local network
interface. Parses TLS ClientHello SNI and DNS queries, matches them against a
catalog of known authentication endpoints, correlates each event to a source
device, and streams the result to a browser dashboard over WebSocket.

**No credentials are extracted or stored.** TLS payload is never decrypted —
only visible connection metadata (hostnames from SNI and DNS) is inspected,
the same information Wireshark or your router already sees.

Built for auditing your own traffic: which sites are being contacted, when
authentication flows happen, and from what device on the network.

## What the dashboard shows

Two columns, updating live:

- **Devices** — active source devices, with vendor guess from the MAC prefix
  (OUI database via `manuf`) and rolling per-provider event counts.
- **Events** — every hostname hit, categorised as one of:
  - `LOGIN` — dedicated identity endpoints (`accounts.google.com`,
    `login.microsoftonline.com`, `auth.openai.com`, Okta, Auth0, Apple ID,
    Discord's remote-auth-gateway, etc.)
  - `2FA` — second-factor endpoints (Duo, PingID)
  - `VISIT` — general site loads (Slack, Figma, LinkedIn, Chase, YouTube,
    Instagram, ChatGPT, ...) with the real site favicon

Header has a green Start / red Stop control and a System / Light / Dark theme
switch.

## Requirements

- macOS 11 or newer (Linux should work with interface tweaks; untested)
- Python 3.10+
- Root or BPF-group access for packet capture

## Run from source

```bash
git clone https://github.com/<your-username>/sso-watcher.git
cd sso-watcher
open start.command
```

`start.command` bootstraps a Python virtualenv, installs `scapy`, `aiohttp`
and `manuf`, kills anything left on port 8765, and launches the server.
Enter your Mac password when Terminal prompts.

The dashboard opens automatically at [http://127.0.0.1:8765](http://127.0.0.1:8765).
Click **Start capture** to begin. Double-click `stop.command` or hit
`Ctrl-C` in Terminal to shut down.

## How it works

1. Auto-discovers active `en*` and `utun*` interfaces (physical + VPN).
2. Captures with a BPF filter of `udp port 53 or tcp port 443 or tcp port 8443`.
3. Extracts the hostname from either the **DNS query name** or the **TLS
   ClientHello SNI extension** (parsed inline, no external TLS library).
4. Classifies against `SSO_CATALOG` in `sso_watcher.py`. Unmatched
   hostnames fall through to a generic `web_visit` using the registrable
   domain as the "brand," unless they look like CDN / tracker / infra
   (see `is_infra_host`).
5. Debounces per `(device, provider, kind)` for 20 s so background token
   refreshes don't spam the UI.
6. Appends every emitted event to `logs/events-YYYY-MM-DD.jsonl` and
   aggregates every hostname seen (matched or not) into
   `logs/hosts-YYYY-MM-DD.jsonl` — grep-friendly for catalog gap-hunting.

## What SSO Watcher can't see

- Passwords, tokens, cookies, or request bodies — anything inside TLS.
- Traffic that doesn't cross the sniffed interface. On a normal Mac that's
  your own machine only; to watch a whole network you'd need to run this on
  a router or a switch port configured for mirroring / SPAN.
- Sites using Encrypted Client Hello (ECH), or ClientHellos that fragment
  across TCP segments — DNS is the backup signal there, but the OS
  resolver's cache can hide repeat queries.

## Extending the catalog

`sso_watcher.py` → `SSO_CATALOG` is a list of 4-tuples:

```python
("Provider name", r"hostname-regex", "sso" | "mfa" | "web_visit", "favicon-domain.com"),
```

The regex is `re.fullmatch`ed against the lowercased hostname. Favicon comes
from Google's `s2/favicons?domain=...&sz=64` service.

To find candidates after a session, grep `logs/hosts-YYYY-MM-DD.jsonl` for
entries where `"matched": false` — those are hostnames the sniffer saw that
no rule caught.

## Suppressing noise

`NOISE_REGISTRABLES` and `NOISE_SUBDOMAINS` in `sso_watcher.py` are the
filter that keeps CDN / ad / tracker / infra hostnames out of the
fall-through `web_visit` stream. Edit those sets if the dashboard is showing
something you don't care about, or hiding something you do.

## File tour

| Path | What it is |
|---|---|
| `sso_watcher.py` | Sniffer, classifier, aiohttp web server, event log |
| `dashboard.html` | Single-file browser UI (WebSocket client, favicons, theme toggle) |
| `start.command` / `stop.command` | Double-clickable dev launchers |
| `requirements.txt` | `scapy`, `aiohttp`, `manuf` |
| `build/setup.py` | py2app config |
| `build/build.sh` | Orchestrates py2app + pkgbuild + hdiutil to produce the .dmg |
| `build/chmodbpf/` | LaunchDaemon + postinstall for the ChmodBPF helper package |

## Logs and privacy

`logs/` is in `.gitignore` and never committed — it contains a record of
every hostname your machine contacted while the sniffer was running. Treat
it as sensitive (browsing history is metadata about you). If you share
captured data with someone, share only what you've reviewed.
