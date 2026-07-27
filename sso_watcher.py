#!/usr/bin/env python3
"""
SSO Watcher — real-time detection of SSO / auth-provider login flows on a
local network interface.

Captures TLS ClientHello SNI and DNS queries, matches against a catalog of
known authentication endpoints, correlates each event to a source device
(IP + MAC + best-guess vendor), and streams the result to a browser
dashboard over WebSocket.

No credentials are extracted or stored. TLS payload is never decrypted.
Only the target hostname (visible metadata) and source device are recorded.

Requires root/admin for packet capture.

    sudo python3 sso_watcher.py --iface en0
    # then open http://127.0.0.1:8765
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import socket
import struct
import subprocess
import sys
import time
from collections import deque
from pathlib import Path
from threading import Lock

from aiohttp import WSMsgType, web
from scapy.all import DNS, DNSQR, IP, IPv6, TCP, AsyncSniffer, Raw, get_if_list

try:
    from manuf import manuf as _manuf
    _OUI_DB = _manuf.MacParser()
except Exception:
    _OUI_DB = None


# ---------------------------------------------------------------------------
# SSO / auth endpoint catalog
# ---------------------------------------------------------------------------
# Each entry: (provider label, hostname regex, kind).
# kind is used in the UI to color/badge the event:
#   sso        — dedicated identity endpoint; a hit here means a login flow
#   mfa        — second-factor endpoint
#   web_visit  — general site load; not necessarily a login, but the user was there
SSO_CATALOG = [
    # (provider label, hostname regex, kind, favicon domain)
    # Google
    ("Google",       r"accounts\.google\.com",              "sso",       "google.com"),
    ("Google",       r"oauth2\.googleapis\.com",            "sso",       "google.com"),
    # YouTube (split from Google so its login/visit show as its own events)
    ("YouTube",      r"accounts\.youtube\.com",             "sso",       "youtube.com"),
    ("YouTube",      r"www\.youtube\.com",                  "web_visit", "youtube.com"),
    # Microsoft
    ("Microsoft",    r"login\.microsoftonline\.com",        "sso",       "microsoft.com"),
    ("Microsoft",    r"login\.live\.com",                   "sso",       "microsoft.com"),
    ("Microsoft",    r"login\.microsoft\.com",              "sso",       "microsoft.com"),
    ("Microsoft",    r"login\.windows\.net",                "sso",       "microsoft.com"),
    # Apple
    ("Apple ID",     r"appleid\.apple\.com",                "sso",       "apple.com"),
    ("Apple ID",     r"idmsa\.apple\.com",                  "sso",       "apple.com"),
    ("Apple ID",     r"gsa\.apple\.com",                    "sso",       "apple.com"),
    # Identity providers
    ("Okta",         r"[^.]+\.okta\.com",                   "sso",       "okta.com"),
    ("Okta",         r"[^.]+\.oktapreview\.com",            "sso",       "okta.com"),
    ("Auth0",        r"[^.]+\.auth0\.com",                  "sso",       "auth0.com"),
    ("Duo MFA",      r"[^.]+\.duosecurity\.com",            "mfa",       "duo.com"),
    ("OneLogin",     r"[^.]+\.onelogin\.com",               "sso",       "onelogin.com"),
    ("PingID",       r"[^.]+\.pingone\.com",                "sso",       "pingidentity.com"),
    ("PingID",       r"[^.]+\.pingidentity\.com",           "sso",       "pingidentity.com"),
    ("AWS SSO",      r"signin\.aws\.amazon\.com",           "sso",       "aws.amazon.com"),
    ("AWS SSO",      r".+\.awsapps\.com",                   "sso",       "aws.amazon.com"),
    ("Amazon",       r"signin\.amazon\.com",                "sso",       "amazon.com"),
    # Meta family
    ("Meta",         r"accounts\.meta\.com",                "sso",       "meta.com"),
    ("Facebook",     r"(?:www|m|login)\.facebook\.com",     "web_visit", "facebook.com"),
    ("Instagram",    r"(?:www|gateway|i|graph|edge-chat)\.instagram\.com",
                                                            "web_visit", "instagram.com"),
    # AI chat
    ("ChatGPT",      r"auth\.openai\.com",                  "sso",       "openai.com"),
    ("ChatGPT",      r"chat\.openai\.com",                  "web_visit", "openai.com"),
    ("ChatGPT",      r"(?:[^.]+\.)?chatgpt\.com",           "web_visit", "openai.com"),
    ("Claude",       r"claude\.ai",                         "web_visit", "claude.ai"),
    # Discord
    ("Discord",      r"remote-auth-gateway\.discord\.gg",   "sso",       "discord.com"),
    ("Discord",      r"(?:[^.]+\.)?discord\.com",           "web_visit", "discord.com"),
    ("Discord",      r"(?:[^.]+\.)?discord\.gg",            "web_visit", "discord.com"),
    # Dev / work
    ("GitHub",       r"github\.com",                        "web_visit", "github.com"),
    ("LinkedIn",     r"www\.linkedin\.com",                 "web_visit", "linkedin.com"),
    ("Slack",        r"(?:[^.]+\.)?slack\.com",             "web_visit", "slack.com"),
    ("Zoom",         r"(?:[^.]+\.)?zoom\.us",               "web_visit", "zoom.us"),
    ("Dropbox",      r"www\.dropbox\.com",                  "web_visit", "dropbox.com"),
    ("Figma",        r"www\.figma\.com",                    "web_visit", "figma.com"),
    ("Notion",       r"(?:www\.)?notion\.so",               "web_visit", "notion.so"),
    ("Canva",        r"www\.canva\.com",                    "web_visit", "canva.com"),
    ("Coursera",     r"www\.coursera\.org",                 "web_visit", "coursera.org"),
    # Social
    ("X / Twitter",  r"twitter\.com",                       "web_visit", "x.com"),
    ("X / Twitter",  r"x\.com",                             "web_visit", "x.com"),
    ("Reddit",       r"www\.reddit\.com",                   "web_visit", "reddit.com"),
    ("TikTok",       r"www\.tiktok\.com",                   "web_visit", "tiktok.com"),
    ("Twitch",       r"id\.twitch\.tv",                     "sso",       "twitch.tv"),
    ("Twitch",       r"www\.twitch\.tv",                    "web_visit", "twitch.tv"),
    ("Snapchat",     r"accounts\.snapchat\.com",            "sso",       "snapchat.com"),
    # Music / streaming
    ("Spotify",      r"accounts\.spotify\.com",             "sso",       "spotify.com"),
    ("Spotify",      r"open\.spotify\.com",                 "web_visit", "spotify.com"),
    # Jobs / hospitality
    ("Culinary Agents", r"(?:www\.)?culinaryagents\.com",   "web_visit", "culinaryagents.com"),
]
_COMPILED = [(re.compile(rx), label, kind, fav) for label, rx, kind, fav in SSO_CATALOG]


def classify_host(host: str | None) -> dict | None:
    if not host:
        return None
    h = host.lower().strip(".")
    # 1. Try the catalog — known auth / brand endpoints get labelled precisely.
    for rx, label, kind, fav in _COMPILED:
        if rx.fullmatch(h):
            return {"provider": label, "kind": kind, "host": h, "favicon": fav}
    # 2. Fall through: any real site visit becomes a generic web_visit event.
    if is_infra_host(h):
        return None
    reg = registrable_domain(h)
    if not reg:
        return None
    brand = reg.split(".")[0].capitalize()
    return {"provider": brand, "kind": "web_visit", "host": h, "favicon": reg}


# ---------------------------------------------------------------------------
# Noise filter — infrastructure / CDN / tracker hosts that shouldn't count
# as "site visits" from a user's perspective.
# ---------------------------------------------------------------------------

# Registrable domains (last-two-labels) that are pure infrastructure.
# Anything ending in one of these is skipped for the fall-through web_visit.
NOISE_REGISTRABLES = {
    # Google infra
    "gstatic.com", "googleusercontent.com", "googletagmanager.com",
    "googleadservices.com", "googlesyndication.com", "googlevideo.com",
    "doubleclick.net", "google-analytics.com", "googleapis.com",
    "googlezip.net", "adtrafficquality.google",
    "gvt1.com", "gvt2.com",
    # AWS / cloud infra
    "cloudfront.net", "amazonaws.com",
    # Akamai
    "akamaiedge.net", "akadns.net", "akamaihd.net", "akamai.net", "akstat.io",
    # Apple background
    "aaplimg.com", "apple-dns.net", "mzstatic.com", "icloud-content.com",
    # Meta CDN
    "fbcdn.net", "cdninstagram.com",
    # Microsoft / Azure infra
    "msftauth.net", "msauth.net", "azureedge.net", "azurefd.net",
    "trafficmanager.net", "microsoft-falcon.io", "microsofttranslator.com",
    # LinkedIn CDN
    "licdn.com",
    # Discord CDN
    "discordapp.com",
    # Chase CDN
    "chasecdn.com",
    # Generic CDNs
    "jsdelivr.net", "cdnjs.com", "map.fastly.net",
    # Antivirus / Avast
    "avast.com", "avcdn.net", "avastdns.com",
    # Ads / trackers / analytics
    "adnxs.com", "demdex.net", "adobedc.net", "adobedtm.com", "clarity.ms",
    "protechts.net", "impactcdn.com", "bidr.io",
    "3lift.com", "rubiconproject.com", "33across.com", "teads.tv",
    "quantserve.com", "scorecardresearch.com", "ads-twitter.com",
    "amazon-adsystem.com", "arkoselabs.com", "boost.ai",
    "sentry.io", "sentry-cdn.com", "datadoghq.com", "newrelic.com",
    "amplitude.com", "braze.com", "pendo.io", "segment.io", "segment.com",
    "hotjar.com", "fullstory.com",
    "onetrust.com", "cookielaw.org", "zdassets.com",
    "pusher.com", "sprig.com",
    "cloudflare-ech.com", "cloudflareinsights.com",
    "vaultdcr.com", "go-mpulse.net", "loclx.io",
    "hubspotonwebflow.com", "website-files.com", "gist.build", "localizeapi.com",
    "appboycdn.com", "grammarlyusercontent.com",
    "grammarly.com", "grammarly.io",     # noisy browser extension
    "wns.windows.com",
    "xboxservices.com", "xboxlive.com",  # background pings
    "redditstatic.com", "ttdns2.com", "nheos.com", "naver.net", "pinimg.com",
    "stripe.network", "pstatic.net",
}

# Left-most subdomains that mark a 3-label host as infra even if the
# registrable domain is user-facing (e.g. clients4.google.com, cdn.foo.com).
NOISE_SUBDOMAINS = {
    "cdn", "cdnjs", "static", "assets", "img", "images", "media",
    "pixel", "tags", "snap", "js", "css", "font", "fonts",
    "analytics", "log", "logs", "metrics", "telemetry", "ingest",
    "resolver", "dns", "_dns",
    "clients4", "clients5", "clients6", "apis", "ogs", "mtalk",
    "safebrowsing", "content-autofill", "passwordsleakcheck-pa",
    "oauthaccountmanager", "optimizationguide-pa", "waa-pa", "ogads-pa",
    "signaler-pa", "peoplestack-pa", "peoplestackwebexperiments-pa",
    "appsgrowthpromo-pa", "appsgenaiserver-pa", "taskassist-pa", "addons-pa",
    "aadcdn", "acctcdn", "logincdn",
    "platform", "dms", "dms-akam",
    "beacon", "track",
    "errors", "marketing",
}

# Also skip these leading-label prefixes.
NOISE_SUBDOMAIN_PREFIXES = ("s3-", "s3.", "static-", "ep", "log-", "logs-",
                            "api-", "rr", "r5", "r4", "r2", "sc", "scontent",
                            "aus", "encrypted-tbn", "browser-intake")

_BARE_IP_RE = re.compile(r"\d+\.\d+\.\d+\.\d+")


def registrable_domain(host: str) -> str:
    """Simple 'brand' extraction: last two labels of the hostname.
    (Doesn't handle compound TLDs like .co.uk — good enough for common cases.)"""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


def is_infra_host(host: str) -> bool:
    """Heuristic: this hostname is CDN / tracker / infra chatter,
    not something a user would call 'a website I visited'."""
    if host.endswith(".arpa"):
        return True
    if _BARE_IP_RE.fullmatch(host):
        return True
    labels = host.split(".")
    # Deeply nested hostnames are almost always infra (e.g. rr5---sn-X.googlevideo.com).
    if len(labels) >= 4:
        return True
    reg = registrable_domain(host)
    if reg in NOISE_REGISTRABLES:
        return True
    if len(labels) == 3:
        first = labels[0]
        if first in NOISE_SUBDOMAINS:
            return True
        for pfx in NOISE_SUBDOMAIN_PREFIXES:
            if first.startswith(pfx):
                return True
    return False


# ---------------------------------------------------------------------------
# TLS ClientHello SNI parser (no external TLS lib needed)
# ---------------------------------------------------------------------------
def parse_sni(payload: bytes) -> str | None:
    try:
        if len(payload) < 43 or payload[0] != 0x16:
            return None
        # Handshake type ClientHello
        if payload[5] != 0x01:
            return None
        pos = 9 + 2 + 32  # record hdr + handshake hdr + version + random
        if pos >= len(payload):
            return None
        sid_len = payload[pos]; pos += 1 + sid_len
        if pos + 2 > len(payload): return None
        cs_len = struct.unpack(">H", payload[pos:pos+2])[0]; pos += 2 + cs_len
        if pos + 1 > len(payload): return None
        cm_len = payload[pos]; pos += 1 + cm_len
        if pos + 2 > len(payload): return None
        ext_len = struct.unpack(">H", payload[pos:pos+2])[0]; pos += 2
        end = min(pos + ext_len, len(payload))
        while pos + 4 <= end:
            etype = struct.unpack(">H", payload[pos:pos+2])[0]
            elen  = struct.unpack(">H", payload[pos+2:pos+4])[0]
            pos += 4
            if etype == 0x0000:  # server_name
                if pos + 5 > len(payload): return None
                nlen = struct.unpack(">H", payload[pos+3:pos+5])[0]
                start = pos + 5
                if start + nlen > len(payload): return None
                return payload[start:start+nlen].decode("ascii", errors="ignore")
            pos += elen
    except Exception:
        return None
    return None


# ---------------------------------------------------------------------------
# Device enrichment (ARP + reverse DNS + OUI vendor)
# ---------------------------------------------------------------------------
def arp_table() -> dict[str, str]:
    """IP -> MAC, from `arp -a`. macOS/Linux compatible."""
    try:
        out = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=5,
        ).stdout
    except Exception:
        return {}
    result = {}
    for line in out.splitlines():
        m = re.search(r"\(([\d.]+)\) at ([0-9a-fA-F:]{11,17})", line)
        if not m:
            continue
        ip = m.group(1)
        parts = m.group(2).lower().split(":")
        mac = ":".join(p.zfill(2) for p in parts)
        result[ip] = mac
    return result


def rdns(ip: str) -> str | None:
    try:
        socket.setdefaulttimeout(0.5)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def vendor_of(mac: str | None) -> str | None:
    if not mac or not _OUI_DB:
        return None
    try:
        return _OUI_DB.get_manuf_long(mac) or _OUI_DB.get_manuf(mac)
    except Exception:
        return None


# Very rough device-kind guess from vendor string.
_KIND_HINTS = [
    (re.compile(r"apple", re.I),                       "Apple device"),
    (re.compile(r"samsung|xiaomi|oneplus|huawei|oppo|vivo", re.I), "Android phone"),
    (re.compile(r"google", re.I),                      "Google device"),
    (re.compile(r"microsoft", re.I),                   "Microsoft device"),
    (re.compile(r"amazon", re.I),                      "Amazon device"),
    (re.compile(r"intel|dell|lenovo|asus|hp|acer",re.I),"Computer"),
    (re.compile(r"raspberry", re.I),                   "Raspberry Pi"),
    (re.compile(r"nest|ring|sonos|roku|philips|tuya|espressif|shenzhen", re.I), "IoT"),
]

def guess_kind(vendor: str | None) -> str | None:
    if not vendor:
        return None
    for rx, kind in _KIND_HINTS:
        if rx.search(vendor):
            return kind
    return None


# ---------------------------------------------------------------------------
# Runtime state
# ---------------------------------------------------------------------------
class State:
    def __init__(self, max_events: int = 500):
        self.lock = Lock()
        self.events: deque[dict] = deque(maxlen=max_events)
        self.devices: dict[str, dict] = {}   # key = ip
        self.arp: dict[str, str] = {}
        self._last_emit: dict[tuple, float] = {}  # (ip, provider) -> ts
        self.debounce_sec = 20.0
        self.subscribers: set[web.WebSocketResponse] = set()

    def refresh_arp(self):
        self.arp = arp_table()

    def should_emit(self, ip: str, provider: str, kind: str, now: float) -> bool:
        key = (ip, provider, kind)
        last = self._last_emit.get(key, 0.0)
        if now - last < self.debounce_sec:
            return False
        self._last_emit[key] = now
        return True

    def touch_device(self, ip: str, mac: str | None, now: float) -> dict:
        with self.lock:
            dev = self.devices.get(ip)
            if not dev:
                mac = mac or self.arp.get(ip)
                vendor = vendor_of(mac)
                hostname = rdns(ip)
                dev = {
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "kind": guess_kind(vendor),
                    "hostname": hostname,
                    "first_seen": now,
                    "last_seen": now,
                    "events": 0,
                    "providers": {},
                }
                self.devices[ip] = dev
            else:
                dev["last_seen"] = now
                if not dev.get("mac"):
                    dev["mac"] = mac or self.arp.get(ip)
                    if dev["mac"] and not dev.get("vendor"):
                        dev["vendor"] = vendor_of(dev["mac"])
                        dev["kind"] = guess_kind(dev["vendor"])
                if not dev.get("hostname"):
                    dev["hostname"] = rdns(ip)
            return dev

    def add_event(self, evt: dict):
        with self.lock:
            self.events.appendleft(evt)
            ip = evt["src_ip"]
            dev = self.devices.get(ip)
            if dev:
                dev["events"] += 1
                dev["providers"][evt["provider"]] = dev["providers"].get(evt["provider"], 0) + 1


STATE = State()

# Set by main() after sniffers start — exposed to the UI for the "vantage" strip.
_ACTIVE_IFACES: list[dict] = []


class EventLog:
    """Append-only per-day log of matched events, plus a running list of every
    unique hostname the sniffer saw (helpful for spotting misses and expanding
    the catalog). Thread-safe; called from the sniffer thread."""

    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.lock = Lock()
        self.events_fh = None
        self.current_date: str | None = None
        self.hosts: dict[str, dict] = {}

    def _rotate(self, ts: float):
        d = time.strftime("%Y-%m-%d", time.localtime(ts))
        if d != self.current_date:
            if self.events_fh:
                try: self.events_fh.close()
                except Exception: pass
            self.events_fh = open(
                self.log_dir / f"events-{d}.jsonl", "a", buffering=1, encoding="utf-8",
            )
            self.current_date = d

    def log_event(self, evt: dict):
        with self.lock:
            self._rotate(evt["ts"])
            iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(evt["ts"]))
            self.events_fh.write(json.dumps({**evt, "iso_time": iso}) + "\n")

    def note_host(self, host: str, signal: str, src_ip: str, ts: float, matched: bool):
        with self.lock:
            entry = self.hosts.get(host)
            if entry is None:
                self.hosts[host] = {
                    "host":       host,
                    "signal":     signal,
                    "matched":    matched,
                    "count":      1,
                    "first_seen": ts,
                    "last_seen":  ts,
                    "sources":    {src_ip},
                }
            else:
                entry["count"] += 1
                entry["last_seen"] = ts
                entry["sources"].add(src_ip)
                if matched: entry["matched"] = True

    def flush_hosts(self):
        with self.lock:
            if not self.hosts:
                return
            self._rotate(time.time())
            path = self.log_dir / f"hosts-{self.current_date}.jsonl"
            with open(path, "w", encoding="utf-8") as f:
                for e in sorted(self.hosts.values(), key=lambda e: -e["count"]):
                    row = {**e, "sources": sorted(e["sources"])}
                    f.write(json.dumps(row) + "\n")

    def close(self):
        try: self.flush_hosts()
        except Exception: pass
        if self.events_fh:
            try: self.events_fh.close()
            except Exception: pass


EVENT_LOG: EventLog | None = None


class SniffController:
    """Owns the AsyncSniffer instances. The web server runs continuously; this
    controller starts and stops capture in response to Play / Stop clicks in the UI."""

    def __init__(self, ifaces: list[str], bpf: str, loop, debug: bool = False):
        self.ifaces = ifaces
        self.bpf    = bpf
        self.loop   = loop
        self.debug  = debug
        self.lock   = Lock()
        self.sniffers: list[tuple[str, "AsyncSniffer"]] = []
        self.state  = "idle"                 # idle | running | error
        self.error: str | None = None

    def snapshot(self) -> dict:
        return {
            "state":  self.state,
            "error":  self.error,
            "ifaces": [describe_iface(i) for i in self.ifaces],
            "active": [name for name, _ in self.sniffers],
        }

    def start(self) -> tuple[bool, str | None]:
        with self.lock:
            if self.state == "running":
                return True, None
            self.sniffers.clear()
            errors = []
            for iface in self.ifaces:
                s = AsyncSniffer(
                    iface=iface, filter=self.bpf,
                    prn=make_callback(self.loop, local_addrs(), debug=self.debug),
                    store=False,
                )
                try:
                    s.start()
                    self.sniffers.append((iface, s))
                except PermissionError:
                    errors.append(f"{iface}: permission denied — the server must run with sudo")
                except Exception as e:
                    errors.append(f"{iface}: {e}")
            if not self.sniffers:
                self.state = "error"
                self.error = " · ".join(errors) or "no sniffers started"
                return False, self.error
            self.state = "running"
            self.error = None
            return True, None

    def stop(self):
        with self.lock:
            for _, s in self.sniffers:
                try: s.stop()
                except Exception: pass
            self.sniffers.clear()
            if self.state != "error":
                self.state = "idle"
                self.error = None


CONTROLLER: SniffController | None = None


def default_log_dir() -> Path:
    """Where to write logs by default. In a py2app bundle, Contents/Resources
    is read-only after install, so write under the user's Library instead."""
    if getattr(sys, "frozen", False):
        return Path.home() / "Library/Application Support/SSO Watcher/logs"
    return Path(__file__).parent / "logs"


def describe_iface(name: str) -> dict:
    if re.match(r"^(utun|ppp|tun)", name):
        return {"name": name, "kind": "vpn",   "label": "VPN tunnel"}
    if re.match(r"^(en|tap)", name):
        return {"name": name, "kind": "lan",   "label": "Local network"}
    return {"name": name, "kind": "other", "label": name}


# ---------------------------------------------------------------------------
# Packet capture
# ---------------------------------------------------------------------------
def _emit(evt: dict, loop: asyncio.AbstractEventLoop):
    """Push an event onto the async event queue (called from sniffer thread)."""
    asyncio.run_coroutine_threadsafe(_broadcast(evt), loop)


async def _broadcast(evt: dict):
    STATE.add_event(evt)
    dead = []
    payload = json.dumps({"type": "event", "event": evt, "device": STATE.devices.get(evt["src_ip"])})
    for ws in list(STATE.subscribers):
        try:
            await ws.send_str(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        STATE.subscribers.discard(ws)


def make_callback(loop: asyncio.AbstractEventLoop, local_ips: set[str], debug: bool = False):
    pkt_count = [0]

    def cb(pkt):
        now = time.time()
        pkt_count[0] += 1
        if debug and pkt_count[0] % 500 == 0:
            print(f"[capture] {pkt_count[0]} packets seen", file=sys.stderr, flush=True)

        # L3
        if IP in pkt:
            src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
        elif IPv6 in pkt:
            src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
        else:
            return
        src_mac = getattr(pkt, "src", None)

        host = None
        signal = None

        # DNS query
        if pkt.haslayer(DNSQR) and pkt.haslayer(DNS) and pkt[DNS].qr == 0:
            try:
                host = pkt[DNSQR].qname.decode("ascii", errors="ignore").rstrip(".")
                signal = "dns"
            except Exception:
                host = None

        # TLS ClientHello (443, 8443)
        if not host and TCP in pkt and Raw in pkt and pkt[TCP].dport in (443, 8443):
            sni = parse_sni(bytes(pkt[Raw].load))
            if sni:
                host = sni
                signal = "tls-sni"

        if not host:
            return

        if debug:
            print(f"[{signal}] {src_ip} -> {host}", file=sys.stderr, flush=True)

        match = classify_host(host)

        # Record every host seen — matched or not. Helps expand the catalog.
        if EVENT_LOG is not None:
            EVENT_LOG.note_host(host, signal, src_ip, now, matched=match is not None)

        if not match:
            return

        # Client is whichever side is on this host / local net.
        # For DNS queries, src is the querier. For TLS SNI, src is the client.
        client_ip = src_ip
        client_mac = src_mac

        # Skip if debounced recently. Same provider + same kind within window
        # collapses; a login and a visit for the same provider stay distinct.
        if not STATE.should_emit(client_ip, match["provider"], match["kind"], now):
            return

        STATE.touch_device(client_ip, client_mac, now)
        evt = {
            "ts": now,
            "src_ip": client_ip,
            "src_mac": client_mac,
            "provider": match["provider"],
            "kind": match["kind"],
            "host": match["host"],
            "favicon": match["favicon"],
            "signal": signal,
        }
        if EVENT_LOG is not None:
            EVENT_LOG.log_event(evt)
        _emit(evt, loop)
    return cb


def local_addrs() -> set[str]:
    try:
        out = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=3).stdout
        return set(re.findall(r"inet (\d+\.\d+\.\d+\.\d+)", out))
    except Exception:
        return set()


def discover_ifaces() -> list[str]:
    """Return active physical (en*) and VPN tunnel (utun*, ppp*) interfaces
    that currently have an inet address. Skips loopback and Apple's internal
    wireless-direct interfaces (awdl*, llw*)."""
    try:
        out = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=3).stdout
    except Exception:
        return []
    # Split ifconfig output into per-interface blocks.
    blocks = re.split(r"\n(?=\S)", out)
    ifaces = []
    for b in blocks:
        m = re.match(r"([a-z0-9]+):", b)
        if not m:
            continue
        name = m.group(1)
        if not re.match(r"^(en|utun|ppp|tap|tun)\d+$", name):
            continue
        if "status: inactive" in b:
            continue
        if not re.search(r"\binet \d", b):
            continue
        ifaces.append(name)
    return ifaces


# ---------------------------------------------------------------------------
# Web app
# ---------------------------------------------------------------------------
STATIC_DIR = Path(__file__).parent


async def index(request: web.Request) -> web.Response:
    html = (STATIC_DIR / "dashboard.html").read_text(encoding="utf-8")
    return web.Response(text=html, content_type="text/html")


async def snapshot(request: web.Request) -> web.Response:
    with STATE.lock:
        snap = CONTROLLER.snapshot() if CONTROLLER else {"state": "idle", "error": None, "ifaces": [], "active": []}
        return web.json_response({
            **snap,
            "interfaces": _ACTIVE_IFACES,
            "devices":    list(STATE.devices.values()),
            "events":     list(STATE.events),
        })


async def api_status(request: web.Request) -> web.Response:
    return web.json_response(CONTROLLER.snapshot() if CONTROLLER else {})


async def api_start(request: web.Request) -> web.Response:
    if CONTROLLER is None:
        return web.json_response({"ok": False, "error": "controller not initialised"}, status=500)
    ok, err = CONTROLLER.start()
    await _broadcast_state()
    return web.json_response({"ok": ok, "error": err})


async def api_stop(request: web.Request) -> web.Response:
    if CONTROLLER is None:
        return web.json_response({"ok": False, "error": "controller not initialised"}, status=500)
    CONTROLLER.stop()
    await _broadcast_state()
    return web.json_response({"ok": True})


async def _broadcast_state():
    if CONTROLLER is None:
        return
    payload = json.dumps({"type": "state", **CONTROLLER.snapshot()})
    for ws in list(STATE.subscribers):
        try:
            await ws.send_str(payload)
        except Exception:
            STATE.subscribers.discard(ws)


async def _open_browser(bind: str, port: int):
    """Open the dashboard in the user's default browser once the server is up.
    Called from on_start. If we're running under sudo, drop back to the invoking
    user so `open` finds their default browser (not root's)."""
    await asyncio.sleep(0.8)
    host = "127.0.0.1" if bind in ("0.0.0.0", "::") else bind
    url = f"http://{host}:{port}"
    try:
        import os
        user = os.environ.get("SUDO_USER")
        if user and os.geteuid() == 0:
            subprocess.Popen(["/usr/bin/sudo", "-u", user, "/usr/bin/open", url])
        else:
            subprocess.Popen(["/usr/bin/open", url])
    except Exception as e:
        print(f"[!] failed to open browser: {e}", file=sys.stderr)


async def ws_handler(request: web.Request) -> web.WebSocketResponse:
    ws = web.WebSocketResponse(heartbeat=20)
    await ws.prepare(request)
    STATE.subscribers.add(ws)
    # Send initial snapshot
    with STATE.lock:
        snap = CONTROLLER.snapshot() if CONTROLLER else {"state": "idle", "error": None}
        await ws.send_str(json.dumps({
            "type":       "snapshot",
            "state":      snap.get("state"),
            "error":      snap.get("error"),
            "interfaces": _ACTIVE_IFACES,
            "devices":    list(STATE.devices.values()),
            "events":     list(STATE.events),
        }))
    try:
        async for msg in ws:
            if msg.type == WSMsgType.ERROR:
                break
    finally:
        STATE.subscribers.discard(ws)
    return ws


async def arp_refresher():
    while True:
        try:
            STATE.refresh_arp()
        except Exception:
            pass
        await asyncio.sleep(15)


async def hosts_flusher():
    while True:
        await asyncio.sleep(30)
        try:
            if EVENT_LOG is not None:
                EVENT_LOG.flush_hosts()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="auto",
                    help='capture interface(s): "auto" for all active en*/utun*, '
                         'a single name (en0), or a comma list (en0,utun4)')
    ap.add_argument("--port",  type=int, default=8765, help="web port")
    ap.add_argument("--bind",  default="127.0.0.1", help="bind address")
    ap.add_argument("--list-ifaces", action="store_true", help="list interfaces and exit")
    ap.add_argument("--debug", action="store_true", help="print every DNS query and TLS SNI seen")
    ap.add_argument("--log-dir", default=None,
                    help='log folder (default: ./logs from the source dir, or '
                         '~/Library/Application Support/SSO Watcher/logs when running as a .app). '
                         'Written: events-YYYY-MM-DD.jsonl (matched events), '
                         'hosts-YYYY-MM-DD.jsonl (every hostname seen — useful for expanding the catalog).')
    args = ap.parse_args()

    if args.list_ifaces:
        for i in get_if_list():
            print(i)
        return

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    global EVENT_LOG
    if args.log_dir:
        log_dir = Path(args.log_dir)
        if not log_dir.is_absolute():
            log_dir = Path(__file__).parent / log_dir
    else:
        log_dir = default_log_dir()
    EVENT_LOG = EventLog(log_dir)
    print(f"[+] logging to {log_dir}/", file=sys.stderr)

    local = local_addrs()
    STATE.refresh_arp()

    # Resolve interface selection.
    if args.iface == "auto":
        ifaces = discover_ifaces()
        if not ifaces:
            print("[!] auto-discovery found no active interfaces; use --iface", file=sys.stderr)
            sys.exit(1)
    else:
        ifaces = [i.strip() for i in args.iface.split(",") if i.strip()]

    # BPF filter — DNS + TLS on 443/8443
    bpf = "udp port 53 or tcp port 443 or tcp port 8443"

    # Init the controller — sniffers stay OFF until the user clicks ▶ Start
    # in the browser. The web server itself always runs.
    global CONTROLLER
    CONTROLLER = SniffController(ifaces, bpf, loop, debug=args.debug)
    _ACTIVE_IFACES.extend(describe_iface(name) for name in ifaces)

    app = web.Application()
    app.router.add_get( "/",             index)
    app.router.add_get( "/api/snapshot", snapshot)
    app.router.add_get( "/api/status",   api_status)
    app.router.add_post("/api/start",    api_start)
    app.router.add_post("/api/stop",     api_stop)
    app.router.add_get( "/ws",           ws_handler)

    async def on_start(app):
        app["arp_task"]     = asyncio.create_task(arp_refresher())
        app["hosts_task"]   = asyncio.create_task(hosts_flusher())
        app["browser_task"] = asyncio.create_task(_open_browser(args.bind, args.port))

    async def on_cleanup(app):
        if CONTROLLER is not None:
            CONTROLLER.stop()
        app["arp_task"].cancel()
        app["hosts_task"].cancel()
        if EVENT_LOG is not None:
            EVENT_LOG.close()

    app.on_startup.append(on_start)
    app.on_cleanup.append(on_cleanup)

    print(f"[+] dashboard: http://{args.bind}:{args.port}  "
          f"(click ▶ Start to begin capture; interfaces: {', '.join(ifaces)})")
    web.run_app(app, host=args.bind, port=args.port, loop=loop, print=None)


if __name__ == "__main__":
    main()
