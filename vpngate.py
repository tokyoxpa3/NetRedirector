"""Fetch and parse the VPN Gate real-time node list.

The CSV at http://www.vpngate.net/api/iphone/ has this shape:

    *vpn_servers
    #HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,...
    public-vpn-72,219.100.37.22,2949769,19,474228410,Japan,JP,...

The final column (OpenVPN_ConfigData_Base64) is a base64 OpenVPN config whose
`remote <ip> <port>` line reveals the TCP port. That same port is what the
SoftEther protocol connects on (SoftEther VPN Server auto-detects both
protocols on a single listener), so we reuse it verbatim.
"""

import base64
import csv
import io
import re
from dataclasses import dataclass

import requests

import vpngate_config as config


@dataclass
class VpnGateNode:
    hostname: str
    ip: str
    score: int
    ping_ms: int
    speed_bps: int
    country_long: str
    country_short: str
    num_sessions: int
    port: int


_REMOTE_RE = re.compile(r"^\s*remote\s+\S+\s+(\d+)\s*$", re.IGNORECASE | re.MULTILINE)


def fetch_nodes(url: str = config.VPNGATE_API_URL, timeout: int = 30) -> list[VpnGateNode]:
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    text = resp.text
    lines = text.splitlines()
    header_idx = next(
        (i for i, ln in enumerate(lines) if ln.lstrip().startswith("#HostName")),
        None,
    )
    if header_idx is None:
        return []

    reader = csv.reader(io.StringIO("\n".join(lines[header_idx:])))
    header = next(reader)
    col = {name.strip().lstrip("#"): i for i, name in enumerate(header)}

    nodes: list[VpnGateNode] = []
    for row in reader:
        if len(row) < 15:
            continue
        try:
            hostname = row[col["HostName"]].strip()
            ip = row[col["IP"]].strip()
            if not hostname or not ip:
                continue
            score = int(row[col["Score"]].strip())
            ping = int(row[col["Ping"]].strip())
            speed = int(row[col["Speed"]].strip())
            country_long = row[col["CountryLong"]].strip()
            country_short = row[col["CountryShort"]].strip()
            sessions = int(row[col["NumVpnSessions"]].strip())
            b64 = row[col["OpenVPN_ConfigData_Base64"]].strip()
        except (KeyError, IndexError, ValueError):
            continue

        port = _extract_port(b64)
        if port is None:
            continue

        nodes.append(
            VpnGateNode(
                hostname=hostname,
                ip=ip,
                score=score,
                ping_ms=ping,
                speed_bps=speed,
                country_long=country_long,
                country_short=country_short,
                num_sessions=sessions,
                port=port,
            )
        )
    return nodes


def _extract_port(b64: str) -> int | None:
    if not b64:
        return None
    try:
        cfg = base64.b64decode(b64).decode("utf-8", errors="ignore")
    except Exception:
        return None
    m = _REMOTE_RE.search(cfg)
    if not m:
        return None
    try:
        port = int(m.group(1))
    except ValueError:
        return None
    if 1 <= port <= 65535:
        return port
    return None


def rank_nodes(
    nodes: list[VpnGateNode],
    min_speed: int = config.MIN_SPEED_BPS,
    exclude_public: bool = True,
    exclude_port_443: bool = True,
    countries: list[str] | None = None,
) -> list[VpnGateNode]:
    candidates = [n for n in nodes if n.speed_bps >= min_speed]
    if exclude_public:
        candidates = [n for n in candidates if "public" not in n.hostname.lower()]
    if exclude_port_443:
        candidates = [n for n in candidates if n.port != 443]
    if countries:
        cs = {c.strip().upper() for c in countries if c.strip()}
        if cs:
            candidates = [
                n
                for n in candidates
                if n.country_short.upper() in cs or n.country_long.upper() in cs
            ]
    candidates.sort(key=lambda n: (-n.score, n.ping_ms))
    return candidates


if __name__ == "__main__":
    ns = fetch_nodes()
    print(f"fetched {len(ns)} nodes")
    for n in rank_nodes(ns)[:15]:
        print(
            f"{n.hostname:20s} {n.ip:16s} port={n.port:<5d} "
            f"score={n.score} ping={n.ping_ms}ms speed={n.speed_bps/1e6:.0f}M "
            f"{n.country_long}"
        )
