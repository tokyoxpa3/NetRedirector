"""Configuration for VPN Gate auto-assign."""

import os

# SoftEther VPN Client vpncmd.exe path (Simplified Chinese build, v4.44)
VPNCMD_PATH = r"C:\Program Files\SoftEther VPN Client\vpncmd.exe"

# VPN Gate real-time node list (CSV format)
VPNGATE_API_URL = "http://www.vpngate.net/api/iphone/"

# Virtual HUB name used by all VPN Gate public relays
VPNGATE_HUB = "VPNGATE"

# Anonymous auth username used by VPN Gate
VPNGATE_USERNAME = "vpn"

# NICs currently in active use (do NOT touch)
ACTIVE_NICS = [f"VPN{i}" for i in range(2, 12)]  # VPN2..VPN11

# NICs opened for testing
TEST_NICS = ["VPN12", "VPN13", "VPN14"]

# Number of connections to manage in production (VPN2..VPN11)
PRODUCTION_NIC_COUNT = 10

# Connection / verification timeouts (seconds)
CONNECT_TIMEOUT = 10
STATUS_POLL_INTERVAL = 2

# vpncmd output encoding (Simplified Chinese build v4.44 actually emits UTF-8)
VPNCMD_ENCODING = "utf-8"

# How many candidate nodes to fetch and rank before assigning
MAX_CANDIDATES = 60

# Minimum acceptable Speed (bps) reported by VPN Gate
MIN_SPEED_BPS = 10_000_000  # 10 Mbps
