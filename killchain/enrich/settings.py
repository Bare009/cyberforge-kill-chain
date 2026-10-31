"""Settings for the threat-intel engine: config/ti.yaml, config/network.yaml and keys from .env."""

from __future__ import annotations

import ipaddress
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml

ROOT = Path(__file__).resolve().parents[2]
TI_YAML = ROOT / "config" / "ti.yaml"
NETWORK_YAML = ROOT / "config" / "network.yaml"
ENV_FILE = ROOT / ".env"
CACHE_PATH = ROOT / "data" / "cache" / "ti.sqlite"

Net = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def load_dotenv(path: Path = ENV_FILE) -> None:
    """Put KEY=value lines of .env into os.environ, without overriding what is already set.

    Values are never printed or logged.
    """
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name = name.strip()
        value = value.strip().strip('"').strip("'")
        if name and value and name not in os.environ:
            os.environ[name] = value


@lru_cache(maxsize=4)
def ti_config(path: str = str(TI_YAML)) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


class Network:
    """Zones and the never-send ranges from config/network.yaml."""

    def __init__(self, data: Dict[str, Any]):
        self.zones: List[Tuple[Net, Dict[str, Any]]] = [
            (ipaddress.ip_network(z["cidr"], strict=False), z) for z in data.get("zones") or []
        ]
        self.private: List[Net] = [ipaddress.ip_network(c, strict=False) for c in data.get("private_ranges") or []]
        self.hubs = data.get("hubs") or {}

    def zone_of(self, ip: str) -> Dict[str, Any]:
        """{zone, role, importance} of an address; "internet" when no range matches."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {"zone": "unknown", "role": None, "importance": None}
        for net, z in self.zones:
            if addr.version == net.version and addr in net:
                return {"zone": z.get("zone", "unknown"), "role": z.get("role"), "importance": z.get("importance")}
        return {"zone": "internet", "role": None, "importance": None}

    def is_private(self, ip: str) -> bool:
        """True for ranges never sent outside: the configured list, plus anything Python says is not global."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True
        if any(addr.version == n.version and addr in n for n in self.private):
            return True
        return not addr.is_global


@lru_cache(maxsize=4)
def network(path: str = str(NETWORK_YAML)) -> Network:
    with open(path, encoding="utf-8") as f:
        return Network(yaml.safe_load(f) or {})


def provider_key(name: str, cfg: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """The API key for a provider from the environment (after load_dotenv), or None."""
    cfg = cfg if cfg is not None else (ti_config().get("providers") or {}).get(name) or {}
    env = cfg.get("key_env")
    return (os.environ.get(env) or None) if env else None
