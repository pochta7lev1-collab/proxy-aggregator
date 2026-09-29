"""Safe URI parser and normalizer for proxy protocols."""

from __future__ import annotations

import base64
import json
import urllib.parse
from dataclasses import dataclass
from typing import Optional


def safe_b64decode(payload: str) -> str:
    """Декодирует standard и URL-safe Base64 с автоматическим выравниванием паддинга."""
    cleaned = payload.strip().replace("-", "+").replace("_", "/")
    padding = "=" * (-len(cleaned) % 4)
    raw_bytes = base64.b64decode(cleaned + padding)
    return raw_bytes.decode("utf-8", errors="ignore")


@dataclass(slots=True, frozen=True)
class ProxyNode:
    raw_uri: str
    protocol: str
    host: str
    port: int
    name: str


def _parse_vmess(uri: str) -> Optional[ProxyNode]:
    try:
        raw_body = uri[8:].split("#", 1)[0]
        decoded = safe_b64decode(raw_body)
        data = json.loads(decoded)
        if not isinstance(data, dict):
            return None

        host = str(data.get("add") or data.get("host") or "").strip().strip("[]")
        port_raw = data.get("port")
        if not host or port_raw is None:
            return None

        port = int(port_raw)
        if not (0 < port <= 65535):
            return None

        name = str(data.get("ps") or "").strip()
        return ProxyNode(raw_uri=uri, protocol="vmess", host=host, port=port, name=name)
    except Exception:
        return None


def _parse_standard_scheme(uri: str, scheme: str) -> Optional[ProxyNode]:
    try:
        parsed = urllib.parse.urlsplit(uri)
        host = parsed.hostname
        if not host:
            return None

        host = host.strip("[]")
        port = parsed.port if parsed.port is not None else 443
        if not (0 < port <= 65535):
            return None

        name = urllib.parse.unquote(parsed.fragment).strip()
        return ProxyNode(raw_uri=uri, protocol=scheme, host=host, port=port, name=name)
    except Exception:
        return None


def _parse_shadowsocks(uri: str) -> Optional[ProxyNode]:
    try:
        parsed = urllib.parse.urlsplit(uri)
        name = urllib.parse.unquote(parsed.fragment).strip()

        # Формат SIP002: ss://base64(userinfo)@host:port#name
        if "@" in parsed.netloc:
            host = parsed.hostname
            if not host:
                return None
            host = host.strip("[]")
            port = parsed.port if parsed.port is not None else 8388
            if not (0 < port <= 65535):
                return None
            return ProxyNode(raw_uri=uri, protocol="ss", host=host, port=port, name=name)

        # Legacy-формат: ss://base64(userinfo@host:port)#name
        raw_body = parsed.netloc
        decoded = safe_b64decode(raw_body)
        if "@" not in decoded:
            return None

        _, host_port = decoded.rsplit("@", 1)
        if host_port.startswith("["):
            # IPv6
            host_part, port_part = host_port[1:].split("]:", 1)
            host = host_part.strip("[]")
            port = int(port_part)
        else:
            host_part, port_part = host_port.rsplit(":", 1)
            host = host_part.strip("[]")
            port = int(port_part)

        if not host or not (0 < port <= 65535):
            return None

        return ProxyNode(raw_uri=uri, protocol="ss", host=host, port=port, name=name)
    except Exception:
        return None


def parse_proxy_uri(uri: str) -> Optional[ProxyNode]:
    """Парсит URI прокси-узла с изоляцией исключений."""
    clean_uri = uri.strip()
    if not clean_uri or "://" not in clean_uri:
        return None

    scheme = clean_uri.split("://", 1)[0].lower()
    match scheme:
        case "vmess":
            return _parse_vmess(clean_uri)
        case "vless" | "trojan":
            return _parse_standard_scheme(clean_uri, scheme)
        case "ss":
            return _parse_shadowsocks(clean_uri)
        case _:
            return None