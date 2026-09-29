"""High-performance TCP and deep Xray-core latency checker."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import shutil
import socket
import tempfile
import time
import urllib.parse
from dataclasses import dataclass
from typing import Optional, Sequence

from parser import ProxyNode

logger = logging.getLogger(__name__)

XRAY_BIN_PATH: str | None = shutil.which("xray")


@dataclass(slots=True, frozen=True)
class CheckedNode:
    node: ProxyNode
    latency_ms: float
    resolved_ip: str


def get_free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def node_to_xray_outbound(node: ProxyNode) -> dict | None:
    """Генерирует исходящую конфигурацию Xray для всех поддерживаемых протоколов."""
    try:
        uri = node.raw_uri.strip()
        scheme = node.protocol.lower()

        if scheme == "vless":
            p = urllib.parse.urlsplit(uri)
            qs = urllib.parse.parse_qs(p.query)
            security = qs.get("security", ["none"])[0].lower()
            net_type = qs.get("type", ["tcp"])[0].lower()
            sni = qs.get("sni", [p.hostname])[0]
            flow = qs.get("flow", [""])[0]

            outbound: dict = {
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": p.hostname,
                        "port": p.port or 443,
                        "users": [{
                            "id": p.username,
                            "encryption": "none",
                            "flow": flow,
                        }],
                    }],
                },
                "streamSettings": {
                    "network": net_type,
                    "security": security,
                },
            }

            if security == "reality":
                outbound["streamSettings"]["realitySettings"] = {
                    "serverName": sni,
                    "fingerprint": qs.get("fp", ["chrome"])[0],
                    "show": False,
                    "publicKey": qs.get("pbk", [""])[0],
                    "shortId": qs.get("sid", [""])[0],
                    "spiderX": qs.get("spx", [""])[0],
                }
            elif security == "tls":
                outbound["streamSettings"]["tlsSettings"] = {
                    "serverName": sni,
                    "allowInsecure": False,
                }

            if net_type == "ws":
                outbound["streamSettings"]["wsSettings"] = {
                    "path": qs.get("path", ["/"])[0],
                    "headers": {"Host": qs.get("host", [""])[0] or p.hostname},
                }
            elif net_type == "grpc":
                outbound["streamSettings"]["grpcSettings"] = {
                    "serviceName": qs.get("serviceName", [""])[0],
                    "multiMode": qs.get("mode", ["gun"])[0] == "multi",
                }
            return outbound

        elif scheme == "trojan":
            p = urllib.parse.urlsplit(uri)
            qs = urllib.parse.parse_qs(p.query)
            sni = qs.get("sni", [p.hostname])[0]
            return {
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": p.hostname,
                        "port": p.port or 443,
                        "password": p.username,
                    }],
                },
                "streamSettings": {
                    "network": qs.get("type", ["tcp"])[0].lower(),
                    "security": "tls",
                    "tlsSettings": {"serverName": sni},
                },
            }

        elif scheme == "vmess":
            raw_body = uri[8:].split("#", 1)[0]
            clean = raw_body.strip().replace("-", "+").replace("_", "/")
            padding = "=" * (-len(clean) % 4)
            data = json.loads(base64.b64decode(clean + padding).decode("utf-8", errors="ignore"))
            return {
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": data.get("add") or data.get("host"),
                        "port": int(data.get("port", 443)),
                        "users": [{
                            "id": data.get("id"),
                            "alterId": int(data.get("aid", 0)),
                            "security": "auto",
                        }],
                    }],
                },
                "streamSettings": {
                    "network": data.get("net", "tcp"),
                    "security": "tls" if data.get("tls") == "tls" else "none",
                },
            }

        elif scheme == "ss":
            p = urllib.parse.urlsplit(uri)
            if "@" in p.netloc:
                userinfo = p.username or ""
                clean = userinfo.strip().replace("-", "+").replace("_", "/")
                padding = "=" * (-len(clean) % 4)
                try:
                    dec = base64.b64decode(clean + padding).decode()
                    method, pwd = dec.split(":", 1)
                except Exception:
                    method, pwd = userinfo.split(":", 1)
                return {
                    "protocol": "shadowsocks",
                    "settings": {
                        "servers": [{
                            "address": p.hostname,
                            "port": p.port or 8388,
                            "method": method,
                            "password": pwd,
                        }],
                    },
                }
        return None
    except Exception:
        return None


async def _socks5_http_keepalive_test(port: int, timeout_sec: float) -> bool:
    """Выполняет реальный GET /generate_204 через локальный SOCKS5 порт Xray."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port),
            timeout=timeout_sec,
        )

        # SOCKS5 Handshake
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout_sec)
        if resp != b"\x05\x00":
            writer.close()
            await writer.wait_closed()
            return False

        # SOCKS5 Connect к cp.cloudflare.com:80
        host = b"cp.cloudflare.com"
        req = b"\x05\x01\x00\x03" + bytes([len(host)]) + host + (80).to_bytes(2, "big")
        writer.write(req)
        await writer.drain()

        reply = await asyncio.wait_for(reader.read(10), timeout=timeout_sec)
        if len(reply) < 4 or reply[1] != 0x00:
            writer.close()
            await writer.wait_closed()
            return False

        # HTTP запрос keepalive
        http_req = b"GET /generate_204 HTTP/1.1\r\nHost: cp.cloudflare.com\r\nUser-Agent: Happ/1.0\r\nConnection: close\r\n\r\n"
        writer.write(http_req)
        await writer.drain()

        http_resp = await asyncio.wait_for(reader.read(128), timeout=timeout_sec)
        writer.close()
        await writer.wait_closed()

        return b"204 No Content" in http_resp or b"200 OK" in http_resp
    except Exception:
        return False


async def check_tcp_latency(node: ProxyNode, semaphore: asyncio.Semaphore, timeout_sec: float) -> CheckedNode | None:
    """Быстрый TCP-скрининг."""
    async with semaphore:
        start = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(node.host, node.port),
                timeout=timeout_sec,
            )
            latency_ms = (time.perf_counter() - start) * 1000.0
            peer = writer.get_extra_info("peername")
            resolved_ip = peer[0] if (peer and len(peer) > 0) else node.host
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return CheckedNode(node=node, latency_ms=latency_ms, resolved_ip=str(resolved_ip))
        except Exception:
            return None


async def run_checker(nodes: Sequence[ProxyNode], concurrency_limit: int, timeout_sec: float) -> list[CheckedNode]:
    """Быстрый параллельный TCP-тест пула."""
    logger.info("TCP pre-check started for %d nodes...", len(nodes))
    semaphore = asyncio.Semaphore(concurrency_limit)
    tasks = [check_tcp_latency(node, semaphore, timeout_sec) for node in nodes]
    results = await asyncio.gather(*tasks, return_exceptions=False)
    alive = [res for res in results if res is not None]
    logger.info("TCP check complete. Alive: %d / %d", len(alive), len(nodes))
    return alive


async def verify_single_proxy_real(checked_node: CheckedNode, semaphore: asyncio.Semaphore, timeout_sec: float) -> CheckedNode | None:
    """Глубокая проверка Reality/VLESS/Trojan туннеля через временный процесс Xray."""
    if not XRAY_BIN_PATH:
        return checked_node

    outbound = node_to_xray_outbound(checked_node.node)
    if not outbound:
        return None

    async with semaphore:
        port = get_free_tcp_port()
        config_data = {
            "log": {"loglevel": "none"},
            "inbounds": [{
                "port": port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }],
            "outbounds": [outbound],
        }

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            config_path = f.name

        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                XRAY_BIN_PATH, "run", "-c", config_path,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )

            await asyncio.sleep(0.15)  # Время на привязку локального сокета

            start = time.perf_counter()
            is_alive = await _socks5_http_keepalive_test(port, timeout_sec)
            real_latency_ms = (time.perf_counter() - start) * 1000.0

            if is_alive:
                return CheckedNode(
                    node=checked_node.node,
                    latency_ms=real_latency_ms,
                    resolved_ip=checked_node.resolved_ip,
                )
            return None
        except Exception:
            return None
        finally:
            if proc:
                try:
                    proc.terminate()
                    await proc.wait()
                except Exception:
                    pass
            try:
                os.unlink(config_path)
            except Exception:
                pass


async def verify_candidates_real(nodes: Sequence[CheckedNode], concurrency: int = 15, timeout_sec: float = 4.0) -> list[CheckedNode]:
    """Запускает глубокий тест через Xray для отобранного пула кандидатов."""
    if not XRAY_BIN_PATH:
        logger.warning("Xray binary not found in PATH! Falling back to TCP results.")
        return list(nodes)

    logger.info("Deep Xray-core proxy validation started for %d candidates...", len(nodes))
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [verify_single_proxy_real(node, semaphore, timeout_sec) for node in nodes]
    results = await asyncio.gather(*tasks, return_exceptions=False)
    verified = [res for res in results if res is not None]
    logger.info("Xray-core validation complete. Verified alive tunnels: %d / %d", len(verified), len(nodes))
    return verified
