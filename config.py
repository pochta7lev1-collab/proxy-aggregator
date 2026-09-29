"""Application configuration module."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Final

from dotenv import load_dotenv

load_dotenv()

# Секреты и токены
IPINFO_TOKEN: Final[str] = os.getenv("IPINFO_TOKEN", "").strip()

# Лимиты параллелизма и тайм-ауты
MAX_CONCURRENT_CHECKS: Final[int] = int(os.getenv("MAX_CONCURRENT_CHECKS", "200"))
TCP_TIMEOUT_SECONDS: Final[float] = float(os.getenv("TCP_TIMEOUT_SECONDS", "3.0"))
REAL_CHECK_TIMEOUT_SECONDS: Final[float] = float(os.getenv("REAL_CHECK_TIMEOUT_SECONDS", "4.0"))
HTTP_TIMEOUT_SECONDS: Final[float] = float(os.getenv("HTTP_TIMEOUT_SECONDS", "12.0"))
MAX_LATENCY_MS: Final[float] = float(os.getenv("MAX_LATENCY_MS", "1500.0"))

# Квоты отбора серверов
MAX_CANDIDATES: Final[int] = int(os.getenv("MAX_CANDIDATES", "10000"))
MAX_OUTPUT_SERVERS: Final[int] = int(os.getenv("MAX_OUTPUT_SERVERS", "50"))
WL_MIN_SERVERS: Final[int] = int(os.getenv("WL_MIN_SERVERS", "15"))
WL_MAX_SERVERS: Final[int] = int(os.getenv("WL_MAX_SERVERS", "20"))

# Параметры подписки
OUTPUT_FILE: Final[str] = os.getenv("OUTPUT_FILE", "sub.txt")
PROFILE_TITLE: Final[str] = os.getenv("PROFILE_TITLE", "LionVPN")
PROFILE_UPDATE_INTERVAL: Final[int] = int(os.getenv("PROFILE_UPDATE_INTERVAL", "4"))

# Белые списки (приоритетные источники для обхода жестких блокировок РФ)
WHITELIST_SOURCES: Final[list[str]] = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-checked.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-all.txt",
]

# Общие проверенные источники (без нефильтрованных гигантских свалок)
GENERAL_SOURCES: Final[list[str]] = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS+All_RUS.txt",
    "https://raw.githubusercontent.com/pog7x/vpn-russia/main/vpn.txt",
]


@dataclass(slots=True, frozen=True)
class SourceItem:
    url: str
    is_whitelist: bool = False


@dataclass(slots=True, frozen=True)
class AppConfig:
    whitelist_sources: list[str] = field(default_factory=lambda: list(WHITELIST_SOURCES))
    general_sources: list[str] = field(default_factory=lambda: list(GENERAL_SOURCES))
    ipinfo_token: str = IPINFO_TOKEN
    max_concurrent_checks: int = MAX_CONCURRENT_CHECKS
    tcp_timeout: float = TCP_TIMEOUT_SECONDS
    real_check_timeout: float = REAL_CHECK_TIMEOUT_SECONDS
    http_timeout: float = HTTP_TIMEOUT_SECONDS
    max_latency_ms: float = MAX_LATENCY_MS
    max_candidates: int = MAX_CANDIDATES
    max_output_servers: int = MAX_OUTPUT_SERVERS
    wl_min_servers: int = WL_MIN_SERVERS
    wl_max_servers: int = WL_MAX_SERVERS
    output_file: str = OUTPUT_FILE
    profile_title: str = PROFILE_TITLE
    profile_update_interval: int = PROFILE_UPDATE_INTERVAL
