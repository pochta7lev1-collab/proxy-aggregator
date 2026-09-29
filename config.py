"""Application configuration module."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Final

from dotenv import load_dotenv

# Загрузка локальных переменных окружения (в CI не вызывает ошибки при отсутствии .env)
load_dotenv()

# Секреты и токены
IPINFO_TOKEN: Final[str] = os.getenv("IPINFO_TOKEN", "").strip()

# Лимиты параллелизма и сетевые тайм-ауты
MAX_CONCURRENT_CHECKS: Final[int] = int(os.getenv("MAX_CONCURRENT_CHECKS", "200"))
TCP_TIMEOUT_SECONDS: Final[float] = float(os.getenv("TCP_TIMEOUT_SECONDS", "3.0"))
HTTP_TIMEOUT_SECONDS: Final[float] = float(os.getenv("HTTP_TIMEOUT_SECONDS", "12.0"))
MAX_LATENCY_MS: Final[float] = float(os.getenv("MAX_LATENCY_MS", "1500.0"))

# Лимиты отбора узлов и кандидатов
MAX_CANDIDATES: Final[int] = int(os.getenv("MAX_CANDIDATES", "10000"))
MAX_OUTPUT_SERVERS: Final[int] = int(os.getenv("MAX_OUTPUT_SERVERS", "50"))
WL_MIN_SERVERS: Final[int] = int(os.getenv("WL_MIN_SERVERS", "10"))
WL_MAX_SERVERS: Final[int] = int(os.getenv("WL_MAX_SERVERS", "15"))

# Параметры подписки
OUTPUT_FILE: Final[str] = os.getenv("OUTPUT_FILE", "sub.txt")
PROFILE_TITLE: Final[str] = os.getenv("PROFILE_TITLE", "LionVPN")
PROFILE_UPDATE_INTERVAL: Final[int] = int(os.getenv("PROFILE_UPDATE_INTERVAL", "4"))

# Белые списки (CIDR / Reality под мобильные операторы РФ)
WHITELIST_SOURCES: Final[list[str]] = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/VAL41K/bypass-rkn-blocks/main/white_list.txt",
]

# Проверенные качественные публичные базы
GENERAL_SOURCES: Final[list[str]] = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS+All_RUS.txt",
    "https://raw.githubusercontent.com/pog7x/vpn-russia/main/vpn.txt",
    "https://raw.githubusercontent.com/VAL41K/bypass-rkn-blocks/main/main_list.txt",
    "https://raw.githubusercontent.com/DarkRoyalty/V2ray-Configs/main/Splitted-By-Protocol/vless.txt",
]


@dataclass(slots=True, frozen=True)
class SourceItem:
    """Элемент источника с признаком белого списка."""
    url: str
    is_whitelist: bool = False


ALL_SOURCES: Final[list[SourceItem]] = [
    *(SourceItem(url=u, is_whitelist=True) for u in WHITELIST_SOURCES),
    *(SourceItem(url=u, is_whitelist=False) for u in GENERAL_SOURCES),
]


@dataclass(slots=True, frozen=True)
class AppConfig:
    whitelist_sources: list[str] = field(default_factory=lambda: list(WHITELIST_SOURCES))
    general_sources: list[str] = field(default_factory=lambda: list(GENERAL_SOURCES))
    ipinfo_token: str = IPINFO_TOKEN
    max_concurrent_checks: int = MAX_CONCURRENT_CHECKS
    tcp_timeout: float = TCP_TIMEOUT_SECONDS
    http_timeout: float = HTTP_TIMEOUT_SECONDS
    max_latency_ms: float = MAX_LATENCY_MS
    max_candidates: int = MAX_CANDIDATES
    max_output_servers: int = MAX_OUTPUT_SERVERS
    wl_min_servers: int = WL_MIN_SERVERS
    wl_max_servers: int = WL_MAX_SERVERS
    output_file: str = OUTPUT_FILE
    profile_title: str = PROFILE_TITLE
    profile_update_interval: int = PROFILE_UPDATE_INTERVAL

    @property
    def sources(self) -> list[SourceItem]:
        return [
            *(SourceItem(url=u, is_whitelist=True) for u in self.whitelist_sources),
            *(SourceItem(url=u, is_whitelist=False) for u in self.general_sources),
        ]
