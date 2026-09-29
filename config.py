"""Application configuration module."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Final

# Токен ipinfo.io из переменных окружения (опционально)
IPINFO_TOKEN: Final[str] = os.getenv("IPINFO_TOKEN", "").strip()

# Лимиты параллелизма и тайм-ауты
MAX_CONCURRENT_CHECKS: Final[int] = int(os.getenv("MAX_CONCURRENT_CHECKS", "200"))
TCP_TIMEOUT_SECONDS: Final[float] = float(os.getenv("TCP_TIMEOUT_SECONDS", "3.0"))
HTTP_TIMEOUT_SECONDS: Final[float] = float(os.getenv("HTTP_TIMEOUT_SECONDS", "12.0"))
MAX_LATENCY_MS: Final[float] = float(os.getenv("MAX_LATENCY_MS", "1500.0"))

# Имя выходного файла подписки
OUTPUT_FILE: Final[str] = os.getenv("OUTPUT_FILE", "sub.txt")

# Целевые raw-источники публичных подписок (Plain text / Base64)
DEFAULT_SOURCES: Final[list[str]] = [
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
]


@dataclass(slots=True, frozen=True)
class AppConfig:
    sources: list[str] = field(default_factory=lambda: list(DEFAULT_SOURCES))
    ipinfo_token: str = IPINFO_TOKEN
    max_concurrent_checks: int = MAX_CONCURRENT_CHECKS
    tcp_timeout: float = TCP_TIMEOUT_SECONDS
    http_timeout: float = HTTP_TIMEOUT_SECONDS
    max_latency_ms: float = MAX_LATENCY_MS
    output_file: str = OUTPUT_FILE