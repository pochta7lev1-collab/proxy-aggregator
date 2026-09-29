"""Application configuration module."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Final

from dotenv import load_dotenv

# Безопасная загрузка .env: если файл отсутствует в GitHub Actions, сбоя не будет
load_dotenv()

# Секреты и токены из переменных окружения
IPINFO_TOKEN: Final[str] = os.getenv("IPINFO_TOKEN", "").strip()

# Метаданные подписки (заголовки для VPN-клиентов)
SUBSCRIPTION_TITLE: Final[str] = os.getenv("SUBSCRIPTION_TITLE", "LionVPN").strip()
PROFILE_UPDATE_INTERVAL: Final[int] = int(os.getenv("PROFILE_UPDATE_INTERVAL", "4"))

# Лимиты параллелизма и тайм-ауты
MAX_CONCURRENT_CHECKS: Final[int] = int(os.getenv("MAX_CONCURRENT_CHECKS", "200"))
TCP_TIMEOUT_SECONDS: Final[float] = float(os.getenv("TCP_TIMEOUT_SECONDS", "3.0"))
HTTP_TIMEOUT_SECONDS: Final[float] = float(os.getenv("HTTP_TIMEOUT_SECONDS", "12.0"))
MAX_LATENCY_MS: Final[float] = float(os.getenv("MAX_LATENCY_MS", "1500.0"))

# Имя выходного артефакта подписки
OUTPUT_FILE: Final[str] = os.getenv("OUTPUT_FILE", "sub.txt")

# Целевые raw-источники публичных подписок:
# Приоритет отдан базам Reality и обхода блокировок/белых списков в РФ
DEFAULT_SOURCES: Final[list[str]] = [
    # --- igareck/vpn-configs-for-russia (Белые списки CIDR и Reality) ---
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS+All_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-checked.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",

    # --- DarkRoyalty/shnajder-vpn-configs (SNI/CIDR Whitelists & Reality) ---
    "https://raw.githubusercontent.com/DarkRoyalty/shnajder-vpn-configs/main/githubmirror/26.txt",
    "https://raw.githubusercontent.com/DarkRoyalty/shnajder-vpn-configs/main/githubmirror/24.txt",
    "https://raw.githubusercontent.com/DarkRoyalty/shnajder-vpn-configs/main/githubmirror/25.txt",

    # --- pog7x/vpn-configs (Агрегатор баз для РФ) ---
    "https://raw.githubusercontent.com/pog7x/vpn-configs/master/githubmirror/23.txt",
    "https://raw.githubusercontent.com/pog7x/vpn-configs/master/githubmirror/24.txt",

    # --- VAL41K/bypass-rkn-blocks (Обход глушилок и белых списков) ---
    "https://raw.githubusercontent.com/VAL41K/bypass-rkn-blocks/main/README.md",

    # --- kort0881/vpn-vless-configs-russia (Проверенные VLESS Reality для РФ) ---
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/proxy_collect_only_new_for_mirror.txt",

    # --- zieng2/wl (Специализированные белые списки VLESS) ---
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",

    # --- AvenCores/goida-vpn-configs (Зеркало CIDR обходов) ---
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/26.txt",

    # --- sevcator & глобальные резервные источники ---
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
]


@dataclass(slots=True, frozen=True)
class AppConfig:
    sources: list[str] = field(default_factory=lambda: list(DEFAULT_SOURCES))
    ipinfo_token: str = IPINFO_TOKEN
    subscription_title: str = SUBSCRIPTION_TITLE
    profile_update_interval: int = PROFILE_UPDATE_INTERVAL
    max_concurrent_checks: int = MAX_CONCURRENT_CHECKS
    tcp_timeout: float = TCP_TIMEOUT_SECONDS
    http_timeout: float = HTTP_TIMEOUT_SECONDS
    max_latency_ms: float = MAX_LATENCY_MS
    output_file: str = OUTPUT_FILE
