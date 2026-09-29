"""Geo-resolution module with ipinfo.io caching and ISO flag emojis."""

from __future__ import annotations

import ipaddress
import logging
from typing import Final

import aiohttp

logger = logging.getLogger(__name__)

DEFAULT_UNKNOWN_TAG: Final[str] = "🌐 UNK"


def country_code_to_flag(country_code: str) -> str:
    """Генерирует эмодзи флага по стандарту ISO-3166-1 alpha-2."""
    if not country_code or len(country_code) != 2 or not country_code.isalpha():
        return DEFAULT_UNKNOWN_TAG

    code = country_code.upper()
    # Смещение: Региональный индикатор 'A' (0x1F1E6) - ord('A') (65) = 127397
    flag = "".join(chr(127397 + ord(char)) for char in code)
    return f"{flag} {code}"


class GeoResolver:
    """Разрешает геолокацию IP-адресов через ipinfo.io с локальным кэшем."""

    def __init__(self, token: str = "", timeout_sec: float = 4.0) -> None:
        self.token = token.strip()
        self.timeout_sec = timeout_sec
        self._cache: dict[str, str] = {}
        self._rate_limited: bool = False

    def _is_bypassed_ip(self, ip_str: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
        except ValueError:
            return False

    async def get_country_code(
        self,
        session: aiohttp.ClientSession,
        ip_str: str,
    ) -> str:
        """Возвращает 2-буквенный ISO-код страны либо 'UNK'."""
        if not ip_str or self._is_bypassed_ip(ip_str):
            return "UNK"

        if ip_str in self._cache:
            return self._cache[ip_str]

        # Если токен не передан или превышен рейт-лимит — экономим запросы
        if not self.token or self._rate_limited:
            self._cache[ip_str] = "UNK"
            return "UNK"

        url = f"https://ipinfo.io/{ip_str}/country"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "text/plain",
        }

        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout_sec)
            async with session.get(url, headers=headers, timeout=timeout) as resp:
                if resp.status == 200:
                    raw_country = (await resp.text()).strip().upper()
                    if len(raw_country) == 2 and raw_country.isalpha():
                        self._cache[ip_str] = raw_country
                        return raw_country
                elif resp.status in (429, 403):
                    logger.warning("ipinfo.io rate limit exceeded or invalid token (HTTP %d). Fallback to UNK.", resp.status)
                    self._rate_limited = True
        except Exception:
            pass

        self._cache[ip_str] = "UNK"
        return "UNK"

    async def get_geo_tag(
        self,
        session: aiohttp.ClientSession,
        ip_str: str,
    ) -> str:
        """Возвращает строку формата '🇩🇪 DE' или '🌐 UNK'."""
        country_code = await self.get_country_code(session, ip_str)
        if country_code == "UNK":
            return DEFAULT_UNKNOWN_TAG
        return country_code_to_flag(country_code)