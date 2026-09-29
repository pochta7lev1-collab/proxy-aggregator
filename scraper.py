"""Asynchronous proxy scraper with deep Base64 detection and whitelist tagging."""

from __future__ import annotations

import asyncio
import base64
import logging
import re
from typing import Final, Sequence

import aiohttp

from config import SourceItem, WHITELIST_SOURCES

logger = logging.getLogger(__name__)

PROXY_URI_REGEX: Final[re.Pattern[str]] = re.compile(
    r"(?:vmess|vless|trojan|ss)://[^\s<>\"']+",
    re.IGNORECASE,
)

WHITELIST_URI_REGISTRY: set[str] = set()


class ScrapedProxy(str):
    """Строка URI, сохраняющая атрибут принадлежности к белому списку."""
    is_whitelist: bool

    def __new__(cls, content: str, is_whitelist: bool = False) -> ScrapedProxy:
        obj = super().__new__(cls, content.strip())
        obj.is_whitelist = is_whitelist
        return obj

    @property
    def raw_uri(self) -> str:
        return str(self)

    def strip(self, chars: str | None = None) -> ScrapedProxy:
        return ScrapedProxy(super().strip(chars), is_whitelist=self.is_whitelist)


def register_whitelist_uri(uri: str) -> None:
    base = uri.strip().split("#", 1)[0]
    if base:
        WHITELIST_URI_REGISTRY.add(base)


def is_uri_whitelisted(uri: str) -> bool:
    if getattr(uri, "is_whitelist", False):
        return True
    base = str(uri).strip().split("#", 1)[0]
    return base in WHITELIST_URI_REGISTRY


def _decode_b64_safe(payload: str) -> str:
    clean = re.sub(r"[\s\r\n]+", "", payload).replace("-", "+").replace("_", "/")
    if not clean:
        return ""
    padding = "=" * (-len(clean) % 4)
    try:
        decoded = base64.b64decode(clean + padding)
        return decoded.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def extract_proxies_from_raw(content: str) -> list[str]:
    """Извлекает URI из Plain text, чистого Base64 или построчно закодированных списков."""
    # 1. Поиск открытых ссылок
    direct_matches = PROXY_URI_REGEX.findall(content)
    if direct_matches:
        return direct_matches

    # 2. Очистка строк от комментариев (#, //) и декодирование всего тела
    lines = content.splitlines()
    clean_lines = [
        line.strip() for line in lines
        if line.strip() and not line.strip().startswith(("#", "//"))
    ]
    full_payload = "".join(clean_lines)

    decoded_full = _decode_b64_safe(full_payload)
    if decoded_full:
        matches = PROXY_URI_REGEX.findall(decoded_full)
        if matches:
            return matches

    # 3. Построчное декодирование
    line_matches: list[str] = []
    for line in clean_lines:
        decoded_line = _decode_b64_safe(line)
        if decoded_line:
            found = PROXY_URI_REGEX.findall(decoded_line)
            if found:
                line_matches.extend(found)

    if line_matches:
        return line_matches

    # 4. Поиск вкрапленных Base64-блоков длиннее 64 символов
    embedded_blocks = re.findall(r"[A-Za-z0-9+/=_-]{64,}", content)
    for block in embedded_blocks:
        dec_block = _decode_b64_safe(block)
        if dec_block:
            found = PROXY_URI_REGEX.findall(dec_block)
            if found:
                line_matches.extend(found)

    return line_matches


async def _fetch_single_source(
    session: aiohttp.ClientSession,
    url: str,
    is_whitelist: bool,
    timeout_sec: float,
) -> list[ScrapedProxy]:
    category = "WHITELIST" if is_whitelist else "GENERAL"
    logger.info("Scraping source [%s]: %s", category, url)
    try:
        timeout = aiohttp.ClientTimeout(total=timeout_sec)
        async with session.get(url, timeout=timeout, allow_redirects=True) as resp:
            if resp.status != 200:
                logger.warning("Failed to fetch %s (HTTP %d)", url, resp.status)
                return []

            content = await resp.text(encoding="utf-8", errors="replace")
            raw_matches = extract_proxies_from_raw(content)

            results: list[ScrapedProxy] = []
            for match in raw_matches:
                item = ScrapedProxy(match, is_whitelist=is_whitelist)
                if is_whitelist:
                    register_whitelist_uri(match)
                results.append(item)

            logger.info("Extracted %d URIs [%s] from %s", len(results), category, url)
            return results
    except Exception as err:
        logger.warning("Error fetching %s: %s", url, err)
        return []


async def scrape_all_sources(
    whitelist_sources: Sequence[str] | None = None,
    general_sources: Sequence[str] | None = None,
    timeout_sec: float = 15.0,
) -> list[ScrapedProxy]:
    """Асинхронно скачивает все источники и проводит дедупликацию с сохранением меток."""
    wl_list = list(whitelist_sources) if whitelist_sources is not None else list(WHITELIST_SOURCES)
    gen_list = list(general_sources) if general_sources is not None else []

    resolved_sources = [
        *(SourceItem(url=u, is_whitelist=True) for u in wl_list),
        *(SourceItem(url=u, is_whitelist=False) for u in gen_list),
    ]

    headers = {
        "User-Agent": "v2rayNG/1.8.12 (Linux; Android 14; en-US)",
        "Accept": "*/*",
    }
    connector = aiohttp.TCPConnector(ssl=False, limit=60)

    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        tasks = [
            _fetch_single_source(session, item.url, item.is_whitelist, timeout_sec)
            for item in resolved_sources
        ]
        results = await asyncio.gather(*tasks, return_exceptions=False)

    flat_list = [proxy for sublist in results for proxy in sublist]

    unique_map: dict[str, ScrapedProxy] = {}
    for item in flat_list:
        dedup_key = str(item).strip().split("#", 1)[0]
        if not dedup_key:
            continue
        if dedup_key not in unique_map:
            unique_map[dedup_key] = item
        elif item.is_whitelist and not unique_map[dedup_key].is_whitelist:
            unique_map[dedup_key] = item

    unique_proxies = list(unique_map.values())
    wl_count = sum(1 for p in unique_proxies if p.is_whitelist)
    logger.info(
        "Total unique URIs collected: %d (WhiteList: %d, General: %d)",
        len(unique_proxies),
        wl_count,
        len(unique_proxies) - wl_count,
    )
    return unique_proxies
