"""Asynchronous proxy scraper with whitelist tagging."""

from __future__ import annotations

import asyncio
import base64
import logging
import re
from typing import Final, Sequence

import aiohttp

from config import SourceItem, WHITELIST_SOURCES, GENERAL_SOURCES

logger = logging.getLogger(__name__)

PROXY_URI_REGEX: Final[re.Pattern[str]] = re.compile(
    r"(?:vmess|vless|trojan|ss)://[^\s<>\"']+",
    re.IGNORECASE,
)

# Глобальный реестр для сквозной проверки принадлежности к белому списку
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
    """Добавляет базовый URI в реестр белых списков."""
    base = uri.strip().split("#", 1)[0]
    if base:
        WHITELIST_URI_REGISTRY.add(base)


def is_uri_whitelisted(uri: str) -> bool:
    """Проверяет принадлежность URI к белому списку."""
    if getattr(uri, "is_whitelist", False):
        return True
    base = str(uri).strip().split("#", 1)[0]
    return base in WHITELIST_URI_REGISTRY


def _safe_base64_decode_lines(text: str) -> str:
    cleaned = "".join(text.split())
    padding = "=" * (-len(cleaned) % 4)
    try:
        return base64.b64decode(cleaned + padding).decode("utf-8", errors="ignore")
    except Exception:
        return ""


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

            content = await resp.text(encoding="utf-8", errors="ignore")
            raw_matches = PROXY_URI_REGEX.findall(content)

            if not raw_matches:
                decoded_text = _safe_base64_decode_lines(content)
                if decoded_text:
                    raw_matches = PROXY_URI_REGEX.findall(decoded_text)

            results: list[ScrapedProxy] = []
            for match in raw_matches:
                item = ScrapedProxy(match, is_whitelist=is_whitelist)
                if is_whitelist:
                    register_whitelist_uri(match)
                results.append(item)

            logger.info("Extracted %d URIs [%s] from %s", len(results), category, url)
            return results
    except (aiohttp.ClientError, asyncio.TimeoutError) as err:
        logger.warning("Network error fetching %s: %s", url, err)
        return []
    except Exception as err:
        logger.error("Unexpected error parsing %s: %s", url, err)
        return []


async def scrape_all_sources(
    sources: Sequence[SourceItem | str] | None = None,
    timeout_sec: float = 12.0,
    *,
    whitelist_sources: Sequence[str] | None = None,
    regular_sources: Sequence[str] | None = None,
) -> list[ScrapedProxy]:
    """Асинхронно опрашивает все источники и выполняет дедупликацию с сохранением меток."""
    whitelist_set = set(WHITELIST_SOURCES)
    resolved_sources: list[SourceItem] = []

    if sources is not None:
        for s in sources:
            if isinstance(s, SourceItem):
                resolved_sources.append(s)
            elif isinstance(s, str):
                resolved_sources.append(SourceItem(url=s, is_whitelist=(s in whitelist_set)))
    elif whitelist_sources is not None or regular_sources is not None:
        if whitelist_sources:
            resolved_sources.extend(SourceItem(url=u, is_whitelist=True) for u in whitelist_sources)
        if regular_sources:
            resolved_sources.extend(SourceItem(url=u, is_whitelist=False) for u in regular_sources)
    else:
        from config import ALL_SOURCES
        resolved_sources = list(ALL_SOURCES)

    headers = {
        "User-Agent": "v2rayNG/1.8.5 (Linux; Android 13; en-US)",
        "Accept": "*/*",
    }
    connector = aiohttp.TCPConnector(ssl=False, limit=50)

    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        tasks = [
            _fetch_single_source(session, item.url, item.is_whitelist, timeout_sec)
            for item in resolved_sources
        ]
        results = await asyncio.gather(*tasks, return_exceptions=False)

    flat_list: list[ScrapedProxy] = [proxy for sublist in results for proxy in sublist]

    # Дедупликация: совпадение по URI без фрагмента, узел из WL имеет высший приоритет
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
