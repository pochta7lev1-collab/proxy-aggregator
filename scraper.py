"""Asynchronous proxy subscription scraper."""

from __future__ import annotations

import asyncio
import base64
import logging
import re
from typing import Final, Sequence

import aiohttp

logger = logging.getLogger(__name__)

PROXY_URI_REGEX: Final[re.Pattern[str]] = re.compile(
    r"(?:vmess|vless|trojan|ss)://[^\s<>\"']+",
    re.IGNORECASE,
)


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
    timeout_sec: float,
) -> list[str]:
    logger.info("Scraping source: %s", url)
    try:
        timeout = aiohttp.ClientTimeout(total=timeout_sec)
        async with session.get(url, timeout=timeout, allow_redirects=True) as resp:
            if resp.status != 200:
                logger.warning("Failed to fetch %s (HTTP %d)", url, resp.status)
                return []

            content = await resp.text(encoding="utf-8", errors="ignore")
            # 1. Поиск в открытом тексте
            matches = PROXY_URI_REGEX.findall(content)

            # 2. Если прямых ссылок нет, пробуем декодировать весь payload как Base64
            if not matches:
                decoded_text = _safe_base64_decode_lines(content)
                if decoded_text:
                    matches = PROXY_URI_REGEX.findall(decoded_text)

            logger.info("Extracted %d URIs from %s", len(matches), url)
            return matches
    except (aiohttp.ClientError, asyncio.TimeoutError) as err:
        logger.warning("Network error fetching %s: %s", url, err)
        return []
    except Exception as err:
        logger.error("Unexpected error parsing %s: %s", url, err)
        return []


async def scrape_all_sources(sources: Sequence[str], timeout_sec: float) -> list[str]:
    """Асинхронно опрашивает все URL-источники и возвращает дедуплицированный список ссылок."""
    headers = {
        "User-Agent": "v2rayNG/1.8.5 (Linux; Android 13; en-US)",
        "Accept": "*/*",
    }
    connector = aiohttp.TCPConnector(ssl=False, limit=50)

    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        tasks = [
            _fetch_single_source(session, url, timeout_sec)
            for url in sources
        ]
        results = await asyncio.gather(*tasks, return_exceptions=False)

    flat_list: list[str] = [uri for sublist in results for uri in sublist]
    # Сохраняем исходный порядок при дедупликации
    unique_uris: list[str] = list(dict.fromkeys(flat_list))
    logger.info("Total unique URIs collected: %d", len(unique_uris))
    return unique_uris