"""Entrypoint for proxy subscription pipeline."""

from __future__ import annotations

import asyncio
import logging
import sys
from collections import Counter

import aiohttp

from builder import EnrichedNode, build_subscription
from checker import CheckedNode, run_checker, verify_candidates_real
from config import AppConfig
from geo import GeoResolver
from parser import parse_proxy_uri
from scraper import is_uri_whitelisted, scrape_all_sources

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("main")


def check_is_whitelist(node: CheckedNode) -> bool:
    raw_uri = getattr(node.node, "raw_uri", None)
    if raw_uri is not None and getattr(raw_uri, "is_whitelist", False):
        return True
    return is_uri_whitelisted(str(raw_uri))


async def async_main() -> None:
    config = AppConfig()
    logger.info(
        "Starting LionVPN pipeline. Target: %d servers (WL quota: %d-%d)",
        config.max_output_servers,
        config.wl_min_servers,
        config.wl_max_servers,
    )

    # 1. Асинхронный сбор данных с авто-детектом base64
    raw_proxies = await scrape_all_sources(
        whitelist_sources=config.whitelist_sources,
        general_sources=config.general_sources,
        timeout_sec=config.http_timeout,
    )
    if not raw_proxies:
        logger.warning("No URIs were scraped. Exiting.")
        return

    # 2. Безопасный парсинг схем URI
    parsed_nodes = []
    for item in raw_proxies:
        node = parse_proxy_uri(item)
        if node is not None:
            parsed_nodes.append(node)

    logger.info("Successfully parsed %d valid nodes from %d links", len(parsed_nodes), len(raw_proxies))
    if not parsed_nodes:
        logger.warning("No valid proxy nodes parsed. Exiting.")
        return

    # Ограничение входящих кандидатов до MAX_CANDIDATES с сохранением белых списков
    if len(parsed_nodes) > config.max_candidates:
        wl_candidates = [n for n in parsed_nodes if getattr(n.raw_uri, "is_whitelist", False)]
        gen_candidates = [n for n in parsed_nodes if not getattr(n.raw_uri, "is_whitelist", False)]
        parsed_nodes = (wl_candidates + gen_candidates)[: config.max_candidates]
        logger.info("Limited candidates to %d (WL: %d, General: %d)", len(parsed_nodes), len(wl_candidates), len(parsed_nodes) - len(wl_candidates))

    # 3. Быстрый предварительный TCP-скрининг
    alive_checked = await run_checker(
        nodes=parsed_nodes,
        concurrency_limit=config.max_concurrent_checks,
        timeout_sec=config.tcp_timeout,
    )
    if not alive_checked:
        logger.warning("All nodes failed TCP latency check. Exiting.")
        return

    alive_valid = [n for n in alive_checked if n.latency_ms <= config.max_latency_ms]
    if not alive_valid:
        logger.warning("No nodes passed latency threshold. Exiting.")
        return

    # 4. Разделение пулов и подготовка к глубокой проверке Reality
    alive_wl = [n for n in alive_valid if check_is_whitelist(n)]
    alive_gen = [n for n in alive_valid if not check_is_whitelist(n)]
    alive_wl.sort(key=lambda x: x.latency_ms)
    alive_gen.sort(key=lambda x: x.latency_ms)

    # 5. Реальная валидация туннелей через Xray-core (отсеивает мертвый Reality)
    verified_wl = await verify_candidates_real(alive_wl[:50], concurrency=15, timeout_sec=config.real_check_timeout)
    verified_gen = await verify_candidates_real(alive_gen[:80], concurrency=15, timeout_sec=config.real_check_timeout)

    verified_wl.sort(key=lambda x: x.latency_ms)
    verified_gen.sort(key=lambda x: x.latency_ms)

    # 6. Балансировка: берем 15-20 серверов из белых списков, остальное дополняем общими
    wl_take_count = min(len(verified_wl), config.wl_max_servers)
    selected_wl = verified_wl[:wl_take_count]

    needed_general = max(0, config.max_output_servers - len(selected_wl))
    selected_gen = verified_gen[:needed_general]

    final_pool = selected_wl + selected_gen
    logger.info("Final pool: %d servers (WL: %d, General: %d)", len(final_pool), len(selected_wl), len(selected_gen))

    # 7. Запрос геолокации ТОЛЬКО для отобранных ~50 серверов (экономия ipinfo.io)
    geo_resolver = GeoResolver(token=config.ipinfo_token)
    enriched_nodes: list[EnrichedNode] = []

    conn = aiohttp.TCPConnector(limit=20)
    async with aiohttp.ClientSession(connector=conn) as session:
        for item in final_pool:
            is_wl = check_is_whitelist(item)
            tag = await geo_resolver.get_geo_tag(session, item.resolved_ip)
            enriched_nodes.append(EnrichedNode(checked_node=item, geo_tag=tag, is_whitelist=is_wl))

    country_counts = Counter(node.geo_tag for node in enriched_nodes)
    logger.info("Top regions: %s", dict(country_counts.most_common(5)))

    # 8. Сборка финальной подписки
    total_written, out_file = build_subscription(
        nodes=enriched_nodes,
        output_filepath=config.output_file,
        profile_title=config.profile_title,
        profile_update_interval=config.profile_update_interval,
    )

    logger.info("Subscription created: %s (%d nodes, %d bytes)", out_file.resolve(), total_written, out_file.stat().st_size)


def main() -> None:
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        logger.info("Execution interrupted by user.")
    except Exception as err:
        logger.critical("Fatal error: %s", err, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
