"""Entrypoint for proxy subscription pipeline."""

from __future__ import annotations

import asyncio
import logging
import sys
from collections import Counter

import aiohttp

from builder import EnrichedNode, build_subscription
from checker import CheckedNode, run_checker
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
    """Определяет признак белого списка для проверенного узла."""
    raw_uri = getattr(node.node, "raw_uri", None)
    if raw_uri is not None and getattr(raw_uri, "is_whitelist", False):
        return True
    return is_uri_whitelisted(str(raw_uri))


async def async_main() -> None:
    config = AppConfig()
    logger.info(
        "Starting pipeline. Targets: max candidates=%d, output servers=%d (WL quota: %d-%d)",
        config.max_candidates,
        config.max_output_servers,
        config.wl_min_servers,
        config.wl_max_servers,
    )

    # Шаг 1: Асинхронный сбор источников с маркировкой WL
    raw_proxies = await scrape_all_sources(
        whitelist_sources=config.whitelist_sources,
        regular_sources=config.general_sources,
        timeout_sec=config.http_timeout,
    )
    if not raw_proxies:
        logger.warning("No URIs were scraped. Exiting.")
        return

    # Шаг 2: Парсинг и валидация
    parsed_nodes = []
    for item in raw_proxies:
        node = parse_proxy_uri(item)
        if node is not None:
            parsed_nodes.append(node)

    logger.info("Successfully parsed %d valid nodes from %d raw links", len(parsed_nodes), len(raw_proxies))
    if not parsed_nodes:
        logger.warning("No valid proxy nodes parsed. Exiting.")
        return

    # Шаг 2.1: Срез кандидатов до MAX_CANDIDATES с сохранением белых списков
    if len(parsed_nodes) > config.max_candidates:
        logger.info("Parsed nodes count (%d) exceeds limit (%d). Slicing candidates...", len(parsed_nodes), config.max_candidates)
        wl_candidates = [n for n in parsed_nodes if getattr(n.raw_uri, "is_whitelist", False)]
        gen_candidates = [n for n in parsed_nodes if not getattr(n.raw_uri, "is_whitelist", False)]
        parsed_nodes = (wl_candidates + gen_candidates)[: config.max_candidates]
        logger.info("Reduced candidates to %d (WL: %d, General: %d)", len(parsed_nodes), len(wl_candidates), len(parsed_nodes) - len(wl_candidates))

    # Шаг 3: TCP-тестирование задержки
    alive_checked = await run_checker(
        nodes=parsed_nodes,
        concurrency_limit=config.max_concurrent_checks,
        timeout_sec=config.tcp_timeout,
    )
    if not alive_checked:
        logger.warning("All nodes failed TCP latency check. Exiting.")
        return

    # Фильтрация по максимальному допустимому порогу задержки
    alive_valid = [node for node in alive_checked if node.latency_ms <= config.max_latency_ms]
    logger.info("Alive nodes with latency <= %.0fms: %d", config.max_latency_ms, len(alive_valid))
    if not alive_valid:
        logger.warning("No nodes passed the latency threshold. Exiting.")
        return

    # Шаг 4: Разделение на корзины alive_whitelist и alive_general
    alive_whitelist = [node for node in alive_valid if check_is_whitelist(node)]
    alive_general = [node for node in alive_valid if not check_is_whitelist(node)]

    # Сортировка каждой корзины по задержке (от быстрых к медленным)
    alive_whitelist.sort(key=lambda x: x.latency_ms)
    alive_general.sort(key=lambda x: x.latency_ms)

    logger.info(
        "Available alive pools: Whitelist=%d, General=%d",
        len(alive_whitelist),
        len(alive_general),
    )

    # Отбор от 10 до 15 быстрейших узлов из белых списков (если меньше 10 — берем все живые)
    wl_target_count = min(len(alive_whitelist), config.wl_max_servers)
    selected_wl = alive_whitelist[:wl_target_count]

    # Добор оставшихся мест быстрейшими обычными узлами до лимита в 50 серверов
    needed_general = max(0, config.max_output_servers - len(selected_wl))
    selected_general = alive_general[:needed_general]

    # Итоговый сбалансированный пул
    selected_pool = selected_wl + selected_general
    logger.info(
        "Final balanced pool selected: %d nodes (Whitelist: %d, General: %d)",
        len(selected_pool),
        len(selected_wl),
        len(selected_general),
    )

    # Шаг 5: Гео-маркировка ТОЛЬКО для отобранных ~50 серверов (экономия API ipinfo.io)
    geo_resolver = GeoResolver(token=config.ipinfo_token)
    enriched_nodes: list[EnrichedNode] = []

    conn = aiohttp.TCPConnector(limit=20)
    async with aiohttp.ClientSession(connector=conn) as session:
        for item in selected_pool:
            is_wl = check_is_whitelist(item)
            tag = await geo_resolver.get_geo_tag(session, item.resolved_ip)
            enriched_nodes.append(
                EnrichedNode(
                    checked_node=item,
                    geo_tag=tag,
                    is_whitelist=is_wl,
                )
            )

    # Статистика распределения
    country_counts = Counter(node.geo_tag for node in enriched_nodes)
    logger.info("Top regions among selected servers:")
    for region, count in country_counts.most_common(10):
        logger.info("  %s: %d", region, count)

    # Шаг 6: Генерация Base64 подписки и сохранение файла
    total_written, out_file = build_subscription(
        nodes=enriched_nodes,
        output_filepath=config.output_file,
        profile_title=config.profile_title,
        profile_update_interval=config.profile_update_interval,
    )

    logger.info(
        "Subscription successfully generated: %s (%d nodes, %d bytes)",
        out_file.resolve(),
        total_written,
        out_file.stat().st_size,
    )


def main() -> None:
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        logger.info("Execution interrupted by user.")
    except Exception as err:
        logger.critical("Fatal pipeline error: %s", err, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
