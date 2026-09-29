"""Entrypoint for proxy subscription pipeline."""

from __future__ import annotations

import asyncio
import logging
import sys
from collections import Counter

import aiohttp

from builder import EnrichedNode, build_subscription
from checker import run_checker
from config import AppConfig
from geo import GeoResolver
from parser import parse_proxy_uri
from scraper import scrape_all_sources

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("main")


async def async_main() -> None:
    config = AppConfig()
    logger.info("Pipeline started with max latency threshold: %.1fms", config.max_latency_ms)

    # Шаг 1: Сбор raw-ссылок из источников
    raw_uris = await scrape_all_sources(config.sources, config.http_timeout)
    if not raw_uris:
        logger.warning("No URIs were scraped. Exiting.")
        return

    # Шаг 2: Безопасный парсинг и валидация URI
    parsed_nodes = []
    for uri in raw_uris:
        node = parse_proxy_uri(uri)
        if node is not None:
            parsed_nodes.append(node)

    logger.info("Valid parsed nodes: %d / %d", len(parsed_nodes), len(raw_uris))
    if not parsed_nodes:
        logger.warning("No valid proxy nodes parsed. Exiting.")
        return

    # Шаг 3: TCP-проверка задержки через пул сокетов
    alive_checked_nodes = await run_checker(
        nodes=parsed_nodes,
        concurrency_limit=config.max_concurrent_checks,
        timeout_sec=config.tcp_timeout,
    )
    if not alive_checked_nodes:
        logger.warning("All nodes failed TCP latency check. Exiting.")
        return

    # Шаг 4: Гео-маркировка только живых узлов (экономия лимитов API)
    geo_resolver = GeoResolver(token=config.ipinfo_token)
    enriched_nodes: list[EnrichedNode] = []

    conn = aiohttp.TCPConnector(limit=50)
    async with aiohttp.ClientSession(connector=conn) as session:
        for item in alive_checked_nodes:
            tag = await geo_resolver.get_geo_tag(session, item.resolved_ip)
            enriched_nodes.append(EnrichedNode(checked_node=item, geo_tag=tag))

    # Статистика по странам
    country_counts = Counter(node.geo_tag for node in enriched_nodes)
    logger.info("Node distribution by region:")
    for region, count in country_counts.most_common(10):
        logger.info("  %s: %d", region, count)

    # Шаг 5: Форматирование, сортировка и генерация Base64-подписки
    total_written, out_file = build_subscription(
        nodes=enriched_nodes,
        max_latency_ms=config.max_latency_ms,
        output_filepath=config.output_file,
    )

    logger.info(
        "Finished pipeline successfully. Output file: %s (%d bytes, %d nodes)",
        out_file.resolve(),
        out_file.stat().st_size,
        total_written,
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