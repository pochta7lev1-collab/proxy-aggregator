"""Entrypoint for proxy subscription pipeline with protocol balancing."""

from __future__ import annotations

import asyncio
import logging
import sys
import urllib.parse
from collections import Counter, defaultdict

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


def classify_protocol(node: CheckedNode) -> str:
    """Классифицирует узел по протоколу для обеспечения балансировки."""
    proto = node.node.protocol.lower()
    if proto in ("ss", "shadowsocks"):
        return "ss"
    if proto == "trojan":
        return "trojan"
    if proto == "vmess":
        return "vmess"
    if proto == "vless":
        try:
            p = urllib.parse.urlsplit(str(node.node.raw_uri))
            qs = urllib.parse.parse_qs(p.query)
            sec = qs.get("security", [""])[0].lower()
            net = qs.get("type", [""])[0].lower()
            if sec == "reality":
                return "vless-reality"
            if net == "ws":
                return "vless-ws"
            return "vless-tls" if sec == "tls" else "vless-other"
        except Exception:
            return "vless-other"
    return "other"


def select_balanced_general(buckets: dict[str, list[CheckedNode]], target_count: int) -> list[CheckedNode]:
    """Сбалансированно отбирает узлы методом round-robin по протоколам."""
    for cat in buckets:
        buckets[cat].sort(key=lambda x: x.latency_ms)

    selected: list[CheckedNode] = []
    queues = {cat: list(nodes) for cat, nodes in buckets.items()}

    while len(selected) < target_count:
        added_in_pass = False
        for cat in list(queues.keys()):
            if queues[cat]:
                selected.append(queues[cat].pop(0))
                added_in_pass = True
                if len(selected) >= target_count:
                    break
        if not added_in_pass:
            break

    return selected


async def async_main() -> None:
    config = AppConfig()
    logger.info(
        "Starting LionVPN pipeline. Target: %d servers (WL quota: %d-%d)",
        config.max_output_servers,
        config.wl_min_servers,
        config.wl_max_servers,
    )

    # 1. Асинхронный сбор данных
    raw_proxies = await scrape_all_sources(
        whitelist_sources=config.whitelist_sources,
        general_sources=config.general_sources,
        timeout_sec=config.http_timeout,
    )
    if not raw_proxies:
        logger.warning("No URIs were scraped. Exiting.")
        return

    # 2. Безопасный парсинг URI
    parsed_nodes = []
    for item in raw_proxies:
        node = parse_proxy_uri(item)
        if node is not None:
            parsed_nodes.append(node)

    logger.info("Parsed %d valid nodes from %d scraped URIs", len(parsed_nodes), len(raw_proxies))
    if not parsed_nodes:
        logger.warning("No valid proxy nodes parsed. Exiting.")
        return

    # 2.1. Ограничение кандидатов до MAX_CANDIDATES (приоритет белым спискам)
    if len(parsed_nodes) > config.max_candidates:
        wl_cand = [n for n in parsed_nodes if getattr(n.raw_uri, "is_whitelist", False)]
        gen_cand = [n for n in parsed_nodes if not getattr(n.raw_uri, "is_whitelist", False)]
        parsed_nodes = (wl_cand + gen_cand)[: config.max_candidates]
        logger.info(
            "Limited candidates to %d (WL: %d, General: %d)",
            len(parsed_nodes),
            len(wl_cand),
            len(parsed_nodes) - len(wl_cand),
        )

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

    # 4. Разделение живых узлов на WhiteList и General
    alive_wl = [n for n in alive_valid if check_is_whitelist(n)]
    alive_gen = [n for n in alive_valid if not check_is_whitelist(n)]
    alive_wl.sort(key=lambda x: x.latency_ms)
    alive_gen.sort(key=lambda x: x.latency_ms)

    logger.info("TCP Alive pools: Whitelist=%d, General=%d", len(alive_wl), len(alive_gen))

    # 5. Классификация общего пула по протоколам
    gen_by_protocol: dict[str, list[CheckedNode]] = defaultdict(list)
    for n in alive_gen:
        category = classify_protocol(n)
        gen_by_protocol[category].append(n)

    for cat, items in gen_by_protocol.items():
        logger.info("  Protocol [%s]: %d alive nodes", cat, len(items))

    # 6. Отбор кандидатов для глубокой валидации через Xray-core
    # Отбираем сбалансированную выборку (до 40 узлов на каждый протокол)
    verify_wl_pool = alive_wl[:40]
    verify_gen_pool: list[CheckedNode] = []
    for cat in ("ss", "trojan", "vless-ws", "vless-reality", "vless-tls", "vmess"):
        verify_gen_pool.extend(gen_by_protocol[cat][:40])

    verified_wl = await verify_candidates_real(
        verify_wl_pool,
        concurrency=15,
        timeout_sec=config.real_check_timeout,
    )
    verified_gen = await verify_candidates_real(
        verify_gen_pool,
        concurrency=15,
        timeout_sec=config.real_check_timeout,
    )

    verified_wl.sort(key=lambda x: x.latency_ms)

    # 7. Балансировка итоговой подписки (ровно 80 узлов)
    # Отбираем 10-15 живых узлов из белых списков
    wl_take_count = min(len(verified_wl), config.wl_max_servers)
    selected_wl = verified_wl[:wl_take_count]

    # Группируем проверенные общие узлы по категориям
    verified_gen_buckets: dict[str, list[CheckedNode]] = defaultdict(list)
    for n in verified_gen:
        cat = classify_protocol(n)
        verified_gen_buckets[cat].append(n)

    # Заполняем оставшиеся 65-70 мест сбалансированно по протоколам
    needed_general = max(0, config.max_output_servers - len(selected_wl))
    selected_gen = select_balanced_general(verified_gen_buckets, needed_general)

    final_pool = selected_wl + selected_gen
    logger.info(
        "Final selected pool: %d servers (WL: %d, General: %d)",
        len(final_pool),
        len(selected_wl),
        len(selected_gen),
    )

    # Статистика распределения по протоколам
    protocol_stats = Counter(classify_protocol(n) for n in final_pool)
    logger.info("Final protocol balance: %s", dict(protocol_stats))

    # 8. Гео-маркировка ТОЛЬКО для отобранных серверов (экономия API ipinfo.io)
    geo_resolver = GeoResolver(token=config.ipinfo_token)
    enriched_nodes: list[EnrichedNode] = []

    conn = aiohttp.TCPConnector(limit=20)
    async with aiohttp.ClientSession(connector=conn) as session:
        for item in final_pool:
            is_wl = check_is_whitelist(item)
            tag = await geo_resolver.get_geo_tag(session, item.resolved_ip)
            enriched_nodes.append(
                EnrichedNode(
                    checked_node=item,
                    geo_tag=tag,
                    is_whitelist=is_wl,
                )
            )

    country_counts = Counter(node.geo_tag for node in enriched_nodes)
    logger.info("Top regions: %s", dict(country_counts.most_common(5)))

    # 9. Сборка и Base64-кодирование подписки
    total_written, out_file = build_subscription(
        nodes=enriched_nodes,
        output_filepath=config.output_file,
        profile_title=config.profile_title,
        profile_update_interval=config.profile_update_interval,
    )

    logger.info(
        "Subscription created: %s (%d nodes, %d bytes)",
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
        logger.critical("Fatal error: %s", err, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
