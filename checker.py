"""High-performance asynchronous TCP latency checker."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Optional, Sequence

from parser import ProxyNode

logger = logging.getLogger(__name__)


@dataclass(slots=True, frozen=True)
class CheckedNode:
    node: ProxyNode
    latency_ms: float
    resolved_ip: str


async def check_tcp_latency(
    node: ProxyNode,
    semaphore: asyncio.Semaphore,
    timeout_sec: float,
) -> Optional[CheckedNode]:
    """Выполняет TCP-рукопожатие и замеряет round-trip latency в миллисекундах."""
    async with semaphore:
        start_time = time.perf_counter()
        try:
            connect_coro = asyncio.open_connection(
                host=node.host,
                port=node.port,
            )
            reader, writer = await asyncio.wait_for(connect_coro, timeout=timeout_sec)
            latency_ms = (time.perf_counter() - start_time) * 1000.0

            # Получаем фактический IP-адрес из установленного сокета
            peer = writer.get_extra_info("peername")
            resolved_ip = peer[0] if (peer and len(peer) > 0) else node.host

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            return CheckedNode(
                node=node,
                latency_ms=latency_ms,
                resolved_ip=str(resolved_ip),
            )
        except (
            asyncio.TimeoutError,
            TimeoutError,
            ConnectionRefusedError,
            ConnectionResetError,
            OSError,
            Exception,
        ):
            return None


async def run_checker(
    nodes: Sequence[ProxyNode],
    concurrency_limit: int,
    timeout_sec: float,
) -> list[CheckedNode]:
    """Запускает параллельное TCP-тестирование для списка узлов."""
    logger.info("Initiating TCP check for %d nodes with concurrency %d...", len(nodes), concurrency_limit)
    semaphore = asyncio.Semaphore(concurrency_limit)

    tasks = [
        check_tcp_latency(node, semaphore, timeout_sec)
        for node in nodes
    ]

    results = await asyncio.gather(*tasks, return_exceptions=False)
    alive_nodes = [res for res in results if res is not None]
    logger.info("TCP check complete. Alive: %d / %d", len(alive_nodes), len(nodes))
    return alive_nodes