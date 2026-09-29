"""Proxy subscription builder and formatter."""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from checker import CheckedNode
from parser import safe_b64decode

logger = logging.getLogger(__name__)


@dataclass(slots=True, frozen=True)
class EnrichedNode:
    checked_node: CheckedNode
    geo_tag: str


def _format_vmess_uri(node: CheckedNode, new_name: str) -> str:
    try:
        raw_body = node.node.raw_uri[8:].split("#", 1)[0]
        decoded = safe_b64decode(raw_body)
        data = json.loads(decoded)
        data["ps"] = new_name
        compact_json = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        encoded = base64.b64encode(compact_json.encode("utf-8")).decode("utf-8")
        return f"vmess://{encoded}"
    except Exception:
        base = node.node.raw_uri.split("#", 1)[0]
        return f"{base}#{new_name}"


def _format_standard_uri(node: CheckedNode, new_name: str) -> str:
    base = node.node.raw_uri.split("#", 1)[0]
    return f"{base}#{new_name}"


def format_node_uri(node: CheckedNode, geo_tag: str) -> str:
    """Обновляет имя узла на формат '#🇩🇪 DE | 48ms'."""
    new_name = f"{geo_tag} | {int(node.latency_ms)}ms"
    if node.node.protocol == "vmess":
        return _format_vmess_uri(node, new_name)
    return _format_standard_uri(node, new_name)


def build_subscription(
    nodes: Sequence[EnrichedNode],
    max_latency_ms: float,
    output_filepath: str,
) -> tuple[int, Path]:
    """Фильтрует, сортирует по пингу, пакует в Base64 и сохраняет на диск."""
    # 1. Фильтрация по допустимой задержке
    valid_nodes = [
        item for item in nodes
        if item.checked_node.latency_ms <= max_latency_ms
    ]

    # 2. Сортировка по возрастанию задержки
    sorted_nodes = sorted(valid_nodes, key=lambda x: x.checked_node.latency_ms)

    # 3. Переименование URI
    formatted_uris: list[str] = [
        format_node_uri(item.checked_node, item.geo_tag)
        for item in sorted_nodes
    ]

    # 4. Сборка в Base64-подписку
    combined_payload = "\n".join(formatted_uris)
    encoded_bytes = base64.b64encode(combined_payload.encode("utf-8"))

    # 5. Запись на диск
    out_path = Path(output_filepath)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(encoded_bytes)

    logger.info("Successfully compiled %d nodes into '%s'", len(formatted_uris), out_path)
    return len(formatted_uris), out_path