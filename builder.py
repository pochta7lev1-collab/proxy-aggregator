"""Proxy subscription builder and formatter."""

from __future__ import annotations

import base64
import json
import logging
import urllib.parse
from collections import defaultdict
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


def _format_vmess_uri(raw_uri: str, new_name: str) -> str:
    """Обновляет имя узла VMess в поле 'ps' внутри Base64 JSON."""
    try:
        raw_body = raw_uri[8:].split("#", 1)[0]
        decoded = safe_b64decode(raw_body)
        data = json.loads(decoded)
        if isinstance(data, dict):
            data["ps"] = new_name
            compact_json = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
            encoded = base64.b64encode(compact_json.encode("utf-8")).decode("utf-8")
            return f"vmess://{encoded}"
    except Exception as err:
        logger.debug("Failed to update VMess JSON ps field: %s", err)

    # Резервный вариант через обновление фрагмента URI
    parsed = urllib.parse.urlsplit(raw_uri)
    return urllib.parse.urlunsplit(parsed._replace(fragment=new_name))


def _format_standard_uri(raw_uri: str, new_name: str) -> str:
    """Обновляет фрагмент URI через urllib.parse (VLESS, Trojan, Shadowsocks)."""
    try:
        parsed = urllib.parse.urlsplit(raw_uri)
        return urllib.parse.urlunsplit(parsed._replace(fragment=new_name))
    except Exception:
        base = raw_uri.split("#", 1)[0]
        return f"{base}#{new_name}"


def format_node_uri(node: CheckedNode, new_name: str) -> str:
    """Направляет URI на соответствующий форматировщик в зависимости от протокола."""
    if node.node.protocol == "vmess":
        return _format_vmess_uri(node.node.raw_uri, new_name)
    return _format_standard_uri(node.node.raw_uri, new_name)


def build_subscription(
    nodes: Sequence[EnrichedNode],
    max_latency_ms: float,
    output_filepath: str,
    subscription_title: str = "LionVPN",
    update_interval_hours: int = 4,
) -> tuple[int, Path]:
    """
    Фильтрует узлы по задержке, сортирует по возрастанию пинга, присваивает
    порядковые номера внутри каждой страны, добавляет служебные заголовки
    и компилирует подписку в единый Base64-файл.
    """
    # 1. Фильтрация по допустимой задержке
    valid_nodes = [
        item for item in nodes
        if item.checked_node.latency_ms <= max_latency_ms
    ]

    # 2. Сортировка по возрастанию задержки (быстрые серверы идут первыми)
    sorted_nodes = sorted(valid_nodes, key=lambda x: x.checked_node.latency_ms)

    # 3. Переименование серверов в формат: {Флаг} {Код} #{Порядковый номер по стране}
    # Например: 🇩🇪 DE #01, 🇩🇪 DE #02, 🇳🇱 NL #01
    country_counters: dict[str, int] = defaultdict(int)
    formatted_uris: list[str] = []

    for item in sorted_nodes:
        tag = item.geo_tag.strip() or "🌐 UNK"
        country_counters[tag] += 1
        index = country_counters[tag]
        clean_node_name = f"{tag} #{index:02d}"

        formatted_uris.append(format_node_uri(item.checked_node, clean_node_name))

    # 4. Формирование служебных заголовков для авто-именования профиля клиентами
    # (поддерживается Happ, NekoBox, v2rayNG, Sing-box и др.)
    header_lines = [
        f"# profile-title: {subscription_title}",
        f"# profile-update-interval: {update_interval_hours}",
    ]

    # 5. Сборка полного содержимого и кодирование в Base64
    full_payload = "\n".join(header_lines + formatted_uris)
    encoded_bytes = base64.b64encode(full_payload.encode("utf-8"))

    # 6. Запись в файл
    out_path = Path(output_filepath)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(encoded_bytes)

    logger.info(
        "Successfully compiled %d nodes (title: '%s', interval: %dh) into '%s'",
        len(formatted_uris),
        subscription_title,
        update_interval_hours,
        out_path,
    )
    return len(formatted_uris), out_path
