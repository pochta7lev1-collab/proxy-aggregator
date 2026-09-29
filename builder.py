"""Proxy subscription builder with ISO flag generator and LionVPN profile title."""

from __future__ import annotations

import base64
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from checker import CheckedNode

logger = logging.getLogger(__name__)


def safe_b64decode(payload: str) -> str:
    cleaned = payload.strip().replace("-", "+").replace("_", "/")
    padding = "=" * (-len(cleaned) % 4)
    raw_bytes = base64.b64decode(cleaned + padding)
    return raw_bytes.decode("utf-8", errors="ignore")


@dataclass(slots=True, frozen=True)
class EnrichedNode:
    checked_node: CheckedNode
    geo_tag: str
    is_whitelist: bool = False


def is_node_whitelist(item: EnrichedNode) -> bool:
    if getattr(item, "is_whitelist", False):
        return True
    checked_node = getattr(item, "checked_node", None)
    if checked_node is not None:
        if getattr(checked_node, "is_whitelist", False):
            return True
        node = getattr(checked_node, "node", None)
        if node is not None:
            raw_uri = getattr(node, "raw_uri", None)
            if raw_uri is not None and getattr(raw_uri, "is_whitelist", False):
                return True
    return False


def country_code_to_flag(country_code: str) -> str:
    """Генерирует эмодзи флага по ISO-3166-1 alpha-2."""
    if not country_code or len(country_code) != 2 or not country_code.isalpha() or country_code.upper() == "UNK":
        return "🌐"
    code = country_code.upper()
    return "".join(chr(ord(c) + 127397) for c in code)


def extract_iso_country(raw_geo: str) -> tuple[str, str]:
    """
    Извлекает чистый 2-буквенный ISO-код страны и эмодзи флага.
    Гарантированно устраняет баги дублирования (например, 'RU RU' -> flag='🇷🇺', code='RU').
    """
    if not raw_geo:
        return "🌐", "UNK"

    clean_str = raw_geo.strip().upper()
    if "UNK" in clean_str:
        return "🌐", "UNK"

    # Ищем все двухбуквенные коды
    letters = re.findall(r"[A-Z]{2}", clean_str)
    for code in letters:
        if code != "UN":  # Исключаем артефакты от UNK
            flag = country_code_to_flag(code)
            return flag, code

    return "🌐", "UNK"


def _format_vmess_uri(raw_uri: str, new_name: str) -> str:
    try:
        raw_body = raw_uri[8:].split("#", 1)[0]
        decoded = safe_b64decode(raw_body)
        data = json.loads(decoded)
        if isinstance(data, dict):
            data["ps"] = new_name
            compact_json = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
            encoded = base64.b64encode(compact_json.encode("utf-8")).decode("utf-8")
            return f"vmess://{encoded}"
    except Exception:
        pass
    base = raw_uri.split("#", 1)[0]
    return f"{base}#{new_name}"


def _format_standard_uri(raw_uri: str, new_name: str) -> str:
    base = raw_uri.split("#", 1)[0]
    return f"{base}#{new_name}"


def format_node_uri(node: CheckedNode, new_name: str) -> str:
    raw_uri = str(node.node.raw_uri)
    if node.node.protocol.lower() == "vmess":
        return _format_vmess_uri(raw_uri, new_name)
    return _format_standard_uri(raw_uri, new_name)


def build_subscription(
    nodes: Sequence[EnrichedNode],
    output_filepath: str,
    profile_title: str = "LionVPN",
    profile_update_interval: int = 4,
) -> tuple[int, Path]:
    """Генерирует финальную Base64-подписку без пинга в именах и без дублирования страны."""
    category_counters: dict[str, int] = {}
    formatted_uris: list[str] = []

    for item in nodes:
        is_wl = is_node_whitelist(item)
        flag, country_code = extract_iso_country(item.geo_tag)

        # Формирование префикса строго по ТЗ
        if is_wl:
            base_prefix = f"🏳️ [WL] {flag} {country_code}"
        else:
            base_prefix = f"{flag} {country_code}" if country_code != "UNK" else "🌐 UNK"

        count = category_counters.get(base_prefix, 0) + 1
        category_counters[base_prefix] = count

        # Формат: '🏳️ [WL] 🇷🇺 RU #01' или '🇩🇪 DE #01'
        node_name = f"{base_prefix} #{count:02d}"
        formatted_uris.append(format_node_uri(item.checked_node, node_name))

    # Служебные заголовки автоматического профиля
    profile_headers = [
        f"# profile-title: {profile_title}",
        f"# profile-update-interval: {profile_update_interval}",
    ]

    # Сборка и Base64-кодирование
    combined_payload = "\n".join(profile_headers + formatted_uris)
    encoded_bytes = base64.b64encode(combined_payload.encode("utf-8"))

    out_path = Path(output_filepath)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(encoded_bytes)

    logger.info(
        "Successfully compiled %d nodes (Profile: %s) into '%s'",
        len(formatted_uris),
        profile_title,
        out_path,
    )
    return len(formatted_uris), out_path
