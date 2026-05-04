from __future__ import annotations

from typing import Any, Dict, List, Tuple

from ..graph_client import GraphClient


def try_list_all(client: GraphClient, endpoint: str, params: Dict[str, Any] | None = None) -> tuple[list[dict[str, Any]], str | None]:
    try:
        return client.list_all(endpoint, params=params), None
    except Exception as exc:  # noqa: BLE001
        return [], str(exc)


def try_get(client: GraphClient, endpoint: str, params: Dict[str, Any] | None = None) -> tuple[dict[str, Any], str | None]:
    try:
        return client.get(endpoint, params=params), None
    except Exception as exc:  # noqa: BLE001
        return {}, str(exc)


def lower_blob(value: Any) -> str:
    return str(value or "").lower()


def object_contains_any(obj: Any, keywords: list[str]) -> bool:
    blob = lower_blob(obj)
    return any(k.lower() in blob for k in keywords)


def compact_items(items: list[dict[str, Any]], fields: list[str], limit: int = 25) -> list[dict[str, Any]]:
    output = []
    for item in items[:limit]:
        output.append({field: item.get(field) for field in fields})
    return output
