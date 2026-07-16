from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import EndpointSnapshot
from app.services.tanium_client import TaniumGatewayClient


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _endpoint_nodes(data: dict[str, Any]) -> list[dict[str, Any]]:
    edges = data.get("data", {}).get("endpoints", {}).get("edges", [])
    return [edge.get("node", {}) for edge in edges if edge.get("node")]


def _endpoint_map(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(node.get("id")): node for node in _endpoint_nodes(data) if node.get("id") is not None}


def _first_value(*values: Any) -> str | None:
    for value in values:
        if value is None:
            continue
        if isinstance(value, dict):
            nested = _first_value(*value.values())
            if nested:
                return nested
            continue
        if isinstance(value, list):
            nested = _first_value(*value)
            if nested:
                return nested
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _is_tanium_empty_or_error(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return not text or text in {"[no results]", "no results"} or text.startswith(("tse-error:", "sensor evaluation timed out"))


def _clean_value(value: Any) -> str | None:
    return None if _is_tanium_empty_or_error(value) else str(value).strip()


def _clean_records(records: Any, required_key: str = "name") -> list[dict[str, Any]]:
    if not isinstance(records, list):
        return []
    cleaned: list[dict[str, Any]] = []
    for item in records:
        if not isinstance(item, dict):
            continue
        if _is_tanium_empty_or_error(item.get(required_key)):
            continue
        cleaned.append(item)
    return cleaned


def _sensor_columns(node: dict[str, Any]) -> list[dict[str, Any]]:
    return node.get("sensorReadings", {}).get("columns", []) or []


def _process_rows(node: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for column in _sensor_columns(node):
        values = [value for value in column.get("values") or [] if not _is_tanium_empty_or_error(value)]
        if not values:
            continue
        rows.append(
            {
                "sensor": (column.get("sensor") or {}).get("name"),
                "column": column.get("name"),
                "values": values[:250],
            }
        )
    return rows


async def sync_endpoint_inventory(db: Session, first: int = 100) -> tuple[int, int]:
    client = TaniumGatewayClient()
    data = await client.get_endpoint_inventory(first=first)
    try:
        process_nodes = _endpoint_map(await client.get_endpoint_process_readings(first=first))
    except Exception:
        process_nodes = {}
    nodes = _endpoint_nodes(data)
    changed = 0

    for node in nodes:
        tanium_id = str(node.get("id") or "")
        hostname = node.get("name")
        if not tanium_id and not hostname:
            continue

        endpoint = db.scalar(
            select(EndpointSnapshot).where(
                EndpointSnapshot.tanium_endpoint_id == tanium_id,
                EndpointSnapshot.hostname == hostname,
            )
        )
        if endpoint is None:
            endpoint = EndpointSnapshot(tanium_endpoint_id=tanium_id, hostname=hostname)
            db.add(endpoint)

        os_info = node.get("os") or {}
        endpoint.ip_address = _clean_value(node.get("ipAddress"))
        endpoint.mac_address = _first_value(node.get("macAddress"), node.get("macAddresses"), node.get("mac"), node.get("networkAdapters"))
        endpoint.os_name = _clean_value(os_info.get("name")) or _clean_value(os_info.get("generation")) or _clean_value(os_info.get("platform"))
        endpoint.os_version = _clean_value(os_info.get("generation"))
        endpoint.platform = _clean_value(os_info.get("platform")) or _clean_value(node.get("platform"))
        endpoint.software = _clean_records(node.get("installedApplications"), required_key="name")
        endpoint.services = _clean_records(node.get("services"), required_key="name")
        endpoint.processes = _process_rows(process_nodes.get(tanium_id, {}))
        endpoint.sbom = []
        endpoint.last_seen_at = _parse_time(node.get("eidLastSeen"))
        endpoint.raw = node
        changed += 1

    db.commit()
    return len(nodes), changed
