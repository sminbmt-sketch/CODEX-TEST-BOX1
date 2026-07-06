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


async def sync_endpoint_inventory(db: Session, first: int = 100) -> tuple[int, int]:
    client = TaniumGatewayClient()
    data = await client.get_endpoint_inventory(first=first)
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
        endpoint.ip_address = node.get("ipAddress")
        endpoint.mac_address = _first_value(node.get("macAddress"), node.get("macAddresses"), node.get("mac"), node.get("networkAdapters"))
        endpoint.os_name = os_info.get("name") or os_info.get("generation") or os_info.get("platform")
        endpoint.os_version = os_info.get("generation")
        endpoint.platform = os_info.get("platform") or node.get("platform")
        endpoint.software = node.get("installedApplications") or []
        endpoint.last_seen_at = _parse_time(node.get("eidLastSeen"))
        endpoint.raw = node
        changed += 1

    db.commit()
    return len(nodes), changed
