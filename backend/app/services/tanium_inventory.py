from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import EndpointSnapshot
from app.services.tanium_client import TaniumGatewayClient


SENSOR_CANDIDATES = {
    "processes": ("Running Processes",),
    "mac_address": ("MAC Address", "Mac Address"),
    "windows_build_number": ("Windows-Operating System Build Number", "Operating System Build Number"),
    "chassis_type": ("Chassis Type",),
    "is_virtual": ("Is Virtual",),
    "open_ports": ("Open Port", "Open Ports", "Listening Ports"),
}

HARDWARE_SENSOR_LABELS = {
    "windows_build_number": "OS Build Number",
    "chassis_type": "Chassis Type",
    "is_virtual": "Is Virtual",
    "mac_address": "MAC Address",
}


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
    return (
        not text
        or text in {"[no results]", "no results", "n/a", "not applicable"}
        or text.startswith(("n/a on ", "tse-error:", "sensor evaluation timed out"))
    )


def _clean_value(value: Any) -> str | None:
    return None if _is_tanium_empty_or_error(value) else str(value).strip()


def _unique_values(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = str(value).strip()
        key = text.lower()
        if not text or key in seen:
            continue
        seen.add(key)
        result.append(text)
    return result


def _hostname_keys(hostname: str | None) -> list[str]:
    text = str(hostname or "").strip().lower()
    if not text:
        return []
    short = text.split(".", 1)[0]
    return _unique_values([text, short])


def _expects_kernel_version(os_name: str | None, platform: str | None) -> bool:
    text = f"{os_name or ''} {platform or ''}".lower()
    return any(
        term in text
        for term in (
            "linux",
            "ubuntu",
            "debian",
            "centos",
            "red hat",
            "rhel",
            "rocky",
            "forescout",
            "mac",
            "aix",
            "sunos",
            "solaris",
        )
    )


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


def _sensor_values(node: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for row in _process_rows(node):
        values.extend(str(value) for value in row.get("values") or [] if not _is_tanium_empty_or_error(value))
    return _unique_values(values)


def _rest_cell_values(cell: Any) -> list[str]:
    values: list[str] = []
    if isinstance(cell, list):
        for item in cell:
            if isinstance(item, dict):
                value = _clean_value(item.get("text") or item.get("value"))
            else:
                value = _clean_value(item)
            if value:
                values.append(value)
    else:
        value = _clean_value(cell)
        if value:
            values.append(value)
    return _unique_values(values)


def _rest_result_values_by_hostname(data: dict[str, Any], value_column_name: str) -> dict[str, list[str]]:
    results: dict[str, list[str]] = {}
    result_sets = data.get("data", {}).get("result_sets", []) if isinstance(data.get("data"), dict) else []
    for result_set in result_sets:
        columns = [str(column.get("name") or "") for column in result_set.get("columns") or [] if isinstance(column, dict)]
        try:
            hostname_index = columns.index("Computer Name")
            value_index = columns.index(value_column_name)
        except ValueError:
            continue
        for row in result_set.get("rows") or []:
            cells = row.get("data") if isinstance(row, dict) else None
            if not isinstance(cells, list) or len(cells) <= max(hostname_index, value_index):
                continue
            hostnames = _rest_cell_values(cells[hostname_index])
            values = _rest_cell_values(cells[value_index])
            if not hostnames or not values:
                continue
            for key in _hostname_keys(hostnames[0]):
                results[key] = _unique_values([*(results.get(key) or []), *values])
    return results


async def _read_rest_kernel_versions(client: TaniumGatewayClient) -> dict[str, list[str]]:
    try:
        data = await client.ask_rest_question("Get Computer Name and Kernel Version from all machines")
    except Exception:
        return {}
    return _rest_result_values_by_hostname(data, "Kernel Version")


async def _read_sensor_map(
    client: TaniumGatewayClient,
    first: int,
    sensor_names: tuple[str, ...],
) -> tuple[str, dict[str, dict[str, Any]]]:
    last_sensor_name = sensor_names[0]
    for sensor_name in sensor_names:
        last_sensor_name = sensor_name
        try:
            data = await client.get_endpoint_sensor_readings(first=first, sensor_name=sensor_name)
        except Exception:
            continue
        nodes = _endpoint_map(data)
        if any(_sensor_values(node) for node in nodes.values()):
            return sensor_name, nodes
    return last_sensor_name, {}


def _hardware_items(
    tanium_id: str,
    hostname: str | None,
    os_name: str | None,
    platform: str | None,
    sensor_sources: dict[str, tuple[str, dict[str, dict[str, Any]]]],
    kernel_versions: dict[str, list[str]],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for key, label in HARDWARE_SENSOR_LABELS.items():
        sensor_name, nodes = sensor_sources.get(key, (key, {}))
        values = _sensor_values(nodes.get(tanium_id, {}))
        if not values:
            continue
        items.append({"key": key, "label": label, "sensor": sensor_name, "values": values[:50]})
    existing_keys = {str(item.get("key")) for item in items}
    kernel_values: list[str] = []
    for key in _hostname_keys(hostname):
        kernel_values.extend(kernel_versions.get(key) or [])
    kernel_values = _unique_values(kernel_values)
    if kernel_values and "kernel_version" not in existing_keys:
        items.append(
            {
                "key": "kernel_version",
                "label": "Kernel Version",
                "sensor": "REST Question: Kernel Version",
                "values": kernel_values[:50],
            }
        )
    elif "kernel_version" not in existing_keys and _expects_kernel_version(os_name, platform):
        items.append(
            {
                "key": "kernel_version",
                "label": "Kernel Version",
                "sensor": "REST Question: Kernel Version",
                "status": "missing",
                "value": "No result from Tanium REST question",
                "values": [],
            }
        )
    return items


async def sync_endpoint_inventory(db: Session, first: int = 100) -> tuple[int, int]:
    client = TaniumGatewayClient()
    data = await client.get_endpoint_inventory(first=first)
    sensor_sources: dict[str, tuple[str, dict[str, dict[str, Any]]]] = {}
    for key, sensor_names in SENSOR_CANDIDATES.items():
        sensor_sources[key] = await _read_sensor_map(client, first, sensor_names)
    kernel_versions = await _read_rest_kernel_versions(client)
    nodes = _endpoint_nodes(data)
    changed = 0
    updated_keys: set[tuple[str, str]] = set()

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
        mac_values = _sensor_values(sensor_sources.get("mac_address", ("MAC Address", {}))[1].get(tanium_id, {}))
        endpoint.ip_address = _clean_value(node.get("ipAddress"))
        endpoint.mac_address = _first_value(mac_values, node.get("macAddress"), node.get("macAddresses"), node.get("mac"), node.get("networkAdapters"))
        endpoint.os_name = _clean_value(os_info.get("name")) or _clean_value(os_info.get("generation")) or _clean_value(os_info.get("platform"))
        endpoint.os_version = _clean_value(os_info.get("generation"))
        endpoint.platform = _clean_value(os_info.get("platform")) or _clean_value(node.get("platform"))
        endpoint.software = _clean_records(node.get("installedApplications"), required_key="name")
        endpoint.services = _clean_records(node.get("services"), required_key="name")
        endpoint.processes = _process_rows(sensor_sources.get("processes", ("Running Processes", {}))[1].get(tanium_id, {}))
        endpoint.hardware = _hardware_items(tanium_id, hostname, endpoint.os_name, endpoint.platform, sensor_sources, kernel_versions)
        endpoint.ports = _process_rows(sensor_sources.get("open_ports", ("Open Port", {}))[1].get(tanium_id, {}))
        endpoint.sbom = []
        endpoint.last_seen_at = _parse_time(node.get("eidLastSeen"))
        endpoint.raw = {
            **node,
            "securewatchSensorSources": {key: sensor_name for key, (sensor_name, _) in sensor_sources.items()},
        }
        updated_keys.add((endpoint.tanium_endpoint_id or "", endpoint.hostname or ""))
        changed += 1

    for endpoint in db.scalars(select(EndpointSnapshot)).all():
        key = (endpoint.tanium_endpoint_id or "", endpoint.hostname or "")
        if key in updated_keys:
            continue
        hardware = endpoint.hardware if isinstance(endpoint.hardware, list) else []
        has_kernel_item = any(isinstance(item, dict) and item.get("key") == "kernel_version" for item in hardware)
        if has_kernel_item or not _expects_kernel_version(endpoint.os_name, endpoint.platform):
            continue
        endpoint.hardware = [
            *hardware,
            *_hardware_items(endpoint.tanium_endpoint_id or "", endpoint.hostname, endpoint.os_name, endpoint.platform, {}, kernel_versions),
        ]
        changed += 1

    db.commit()
    return len(nodes), changed
