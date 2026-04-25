from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import netmiko
from netmiko.exceptions import NetMikoAuthenticationException, NetMikoTimeoutException


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_INVENTORY_PATH = BASE_DIR / "inventory.json"
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)


class InventoryError(ValueError):
    pass


class ConnectionError(RuntimeError):
    pass


class ActionError(RuntimeError):
    pass


NETMIKO_EXCEPTIONS = (
    NetMikoTimeoutException,
    NetMikoAuthenticationException,
)

# ── Bantuan Keamanan ──────────────────────────────────────────────────────────

_DANGEROUS_CHARS = re.compile(r"[\r\n\x00-\x1f\x7f|;&`$]")  # cegah injeksi CLI


def sanitize_cli_value(value: str) -> str:
    """Buang karakter yang berpotensi bikin injeksi CLI Cisco."""
    cleaned = _DANGEROUS_CHARS.sub("", value).strip()
    if len(cleaned) > 200:
        raise ActionError("Value terlalu panjang (maks 200 karakter).")
    return cleaned


ERROR_PATTERNS = (
    re.compile(r"bad mask", re.IGNORECASE),
    re.compile(r"invalid input", re.IGNORECASE),
    re.compile(r"incomplete command", re.IGNORECASE),
    re.compile(r"ambiguous command", re.IGNORECASE),
    re.compile(r"^\s*%", re.MULTILINE),
    re.compile(r"overlaps with", re.IGNORECASE),
)


# Whitelist device_type yang didukung Netmiko
ALLOWED_DEVICE_TYPES = {
    "cisco_ios", "cisco_xe", "cisco_xr", "cisco_nxos", "cisco_asa",
    "arista_eos", "juniper_junos", "huawei", "mikrotik_routeros",
    "linux", "autodetect",
}


def _validate_host(host: str, device_id: str) -> None:
    """Validasi format IP address atau hostname."""
    try:
        ipaddress.ip_address(host)
        return
    except ValueError:
        pass
    # Bukan IP → cek apakah hostname valid (alfanumerik + titik + strip)
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.\-]{0,253}[a-zA-Z0-9]$", host):
        raise InventoryError(
            f"Device '{device_id}': host '{host}' bukan IP atau hostname yang valid."
        )


def load_inventory(path: str | Path = DEFAULT_INVENTORY_PATH) -> list[dict[str, Any]]:
    inventory_path = Path(path)
    with inventory_path.open() as handle:
        raw = json.load(handle)
    if not isinstance(raw, list):
        raise InventoryError("Inventory must be a JSON list.")

    devices: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise InventoryError("Each inventory item must be a JSON object.")

        device_id = str(item.get("id") or item.get("name") or item.get("host") or "").strip()
        host = str(item.get("host") or item.get("ip") or "").strip()
        if not device_id:
            raise InventoryError("Every inventory device needs an id.")
        if not host:
            raise InventoryError(f"Device {device_id} needs a host value.")

        # Validasi host
        _validate_host(host, device_id)

        # Validasi port
        port = int(item.get("port") or 22)
        if not (1 <= port <= 65535):
            raise InventoryError(
                f"Device '{device_id}': port {port} di luar range (1-65535)."
            )

        # Validasi device_type
        device_type = str(item.get("device_type") or "cisco_ios").strip()
        if device_type not in ALLOWED_DEVICE_TYPES:
            raise InventoryError(
                f"Device '{device_id}': device_type '{device_type}' tidak dikenali. "
                f"Yang diizinkan: {', '.join(sorted(ALLOWED_DEVICE_TYPES))}"
            )

        devices.append(
            {
                "id": device_id,
                "name": str(item.get("name") or device_id).strip(),
                "host": host,
                "port": port,
                "device_type": device_type,
                "role": str(item.get("role") or "router").strip(),
                "enabled": bool(item.get("enabled", True)),
            }
        )
    return devices


def update_inventory_device(device_id: str, updates: dict[str, Any], path: str | Path = DEFAULT_INVENTORY_PATH) -> None:
    inventory_path = Path(path)
    with inventory_path.open() as handle:
        raw = json.load(handle)
        
    updated = False
    for item in raw:
        current_id = str(item.get("id") or item.get("name") or item.get("host") or "").strip()
        if current_id == device_id:
            item.update(updates)
            updated = True
            break
            
    if updated:
        with inventory_path.open("w") as handle:
            json.dump(raw, handle, indent=4)
    else:
        raise InventoryError(f"Device '{device_id}' was not found in inventory for updating.")


def find_device(inventory: list[dict[str, Any]], lookup: str) -> dict[str, Any]:
    normalized = lookup.strip().lower()
    for device in inventory:
        candidates = {
            str(device["id"]).lower(),
            str(device["name"]).lower(),
            str(device["host"]).lower(),
        }
        if normalized in candidates:
            return device
    raise InventoryError(f"Device '{lookup}' was not found in the inventory.")


def build_connection_params(
    device: dict[str, Any],
    username: str,
    password: str,
    secret: str | None = None,
    host: str | None = None,
    port: int | str | None = None,
    device_type: str | None = None,
) -> dict[str, Any]:
    device_id = device.get("id", "unknown")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    params = {
        "device_type": device_type or device["device_type"],
        "host": host or device["host"],
        "port": int(port or device["port"]),
        "username": username,
        "password": password,
        "fast_cli": True,
        "session_log": str(LOGS_DIR / f"{device_id}_{timestamp}.log"),
    }
    if secret:
        params["secret"] = secret
    return params


def connect_device(
    device: dict[str, Any],
    username: str,
    password: str,
    secret: str | None = None,
    host: str | None = None,
    port: int | str | None = None,
    device_type: str | None = None,
):
    params = build_connection_params(device, username, password, secret, host, port, device_type)
    try:
        return netmiko.ConnectHandler(**params)
    except NETMIKO_EXCEPTIONS as exc:
        raise ConnectionError(str(exc)) from exc


def _normalize_textfsm_row(row: dict[str, str]) -> dict[str, str]:
    """Normalisasi key dari NTC Templates ke format yang dipakai views."""
    return {
        "interface": row.get("intf") or row.get("interface") or "",
        "ip_address": row.get("ipaddr") or row.get("ipaddress") or row.get("ip_address") or "unassigned",
        "method": row.get("proto") or row.get("method") or "",
        "status": row.get("status") or "",
        "protocol": row.get("proto") or row.get("protocol") or "",
    }


def _parse_interface_brief_fallback(output: str) -> list[dict[str, str]]:
    """Fallback parser kalau TextFSM gagal (misal template tidak ditemukan)."""
    rows: list[dict[str, str]] = []
    started = False
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("Interface") and "IP-Address" in line:
            started = True
            continue
        if not started:
            continue
        if line.startswith("---"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        rows.append(
            {
                "interface": parts[0],
                "ip_address": parts[1],
                "method": parts[2],
                "status": " ".join(parts[3:-1]),
                "protocol": parts[-1],
            }
        )
    return rows


def get_interface_summary(
    device: dict[str, Any],
    username: str,
    password: str,
    secret: str | None = None,
    host: str | None = None,
    port: int | str | None = None,
    device_type: str | None = None,
) -> tuple[list[dict[str, str]], str]:
    connection = connect_device(device, username, password, secret, host, port, device_type)
    try:
        # Coba TextFSM dulu untuk structured data otomatis
        parsed = connection.send_command("show ip interface brief", use_textfsm=True)
        raw_output = connection.send_command("show ip interface brief")

        if isinstance(parsed, list) and parsed:
            interfaces = [_normalize_textfsm_row(row) for row in parsed]
        else:
            # TextFSM gagal / template tidak ditemukan → fallback ke parser manual
            interfaces = _parse_interface_brief_fallback(raw_output)

        return interfaces, raw_output
    finally:
        connection.disconnect()


def get_device_snapshot(
    device: dict[str, Any],
    username: str,
    password: str,
    secret: str | None = None,
    host: str | None = None,
    port: int | str | None = None,
    device_type: str | None = None,
) -> dict[str, Any]:
    snapshot = {
        "id": device["id"],
        "name": device["name"],
        "host": host or device["host"],
        "port": int(port or device["port"]),
        "device_type": device_type or device["device_type"],
        "role": device["role"],
        "enabled": device["enabled"],
        "reachable": False,
        "interface_count": 0,
        "interfaces": [],
        "raw_output": "",
        "error": "",
    }
    try:
        interfaces, raw_output = get_interface_summary(
            device,
            username=username,
            password=password,
            secret=secret,
            host=host,
            port=port,
            device_type=device_type,
        )
        snapshot["reachable"] = True
        snapshot["interface_count"] = len(interfaces)
        snapshot["interfaces"] = interfaces
        snapshot["raw_output"] = raw_output
    except (ConnectionError, ValueError) as exc:
        snapshot["error"] = str(exc)
    return snapshot


def get_topology_snapshot(
    inventory: list[dict[str, Any]],
    username: str,
    password: str,
    secret: str | None = None,
) -> list[dict[str, Any]]:
    return [
        get_device_snapshot(device, username=username, password=password, secret=secret)
        for device in inventory
        if device.get("enabled", True)
    ]


def build_interface_config(action: str, interface: str, value: str | None = None) -> list[str]:
    normalized = action.strip().lower()
    
    if normalized == "ssh_port":
        if not value or not value.isdigit() or not (1 <= int(value) <= 65535):
            raise ActionError("Value port tidak valid (harus angka 1-65535).")
        return [f"ip ssh port {value}"]
        
    # Bersihin nama interface biar aman dari injeksi
    interface = sanitize_cli_value(interface)
    if normalized in {"add", "change", "set", "ip"}:
        if not value:
            raise ActionError("CIDR notation is required for add/change actions.")
        normalized_value = sanitize_cli_value(value)
        if "/" not in normalized_value:
            normalized_value = f"{normalized_value}/24"
        interface_value = ipaddress.ip_interface(normalized_value)
        return [
            f"interface {interface}",
            f" ip address {interface_value.ip} {interface_value.network.netmask}",
            " no shutdown",
        ]
    if normalized in {"delete", "remove", "unset"}:
        return [f"interface {interface}", " no ip address"]
    if normalized in {"description", "desc", "label"}:
        if not value:
            raise ActionError("Description text is required for description changes.")
        return [f"interface {interface}", f" description {sanitize_cli_value(value)}"]
    raise ActionError(f"Unsupported action '{action}'.")


def apply_interface_action(
    device: dict[str, Any],
    username: str,
    password: str,
    interface: str,
    action: str,
    value: str | None = None,
    secret: str | None = None,
    host: str | None = None,
    port: int | str | None = None,
    device_type: str | None = None,
) -> dict[str, Any]:
    config = build_interface_config(action, interface, value)
    connection = connect_device(device, username, password, secret, host, port, device_type)
    try:
        output = connection.send_config_set(config)
        if any(pattern.search(output) for pattern in ERROR_PATTERNS):
            raise ActionError(output.strip())
        save_output = connection.save_config()
        return {
            "device": device["id"],
            "host": host or device["host"],
            "interface": interface,
            "action": action,
            "value": value or "",
            "commands": config,
            "output": output,
            "save_output": save_output,
            "status": "success",
        }
    finally:
        connection.disconnect()


def parse_batch_rows(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 3:
            errors.append(
                f"Line {line_number}: expected 'device1;device2,interface,action,value'."
            )
            continue

        device_ids = [item.strip() for item in parts[0].split(";") if item.strip()]
        interface = parts[1]
        action = parts[2]
        value = ",".join(parts[3:]).strip()
        if not device_ids:
            errors.append(f"Line {line_number}: at least one device is required.")
            continue
        if not interface and action.lower() != "ssh_port":
            errors.append(f"Line {line_number}: interface is required.")
            continue

        rows.append(
            {
                "line_number": line_number,
                "device_ids": device_ids,
                "interface": interface,
                "action": action,
                "value": value,
            }
        )
    return rows, errors


def execute_batch(
    inventory: list[dict[str, Any]],
    batch_rows: list[dict[str, Any]],
    username: str,
    password: str,
    secret: str | None = None,
) -> dict[str, list[dict[str, Any]]]:
    results: dict[str, list[dict[str, Any]]] = {"successful": [], "failed": []}
    for row in batch_rows:
        for device_id in row["device_ids"]:
            try:
                device = find_device(inventory, device_id)
                result = apply_interface_action(
                    device,
                    username=username,
                    password=password,
                    secret=secret,
                    interface=row["interface"],
                    action=row["action"],
                    value=row["value"] or None,
                )
                result["line_number"] = row["line_number"]
                results["successful"].append(result)
            except (InventoryError, ActionError, ConnectionError, ValueError) as exc:
                results["failed"].append(
                    {
                        "line_number": row["line_number"],
                        "device": device_id,
                        "interface": row["interface"],
                        "action": row["action"],
                        "value": row["value"],
                        "error": str(exc),
                    }
                )
    return results
