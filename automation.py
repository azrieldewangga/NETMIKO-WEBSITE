from __future__ import annotations

import ipaddress
import json
import re
import socket
import subprocess
import threading
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any

import psutil
import netmiko
from netmiko.exceptions import (
    NetMikoAuthenticationException,
    NetMikoTimeoutException,
    ReadException,
    ReadTimeout,
)
from netmiko.ssh_autodetect import SSHDetect
from netmiko.utilities import get_structured_data_textfsm


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_INVENTORY_PATH = BASE_DIR / "inventory.json"
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)

_log_locks: dict[str, threading.Lock] = {}


# ── Custom Exceptions ─────────────────────────────────────────────────────────

class InventoryError(ValueError):
    """Error yang dilempar kalau ada masalah di inventory (format salah, device tidak ditemukan, dll)."""
    pass


class ConnectionError(RuntimeError):
    """Error yang dilempar kalau koneksi SSH ke device gagal."""
    pass


class ActionError(RuntimeError):
    """Error yang dilempar kalau aksi konfigurasi ke device gagal atau tidak valid."""
    pass


# Daftar exception dari library Netmiko yang akan kita tangkap
NETMIKO_EXCEPTIONS = (
    NetMikoTimeoutException,
    NetMikoAuthenticationException,
    ReadException,
    ReadTimeout,
    socket.error,
    OSError,
    EOFError,
)

# ── Bantuan Keamanan ──────────────────────────────────────────────────────────

# Regex untuk nangkep karakter berbahaya yang bisa bikin CLI injection
_DANGEROUS_CHARS = re.compile(r"[\r\n\x00-\x1f\x7f|;&`$]")


def sanitize_cli_value(value: str) -> str:
    """
    Bersiin value dari karakter berbahaya sebelum dikirim ke CLI Cisco.
    Kalau panjangnya lebih dari 200 karakter, langsung tolak.
    """
    cleaned = _DANGEROUS_CHARS.sub("", value).strip()
    if len(cleaned) > 200:
        raise ActionError("Value terlalu panjang (maks 200 karakter).")
    return cleaned


# Pola error dari output CLI Cisco yang perlu kita deteksi
ERROR_PATTERNS = (
    re.compile(r"bad mask", re.IGNORECASE),
    re.compile(r"invalid input", re.IGNORECASE),
    re.compile(r"incomplete command", re.IGNORECASE),
    re.compile(r"ambiguous command", re.IGNORECASE),
    re.compile(r"^\s*%", re.MULTILINE),
    re.compile(r"overlaps with", re.IGNORECASE),
)


# Daftar device_type yang didukung Netmiko (whitelist)
ALLOWED_DEVICE_TYPES = {
    "cisco_ios", "cisco_xe", "cisco_xr", "cisco_nxos", "cisco_asa",
    "arista_eos", "juniper_junos", "huawei", "mikrotik_routeros",
    "linux", "autodetect",
}


def _validate_host(host: str, device_id: str) -> None:
    """
    Validasi format host — boleh berupa IP address atau hostname yang valid.
    Kalau formatnya salah, lempar InventoryError.
    """
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


def _parse_device_list(raw_list: list) -> list[dict[str, Any]]:
    """
    Parse dan validasi list device dari inventory JSON.
    Setiap item dicek: harus punya id, host valid, port 1-65535, dan device_type yang dikenali.
    """
    devices: list[dict[str, Any]] = []
    for item in raw_list:
        if not isinstance(item, dict):
            raise InventoryError("Each inventory item must be a JSON object.")

        device_id = str(item.get("id") or item.get("name") or item.get("host") or "").strip()
        host = str(item.get("host") or item.get("ip") or "").strip()
        if not device_id:
            raise InventoryError("Every inventory device needs an id.")
        if not host:
            raise InventoryError(f"Device {device_id} needs a host value.")

        _validate_host(host, device_id)

        port = int(item.get("port") or 22)
        if not (1 <= port <= 65535):
            raise InventoryError(
                f"Device '{device_id}': port {port} di luar range (1-65535)."
            )

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


def load_inventory(path: str | Path = DEFAULT_INVENTORY_PATH) -> dict[str, Any]:
    """
    Load inventory dari file JSON.
    Support dua format: list lama (auto-migrate ke dict baru) dan dict baru lengkap dengan links & switch.
    """
    inventory_path = Path(path)
    with inventory_path.open() as handle:
        raw = json.load(handle)

    # Auto-migrate: kalau format lama (list), konversi ke format dict baru
    if isinstance(raw, list):
        devices = _parse_device_list(raw)
        return {
            "devices": devices,
            "links": [],
            "switch": {"name": "switch", "host": ""},
        }

    if not isinstance(raw, dict):
        raise InventoryError("Inventory must be a JSON list or object.")

    devices = _parse_device_list(raw.get("devices", []))
    links = raw.get("links", [])
    switch_info = raw.get("switch", {"name": "switch", "host": ""})

    return {
        "devices": devices,
        "links": links,
        "switch": switch_info,
    }


def load_inventory_devices(path: str | Path = DEFAULT_INVENTORY_PATH) -> list[dict[str, Any]]:
    """
    Shortcut: load inventory tapi langsung return list devices-nya aja.
    Cocok dipakai kalau hanya butuh daftar device tanpa info links dan switch.
    """
    return load_inventory(path)["devices"]


def _load_raw_inventory(path: str | Path = DEFAULT_INVENTORY_PATH) -> dict:
    """
    Load JSON mentah dari file inventory dan normalisasi ke format dict.
    Digunakan internal untuk operasi baca-tulis langsung ke file.
    """
    inventory_path = Path(path)
    with inventory_path.open() as handle:
        raw = json.load(handle)
    if isinstance(raw, list):
        return {"devices": raw, "links": [], "switch": {"name": "switch", "host": ""}}
    return raw


def _save_raw_inventory(data: dict, path: str | Path = DEFAULT_INVENTORY_PATH) -> None:
    """
    Simpan dict inventory ke file JSON dengan indentasi 2 spasi.
    Dipanggil setelah ada perubahan data (tambah/update device).
    """
    inventory_path = Path(path)
    with inventory_path.open("w") as handle:
        json.dump(data, handle, indent=2)


def update_inventory_device(device_id: str, updates: dict[str, Any], path: str | Path = DEFAULT_INVENTORY_PATH) -> None:
    """
    Update field tertentu dari device yang sudah ada di inventory.
    Cari device berdasarkan id, lalu update field-nya dan simpan kembali ke file.
    Kalau device tidak ditemukan, lempar InventoryError.
    """
    raw = _load_raw_inventory(path)
    updated = False
    for item in raw["devices"]:
        current_id = str(item.get("id") or item.get("name") or item.get("host") or "").strip()
        if current_id == device_id:
            item.update(updates)
            updated = True
            break
    if updated:
        _save_raw_inventory(raw, path)
    else:
        raise InventoryError(f"Device '{device_id}' was not found in inventory for updating.")


def add_device_to_inventory(
    device_data: dict[str, Any],
    link_data: dict[str, Any] | None = None,
    path: str | Path = DEFAULT_INVENTORY_PATH,
) -> None:
    """
    Tambah device baru ke inventory JSON.
    Opsional: sekalian tambah data link (koneksi ke switch/device lain).
    Kalau id device sudah ada, lempar InventoryError (tidak boleh duplikat).
    """
    raw = _load_raw_inventory(path)

    device_id = str(device_data.get("id", "")).strip()
    if not device_id:
        raise InventoryError("Device ID is required.")
    host = str(device_data.get("host", "")).strip()
    if not host:
        raise InventoryError("Host / IP address is required.")
    _validate_host(host, device_id)

    # Cek duplikat — id harus unik
    for existing in raw["devices"]:
        if str(existing.get("id", "")).strip() == device_id:
            raise InventoryError(f"Device '{device_id}' already exists in inventory.")

    port = int(device_data.get("port", 22))
    if not (1 <= port <= 65535):
        raise InventoryError(f"Port {port} di luar range (1-65535).")
    device_type = str(device_data.get("device_type", "cisco_ios")).strip()
    if device_type not in ALLOWED_DEVICE_TYPES:
        raise InventoryError(f"Device type '{device_type}' tidak dikenali.")

    new_device = {
        "id": device_id,
        "name": str(device_data.get("name") or device_id).strip(),
        "host": host,
        "port": port,
        "device_type": device_type,
        "role": str(device_data.get("role", "router")).strip(),
        "enabled": bool(device_data.get("enabled", True)),
    }
    raw["devices"].append(new_device)

    # Kalau ada data link, tambahkan juga ke inventory
    if link_data:
        raw.setdefault("links", []).append(link_data)

    _save_raw_inventory(raw, path)


def find_device(inventory: list[dict[str, Any]], lookup: str) -> dict[str, Any]:
    """
    Cari device di inventory berdasarkan id, name, atau host (case-insensitive).
    Kalau tidak ketemu, lempar InventoryError.
    """
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
    log_session: bool = True,
) -> dict[str, Any]:
    """
    Buat dict parameter koneksi yang siap dipakai oleh Netmiko ConnectHandler.
    Set log_session=False untuk koneksi singkat (polling) agar tidak menumpuk file log.
    """
    params = {
        "device_type": device_type or device["device_type"],
        "host": host or device["host"],
        "port": int(port or device["port"]),
        "username": username,
        "password": password,
        "fast_cli": False,
    }
    if log_session:
        device_id = device.get("id", "unknown")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        params["session_log"] = str(LOGS_DIR / f"{device_id}_{timestamp}.log")
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
    """
    Buka koneksi SSH ke device via Netmiko.
    Kalau gagal (timeout atau autentikasi salah), lempar ConnectionError.
    """
    params = build_connection_params(device, username, password, secret, host, port, device_type)
    try:
        return netmiko.ConnectHandler(**params)
    except NETMIKO_EXCEPTIONS as exc:
        raise ConnectionError(str(exc)) from exc


def check_device_reachable(
    device: dict[str, Any],
    username: str = "admin",
    password: str = "admin",
    secret: str | None = None,
    timeout: int = 5,
) -> str:
    """
    Cek apakah device bisa dijangkau via SSH dengan mencoba buka koneksi singkat.
    Return: 'online' kalau sukses, 'offline' kalau timeout/auth gagal, 'unknown' kalau error lain.
    log_session=False agar tidak menumpuk file log tiap polling.
    """
    try:
        params = build_connection_params(device, username, password, secret, log_session=False)
        params["timeout"] = timeout
        params["banner_timeout"] = timeout
        params["auth_timeout"] = timeout  # penting! default Netmiko = 10s, wajib di-set biar tidak lama
        conn = netmiko.ConnectHandler(**params)
        conn.disconnect()
        return "online"
    except NETMIKO_EXCEPTIONS:
        return "offline"
    except Exception:
        return "unknown"


def _normalize_textfsm_row(row: dict[str, str]) -> dict[str, str]:
    """
    Normalisasi key dari hasil parsing NTC Templates ke format yang dipakai oleh views.
    Menangani variasi nama key yang berbeda antar template.
    """
    return {
        "interface": row.get("intf") or row.get("interface") or "",
        "ip_address": row.get("ipaddr") or row.get("ipaddress") or row.get("ip_address") or "unassigned",
        "method": row.get("proto") or row.get("method") or "",
        "status": row.get("status") or "",
        "protocol": row.get("proto") or row.get("protocol") or "",
    }


def _parse_interface_brief_fallback(output: str) -> list[dict[str, str]]:
    """
    Parser manual untuk output 'show ip interface brief' kalau TextFSM gagal.
    Parsing dilakukan baris per baris, skip header dan baris kosong.
    """
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
    """
    Ambil daftar interface dari device via SSH menggunakan 'show ip interface brief'.
    Coba parsing pakai TextFSM dulu; kalau gagal, fallback ke parser manual.
    Return: (list interface terstruktur, raw output CLI).
    """
    actual_type = device_type or device["device_type"]
    connection = connect_device(device, username, password, secret, host, port, device_type)
    try:
        raw_output = connection.send_command("show ip interface brief")
        try:
            parsed = get_structured_data_textfsm(raw_output, platform=actual_type, command="show ip interface brief")
        except Exception:
            parsed = None

        if isinstance(parsed, list) and parsed:
            interfaces = [_normalize_textfsm_row(row) for row in parsed]
        else:
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
    """
    Ambil snapshot lengkap satu device: info dasar + daftar interface.
    Kalau koneksi gagal, status reachable=False dan error dicatat di field 'error'.
    """
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
    """
    Ambil snapshot semua device yang aktif (enabled=True) di inventory secara berurutan.
    Return: list snapshot tiap device.
    """
    return [
        get_device_snapshot(device, username=username, password=password, secret=secret)
        for device in inventory
        if device.get("enabled", True)
    ]


def build_interface_config(action: str, interface: str, value: str | None = None) -> list[str]:
    """
    Generate perintah konfigurasi CLI Cisco berdasarkan action yang diminta.
    Action yang didukung: add/change/set/ip (set IP), delete/remove/unset (hapus IP),
    description/desc/label (ubah deskripsi), ssh_port (ubah port SSH).
    Return: list perintah CLI yang siap dikirim ke device.
    """
    normalized = action.strip().lower()

    if normalized == "ssh_port":
        # Ubah port SSH router secara global
        if not value or not value.isdigit() or not (1 <= int(value) <= 65535):
            raise ActionError("Value port tidak valid (harus angka 1-65535).")
        return [f"ip ssh port {value}"]

    # Bersiin nama interface dari karakter berbahaya
    interface = sanitize_cli_value(interface)
    if normalized in {"add", "change", "set", "ip"}:
        # Set / ganti IP address di interface
        if not value:
            raise ActionError("CIDR notation is required for add/change actions.")
        normalized_value = sanitize_cli_value(value)
        if "/" not in normalized_value:
            normalized_value = f"{normalized_value}/24"  # default prefix /24 kalau tidak disebutkan
        interface_value = ipaddress.ip_interface(normalized_value)
        return [
            f"interface {interface}",
            f" ip address {interface_value.ip} {interface_value.network.netmask}",
            " no shutdown",
        ]
    if normalized in {"delete", "remove", "unset"}:
        # Hapus IP address dari interface
        return [f"interface {interface}", " no ip address"]
    if normalized in {"description", "desc", "label"}:
        # Ubah deskripsi interface
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
    """
    Eksekusi aksi konfigurasi interface ke device via SSH.
    Bangun perintah CLI → kirim ke device → cek output error → simpan config.
    Return: dict hasil eksekusi (device, host, interface, action, output, status).
    """
    config = build_interface_config(action, interface, value)
    connection = connect_device(device, username, password, secret, host, port, device_type)
    try:
        output = connection.send_config_set(config)
        # Deteksi pesan error dari output CLI Cisco
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
    """
    Parse teks batch menjadi list baris perintah terstruktur.
    Format per baris: device1;device2, interface, action, value
    Baris kosong dan baris komentar (#) diabaikan.
    Return: (list baris valid, list pesan error format).
    """
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue  # lewati baris kosong dan komentar

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
    """
    Jalankan semua baris batch ke device yang sesuai di inventory.
    Tiap device di tiap baris dieksekusi satu per satu.
    Return: dict berisi 'successful' (berhasil) dan 'failed' (gagal).
    """
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


# ── Activity Logging ──────────────────────────────────────────────────────────

def log_activity(device_id: str, level: str, action: str, detail: str, user: str | None = None) -> None:
    """Catat event ke logs/activity_<device_id>.json, thread-safe, max 500 entri."""
    if device_id not in _log_locks:
        _log_locks[device_id] = threading.Lock()
    lock = _log_locks[device_id]
    log_path = LOGS_DIR / f"activity_{device_id}.json"
    entry = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "level": level,
        "action": action,
        "detail": detail,
        "user": user,
    }
    with lock:
        try:
            entries = json.loads(log_path.read_text(encoding="utf-8")) if log_path.exists() else []
        except (json.JSONDecodeError, OSError):
            entries = []
        entries.append(entry)
        if len(entries) > 500:
            entries = entries[-500:]
        log_path.write_text(json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8")


def get_activity_log(device_id: str, limit: int = 100) -> list[dict]:
    """Baca log aktivitas device, return limit entri terbaru (newest first)."""
    log_path = LOGS_DIR / f"activity_{device_id}.json"
    if not log_path.exists():
        return []
    try:
        entries = json.loads(log_path.read_text(encoding="utf-8"))
        return list(reversed(entries[-limit:]))
    except (json.JSONDecodeError, OSError):
        return []


# ── Terminal Shell Session (persistent, interactive) ─────────────────────────

_TERMINAL_BLOCKED = re.compile(
    r"^\s*(reload|erase\s+nvram[:\s]?|erase\s+startup|write\s+erase|format\s)\b",
    re.IGNORECASE,
)


def open_terminal_session(
    device: dict[str, Any],
    username: str,
    password: str,
    secret: str | None = None,
) -> Any:
    """Buka koneksi Netmiko persisten untuk sesi terminal interaktif."""
    return connect_device(device, username, password, secret)


def terminal_send(conn: Any, command: str) -> tuple[str, str]:
    """
    Kirim satu perintah ke koneksi Netmiko persisten.
    Pakai send_command_timing agar command tanpa output (conf t, ip address, dll)
    tidak timeout karena tidak menunggu prompt pattern.
    Returns (output, current_prompt).
    """
    cmd = command.strip()
    if not cmd:
        raise ActionError("Command tidak boleh kosong.")
    if _TERMINAL_BLOCKED.match(cmd):
        raise ActionError(f"Perintah '{cmd}' diblokir karena berbahaya.")

    try:
        output = conn.send_command_timing(
            cmd,
            delay_factor=2,
            strip_prompt=True,
            strip_command=True,
        )
        output = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", output).strip()
    except Exception as exc:
        raise ConnectionError(f"Gagal mengirim perintah: {exc}") from exc

    try:
        prompt = conn.find_prompt()
    except Exception:
        prompt = ""

    return output, prompt


# ── Enhanced Device Detail ────────────────────────────────────────────────────

def _parse_show_version(output: str) -> dict:
    """Ekstrak uptime, IOS version, hardware, dan serial dari output show version."""
    uptime_m = re.search(r"uptime is (.+)", output, re.IGNORECASE)
    ios_m = re.search(r"Version\s+([\w.()\-]+)", output, re.IGNORECASE)
    hw_m = re.search(r"[Cc]isco\s+(\S+)\s.*[Pp]rocessor", output)
    serial_m = re.search(r"[Pp]rocessor [Bb]oard ID\s+(\S+)", output)
    return {
        "uptime": uptime_m.group(1).strip() if uptime_m else "unknown",
        "ios_version": ios_m.group(1).strip() if ios_m else "unknown",
        "hardware": hw_m.group(1).strip() if hw_m else "unknown",
        "serial": serial_m.group(1).strip() if serial_m else "unknown",
    }


def _parse_route_count(output: str) -> int:
    """Ambil total route count dari output 'show ip route summary'.

    Support multiple output formats:
    1. Standard format: Total + 5 columns (Networks, Subnets, Replicating, Total Route Entry, Total Routes)
    2. Alternate format: Total + 4 columns (Networks, Subnets, Overhead, Memory)
    3. Fallback: Sum Networks dari semua route sources
    """
    if not output or not output.strip():
        return 0

    # Approach 1: Format standard 5-column (ambil kolom ke-5: Total Routes)
    m = re.search(r"^\s*Total\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$", output, re.MULTILINE)
    if m:
        return int(m.group(5))

    # Approach 2: Format alternate 4-column dengan Networks sebagai total (ambil kolom ke-1)
    # Route Source    Networks    Subnets     Overhead   Memory (bytes)
    # Total             3            0           216        408
    m = re.search(r"^\s*Total\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$", output, re.MULTILINE)
    if m:
        # Ambil kolom pertama (Networks) sebagai total route count
        return int(m.group(1))

    # Approach 3: Count manual dari routes yang listed
    count = 0
    for line in output.splitlines():
        if " is " in line and re.search(r"\b(connected|static|ospf|bgp|rip|eigrp|isis)\b", line, re.IGNORECASE):
            count += 1
    if count > 0:
        return count

    return 0


def get_device_detail(
    device: dict[str, Any],
    username: str,
    password: str,
    secret: str | None = None,
) -> dict[str, Any]:
    """
    Ambil detail lengkap device dalam 1 sesi SSH:
    show version + show ip interface brief + show ip route summary.
    """
    result: dict[str, Any] = {
        "uptime": "unknown",
        "ios_version": "unknown",
        "hardware": "unknown",
        "serial": "unknown",
        "interfaces": [],
        "route_count": 0,
        "raw_version": "",
        "checked_at": datetime.now().isoformat(timespec="seconds"),
        "error": "",
    }
    connection = None
    try:
        connection = connect_device(device, username, password, secret)

        raw_version = connection.send_command("show version")
        result["raw_version"] = raw_version
        result.update(_parse_show_version(raw_version))

        try:
            raw_intf = connection.send_command("show ip interface brief")
            try:
                parsed_intf = get_structured_data_textfsm(
                    raw_intf, platform=device["device_type"], command="show ip interface brief"
                )
            except Exception:
                parsed_intf = None
            if isinstance(parsed_intf, list) and parsed_intf:
                result["interfaces"] = [_normalize_textfsm_row(r) for r in parsed_intf]
            else:
                result["interfaces"] = _parse_interface_brief_fallback(raw_intf)
        except Exception:
            result["interfaces"] = []

        try:
            route_out = connection.send_command("show ip route summary")
            result["route_count"] = _parse_route_count(route_out)
            # Debug: log raw output jika parsing hasil 0 (untuk troubleshooting)
            if result["route_count"] == 0 and route_out.strip():
                import sys
                print(f"DEBUG: route_out parsing result 0 for {device['id']}:\n{route_out[:500]}", file=sys.stderr)
        except Exception as exc:
            result["route_count"] = 0
            import sys
            print(f"DEBUG: Exception on show ip route summary for {device['id']}: {exc}", file=sys.stderr)

    except ConnectionError as exc:
        result["error"] = str(exc)
    finally:
        if connection:
            try:
                connection.disconnect()
            except Exception:
                pass
    return result


# ── Network Auto-Scanner ──────────────────────────────────────────────────────

def get_local_subnets() -> list[str]:
    """Detect semua subnet lokal dari interface PC (skip loopback & link-local)."""
    subnets: list[str] = []
    for _iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family != socket.AF_INET:
                continue
            ip = addr.address or ""
            netmask = addr.netmask or ""
            if not ip or ip.startswith("127.") or ip.startswith("169.254."):
                continue
            try:
                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                s = str(network)
                if s not in subnets:
                    subnets.append(s)
            except ValueError:
                pass
    return subnets


def ping_host(ip: str) -> bool:
    """Ping satu IP address. Return True kalau reachable (Windows: ping -n 1 -w 500)."""
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", "500", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )
        return result.returncode == 0
    except Exception:
        return False


def try_ssh_discover(
    ip: str,
    username: str,
    password: str,
    secret: str | None = None,
) -> dict | None:
    """
    SSH ke IP, autodetect device_type via SSHDetect, ambil hostname dan CDP neighbors.
    Return None kalau koneksi gagal atau bukan network device.
    """
    try:
        autodetect_params = {
            "device_type": "autodetect",
            "host": ip,
            "username": username,
            "password": password,
            "timeout": 8,
            "banner_timeout": 8,
            "auth_timeout": 8,
        }
        if secret:
            autodetect_params["secret"] = secret

        guesser = SSHDetect(**autodetect_params)
        device_type = guesser.autodetect() or "cisco_ios"

        conn_params = {
            "device_type": device_type,
            "host": ip,
            "username": username,
            "password": password,
            "timeout": 8,
            "banner_timeout": 8,
            "auth_timeout": 8,
        }
        if secret:
            conn_params["secret"] = secret

        conn = netmiko.ConnectHandler(**conn_params)
        try:
            prompt = conn.find_prompt()
            hostname = re.sub(r"[>#\s].*$", "", prompt).strip().lower()
            if not hostname:
                hostname = ip.replace(".", "_")

            cdp_output = ""
            try:
                cdp_output = conn.send_command("show cdp neighbors detail", read_timeout=15)
            except Exception:
                pass

            return {
                "id": hostname,
                "name": hostname,
                "host": ip,
                "port": 22,
                "device_type": device_type,
                "role": "router",
                "enabled": True,
                "cdp_output": cdp_output,
            }
        finally:
            conn.disconnect()
    except Exception:
        return None


def parse_cdp_detail(cdp_output: str) -> list[dict]:
    """
    Parse 'show cdp neighbors detail' → list neighbor dengan IP, device_type, role, dan interface pair.
    IP neighbor adalah kunci untuk BFS topology walk — tanpa IP, kita tidak bisa SSH ke neighbor berikutnya.
    """
    neighbors: list[dict] = []
    blocks = re.split(r"-{10,}", cdp_output)

    for block in blocks:
        if not block.strip():
            continue

        # Hostname neighbor dari "Device ID:"
        device_id_m = re.search(r"Device ID:\s*(\S+)", block)
        if not device_id_m:
            continue
        raw_id = device_id_m.group(1).strip()
        hostname = raw_id.split(".")[0].lower()  # strip domain suffix (R1.lab.com → r1)

        # IP address neighbor — inilah yang dipakai SSH ke hop berikutnya di BFS
        # CDP bisa tampilkan "IP address:" atau "IPv4 Address:"
        ip_m = re.search(r"IP(?:v4)?\s+[Aa]ddress:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", block)
        neighbor_ip = ip_m.group(1) if ip_m else None

        # Platform string — untuk infer device_type Netmiko
        platform_m = re.search(r"Platform:\s*([^,\n]+)", block)
        platform = platform_m.group(1).strip() if platform_m else ""
        p_low = platform.lower()
        if "nx-os" in p_low or "nexus" in p_low:
            device_type = "cisco_nxos"
        elif "ios xe" in p_low or "ios-xe" in p_low:
            device_type = "cisco_xe"
        elif "ios xr" in p_low:
            device_type = "cisco_xr"
        elif "asa" in p_low:
            device_type = "cisco_asa"
        else:
            device_type = "cisco_ios"

        # Capabilities → tentukan role (router vs switch)
        cap_m = re.search(r"Capabilities:\s*(.+)", block)
        capabilities = cap_m.group(1).strip() if cap_m else ""
        role = "switch" if ("Switch" in capabilities and "Router" not in capabilities) else "router"

        # Interface pair: local (port di device kita) dan remote (port di neighbor)
        intf_m = re.search(r"Interface:\s*(\S+?),\s*Port ID[^:]*:\s*(\S+)", block)
        local_intf = intf_m.group(1).rstrip(",") if intf_m else ""
        remote_intf = intf_m.group(2) if intf_m else ""

        neighbors.append({
            "hostname": hostname,
            "ip": neighbor_ip,
            "platform": platform,
            "device_type": device_type,
            "role": role,
            "local_intf": local_intf,
            "remote_intf": remote_intf,
        })

    return neighbors


def discover_topology(
    seed_devices: list[dict[str, Any]],
    username: str,
    password: str,
    secret: str | None = None,
) -> dict:
    """
    BFS topology discovery mulai dari seed_devices (inventory yang sudah ada).

    Alur:
      1. SSH ke seed → find_prompt() → dapat hostname
      2. show cdp neighbors detail → parse_cdp_detail() → dapat IP + info tiap neighbor
      3. Queue IP neighbor yang belum dikunjungi → SSH ke sana → repeat
      4. Sampai tidak ada IP baru yang ditemukan

    Tidak perlu ping sweep — CDP memberikan IP tetangga secara eksplisit.
    Bekerja selama router seed sudah bisa di-SSH dari web UI.
    """
    visited_ips: set[str] = set()
    visited_ids: set[str] = set()
    queue: deque[dict] = deque(seed_devices)

    discovered: list[dict] = []
    all_links: list[dict] = []
    errors: list[str] = []

    while queue:
        seed = queue.popleft()
        ip = (seed.get("host") or "").strip()
        if not ip or ip in visited_ips:
            continue
        visited_ips.add(ip)

        try:
            params: dict[str, Any] = {
                "device_type": seed.get("device_type", "cisco_ios"),
                "host": ip,
                "username": username,
                "password": password,
                "timeout": 10,
                "banner_timeout": 10,
                "auth_timeout": 10,
                "fast_cli": True,
            }
            if secret:
                params["secret"] = secret

            conn = netmiko.ConnectHandler(**params)
            try:
                # Hostname dari prompt (misal "R1#" → "r1", "Router>" → "router")
                prompt = conn.find_prompt()
                hostname = re.sub(r"[>#\s].*$", "", prompt).strip().lower()
                if not hostname:
                    hostname = ip.replace(".", "_")

                # CDP neighbors detail — kunci BFS: tiap neighbor ada IP-nya
                cdp_output = ""
                try:
                    cdp_output = conn.send_command("show cdp neighbors detail", read_timeout=15)
                except Exception:
                    pass

                # Daftarkan device ini ke hasil
                dev: dict[str, Any] = {
                    "id": hostname,
                    "name": hostname,
                    "host": ip,
                    "port": int(seed.get("port", 22)),
                    "device_type": seed.get("device_type", "cisco_ios"),
                    "role": seed.get("role", "router"),
                    "enabled": True,
                }
                if hostname not in visited_ids:
                    visited_ids.add(hostname)
                    discovered.append(dev)

                # Parse CDP → tambah links + queue IP neighbor baru
                if cdp_output:
                    for nbr in parse_cdp_detail(cdp_output):
                        all_links.append({
                            "from": hostname,
                            "from_intf": nbr["local_intf"],
                            "to": nbr["hostname"],
                            "to_intf": nbr["remote_intf"],
                        })
                        if nbr["ip"] and nbr["ip"] not in visited_ips:
                            queue.append({
                                "host": nbr["ip"],
                                "id": nbr["hostname"],
                                "device_type": nbr["device_type"],
                                "role": nbr["role"],
                                "port": 22,
                            })
            finally:
                conn.disconnect()

        except NETMIKO_EXCEPTIONS:
            errors.append(f"{ip}: SSH gagal (timeout / auth salah)")
        except Exception as exc:
            errors.append(f"{ip}: {exc}")

    # Dedup links: pair (A→B) dan (B→A) dianggap satu link yang sama
    seen_pairs: set[frozenset] = set()
    unique_links: list[dict] = []
    for lk in all_links:
        pair = frozenset([lk["from"], lk["to"]])
        if pair not in seen_pairs:
            seen_pairs.add(pair)
            unique_links.append(lk)

    return {
        "found": [d["id"] for d in discovered],
        "devices": discovered,
        "links": unique_links,
        "errors": errors,
    }


def scan_network(
    username: str,
    password: str,
    secret: str | None = None,
    subnets: list[str] | None = None,
    seed_devices: list[dict[str, Any]] | None = None,
) -> dict:
    """
    Auto-discover router di jaringan.
    Jika seed_devices tersedia (inventory ada isinya): pakai BFS via CDP — lebih akurat, tidak butuh ping.
    Jika inventory kosong: fallback ke ping sweep subnet lokal (bootstrap pertama kali).
    """
    # Prioritas utama: BFS dari seeds yang sudah SSH-able
    if seed_devices:
        return discover_topology(seed_devices, username, password, secret)

    # Fallback: ping sweep untuk kasus inventory benar-benar kosong
    if subnets is None:
        subnets = get_local_subnets()

    if not subnets:
        return {
            "found": [],
            "devices": [],
            "links": [],
            "subnets_scanned": [],
            "errors": ["Inventory kosong dan tidak ada subnet lokal yang terdeteksi."],
        }

    all_ips: list[str] = []
    for subnet_str in subnets:
        try:
            network = ipaddress.IPv4Network(subnet_str, strict=False)
            all_ips.extend(str(h) for h in network.hosts())
        except ValueError:
            pass

    live_ips: list[str] = []
    with ThreadPoolExecutor(max_workers=64) as pool:
        futures = {pool.submit(ping_host, ip): ip for ip in all_ips}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    live_ips.append(ip)
            except Exception:
                pass

    # Dari tiap live IP, coba SSH — kalau berhasil langsung BFS via CDP
    if live_ips:
        bootstrap_seeds = [{"host": ip, "device_type": "cisco_ios", "role": "router", "port": 22} for ip in live_ips]
        result = discover_topology(bootstrap_seeds, username, password, secret)
        result["subnets_scanned"] = subnets
        return result

    return {
        "found": [],
        "devices": [],
        "links": [],
        "subnets_scanned": subnets,
        "errors": ["Ping sweep: tidak ada host yang merespons di subnet lokal."],
    }


# ── Batch Raw CLI ─────────────────────────────────────────────────────────────

def batch_raw_cli(
    device_ids: list[str],
    commands: list[str],
    inventory: list[dict[str, Any]],
    username: str,
    password: str,
    secret: str | None = None,
) -> dict[str, list[dict]]:
    """
    Kirim raw CLI config commands ke beberapa device sekaligus secara paralel.
    Satu koneksi SSH per device, semua commands dikirim via send_config_set().
    Return: {successful: [{device, output}], failed: [{device, error}]}.
    """
    results: dict[str, list[dict]] = {"successful": [], "failed": []}

    def _exec(device_id: str) -> tuple[str, bool, str]:
        try:
            device = find_device(inventory, device_id)
            conn = connect_device(device, username, password, secret)
            try:
                output = conn.send_config_set(commands)
                conn.save_config()
                return device_id, True, output
            finally:
                conn.disconnect()
        except (InventoryError, ConnectionError, ActionError, Exception) as exc:
            return device_id, False, str(exc)

    with ThreadPoolExecutor(max_workers=len(device_ids) or 1) as pool:
        futures = {pool.submit(_exec, did): did for did in device_ids}
        for future in as_completed(futures):
            device_id, ok, output = future.result()
            if ok:
                results["successful"].append({"device": device_id, "output": output})
            else:
                results["failed"].append({"device": device_id, "error": output})

    return results
