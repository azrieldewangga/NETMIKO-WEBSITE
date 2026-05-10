from __future__ import annotations

import json
import math
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
from pathlib import Path

from flask import abort, flash, current_app, jsonify, redirect, render_template, request, session, url_for

from .extensions import csrf, limiter

import automation
from automation import (
    ActionError,
    InventoryError,
    add_device_to_inventory,
    apply_interface_action,
    batch_raw_cli,
    check_device_reachable,
    discover_topology,
    execute_batch,
    open_terminal_session,
    terminal_send,
    find_device,
    get_activity_log,
    get_device_detail,
    get_interface_summary,
    load_inventory,
    log_activity,
    parse_batch_rows,
    scan_network,
    update_inventory_device,
)


def _get_inventory_path() -> Path:
    return Path(current_app.config["INVENTORY_PATH"])


def _cred_key(device_id: str) -> str:
    """Dapetin session key yang dipake buat nyimpen kredensial tiap perangkat."""
    return f"creds_{device_id}"


def _get_device_credentials(device_id: str, form=None):
    """
    Cari tau kredensial SSH buat perangkat tertentu.
    Prioritas: isian form -> session key tiap perangkat -> global session -> config bawaan global.
    """
    form = form or request.form
    cred_key = _cred_key(device_id)
    stored = session.get(cred_key, {})

    username = (
        form.get("device_username")
        or stored.get("username")
        or session.get("global_username")
        or current_app.config["LAB_DEVICE_USERNAME"]
    ).strip()
    password = (
        form.get("device_password")
        or stored.get("password")
        or session.get("global_password")
        or current_app.config["LAB_DEVICE_PASSWORD"]
    )
    secret = (
        form.get("device_secret")
        or stored.get("secret")
        or session.get("global_secret")
        or current_app.config["LAB_DEVICE_SECRET"]
    )
    return username, password, secret


def _save_device_credentials(device_id: str, username: str, password: str, secret: str):
    """Simpen kredensial tiap perangkat di session server (BUKAN teks biasa di cookie)."""
    # Kita cuma nyimpen secret yang ada isinya aja, biar gak nimpa kredensial lama pake yang kosong
    cred_key = _cred_key(device_id)
    entry = session.get(cred_key, {})
    if username:
        entry["username"] = username
    if password:
        entry["password"] = password
    if secret:
        entry["secret"] = secret
    session[cred_key] = entry


def _get_connection_fields(form=None, device=None) -> dict[str, str]:
    form = form or request.form
    device = device or {}
    host = (form.get("host") or device.get("host") or "").strip()
    port = str(form.get("port") or device.get("port") or 22).strip()
    device_type = (form.get("device_type") or device.get(
        "device_type") or "cisco_ios").strip()
    label = (form.get("label") or device.get("name")
             or device.get("id") or host).strip()
    return {
        "host": host,
        "port": port,
        "device_type": device_type,
        "label": label,
    }


# ── Device Status Cache ───────────────────────────────────────────────────────

_STATUS_TTL = 120  # 2 menit
_status_cache: dict[str, str] = {}   # {str(device_id): "online"/"offline"/"unknown"}
_status_lock = threading.Lock()
_status_refresh_alive = False


def _refresh_status_once(app) -> None:
    """SSH ke semua device paralel, update cache. Tidak butuh Flask request context."""
    try:
        inv_data = automation.load_inventory(Path(app.config["INVENTORY_PATH"]))
        devices = inv_data.get("devices", [])
        username = app.config["LAB_DEVICE_USERNAME"]
        password = app.config["LAB_DEVICE_PASSWORD"]
        secret = app.config["LAB_DEVICE_SECRET"]
    except Exception:
        return

    if not devices:
        return

    def _check(device):
        if not device.get("enabled"):
            return str(device["id"]), "offline"
        status = check_device_reachable(device, username=username, password=password,
                                        secret=secret, timeout=4)
        level = "INFO" if status == "online" else "WARNING"
        last = get_activity_log(device["id"], limit=1)
        last_status = last[0].get("detail") if last and last[0].get("action") == "connectivity_check" else None
        if last_status != status:
            log_activity(device["id"], level, "connectivity_check", status)
        return str(device["id"]), status

    with ThreadPoolExecutor(max_workers=len(devices)) as pool:
        futures = {pool.submit(_check, d): d for d in devices}
        new_cache: dict[str, str] = {}
        for future in as_completed(futures):
            dev_id, status = future.result()
            new_cache[dev_id] = status

    with _status_lock:
        _status_cache.clear()
        _status_cache.update(new_cache)


def _start_status_refresh_loop(app) -> None:
    """Loop background: refresh cache sekarang lalu setiap _STATUS_TTL detik."""
    global _status_refresh_alive
    _status_refresh_alive = True
    while _status_refresh_alive:
        _refresh_status_once(app)
        for _ in range(_STATUS_TTL):
            if not _status_refresh_alive:
                break
            time.sleep(1)


def _get_device_statuses(devices: list[dict]) -> dict[str, str]:
    """Baca status dari cache. Kalau belum ada datanya, kembalikan 'unknown'."""
    with _status_lock:
        cached = dict(_status_cache)
    return {str(d["id"]): cached.get(str(d["id"]), "unknown") for d in devices}


# ── Interface Summary Cache ───────────────────────────────────────────────────

_IFACE_TTL = 120  # 2 menit
_iface_cache: dict[str, dict] = {}  # {device_id: {"ts": float, "interfaces": list, "raw": str}}
_iface_lock = threading.Lock()


def _get_cached_iface(device_id: str):
    with _iface_lock:
        entry = _iface_cache.get(str(device_id))
    if entry and (time.time() - entry["ts"]) < _IFACE_TTL:
        return entry["interfaces"], entry["raw"]
    return None, None


def _set_cached_iface(device_id: str, interfaces: list, raw_output: str) -> None:
    with _iface_lock:
        _iface_cache[str(device_id)] = {"ts": time.time(), "interfaces": interfaces, "raw": raw_output}


def _invalidate_cached_iface(device_id: str) -> None:
    with _iface_lock:
        _iface_cache.pop(str(device_id), None)


# ── Terminal Shell Sessions ───────────────────────────────────────────────────
# Persistent Netmiko connections per web session, keyed by UUID.
# Memungkinkan conf t → ip address → end berjalan di satu SSH session yang sama.

_shell_sessions: dict[str, dict] = {}  # {shell_id: {"conn": ..., "device": dict}}
_shell_sessions_lock = threading.Lock()


def _close_shell(shell_id: str) -> None:
    with _shell_sessions_lock:
        data = _shell_sessions.pop(shell_id, None)
    if data:
        try:
            data["conn"].disconnect()
        except Exception:
            pass


# ── Background Network Scan ───────────────────────────────────────────────────

_scan_lock = threading.Lock()
_scan_state: dict = {"running": False, "last_result": None}


def _merge_scan_into_inventory(raw: dict, result: dict) -> None:
    """
    Merge hasil scan ke inventory yang ada — jangan hapus device offline.

    Aturan:
    - Device yang berhasil di-SSH (discovered): update atau tambah ke inventory.
    - Device yang sudah ada tapi tidak ditemukan scan (offline): tetap dipertahankan.
    - Links: pakai hasil CDP (discovered) + pertahankan link lama milik device offline.
    """
    existing: dict[str, dict] = {str(d["id"]): d for d in raw.get("devices", [])}
    discovered: dict[str, dict] = {str(d["id"]): d for d in result.get("devices", [])}

    # Update existing dengan data segar, tambah device baru dari scan
    merged = {**existing, **discovered}
    raw["devices"] = list(merged.values())

    # Links: ambil dari hasil scan, plus pertahankan link lama untuk device yang offline
    offline_ids = set(existing.keys()) - set(discovered.keys())
    old_links = raw.get("links", [])
    new_links = result.get("links", [])

    kept_offline_links = [
        lk for lk in old_links
        if lk.get("from") in offline_ids or lk.get("to") in offline_ids
    ]

    # Dedup berdasarkan pasangan device (arah tidak dipertimbangkan)
    seen: set[frozenset] = set()
    merged_links: list[dict] = []
    for lk in new_links + kept_offline_links:
        pair: frozenset = frozenset([lk.get("from"), lk.get("to")])
        if pair not in seen:
            seen.add(pair)
            merged_links.append(lk)

    raw["links"] = merged_links


def _run_background_scan(inventory_path: Path, username: str, password: str, secret: str | None) -> None:
    """
    Background thread: discover topology dari inventory yang ada sebagai seeds via CDP BFS.
    Kalau inventory kosong, fallback ke ping sweep subnet lokal.
    Update inventory.json jika ada device ditemukan.
    """
    with _scan_lock:
        _scan_state["running"] = True
        _scan_state["last_result"] = None
    try:
        # Load inventory saat ini sebagai seeds — ini yang sudah bisa di-SSH
        try:
            inv_data = automation.load_inventory(inventory_path)
            seeds = inv_data.get("devices", [])
        except Exception:
            seeds = []

        result = scan_network(username, password, secret, seed_devices=seeds if seeds else None)

        if result["found"]:
            raw = automation._load_raw_inventory(inventory_path)
            _merge_scan_into_inventory(raw, result)
            automation._save_raw_inventory(raw, inventory_path)

        with _scan_lock:
            _scan_state["last_result"] = result
    except Exception as exc:
        with _scan_lock:
            _scan_state["last_result"] = {"found": [], "devices": [], "links": [], "errors": [str(exc)]}
    finally:
        with _scan_lock:
            _scan_state["running"] = False


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def register_routes(app):
    # Jalankan background status-refresh loop sekali saat app start
    t = threading.Thread(target=_start_status_refresh_loop, args=(app,), daemon=True)
    t.start()

    @app.route("/")
    @login_required
    def dashboard():
        try:
            inventory_data = load_inventory(_get_inventory_path())
        except InventoryError as exc:
            flash(str(exc), "error")
            inventory_data = {"devices": [], "links": [],
                              "switch": {"name": "switch", "host": ""}}

        devices = inventory_data["devices"]
        links = inventory_data.get("links", [])
        switch_info = inventory_data.get(
            "switch", {"name": "switch", "host": ""})

        # Ambil status dari cache (direfresh background setiap 2 menit — tidak blocking)
        statuses = _get_device_statuses(devices)
        for device in devices:
            device["status"] = statuses.get(str(device["id"]), "unknown")

        # Layout topologi dinamis: tetap rapi walau jumlah router bertambah.
        topo_cx, topo_cy, topo_radius = 250, 195, 116
        topo_nodes: dict[str, dict[str, float | int]] = {}
        total_devices = max(len(devices), 1)
        for idx, device in enumerate(devices):
            angle = (-math.pi / 2) + ((2 * math.pi * idx) / total_devices)
            nx = math.cos(angle)
            ny = math.sin(angle)
            topo_nodes[str(device.get("id", ""))] = {
                "x": int(round(topo_cx + (topo_radius * nx))),
                "y": int(round(topo_cy + (topo_radius * ny))),
                "nx": nx,
                "ny": ny,
            }

        return render_template(
            "dashboard.html",
            title="Topology Dashboard",
            inventory=devices,
            links=links,
            switch_info=switch_info,
            topology_center={"x": topo_cx, "y": topo_cy},
            topology_nodes=topo_nodes,
        )

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("10/minute")
    def login():
        if session.get("logged_in"):
            return redirect(url_for("dashboard"))

        # Initialize session to ensure CSRF token can be generated
        if "csrf_init" not in session:
            session["csrf_init"] = True

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if username == current_app.config["WEB_USERNAME"] and password == current_app.config["WEB_PASSWORD"]:
                csrf_token = session.get("csrf_token")
                session.clear()
                if csrf_token:
                    session["csrf_token"] = csrf_token
                session["logged_in"] = True
                session["web_username"] = username
                flash("Login berhasil.", "success")

                # Trigger background scan sekali per sesi, asal tidak sedang berjalan
                with _scan_lock:
                    already_running = _scan_state["running"]
                if not already_running:
                    dev_user = current_app.config["LAB_DEVICE_USERNAME"]
                    dev_pass = current_app.config["LAB_DEVICE_PASSWORD"]
                    dev_secret = current_app.config["LAB_DEVICE_SECRET"] or None
                    inv_path = _get_inventory_path()
                    t = threading.Thread(
                        target=_run_background_scan,
                        args=(inv_path, dev_user, dev_pass, dev_secret),
                        daemon=True,
                    )
                    t.start()

                return redirect(url_for("dashboard"))
            flash("Username atau password web salah.", "error")
        return render_template("login.html", title="Login")

    @app.route("/logout")
    @login_required
    def logout():
        session.clear()
        flash("Logout berhasil.", "success")
        return redirect(url_for("login"))

    @app.route("/device/<device_id>", methods=["GET", "POST"])
    @login_required
    def device_detail(device_id: str):
        inventory = load_inventory(_get_inventory_path())["devices"]
        try:
            device = find_device(inventory, device_id)
        except InventoryError as exc:
            abort(404, description=str(exc))

        connection = _get_connection_fields(device=device)
        error = ""
        action_result = None
        interfaces = []
        raw_output = ""
        connected = False

        if request.method == "POST":
            connection = _get_connection_fields(request.form, device=device)
            username, password, secret = _get_device_credentials(
                device_id, request.form)

            action = request.form.get("action", "").strip()
            interface = request.form.get("interface", "").strip()
            value = request.form.get("value", "").strip()
            confirmed = request.form.get("confirmed") == "1"

            # Wajibin konfirmasi eksplisit buat aksi destruktif
            destructive = action.lower() in {
                "delete", "remove", "unset", "change", "ssh_port"}
            if action and destructive and not confirmed:
                # Balik ke halaman buat nampilin flag konfirmasi
                username, password, secret = _get_device_credentials(device_id)
                cached_ifaces, cached_raw = _get_cached_iface(device_id)
                if cached_ifaces is not None:
                    interfaces, raw_output = cached_ifaces, cached_raw
                    connected = True
                else:
                    try:
                        interfaces, raw_output = get_interface_summary(
                            device, username=username, password=password, secret=secret,
                            host=connection["host"], port=connection["port"],
                            device_type=connection["device_type"],
                        )
                        _set_cached_iface(device_id, interfaces, raw_output)
                        connected = True
                    except (automation.ConnectionError, ValueError) as exc:
                        error = str(exc)
                return render_template(
                    "device.html",
                    title=f"Device {device['id']}",
                    device={**connection, "id": device["id"]},
                    form_action=url_for(
                        "device_detail", device_id=device["id"]),
                    interfaces=interfaces,
                    raw_output=raw_output,
                    action_result=None,
                    error=error,
                    connected=connected,
                    pending_action={"action": action,
                                    "interface": interface, "value": value},
                )

            if action:
                if action != "ssh_port" and not interface:
                    error = "Interface wajib diisi."
                elif action == "ssh_port" and not value:
                    error = "Value (Port) wajib diisi untuk mengubah SSH Port."
                else:
                    try:
                        action_result = apply_interface_action(
                            device,
                            username=username,
                            password=password,
                            secret=secret,
                            host=connection["host"],
                            port=connection["port"],
                            device_type=connection["device_type"],
                            interface=interface,
                            action=action,
                            value=value or None,
                        )
                        if action == "ssh_port":
                            update_inventory_device(
                                device_id, {"port": int(value)})
                            device["port"] = int(value)
                            connection["port"] = str(value)
                            flash(
                                f"SSH Port router {device['id']} berhasil diubah ke {value} secara permanen.", "success")
                        else:
                            flash(
                                f"Aksi '{action}' pada {device['id']}/{interface} berhasil.", "success")
                        log_activity(device_id, "INFO", action, f"{action} {interface} → {value or '-'}", user=session.get("web_username"))
                        _invalidate_cached_iface(device_id)
                        connected = True
                    except (automation.ConnectionError, ActionError, ValueError) as exc:
                        error = str(exc)
                        log_activity(device_id, "ERROR", action or "connect", str(exc), user=session.get("web_username"))

        # Ambil daftar interface — pakai cache 2 menit, SSH hanya kalau cache miss/expired
        username, password, secret = _get_device_credentials(device_id)
        if not error:
            cached_ifaces, cached_raw = _get_cached_iface(device_id)
            if cached_ifaces is not None:
                interfaces, raw_output = cached_ifaces, cached_raw
                connected = True
            else:
                try:
                    interfaces, raw_output = get_interface_summary(
                        device,
                        username=username,
                        password=password,
                        secret=secret,
                        host=connection["host"],
                        port=connection["port"],
                        device_type=connection["device_type"],
                    )
                    _set_cached_iface(device_id, interfaces, raw_output)
                    connected = True
                except (automation.ConnectionError, ValueError) as exc:
                    error = str(exc)

        cred_key = _cred_key(device_id)
        stored = session.get(cred_key, {})
        return render_template(
            "device.html",
            title=f"Device {device['id']}",
            device={**connection, "id": device["id"]},
            form_action=url_for("device_detail", device_id=device["id"]),
            interfaces=interfaces,
            raw_output=raw_output,
            action_result=action_result,
            error=error,
            connected=connected,
            pending_action=None,
            has_saved_creds=bool(stored),
            default_device_username=stored.get(
                "username", current_app.config["LAB_DEVICE_USERNAME"]),
        )

    @app.route("/connect", methods=["POST"])
    @login_required
    def quick_connect():
        host = request.form.get("host", "").strip()
        if not host:
            flash("Host atau domain wajib diisi.", "error")
            return redirect(url_for("dashboard"))

        connection = _get_connection_fields(request.form)
        ad_hoc_id = connection["label"] or host
        username, password, secret = _get_device_credentials(
            ad_hoc_id, request.form)

        transient_device = {
            "id": ad_hoc_id,
            "name": ad_hoc_id,
            "host": connection["host"],
            "port": connection["port"],
            "device_type": connection["device_type"],
            "role": "ad-hoc",
            "enabled": True,
        }
        action_result = None
        error = ""
        interfaces = []
        raw_output = ""
        connected = False

        action = request.form.get("action", "").strip()
        interface = request.form.get("interface", "").strip()
        value = request.form.get("value", "").strip()

        try:
            if action:
                if action != "ssh_port" and not interface:
                    error = "Interface wajib diisi."
                elif action == "ssh_port" and not value:
                    error = "Value (Port) wajib diisi."
                else:
                    action_result = apply_interface_action(
                        transient_device,
                        username=username,
                        password=password,
                        secret=secret,
                        host=connection["host"],
                        port=connection["port"],
                        device_type=connection["device_type"],
                        interface=interface,
                        action=action,
                        value=value or None,
                    )
                    if action == "ssh_port":
                        flash(
                            f"SSH Port pada {ad_hoc_id} berhasil diubah ke {value}.", "success")
                        connection["port"] = str(value)
                        transient_device["port"] = int(value)
                    else:
                        flash(
                            f"Aksi '{action}' pada {ad_hoc_id}/{interface} berhasil.", "success")

            if not error:
                interfaces, raw_output = get_interface_summary(
                    transient_device,
                    username=username,
                    password=password,
                    secret=secret,
                    host=connection["host"],
                    port=connection["port"],
                    device_type=connection["device_type"],
                )
                connected = True
        except (automation.ConnectionError, ActionError, ValueError) as exc:
            error = str(exc)

        return render_template(
            "device.html",
            title=f"Quick Connect: {ad_hoc_id}",
            device={**connection, "id": ad_hoc_id},
            form_action=url_for("quick_connect"),
            interfaces=interfaces,
            raw_output=raw_output,
            action_result=action_result,
            error=error,
            connected=connected,
            pending_action=None,
            has_saved_creds=True,
            default_device_username=username,
        )

    @app.route("/batch", methods=["GET", "POST"])
    @login_required
    def batch():
        inventory_data = load_inventory(_get_inventory_path())
        inventory = inventory_data["devices"]
        batch_rows = []
        parse_errors = []
        results = None

        # Ambil status dari cache (direfresh background setiap 2 menit — tidak blocking)
        statuses = _get_device_statuses(inventory)
        for device in inventory:
            device["status"] = statuses.get(str(device["id"]), "unknown")

        if request.method == "POST":
            # Batch pake kredensial global session (admin set sekali dari modal seting di Dashboard)
            username = (request.form.get("device_username") or session.get(
                "global_username") or current_app.config["LAB_DEVICE_USERNAME"]).strip()
            password = request.form.get("device_password") or session.get(
                "global_password") or current_app.config["LAB_DEVICE_PASSWORD"]
            secret = request.form.get("device_secret") or session.get(
                "global_secret") or current_app.config["LAB_DEVICE_SECRET"]

            if request.form.get("device_password"):
                session["global_username"] = username
                session["global_password"] = password
                session["global_secret"] = secret

            batch_rows, parse_errors = parse_batch_rows(
                request.form.get("batch_rows", ""))
            if not parse_errors:
                results = execute_batch(
                    inventory,
                    batch_rows,
                    username=username,
                    password=password,
                    secret=secret,
                )
                for r in results.get("successful", []):
                    log_activity(r["device"], "INFO", "batch_action", f"{r['action']} {r['interface']} → {r['value']}", user=session.get("web_username"))
                for r in results.get("failed", []):
                    log_activity(r["device"], "ERROR", "batch_action", r["error"], user=session.get("web_username"))
                if results["successful"]:
                    flash(
                        f"{len(results['successful'])} perubahan berhasil dijalankan.", "success")
                if results["failed"]:
                    flash(
                        f"{len(results['failed'])} perubahan gagal dijalankan.", "error")
        return render_template(
            "batch.html",
            title="Batch Actions",
            inventory=inventory,
            batch_rows=batch_rows,
            parse_errors=parse_errors,
            results=results,
            default_device_username=session.get(
                "global_username", current_app.config["LAB_DEVICE_USERNAME"]),
        )

    @app.route("/credentials/global", methods=["POST"])
    @login_required
    def save_global_credentials():
        """Simpen kredensial SSH global (yang dipake buat Batch) dari modal setting navbar."""
        session["global_username"] = request.form.get(
            "device_username", "").strip() or current_app.config["LAB_DEVICE_USERNAME"]
        session["global_password"] = request.form.get(
            "device_password", "") or current_app.config["LAB_DEVICE_PASSWORD"]
        session["global_secret"] = request.form.get(
            "device_secret", "") or current_app.config["LAB_DEVICE_SECRET"]
        flash("Kredensial global disimpan untuk sesi ini.", "success")
        return redirect(request.referrer or url_for("dashboard"))

    @app.route("/api/topology/add-device", methods=["POST"])
    @login_required
    def api_add_device():
        """API endpoint untuk menambah device baru ke topology via modal form."""
        data = request.get_json(silent=True) or {}
        device_data = {
            "id": data.get("id", "").strip(),
            "name": data.get("name", "").strip(),
            "host": data.get("host", "").strip(),
            "port": data.get("port", 22),
            "device_type": data.get("device_type", "cisco_ios").strip(),
            "role": data.get("role", "router").strip(),
            "enabled": True,
        }
        link_data = None
        local_intf = data.get("local_intf", "").strip()
        remote_intf = data.get("remote_intf", "").strip()
        connected_to = data.get("connected_to", "switch").strip()
        if local_intf and remote_intf:
            link_data = {
                "from": device_data["id"],
                "from_intf": local_intf,
                "to": connected_to,
                "to_intf": remote_intf,
            }
        try:
            add_device_to_inventory(
                device_data, link_data, path=_get_inventory_path()
            )
            return jsonify({"ok": True, "message": f"Device '{device_data['id']}' berhasil ditambahkan."})
        except InventoryError as exc:
            return jsonify({"ok": False, "message": str(exc)}), 400

    @app.route("/api/topology/scan", methods=["POST"])
    @login_required
    def api_topology_scan():
        """
        Manual trigger topology scan. Scan saja, TIDAK langsung simpan ke inventory.
        Hasil disimpan sementara di _scan_state["last_result"] untuk di-apply lewat
        /api/topology/apply setelah user memilih mode (merge atau replace).
        """
        username = current_app.config["LAB_DEVICE_USERNAME"]
        password = current_app.config["LAB_DEVICE_PASSWORD"]
        secret = current_app.config["LAB_DEVICE_SECRET"] or None

        try:
            inv_data = load_inventory(_get_inventory_path())
            seeds = inv_data.get("devices", [])
        except Exception:
            seeds = []

        result = scan_network(username, password, secret, seed_devices=seeds if seeds else None)

        with _scan_lock:
            _scan_state["last_result"] = result

        return jsonify({
            "ok": True,
            "found": result["found"],
            "devices": result["devices"],
            "links": result["links"],
            "subnets_scanned": result.get("subnets_scanned", []),
            "errors": result.get("errors", []),
        })

    @app.route("/api/topology/apply", methods=["POST"])
    @login_required
    def api_topology_apply():
        """
        Terapkan hasil scan terakhir ke inventory.json.
        Body JSON: { "mode": "merge" | "replace" }
          merge   — pertahankan device offline, tambah/update yang ditemukan.
          replace — hapus semua yang tidak ditemukan, tulis ulang inventory.
        """
        body = request.get_json(silent=True, force=True) or {}
        mode = body.get("mode", "merge")

        with _scan_lock:
            result = _scan_state.get("last_result")

        if not result or not result.get("found"):
            return jsonify({"ok": False, "error": "Tidak ada hasil scan yang tersedia."})

        raw = automation._load_raw_inventory(_get_inventory_path())
        if mode == "replace":
            raw["devices"] = result["devices"]
            raw["links"] = result["links"]
        else:
            _merge_scan_into_inventory(raw, result)
        automation._save_raw_inventory(raw, _get_inventory_path())

        return jsonify({"ok": True, "mode": mode})

    @app.route("/api/scan/status")
    @login_required
    def api_scan_status():
        """Status background scan yang berjalan saat login."""
        with _scan_lock:
            running = _scan_state["running"]
            last = _scan_state["last_result"]
        return jsonify({"running": running, "result": last})

    @app.route("/batch/raw", methods=["POST"])
    @login_required
    def batch_raw():
        """Eksekusi raw Cisco CLI ke beberapa device sekaligus (JSON response untuk AJAX)."""
        inventory_data = load_inventory(_get_inventory_path())
        inventory = inventory_data["devices"]

        username = (
            request.form.get("device_username")
            or session.get("global_username")
            or current_app.config["LAB_DEVICE_USERNAME"]
        ).strip()
        password = (
            request.form.get("device_password")
            or session.get("global_password")
            or current_app.config["LAB_DEVICE_PASSWORD"]
        )
        secret = (
            request.form.get("device_secret")
            or session.get("global_secret")
            or current_app.config["LAB_DEVICE_SECRET"]
        ) or None

        raw_text = (request.form.get("raw_cli") or "").strip()
        if not raw_text:
            return jsonify({"ok": False, "error": "Raw CLI tidak boleh kosong."})

        import re as _re

        # Parse multiple blocks: [r1]\ncmds...\n[r2]\ncmds...
        blocks: list[tuple[list[str], list[str]]] = []
        current_devices: list[str] | None = None
        current_commands: list[str] = []
        for line in raw_text.splitlines():
            block_match = _re.match(r"\[([^\]]+)\]", line.strip())
            if block_match:
                if current_devices is not None and current_commands:
                    blocks.append((current_devices, current_commands))
                current_devices = [d.strip() for d in block_match.group(1).split(",") if d.strip()]
                current_commands = []
            elif current_devices is not None and line.strip():
                current_commands.append(line)
        if current_devices is not None and current_commands:
            blocks.append((current_devices, current_commands))

        if not blocks:
            return jsonify({"ok": False, "error": "Format tidak valid. Awali dengan [device1, device2]."})

        all_successful: list[dict] = []
        all_failed: list[dict] = []
        for device_ids, commands in blocks:
            block_results = batch_raw_cli(device_ids, commands, inventory, username, password, secret)
            all_successful.extend(block_results.get("successful", []))
            all_failed.extend(block_results.get("failed", []))
            for r in block_results.get("successful", []):
                log_activity(r["device"], "INFO", "batch_raw_cli", f"{len(commands)} commands", user=session.get("web_username"))
            for r in block_results.get("failed", []):
                log_activity(r["device"], "ERROR", "batch_raw_cli", r["error"], user=session.get("web_username"))

        results = {"successful": all_successful, "failed": all_failed}

        return jsonify({"ok": True, "results": results})

    # ── TERMINAL ─────────────────────────────────────────────

    def _get_terminal_shell_id() -> str | None:
        shell_id = session.get("terminal_shell_id")
        if not shell_id:
            return None
        with _shell_sessions_lock:
            exists = shell_id in _shell_sessions
        return shell_id if exists else None

    @app.route("/terminal")
    @login_required
    def terminal_page():
        inventory = load_inventory(_get_inventory_path())["devices"]
        shell_id = _get_terminal_shell_id()
        terminal_device = None
        if shell_id:
            device_id = session.get("terminal_device_id")
            try:
                terminal_device = find_device(inventory, device_id)
            except InventoryError:
                _close_shell(shell_id)
                for key in ("terminal_device_id", "terminal_shell_id", "terminal_prompt"):
                    session.pop(key, None)
                shell_id = None
        return render_template(
            "terminal.html",
            title="CLI Terminal",
            inventory=inventory,
            has_terminal_session=bool(shell_id),
            terminal_device=terminal_device,
            terminal_prompt=session.get("terminal_prompt", ""),
        )

    @app.route("/terminal/connect", methods=["POST"])
    @login_required
    def terminal_connect():
        inventory = load_inventory(_get_inventory_path())["devices"]
        device_id = request.form.get("device_id", "").strip()
        username = (request.form.get("username", "").strip() or current_app.config["LAB_DEVICE_USERNAME"])
        password = request.form.get("password", "") or current_app.config["LAB_DEVICE_PASSWORD"]
        secret = request.form.get("secret", "").strip() or None

        try:
            device = find_device(inventory, device_id)
        except InventoryError as exc:
            flash(str(exc), "error")
            return redirect(url_for("terminal_page"))

        # Tutup session lama jika ada
        old_shell = session.get("terminal_shell_id")
        if old_shell:
            _close_shell(old_shell)

        try:
            conn = open_terminal_session(device, username, password, secret)
            shell_id = str(uuid.uuid4())
            with _shell_sessions_lock:
                _shell_sessions[shell_id] = {"conn": conn, "device": device}
            try:
                prompt = conn.find_prompt()
            except Exception:
                prompt = device["name"] + "#"
            session["terminal_device_id"] = device_id
            session["terminal_shell_id"] = shell_id
            session["terminal_prompt"] = prompt
            log_activity(device_id, "INFO", "terminal_connect", "Connected via web terminal", user=session.get("web_username"))
            flash(f"Terhubung ke {device['name']}.", "success")
        except automation.ConnectionError as exc:
            log_activity(device_id, "ERROR", "terminal_connect", str(exc), user=session.get("web_username"))
            flash(f"Gagal terhubung: {exc}", "error")

        return redirect(url_for("terminal_page"))

    @app.route("/terminal/execute", methods=["POST"])
    @login_required
    def terminal_execute():
        shell_id = _get_terminal_shell_id()
        if not shell_id:
            return jsonify({"ok": False, "error": "Belum terhubung ke perangkat. Silakan connect ulang."})

        data = request.get_json(silent=True) or {}
        command = data.get("command", "").strip()
        if not command:
            return jsonify({"ok": False, "error": "Command tidak boleh kosong."})

        with _shell_sessions_lock:
            shell_data = _shell_sessions.get(shell_id)
        if not shell_data:
            return jsonify({"ok": False, "error": "Sesi terminal tidak ditemukan."})

        conn = shell_data["conn"]
        if not conn.is_alive():
            _close_shell(shell_id)
            session.pop("terminal_shell_id", None)
            return jsonify({"ok": False, "error": "Koneksi SSH terputus. Silakan connect ulang."})

        try:
            output, prompt = terminal_send(conn, command)
            if prompt:
                session["terminal_prompt"] = prompt
            log_activity(session.get("terminal_device_id", ""), "INFO", "terminal_cmd", command[:120], user=session.get("web_username"))
            return jsonify({"ok": True, "output": output, "prompt": prompt, "command": command})
        except (ActionError, automation.ConnectionError) as exc:
            return jsonify({"ok": False, "error": str(exc)})

    @app.route("/terminal/disconnect", methods=["POST"])
    @login_required
    def terminal_disconnect():
        shell_id = session.get("terminal_shell_id")
        if shell_id:
            _close_shell(shell_id)
        for key in ("terminal_device_id", "terminal_shell_id", "terminal_prompt"):
            session.pop(key, None)
        flash("Berhasil disconnect dari terminal.", "success")
        return redirect(url_for("terminal_page"))

    # ── DEVICE INFO ───────────────────────────────────────────

    @app.route("/device/<device_id>/info")
    @login_required
    def device_info(device_id: str):
        inventory = load_inventory(_get_inventory_path())["devices"]
        try:
            device = find_device(inventory, device_id)
        except InventoryError as exc:
            abort(404, description=str(exc))

        username, password, secret = _get_device_credentials(device_id)
        detail = get_device_detail(device, username, password, secret or None)
        activity = get_activity_log(device_id, limit=100)

        return render_template(
            "device_info.html",
            title=f"Detail — {device['name']}",
            device=device,
            detail=detail,
            activity=activity,
        )

    @app.route("/api/device/<device_id>/log")
    @login_required
    def api_device_log(device_id: str):
        entries = get_activity_log(device_id, limit=100)
        return jsonify({"ok": True, "entries": entries})

    @app.route("/api/device/<device_id>/detail")
    @login_required
    def api_device_detail(device_id: str):
        inventory = load_inventory(_get_inventory_path())["devices"]
        try:
            device = find_device(inventory, device_id)
        except InventoryError as exc:
            return jsonify({"ok": False, "error": str(exc)})
        username, password, secret = _get_device_credentials(device_id)
        detail = get_device_detail(device, username, password, secret or None)
        return jsonify({"ok": True, "detail": detail})

    @app.route("/devices")
    @login_required
    def devices_page():
        inventory = load_inventory(_get_inventory_path())["devices"]
        statuses = _get_device_statuses(inventory)
        for device in inventory:
            device["status"] = statuses.get(str(device["id"]), "unknown")
        return render_template("devices.html", title="Devices", inventory=inventory)

    # ── PROFILE ───────────────────────────────────────────────

    @app.context_processor
    def inject_profile_ctx():
        if session.get("logged_in"):
            try:
                path = Path(current_app.config["PROFILE_PATH"])
                data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
                return {"topbar_avatar": data.get("avatar")}
            except Exception:
                pass
        return {"topbar_avatar": None}

    def _load_profile() -> dict:
        path = Path(current_app.config["PROFILE_PATH"])
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {}

    def _save_profile(data: dict):
        path = Path(current_app.config["PROFILE_PATH"])
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    @app.route("/profile")
    @login_required
    def profile():
        data = _load_profile()
        username = data.get("username") or current_app.config["WEB_USERNAME"]
        avatar = data.get("avatar")
        return render_template(
            "profile.html",
            title="Profile",
            username=username,
            avatar=avatar,
        )

    @app.route("/profile/save", methods=["POST"])
    @login_required
    def profile_save():
        field = request.form.get("field", "").strip()
        value = request.form.get("value", "").strip()

        if field not in ("username", "password"):
            return jsonify({"ok": False, "message": "Field tidak valid."})
        if not value:
            return jsonify({"ok": False, "message": "Value tidak boleh kosong."})

        data = _load_profile()
        data[field] = value
        _save_profile(data)

        # Update runtime config agar login langsung pakai kredensial baru
        if field == "username":
            current_app.config["WEB_USERNAME"] = value
            session["web_username"] = value
        elif field == "password":
            current_app.config["WEB_PASSWORD"] = value

        return jsonify({"ok": True})

    @app.route("/profile/avatar/delete", methods=["POST"])
    @login_required
    def profile_avatar_delete():
        """Hapus foto profil — buang file dari disk dan kosongkan field avatar di profile.json."""
        data = _load_profile()
        old_filename = data.pop("avatar", None)
        _save_profile(data)
        if old_filename:
            old_path = Path(current_app.config["UPLOAD_FOLDER"]) / old_filename
            if old_path.exists():
                old_path.unlink()
        return jsonify({"ok": True})

    @app.route("/profile/avatar", methods=["POST"])
    @login_required
    def profile_avatar():
        file = request.files.get("avatar")
        if not file or not file.filename:
            return jsonify({"ok": False, "message": "Tidak ada file dipilih."})

        ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
        if ext not in {"png", "jpg", "jpeg", "gif", "webp"}:
            return jsonify({"ok": False, "message": "Format tidak didukung (png/jpg/gif/webp)."})

        upload_dir = Path(current_app.config["UPLOAD_FOLDER"])
        upload_dir.mkdir(parents=True, exist_ok=True)

        filename = f"avatar.{ext}"
        file.save(upload_dir / filename)

        data = _load_profile()
        data["avatar"] = filename
        _save_profile(data)

        return jsonify({"ok": True, "url": url_for("static", filename=f"uploads/{filename}")})
