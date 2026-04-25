from __future__ import annotations

from functools import wraps
from pathlib import Path

from flask import abort, flash, current_app, redirect, render_template, request, session, url_for

from .extensions import limiter

from automation import (
    ActionError,
    ConnectionError,
    InventoryError,
    apply_interface_action,
    execute_batch,
    find_device,
    get_interface_summary,
    load_inventory,
    parse_batch_rows,
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
    Prioritas: isian form -> session key tiap perangkat -> config bawaan global.
    """
    form = form or request.form
    cred_key = _cred_key(device_id)
    stored = session.get(cred_key, {})

    username = (
        form.get("device_username")
        or stored.get("username")
        or current_app.config["LAB_DEVICE_USERNAME"]
    ).strip()
    password = (
        form.get("device_password")
        or stored.get("password")
        or current_app.config["LAB_DEVICE_PASSWORD"]
    )
    secret = (
        form.get("device_secret")
        or stored.get("secret")
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
    device_type = (form.get("device_type") or device.get("device_type") or "cisco_ios").strip()
    label = (form.get("label") or device.get("name") or device.get("id") or host).strip()
    return {
        "host": host,
        "port": port,
        "device_type": device_type,
        "label": label,
    }


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def register_routes(app):
    @app.route("/")
    @login_required
    def dashboard():
        try:
            inventory = load_inventory(_get_inventory_path())
        except InventoryError as exc:
            flash(str(exc), "error")
            inventory = []
        # Dashboard CUMA muat daftar inventory — gak otomatis SSH ke router.
        return render_template(
            "dashboard.html",
            title="Topology Dashboard",
            inventory=inventory,
        )

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("10/minute")
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            if username == current_app.config["WEB_USERNAME"] and password == current_app.config["WEB_PASSWORD"]:
                session.clear()
                session["logged_in"] = True
                session["web_username"] = username
                flash("Login berhasil.", "success")
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
        inventory = load_inventory(_get_inventory_path())
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
            username, password, secret = _get_device_credentials(device_id, request.form)

            action = request.form.get("action", "").strip()
            interface = request.form.get("interface", "").strip()
            value = request.form.get("value", "").strip()
            confirmed = request.form.get("confirmed") == "1"

            # Wajibin konfirmasi eksplisit buat aksi destruktif
            destructive = action.lower() in {"delete", "remove", "unset", "change", "ssh_port"}
            if action and destructive and not confirmed:
                # Balik ke halaman buat nampilin flag konfirmasi
                username, password, secret = _get_device_credentials(device_id)
                try:
                    interfaces, raw_output = get_interface_summary(
                        device, username=username, password=password, secret=secret,
                        host=connection["host"], port=connection["port"],
                        device_type=connection["device_type"],
                    )
                    connected = True
                except (ConnectionError, ValueError) as exc:
                    error = str(exc)
                return render_template(
                    "device.html",
                    title=f"Device {device['id']}",
                    device={**connection, "id": device["id"]},
                    form_action=url_for("device_detail", device_id=device["id"]),
                    interfaces=interfaces,
                    raw_output=raw_output,
                    action_result=None,
                    error=error,
                    connected=connected,
                    pending_action={"action": action, "interface": interface, "value": value},
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
                            from automation import update_inventory_device
                            update_inventory_device(device_id, {"port": int(value)})
                            device["port"] = int(value)
                            connection["port"] = str(value)
                            flash(f"SSH Port router {device['id']} berhasil diubah ke {value} secara permanen.", "success")
                        else:
                            flash(f"Aksi '{action}' pada {device['id']}/{interface} berhasil.", "success")
                        connected = True
                    except (ConnectionError, ActionError, ValueError) as exc:
                        error = str(exc)

        # Ambil daftar interface (read-only) pake kredensial di cache atau yang diisi
        username, password, secret = _get_device_credentials(device_id)
        if not error:
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
                connected = True
            except (ConnectionError, ValueError) as exc:
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
            default_device_username=stored.get("username", current_app.config["LAB_DEVICE_USERNAME"]),
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
        username, password, secret = _get_device_credentials(ad_hoc_id, request.form)

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
                        flash(f"SSH Port pada {ad_hoc_id} berhasil diubah ke {value}.", "success")
                        connection["port"] = str(value)
                        transient_device["port"] = int(value)
                    else:
                        flash(f"Aksi '{action}' pada {ad_hoc_id}/{interface} berhasil.", "success")

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
        except (ConnectionError, ActionError, ValueError) as exc:
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
        inventory = load_inventory(_get_inventory_path())
        batch_rows = []
        parse_errors = []
        results = None

        if request.method == "POST":
            # Batch pake kredensial global session (admin set sekali dari modal seting di Dashboard)
            username = (request.form.get("device_username") or session.get("global_username") or current_app.config["LAB_DEVICE_USERNAME"]).strip()
            password = request.form.get("device_password") or session.get("global_password") or current_app.config["LAB_DEVICE_PASSWORD"]
            secret = request.form.get("device_secret") or session.get("global_secret") or current_app.config["LAB_DEVICE_SECRET"]

            if request.form.get("device_password"):
                session["global_username"] = username
                session["global_password"] = password
                session["global_secret"] = secret

            batch_rows, parse_errors = parse_batch_rows(request.form.get("batch_rows", ""))
            if not parse_errors:
                results = execute_batch(
                    inventory,
                    batch_rows,
                    username=username,
                    password=password,
                    secret=secret,
                )
                if results["successful"]:
                    flash(f"{len(results['successful'])} perubahan berhasil dijalankan.", "success")
                if results["failed"]:
                    flash(f"{len(results['failed'])} perubahan gagal dijalankan.", "error")
        return render_template(
            "batch.html",
            title="Batch Actions",
            inventory=inventory,
            batch_rows=batch_rows,
            parse_errors=parse_errors,
            results=results,
            default_device_username=session.get("global_username", current_app.config["LAB_DEVICE_USERNAME"]),
        )

    @app.route("/credentials/global", methods=["POST"])
    @login_required
    def save_global_credentials():
        """Simpen kredensial SSH global (yang dipake buat Batch) dari modal setting navbar."""
        session["global_username"] = request.form.get("device_username", "").strip() or current_app.config["LAB_DEVICE_USERNAME"]
        session["global_password"] = request.form.get("device_password", "") or current_app.config["LAB_DEVICE_PASSWORD"]
        session["global_secret"] = request.form.get("device_secret", "") or current_app.config["LAB_DEVICE_SECRET"]
        flash("Kredensial global disimpan untuk sesi ini.", "success")
        return redirect(request.referrer or url_for("dashboard"))
