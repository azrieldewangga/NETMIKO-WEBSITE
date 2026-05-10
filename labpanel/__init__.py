from __future__ import annotations

import json
import logging
import os
import secrets
import uuid
from pathlib import Path

from dotenv import load_dotenv, set_key
from flask import Flask, flash, redirect, request, session, url_for
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFError
from werkzeug.security import generate_password_hash

from .extensions import csrf, limiter
from .routes import register_routes


PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = PACKAGE_DIR.parent
ENV_PATH = PROJECT_DIR / ".env"

log = logging.getLogger(__name__)


def _ensure_env_file() -> None:
    """Buat .env dari .env.example jika belum ada, lalu load ke os.environ."""
    if not ENV_PATH.exists():
        example = PROJECT_DIR / ".env.example"
        if example.exists():
            ENV_PATH.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
            log.info(".env dibuat dari .env.example")
        else:
            # Buat minimal .env kalau .env.example juga tidak ada
            ENV_PATH.write_text(
                "FLASK_SECRET_KEY=\n"
                "WEB_USERNAME=admin\n"
                "WEB_PASSWORD=admin\n"
                "LAB_DEVICE_USERNAME=admin\n"
                "LAB_DEVICE_PASSWORD=admin\n"
                "LAB_DEVICE_SECRET=\n",
                encoding="utf-8",
            )
            log.info(".env dibuat dengan nilai default")

    # Pastikan FLASK_SECRET_KEY terisi — generate sekali lalu tulis ke .env
    load_dotenv(ENV_PATH, override=True)
    if not os.environ.get("FLASK_SECRET_KEY", "").strip():
        generated = secrets.token_hex(32)
        set_key(str(ENV_PATH), "FLASK_SECRET_KEY", generated)
        os.environ["FLASK_SECRET_KEY"] = generated
        log.info("FLASK_SECRET_KEY di-generate dan disimpan ke .env")


def _bootstrap_users(users_path: Path, web_user: str, web_pass: str) -> None:
    """
    Pastikan users.json selalu ada dan minimal punya satu super_admin.

    Migrasi: jika users.json belum ada, buat akun super_admin pertama
    dari kredensial WEB_USERNAME/WEB_PASSWORD yang sudah ada di .env / profile.json.
    Ini menjamin login lama tetap berfungsi tanpa konfigurasi ulang.
    """
    if users_path.exists():
        # Validasi: pastikan strukturnya ok
        try:
            data = json.loads(users_path.read_text(encoding="utf-8"))
            if isinstance(data.get("users"), list):
                return  # Sudah valid, tidak perlu apa-apa
        except Exception:
            pass

    # Buat users.json dari scratch dengan satu akun super_admin
    log.info("Membuat users.json — migrasi dari kredensial .env lama.")
    initial_user = {
        "id": str(uuid.uuid4()),
        "username": web_user,
        "password_hash": generate_password_hash(web_pass),
        "role": "super_admin",
        "display_name": web_user.capitalize(),
        "avatar": None,
        "created_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "active": True,
    }
    users_path.write_text(
        json.dumps({"users": [initial_user]}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    log.info("Akun super_admin '%s' berhasil dibuat di users.json.", web_user)


def create_app(test_config: dict | None = None) -> Flask:
    _ensure_env_file()

    app = Flask(
        __name__,
        template_folder=str(PROJECT_DIR / "templates"),
        static_folder=str(PROJECT_DIR / "static"),
    )

    # ── Secret Key ────────────────────────────────────────────
    secret_key = os.environ["FLASK_SECRET_KEY"]

    # ── Baca kredensial lama (untuk migrasi ke users.json) ───
    web_user = os.environ.get("WEB_USERNAME", "admin")
    web_pass = os.environ.get("WEB_PASSWORD", "admin")

    # Override dengan profile.json jika ada (backward compat)
    profile_path = PROJECT_DIR / "profile.json"
    if profile_path.exists():
        try:
            _profile = json.loads(profile_path.read_text(encoding="utf-8"))
            if _profile.get("username"):
                web_user = _profile["username"]
            if _profile.get("password"):
                web_pass = _profile["password"]
        except Exception:
            pass

    if web_user == "admin" and web_pass == "admin":
        log.warning(
            "WEB_USERNAME/WEB_PASSWORD masih default (admin/admin). "
            "Ganti segera melalui User Management!"
        )

    device_user = os.environ.get("LAB_DEVICE_USERNAME", "admin")
    device_pass = os.environ.get("LAB_DEVICE_PASSWORD", "admin")
    if device_user == "admin" and device_pass == "admin":
        log.warning(
            "⚠  LAB_DEVICE_USERNAME/LAB_DEVICE_PASSWORD masih default (admin/admin). "
            "Ganti segera untuk keamanan!"
        )

    users_path = PROJECT_DIR / "users.json"

    app.config.from_mapping(
        SECRET_KEY=secret_key,
        WTF_CSRF_ENABLED=True,
        # Credentials lama masih disimpan di config untuk background scan
        WEB_USERNAME=web_user,
        WEB_PASSWORD=web_pass,
        LAB_DEVICE_USERNAME=device_user,
        LAB_DEVICE_PASSWORD=device_pass,
        LAB_DEVICE_SECRET=os.environ.get("LAB_DEVICE_SECRET", ""),
        INVENTORY_PATH=str(PROJECT_DIR / "inventory.json"),
        PROFILE_PATH=str(PROJECT_DIR / "profile.json"),
        USERS_PATH=str(users_path),
        UPLOAD_FOLDER=str(PROJECT_DIR / "static" / "uploads"),
    )
    if test_config:
        app.config.update(test_config)

    # ── Bootstrap users.json (migrasi otomatis) ───────────────
    _bootstrap_users(users_path, web_user, web_pass)

    # ── Extensions ────────────────────────────────────────────
    csrf.init_app(app)
    limiter.init_app(app)

    # Flask-Talisman: HTTP security headers
    # force_https=False karena ini biasanya diakses di lab lokal
    Talisman(
        app,
        force_https=False,
        content_security_policy={
            "default-src": "'self'",
            "script-src": ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net"],
            "style-src": ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "fonts.googleapis.com"],
            "font-src": ["'self'", "fonts.gstatic.com"],
            "img-src": ["'self'", "data:"],
        },
        session_cookie_secure=False,  # lab biasanya HTTP
        session_cookie_samesite="Lax",
    )

    register_routes(app)

    @app.errorhandler(CSRFError)
    def handle_csrf_error(exc):
        # Pulihkan UX ketika form token invalid/stale karena tab lama atau session reset.
        if request.endpoint == "login" and session.get("logged_in"):
            return redirect(url_for("dashboard"))

        session.pop("csrf_token", None)
        flash("Sesi formulir sudah tidak valid. Silakan coba kirim ulang form.", "error")
        log.warning("CSRF rejected at %s: %s", request.path, exc.description)
        if request.endpoint == "login":
            return redirect(url_for("login"))
        return redirect(request.referrer or (url_for("dashboard") if session.get("logged_in") else url_for("login")))

    log.info("Topology Panel started on http://0.0.0.0:5000")

    return app
