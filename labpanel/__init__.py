from __future__ import annotations

import logging
import os
import secrets
from pathlib import Path

from flask import Flask
from flask_talisman import Talisman

from .extensions import csrf, limiter
from .routes import register_routes


PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = PACKAGE_DIR.parent

log = logging.getLogger(__name__)


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(
        __name__,
        template_folder=str(PROJECT_DIR / "templates"),
        static_folder=str(PROJECT_DIR / "static"),
    )

    # ── Secret Key ────────────────────────────────────────────
    secret_key = os.environ.get("FLASK_SECRET_KEY")
    if not secret_key:
        secret_key = secrets.token_hex(32)
        log.warning(
            "⚠  FLASK_SECRET_KEY belum di-set! Menggunakan key acak — "
            "session akan hilang setiap restart. Set env var FLASK_SECRET_KEY "
            "untuk produksi."
        )

    # ── Cek kredensial default ────────────────────────────────
    web_user = os.environ.get("WEB_USERNAME", "admin")
    web_pass = os.environ.get("WEB_PASSWORD", "admin")
    if web_user == "admin" and web_pass == "admin":
        log.warning(
            "⚠  WEB_USERNAME/WEB_PASSWORD masih default (admin/admin). "
            "Ganti segera untuk keamanan!"
        )

    device_user = os.environ.get("LAB_DEVICE_USERNAME", "admin")
    device_pass = os.environ.get("LAB_DEVICE_PASSWORD", "admin")
    if device_user == "admin" and device_pass == "admin":
        log.warning(
            "⚠  LAB_DEVICE_USERNAME/LAB_DEVICE_PASSWORD masih default (admin/admin). "
            "Ganti segera untuk keamanan!"
        )

    app.config.from_mapping(
        SECRET_KEY=secret_key,
        WTF_CSRF_ENABLED=True,
        WEB_USERNAME=web_user,
        WEB_PASSWORD=web_pass,
        LAB_DEVICE_USERNAME=device_user,
        LAB_DEVICE_PASSWORD=device_pass,
        LAB_DEVICE_SECRET=os.environ.get("LAB_DEVICE_SECRET", ""),
        INVENTORY_PATH=str(PROJECT_DIR / "inventory.json"),
    )
    if test_config:
        app.config.update(test_config)

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

    log.info("Topology Panel started on http://0.0.0.0:5000")

    return app
