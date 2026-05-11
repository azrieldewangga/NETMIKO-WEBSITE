# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the App

```bash
pip install flask flask-wtf flask-talisman flask-limiter netmiko python-dotenv psutil werkzeug
python app.py
# Access at: http://localhost:5000
```

The `.env` file is auto-created from `.env.example` on first run. `FLASK_SECRET_KEY` is auto-generated and persisted to `.env` if not set.

## Architecture

**Request flow:** Browser → `labpanel/routes.py` → `automation.py` → Netmiko → Cisco device

### Module roles

- **`app.py`** — entry point, calls `create_app()` and runs the Flask dev server
- **`labpanel/__init__.py`** — app factory: loads `.env`, bootstraps `users.json` from old `.env` credentials (migration), initializes CSRF/rate-limiter/Talisman, calls `register_routes(app)`
- **`labpanel/extensions.py`** — shared `csrf` and `limiter` instances; exists only to break circular imports
- **`labpanel/routes.py`** — all URL handlers in one file, registered via `register_routes(app)`; also owns in-memory caches and background threads
- **`automation.py`** — pure SSH/network layer; no Flask imports; all Netmiko interaction happens here

### Data files

| File | Purpose |
|---|---|
| `inventory.json` | Device list + topology links + switch info. Supports legacy list format (auto-migrated to dict format on load) |
| `users.json` | Multi-user accounts with bcrypt-hashed passwords; auto-bootstrapped from `.env` credentials on first run |
| `logs/activity_<device_id>.json` | Per-device activity log, max 500 entries (newest appended, oldest trimmed) |
| `logs/<device_id>_<timestamp>.log` | Netmiko session logs from full SSH sessions |

### RBAC

Three roles in `ROLE_HIERARCHY`: `user` (0) → `admin` (1) → `super_admin` (2).
- `user`: read-only (dashboard, device info, terminal view)
- `admin`: can execute SSH actions (device config, batch, terminal connect)
- `super_admin`: admin + user management (`/admin/users`)

Decorators: `@login_required` and `@role_required("admin", "super_admin")` in `routes.py`.

### Credential priority chain

SSH credentials resolve in this order for each request:
1. Form field (explicit input)
2. Per-device session key (`creds_<device_id>`)
3. Global session key (set from batch/settings modal)
4. App config defaults (from `.env`)

Credentials are stored server-side in the Flask session, never in cookies.

### Background threads (started in `register_routes`)

- **Status refresh loop** — SSH-polls all inventory devices every 120 s; result stored in `_status_cache`. Non-blocking from request perspective.
- **Background scan on login** — one-shot CDP BFS topology discovery triggered once per session; updates `inventory.json` by merging discovered devices (offline devices are preserved).
- **Interface cache** (`_iface_cache`) — SSH result for `show ip interface brief` per device, 120 s TTL. Invalidated after any config action on that device.

### Topology discovery (`automation.py`)

`scan_network()` → if inventory has seeds: BFS via `discover_topology()` using CDP (`show cdp neighbors detail`) to walk the network hop by hop. If inventory is empty: ping-sweep local subnets → SSH autodetect → BFS. Links are deduped bidirectionally (frozenset pair).

### Batch actions

Structured batch (`/batch`): CSV-like format `device1;device2, interface, action, value` — parsed by `parse_batch_rows()`, executed by `execute_batch()` sequentially per device.

Raw CLI batch (`/batch/raw`): block format `[r1, r2]\ncmd1\ncmd2` — parsed inline in the route, executed in parallel via `batch_raw_cli()`.

### Terminal sessions

Persistent Netmiko connections stored in `_shell_sessions` dict (UUID → conn + device). Commands sent via `terminal_send()` which uses `send_command_timing` to handle commands with no output (e.g., `conf t`). Destructive commands (`reload`, `write erase`, etc.) are blocked by `_TERMINAL_BLOCKED` regex in `automation.py`.

### Supported device types (whitelist)

`cisco_ios`, `cisco_xe`, `cisco_xr`, `cisco_nxos`, `cisco_asa`, `arista_eos`, `juniper_junos`, `huawei`, `mikrotik_routeros`, `linux`, `autodetect`

Validated in `_parse_device_list()` and `add_device_to_inventory()`.

## Security constraints

- CLI injection prevention: `sanitize_cli_value()` strips `[\r\n\x00-\x1f\x7f|;&\`$]` and enforces 200-char max before any value reaches a Cisco command
- Destructive actions (`delete`, `change`, `ssh_port`, etc.) require `confirmed=1` in the form POST
- CSRF protection on all form submissions via Flask-WTF
- HTTP security headers via Flask-Talisman (`force_https=False` because this is a local lab tool)
- Rate limit on `/login`: 10 requests/minute

## Inventory JSON format

```json
{
  "devices": [{"id": "r1", "name": "r1", "host": "192.168.56.11", "port": 22, "device_type": "cisco_ios", "role": "router", "enabled": true}],
  "links": [{"from": "r1", "from_intf": "Gi0/0", "to": "r2", "to_intf": "Gi0/0"}],
  "switch": {"name": "switch", "host": "192.168.56.1"}
}
```

`_load_raw_inventory` / `_save_raw_inventory` in `automation.py` do direct JSON reads/writes for internal operations. `load_inventory` adds validation and auto-migrates the old list format.
