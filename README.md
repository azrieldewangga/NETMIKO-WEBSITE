# 🌐 Topology-Aware Web Panel

Web dashboard berbasis **Flask** untuk mengelola perangkat jaringan **Cisco IOS** secara remote via SSH — tanpa perlu buka terminal. Dibuat sebagai bagian dari seri *YouTube Network Automation*.

---

## 📋 Fitur

| Fitur | Keterangan |
|---|---|
| **Login / Logout** | Autentikasi berbasis session dengan proteksi CSRF |
| **Dashboard** | Tampil daftar semua device dari `inventory.json` |
| **Device Detail** | Lihat interface aktif, ubah IP, deskripsi, atau SSH port |
| **Quick Connect** | Koneksi ad-hoc ke device di luar inventory |
| **Batch Actions** | Kirim konfigurasi ke banyak device sekaligus (format CSV) |
| **Per-device Credentials** | Simpan kredensial SSH per device dalam session |
| **Sanitasi CLI** | Cegah injeksi karakter berbahaya ke perintah Cisco |
| **Konfirmasi Aksi Destruktif** | Aksi `delete`, `change`, `ssh_port` minta konfirmasi |

---

## 🗂️ Struktur Proyek

```
.11.Topology_Aware_Web_Panel/
├── app.py              # Entry point Flask server
├── automation.py       # Core: koneksi SSH, konfigurasi, parsing, batch
├── inventory.json      # Daftar device (host, port, tipe, role)
├── labpanel/
│   ├── __init__.py     # Flask app factory + CSRF init
│   └── routes.py       # Semua URL endpoint
├── templates/          # Template HTML (Jinja2)
│   ├── base.html
│   ├── login.html
│   ├── dashboard.html
│   ├── device.html
│   └── batch.html
└── static/             # Aset CSS / JS
```

---

## ⚙️ Instalasi & Menjalankan

### 1. Install dependensi

```bash
pip install flask flask-wtf netmiko
```

### 2. (Opsional) Atur environment variable

Linux/macOS:

```bash
export FLASK_SECRET_KEY="ganti-dengan-secret-panjang"
export WEB_USERNAME="admin"
export WEB_PASSWORD="admin"

# Kredensial default SSH buat semua device
export LAB_DEVICE_USERNAME="admin"
export LAB_DEVICE_PASSWORD="admin"
export LAB_DEVICE_SECRET=""
```

Windows (PowerShell):

```powershell
setx FLASK_SECRET_KEY "ganti-dengan-secret-panjang"
setx WEB_USERNAME "admin"
setx WEB_PASSWORD "admin"
setx LAB_DEVICE_USERNAME "admin"
setx LAB_DEVICE_PASSWORD "admin"
setx LAB_DEVICE_SECRET ""
```

Jika `FLASK_SECRET_KEY` tidak di-set, aplikasi akan memakai fallback file lokal `.secret_key` agar session tetap stabil saat restart di development.

### 3. Jalankan server

```bash
python app.py
# Akses di: http://localhost:5000
```

---

## 📦 Inventory Device

Device dikelola di `inventory.json`. Tambahkan device baru dengan format:

```json
[
  {
    "id": "r1",
    "name": "r1",
    "host": "192.168.56.11",
    "port": 22,
    "device_type": "cisco_ios",
    "role": "router",
    "enabled": true
  }
]
```

| Field | Keterangan |
|---|---|
| `id` | Identifier unik device |
| `name` | Nama tampilan di dashboard |
| `host` | IP / hostname perangkat |
| `port` | Port SSH (default: `22`) |
| `device_type` | Tipe Netmiko, contoh: `cisco_ios`, `cisco_xr` |
| `role` | Label peran: `router`, `switch`, dll. |
| `enabled` | `true`/`false` — apakah muncul di dashboard |

> ⚠️ **Auto-discovery TIDAK tersedia.** Device baru harus ditambahkan secara manual ke `inventory.json` agar muncul di dashboard.

---

## 🔄 Alur Kerja Aplikasi

```
Browser → Login → Dashboard (daftar inventory)
                      │
          ┌───────────┼────────────────┐
          ▼           ▼                ▼
    Device Detail  Quick Connect   Batch Actions
    (SSH otomatis) (ad-hoc host)  (multi-device CSV)
          │
    ┌─────┴──────┐
    ▼            ▼
  Aksi Normal  Aksi Destruktif
  (langsung)   → Dialog Konfirmasi → Apply + write memory
```

---

## 🔒 Keamanan

- **CSRF Protection** via `Flask-WTF` (token di setiap form POST)
- **Sanitasi input CLI** — karakter seperti `;`, `|`, `&`, newline diblokir
- **Kredensial SSH** disimpan di server-side session, **bukan** di cookie
- `SECRET_KEY` dan semua kredensial sebaiknya diatur via **environment variable** di produksi

---

## 📝 Format Batch Actions

Setiap baris di halaman Batch menggunakan format:

```
device1;device2, interface, action, value
```

Contoh:

```
r1;r2, GigabitEthernet0/0, add, 10.0.0.1/30
r3,     GigabitEthernet0/1, description, Uplink ke ISP
r1,     ,                   ssh_port,    2222
# Baris ini diabaikan (komentar)
```

| Action | Keterangan |
|---|---|
| `add` / `change` | Set IP address (CIDR) |
| `delete` / `remove` | Hapus IP dari interface |
| `description` | Ubah deskripsi interface |
| `ssh_port` | Ubah port SSH global router |

---

## 🧰 Teknologi

- **Python 3.10+**
- **Flask** — web framework
- **Flask-WTF** — CSRF protection
- **Netmiko** — library SSH untuk perangkat jaringan

---

## 🚫 Yang Tidak Boleh Di-push Ke Git Public

- File rahasia lokal: `.secret_key`, `.env`, `.env.*`
- File log runtime: `logs/*.log`
- Cache build Python: `__pycache__/`, `*.pyc`
- File lokal editor/agent: `.claude/settings.local.json`, `.vscode/`, `.idea/`

Semua pola di atas sudah dimasukkan ke `.gitignore`.

### Kalau sudah terlanjur ke-track Git

Jalankan perintah ini sekali untuk melepas dari tracking (file lokal tetap ada):

```bash
git rm --cached .secret_key
git rm --cached -r __pycache__ labpanel/__pycache__
git rm --cached logs/*.log
git rm --cached .claude/settings.local.json
git add .gitignore
git commit -m "chore: ignore local secrets and runtime artifacts"
```

---

## ✅ Agar Clone di VM Tidak Rusak

1. Clone repo biasa.
2. Atur environment variable di VM (lihat bagian Instalasi).
3. Jalankan aplikasi; file `.secret_key` dan folder `logs/` akan dibuat otomatis jika belum ada.

Dengan pola ini, repo aman untuk public, tapi tetap langsung bisa dipakai di mesin baru.
