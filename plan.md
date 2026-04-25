# 📋 Rencana Pengembangan — Topology-Aware Web Panel

> Dokumen ini mencakup tiga area perbaikan utama yang akan dilakukan secara bertahap.

---

## 1. 🔧 Upgrade Penggunaan Netmiko

### 1.1 Ganti parser manual dengan `use_textfsm=True`
- **File:** `automation.py`
- **Masalah:** `parse_interface_brief()` ditulis manual ~30 baris, rentan salah parsing jika output CLI berbeda
- **Solusi:** Gunakan `send_command("show ip interface brief", use_textfsm=True)` → otomatis parse lewat NTC Templates
- **Tambahan:** Perlu install `ntc-templates` → `pip install ntc-templates`

### 1.2 Ganti `send_command("write memory")` dengan `save_config()`
- **File:** `automation.py` → fungsi `apply_interface_action()`
- **Masalah:** Hardcode di Cisco IOS. Jika suatu saat pakai Juniper / Arista, akan error
- **Solusi:** `connection.save_config()` → platform-aware, otomatis pilih perintah yang tepat

### 1.3 Tambahkan `session_log` (Audit Trail SSH)
- **File:** `automation.py` → `build_connection_params()`
- **Solusi:** Log setiap sesi SSH ke file `logs/<device_id>_<timestamp>.log`
- **Manfaat:** Debug mudah, bisa dipakai untuk audit keamanan

### 1.4 Aktifkan `fast_cli=True`
- **File:** `automation.py` → `build_connection_params()`
- **Manfaat:** Mempercepat komunikasi SSH, penting untuk Batch Actions ke banyak device

### 1.5 (Bonus) Tambah fitur `show_command` bebas via UI
- **File:** `routes.py`, `device.html`
- **Deskripsi:** Form input untuk kirim arbitrary show command dan tampilkan outputnya (dengan TextFSM jika tersedia)

---

## 2. 🔒 Audit Keamanan

### 2.1 🔴 KRITIS — Secret Key default tidak aman
- **File:** `labpanel/__init__.py` baris 25
- **Masalah:** `SECRET_KEY` default `"dev-secret-change-me"` — jika env var tidak di-set, Flask berjalan dengan key yang diketahui publik. Session bisa dipalsukan.
- **Solusi:** Generate random key saat startup jika env var tidak ada, dan tampilkan **WARNING** ke console agar admin sadar

### 2.2 🔴 KRITIS — Tidak ada rate limiting di endpoint login
- **File:** `labpanel/routes.py` → route `/login`
- **Masalah:** Tidak ada batas percobaan login → rentan brute-force attack
- **Solusi:** Implementasi simple rate limiter dengan `flask-limiter` (`pip install flask-limiter`), batasi 10 request/menit per IP

### 2.3 🟠 SEDANG — Password SSH tersimpan di memory session tanpa enkripsi
- **File:** `labpanel/routes.py` → `_save_device_credentials()`
- **Masalah:** Kredensial SSH disimpan plaintext di server-side session (Flask session di memory). Jika session di-export/di-dump, password langsung terbaca.
- **Solusi:** Enkripsi value kredensial sebelum disimpan ke session menggunakan `Fernet` dari library `cryptography`

### 2.4 🟠 SEDANG — Tidak ada HTTP security headers
- **File:** `labpanel/__init__.py`
- **Masalah:** Tidak ada header `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`, dll.
- **Solusi:** Tambahkan `flask-talisman` (`pip install flask-talisman`) untuk set security headers otomatis

### 2.5 🟠 SEDANG — CDN eksternal tanpa Subresource Integrity (SRI)
- **File:** `templates/base.html` baris 11 & 75
- **Masalah:** Toastify dimuat dari jsDelivr CDN tanpa SRI hash → jika CDN dikompromikan, script berbahaya bisa diinjeksi
- **Solusi:** Tambahkan atribut `integrity="sha384-..."` dan `crossorigin="anonymous"` pada tag `<link>` dan `<script>` CDN

### 2.6 🟡 RENDAH — `inventory.json` dapat dimodifikasi tanpa validasi schema
- **File:** `automation.py` → `load_inventory()`
- **Masalah:** Validasi hanya cek tipe dasar. Tidak ada validasi format IP/hostname, range port, atau whitelist `device_type`
- **Solusi:** Tambahkan validasi: format IP (`ipaddress.ip_address`), port range 1-65535, whitelist `device_type`

### 2.7 🟡 RENDAH — Web credentials di-hardcode di config
- **File:** `labpanel/__init__.py` baris 27-28
- **Masalah:** Default `admin/admin` bisa lupa diganti
- **Solusi:** Tampilkan WARNING jelas di startup log jika menggunakan kredensial default

---

## 3. 🎨 Redesain Frontend

### Filosofi Desain Baru
- **Tema:** Dark mode premium, terinspirasi terminal/monitoring tool profesional (seperti Grafana, Datadog)
- **Warna:** Deep navy + electric cyan/teal accent, bukan plain indigo
- **Tipografi:** `JetBrains Mono` untuk nilai teknis/IP/interface, `Inter` untuk teks UI
- **Feel:** Glassmorphism subtle, glow effects pada status aktif, animasi smooth

### 3.1 Redesain `styles.css` — Design System Baru
- Palet warna baru: dark navy (`#080d1a`), surface dengan glass effect
- Accent: `#00d4ff` (cyan electric) sebagai warna utama
- Tambahkan CSS variables baru: `--glow`, `--glass`, `--font-mono`
- Navbar: tambahkan gradient accent bar di bawah logo
- Cards: glassmorphism border + subtle glow on hover
- Table rows: highlight berwarna saat hover (bukan polos)
- Status dots: animasi pulse untuk device aktif
- Badges role: warna berbeda per role (router=cyan, switch=purple, dll.)

### 3.2 Redesain `base.html` — Layout & Navigasi
- Navbar: tambahkan ikon (🔷 atau SVG), breadcrumb, dan indikator halaman aktif
- Tambahkan sidebar kolapsibel di desktop untuk navigasi cepat
- Footer kecil dengan versi app dan waktu server

### 3.3 Redesain `login.html` — Halaman Login
- Full-screen centered layout dengan background animated grid/topology pattern
- Card login dengan glassmorphism, logo besar di atas
- Input dengan floating label animation
- Button dengan gradient dan glow effect

### 3.4 Redesain `dashboard.html` — Dashboard Utama
- Tambahkan summary stats bar di atas: total device, device aktif, device nonaktif
- Device table → Device cards grid (bukan tabel biasa):
  - Setiap card: nama device, IP+port, status dot berpulse, role badge berwarna, tombol Open
- Quick Connect: pindahkan ke modal/drawer, bukan card bawah yang full-width

### 3.5 Redesain `device.html` — Halaman Device Detail
- Header lebih informatif: breadcrumb + status koneksi real-time
- Interface table: highlight warna per status (up=hijau-glow, down=merah-dim, unassigned=abu-abu)
- Action panel: grouping yang lebih jelas antara konfigurasi IP vs konfigurasi sistem
- Terminal-style output panel untuk Raw CLI (bukan `<details>` polos)
- Konfirmasi dialog: lebih dramatis dengan warna merah solid + ikon warning besar

### 3.6 Redesain `batch.html` — Batch Actions
- Textarea batch: editor-style dengan line numbers dan syntax highlight sederhana
- Results panel: split view sukses/gagal lebih visual (progress bar jumlah berhasil)
- Inventory sidebar: tampilkan sebagai chip/badge bisa diklik untuk autocomplete device ID

---

## 📐 Urutan Implementasi

```
Phase 1 (Security — KRITIS dulu)
  ├─ Rate limiting login
  └─ Secret key warning + random fallback

Phase 2 (Netmiko Upgrade)
  ├─ use_textfsm=True + install ntc-templates
  ├─ save_config()
  ├─ fast_cli=True
  └─ session_log

Phase 3 (Security — Lanjutan)
  ├─ flask-talisman (security headers)
  ├─ SRI pada CDN
  └─ Validasi inventory schema

Phase 4 (Frontend Redesign)
  ├─ Design system baru (styles.css)
  ├─ base.html + login.html
  ├─ dashboard.html
  ├─ device.html
  └─ batch.html
```
