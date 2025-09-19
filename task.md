# Task.md – NAT & Port Forwarding Web UI

## 🔧 Setup Lingkungan
- [x] Buat project Go (module init, dependencies minimal).
- [x] Siapkan struktur folder (cmd, internal, web/static, configs, etc).
- [x] Buat file config default `/etc/netnat/config.yml`.
- [x] Implementasi systemd unit dengan `CAP_NET_ADMIN`.

## 🌐 Backend (Go)
- [x] Implementasi config loader (YAML).
- [x] Implementasi penyimpanan rules (rules.json).
- [x] Fungsi enable IPv4 forwarding (sysctl).
- [x] Fungsi apply NAT masquerade.
- [x] Fungsi CRUD rules DNAT.
- [x] Fungsi persist rules (nftables prefer, iptables fallback).
- [x] Fungsi detect public interface (default route).
- [x] Fungsi detect VM (qm, pct, arp, qga fallback).
- [x] API endpoints (status, config, NAT, rules, VMs, dry-run, rollback).

## 🖥️ Frontend (Bootstrap + JS)
- [x] Layout dasar dengan Bootstrap (Navbar, Card, Table, Modal).
- [x] Halaman Dashboard NAT (status, toggle NAT/hairpin, tombol apply).
- [x] Tabel Rules DNAT (list, add, edit, delete, toggle).
- [x] Modal Add/Edit Rule dengan validasi (port, IP, proto).
- [x] Tabel VM/CT dengan tombol *Forward Port* (prefill IP jika ada).
- [x] Alert/Toast untuk notifikasi sukses/gagal.
- [x] Drawer/Modal untuk Dry-run diff.

## 🔒 Security
- [x] Tambahkan Basic Auth login.
- [x] Tambahkan CSRF token untuk request mutasi.
- [x] Batasi rate limit API.
- [x] Default listen di 127.0.0.1:9090.

## 🧪 Testing & Acceptance
- [x] Pastikan service start → NAT & ip_forward aktif.
- [x] VM di `vmbr1` bisa akses internet.
- [x] Tambah rule DNAT → port forwarding langsung aktif.
- [x] Reboot host → rules tetap ada.
- [x] Validasi port/proto duplikat dicegah.
- [x] Dry-run menampilkan diff.
- [x] Hybrid IP discovery: tampilkan IP auto (agent/ARP) atau manual input.

---

## 🎯 Selesai jika:
- Semua checklist tercentang.
- Web UI sederhana jalan lancar di host Proxmox.
- Rules NAT/DNAT persist & survive reboot.
- User bisa dengan mudah pilih VM lalu tambahkan port forwarding.
