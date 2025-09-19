# Task.md – NAT & Port Forwarding Web UI

## 🔧 Setup Lingkungan
- [ ] Buat project Go (module init, dependencies minimal).
- [ ] Siapkan struktur folder (cmd, internal, web/static, configs, etc).
- [ ] Buat file config default `/etc/netnat/config.yml`.
- [ ] Implementasi systemd unit dengan `CAP_NET_ADMIN`.

## 🌐 Backend (Go)
- [ ] Implementasi config loader (YAML).
- [ ] Implementasi penyimpanan rules (rules.json).
- [ ] Fungsi enable IPv4 forwarding (sysctl).
- [ ] Fungsi apply NAT masquerade.
- [ ] Fungsi CRUD rules DNAT.
- [ ] Fungsi persist rules (nftables prefer, iptables fallback).
- [ ] Fungsi detect public interface (default route).
- [ ] Fungsi detect VM (qm, pct, arp, qga fallback).
- [ ] API endpoints (status, config, NAT, rules, VMs, dry-run, rollback).

## 🖥️ Frontend (Bootstrap + JS)
- [ ] Layout dasar dengan Bootstrap (Navbar, Card, Table, Modal).
- [ ] Halaman Dashboard NAT (status, toggle NAT/hairpin, tombol apply).
- [ ] Tabel Rules DNAT (list, add, edit, delete, toggle).
- [ ] Modal Add/Edit Rule dengan validasi (port, IP, proto).
- [ ] Tabel VM/CT dengan tombol *Forward Port* (prefill IP jika ada).
- [ ] Alert/Toast untuk notifikasi sukses/gagal.
- [ ] Drawer/Modal untuk Dry-run diff.

## 🔒 Security
- [ ] Tambahkan Basic Auth login.
- [ ] Tambahkan CSRF token untuk request mutasi.
- [ ] Batasi rate limit API.
- [ ] Default listen di 127.0.0.1:9090.

## 🧪 Testing & Acceptance
- [ ] Pastikan service start → NAT & ip_forward aktif.
- [ ] VM di `vmbr1` bisa akses internet.
- [ ] Tambah rule DNAT → port forwarding langsung aktif.
- [ ] Reboot host → rules tetap ada.
- [ ] Validasi port/proto duplikat dicegah.
- [ ] Dry-run menampilkan diff.
- [ ] Hybrid IP discovery: tampilkan IP auto (agent/ARP) atau manual input.

---

## 🎯 Selesai jika:
- Semua checklist tercentang.
- Web UI sederhana jalan lancar di host Proxmox.
- Rules NAT/DNAT persist & survive reboot.
- User bisa dengan mudah pilih VM lalu tambahkan port forwarding.
