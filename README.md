# Panduan: assess.sh v4.4 + Trivy di Kali

Alur: server (offline) → salin manual → Kali (ada internet) → unggah dua file hasil ke chat Claude.

## A. Siapkan Kali — sekali saja

Jalankan sebagai user khusus, bukan root, dan tanpa kredensial produksi di mesin ini.

```bash
sudo useradd -m -s /bin/bash trivyscan && sudo su - trivyscan
mkdir -p ~/trivy && cd ~/trivy

V=0.76.2
curl -fLO https://github.com/aquasecurity/trivy/releases/download/v$V/trivy_${V}_Linux-64bit.tar.gz
curl -fLO https://github.com/aquasecurity/trivy/releases/download/v$V/trivy_${V}_checksums.txt

# WAJIB: harus tertulis "OK". Kalau tidak, hapus file dan jangan dipakai.
sha256sum -c --ignore-missing trivy_${V}_checksums.txt

tar xzf trivy_${V}_Linux-64bit.tar.gz trivy
mkdir -p ~/bin && mv trivy ~/bin/ && export PATH=$HOME/bin:$PATH
echo 'export PATH=$HOME/bin:$PATH' >> ~/.bashrc
trivy --version        # harus 0.76.2
```

Verifikasi tanda tangan (disarankan, butuh `cosign`):

```bash
curl -fLO https://github.com/aquasecurity/trivy/releases/download/v$V/trivy_${V}_Linux-64bit.tar.gz.sigstore.json
cosign verify-blob trivy_${V}_Linux-64bit.tar.gz \
  --bundle trivy_${V}_Linux-64bit.tar.gz.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/aquasecurity/trivy/\.github/workflows/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
# harus tertulis: Verified OK
```

Aturan versi:

- Pakai v0.70 ke atas. **Jangan** pakai 0.69.4, 0.69.5, 0.69.6 (versi berbahaya dari insiden Maret 2026).
- Checksum dan tanda tangan hanya membuktikan file sama dengan yang dirilis. Keduanya **tidak** melindungi dari rilis resmi yang disusupi. Karena itu jangan langsung memakai rilis yang baru keluar; tunggu minimal 7 hari dan pastikan tidak ada pengumuman insiden di GitHub `aquasecurity/trivy`.
- Unduh hanya dari GitHub Releases `aquasecurity/trivy`. Jangan dari Docker Hub, `apt`, atau skrip `curl | sh`.
- Jangan pernah memasang Trivy di server produksi/UAT.

Salin juga `kali_scan.sh` ke `~/trivy/` lalu:

```bash
chmod +x ~/trivy/kali_scan.sh
```

## B. Unduh database — ulangi sebelum tiap sesi pemindaian

```bash
trivy image --download-db-only
trivy image --download-java-db-only
ls ~/.cache/trivy/db/trivy.db ~/.cache/trivy/java-db/trivy-java.db   # keduanya harus ada
```

## C. Di server UAT

```bash
sudo bash assess.sh
```

Tidak perlu parameter. Docker rootless (daemon milik user aplikasi, mis. `application`) dikenali otomatis.

Khusus server yang Docker-nya hanya bisa dijalankan oleh user `application`, pakai:

```bash
sudo bash assess.sh --docker-user application
``` Di akhir tercetak dua baris; catat keduanya:

```
RESULT: /tmp/assess-<host>-<waktu>.tar.gz
SHA256: <64 karakter>
```

Opsi yang berguna:

| Opsi | Kegunaan |
|---|---|
| `--anonymize --anon-key <kata-rahasia>` | Samarkan hostname/IP. Pakai kata rahasia yang sama di semua server. |
| `--docker-user <user>` | Jalankan perintah Docker sebagai user ini (mis. `application`), bila deteksi otomatis gagal. |
| `--docker-host <uri>` | Alamat daemon, mis. `unix:///run/user/1001/docker.sock`. |
| `--no-exec` | Jangan `docker exec`; paket container dibaca dari filesystem saja. |
| `--safe` | Beban paling ringan: tanpa scan izin file, tanpa request jaringan lokal, tanpa `docker exec`. |
| `-o <folder>` | Lokasi arsip hasil (default `/tmp`). |

Salin **satu file** `.tar.gz` itu ke Kali.

## D. Di Kali — pindai

```bash
cd ~/trivy
./kali_scan.sh assess-<host>-<waktu>.tar.gz <SHA256-dari-langkah-C>
```

Skrip ini mencocokkan SHA256, mengekstrak, lalu menjalankan Trivy dengan jaringan diputus. Perintah Trivy yang dijalankan di dalamnya:

```bash
trivy sbom   --skip-db-update --skip-java-db-update --offline-scan sbom/<file>.cdx.json
trivy config --skip-check-update config/
```

## E. Unggah ke chat Claude

Sebelum mengunggah, buka `assess-<host>-<waktu>.txt`, cari bagian `===== FILE: raw/processes.txt =====`, dan hapus password yang mungkin tertulis di argumen proses (mis. `-Ddb.password=...`).

Unggah dua file teks ini ke chat:

1. `assess-<host>-<waktu>.txt`
2. `assess-<host>-<waktu>-trivy.txt`

## Isi arsip

| File | Isi |
|---|---|
| `<nama>.txt` | Laporan lengkap: temuan, aplikasi berjalan, inventaris library, paket OS, akses Docker, indikasi kompromi |
| `sbom/host.cdx.json` | Paket OS host + semua library (Java, Node.js, Python, PHP) di host |
| `sbom/container-<nama>.cdx.json` | Paket OS + library tiap container yang berjalan |
| `sbom/RINGKASAN.txt` | Jumlah paket/library per SBOM, termasuk yang tidak bisa dicocokkan Trivy |
| `config/NNN/…` | Salinan Dockerfile/Compose, nilai secret sudah diganti `REDACTED` |
| `config/INDEX.txt` | Nomor folder → path asli di server |
| `BACA-SAYA.txt` | Penjelasan singkat isi arsip |
| `SHA256SUMS` | Sidik jari tiap file di dalam arsip |

## Temuan penting untuk dicek pertama

| Kode | Arti |
|---|---|
| `WF-DEPST-00` | WildFly berjalan tanpa aplikasi ter-deploy: yang dinilai baru platform |
| `WF-DEPST-01` | Daftar aplikasi yang ter-deploy + context web-nya |
| `WF-DEPST-02` | Ada deployment yang gagal |
| `CNT-FS-02` | Isi container tidak terbaca: library di container itu TIDAK diperiksa |
| `DKR-NOACCESS-01` | Docker tidak bisa ditanya: jalankan ulang dengan `--docker-user` |
| `DKR-DATA-01/02` | Folder data Docker (mis. `/data/docker`) bisa ditulis/dibaca user lain |
| `DKR-BIND-01` | Isi bind mount (mis. `/data/apps`) bisa diubah semua user |
| `DKR-MNT-01` | Folder data/bind mount tanpa opsi `nosuid,nodev` |

## Yang dikenali otomatis

- OS: Rocky Linux 9/10 (juga CentOS/RHEL 7). Trivy mendukung Rocky 8, 9, dan 10.
- Docker rootless milik user aplikasi, socket `/run/user/<uid>/docker.sock`.
- Data-root Docker di luar lokasi bawaan (mis. `/data/docker`): tidak ikut scan disk agar tidak terbaca ganda.
- File di folder bind mount (mis. `/data/apps`) yang dipakai container ditandai *berjalan*, bukan aset host yang menganggur.

## Batasan yang perlu diketahui

- Library Java tanpa `groupId` (versi hanya terbaca dari nama file) tidak bisa dicocokkan Trivy. Jumlahnya tertulis di `sbom/RINGKASAN.txt`; library ini dinilai dari `.txt`.
- Trivy tidak memeriksa Docker Compose. Compose diperiksa oleh `assess.sh` sendiri (temuan `CMP-*`).
- Image yang tersimpan tetapi tidak berjalan hanya didaftar (`CNT-IDLE-01`), isinya tidak dipindai.
- Bila perintah Docker tidak bisa dipakai sama sekali, container dibaca dari file di disk (`DKR-FSONLY-01`); image dan riwayat build tidak diperiksa.
- Biner Go/native hanya ditandai (`APP-UNK-01`), library di dalamnya tidak terbaca.
- Symlink absolut di dalam container tidak diikuti (jarang terjadi pada image WildFly/Java).
- Dockerfile belum dibandingkan dengan isi container yang berjalan.
- Kubernetes belum dicakup.
