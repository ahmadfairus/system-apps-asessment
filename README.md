# Panduan: assess.sh v4.0 + Trivy di Kali

Alur: server (offline) → salin manual → Kali (ada internet) → kirim hasil ke analis.

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

Aturan versi:

- Pakai v0.70 ke atas. **Jangan** pakai 0.69.4, 0.69.5, 0.69.6 (versi berbahaya dari insiden Maret 2026).
- Unduh hanya dari GitHub Releases `aquasecurity/trivy`. Jangan dari Docker Hub, `apt`, atau skrip `curl | sh`.
- Jangan pernah memasang Trivy di server produksi/UAT.

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

Tidak perlu parameter. Di akhir tercetak dua baris; catat keduanya:

```
RESULT: /root/assess-<host>-<waktu>.tar.gz
SHA256: <64 karakter>
```

Opsi yang berguna:

| Opsi | Kegunaan |
|---|---|
| `--anonymize --anon-key <kata-rahasia>` | Samarkan hostname/IP. Pakai kata rahasia yang sama di semua server. |
| `--no-exec` | Jangan `docker exec`; paket container dibaca dari filesystem saja. |
| `--safe` | Beban paling ringan (lewati pengecekan berat). |
| `-o <folder>` | Lokasi arsip hasil. |

Salin **satu file** `.tar.gz` itu ke Kali.

## D. Di Kali — pindai

```bash
./kali_scan.sh assess-<host>-<waktu>.tar.gz <SHA256-dari-langkah-C>
```

Skrip ini mencocokkan SHA256, mengekstrak, lalu menjalankan Trivy dengan jaringan diputus. Perintah Trivy yang dijalankan di dalamnya:

```bash
trivy sbom   --skip-db-update --skip-java-db-update --offline-scan sbom/<file>.cdx.json
trivy config --skip-check-update config/
```

## E. Kirim ke analis

Dua file teks:

1. `assess-<host>-<waktu>.txt`
2. `assess-<host>-<waktu>-trivy.txt`

## Isi arsip

| File | Isi |
|---|---|
| `<nama>.txt` | Laporan lengkap: temuan, aplikasi berjalan, inventaris library, paket OS, indikasi kompromi |
| `sbom/host.cdx.json` | Paket OS host + semua library (Java, Node.js, Python, PHP) di host |
| `sbom/container-<nama>.cdx.json` | Paket OS + library tiap container yang berjalan |
| `config/NNN/…` | Salinan Dockerfile/Compose, nilai secret sudah diganti `REDACTED` |
| `config/INDEX.txt` | Nomor folder → path asli di server |
| `SHA256SUMS` | Sidik jari tiap file di dalam arsip |

## Batasan yang perlu diketahui

- Library Java tanpa `groupId` (versi hanya terbaca dari nama file) tidak bisa dicocokkan Trivy. Jumlahnya tertulis di `sbom/RINGKASAN.txt`; library ini dinilai analis dari `.txt`.
- Trivy tidak memeriksa Docker Compose. Compose diperiksa oleh `assess.sh` sendiri (temuan `CMP-*`).
- Image yang tersimpan tetapi tidak berjalan hanya didaftar (`CNT-IDLE-01`), isinya tidak dipindai.
- Biner Go/native hanya ditandai (`APP-UNK-01`), library di dalamnya tidak terbaca.
- Kubernetes belum dicakup.
