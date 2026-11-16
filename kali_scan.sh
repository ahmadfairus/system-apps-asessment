#!/usr/bin/env bash
# kali_scan.sh v1.0 - pindai arsip hasil assess.sh dengan Trivy di mesin Kali.
#
# Pakai : ./kali_scan.sh <assess-xxx.tar.gz> [SHA256-yang-dicetak-assess.sh]
# Hasil : <nama>-trivy.txt  (gabungan semua hasil, kirim ke analis bersama <nama>.txt)
#         <nama>-trivy/     (hasil JSON per file, arsip lokal)
#
# Syarat: trivy sudah terpasang dan database SUDAH diunduh (lihat PANDUAN-KALI.md).
# Pemindaian dijalankan TANPA jaringan (unshare -rn) bila tersedia.
set -u
ARC="${1:-}"; WANT="${2:-}"
[ -n "$ARC" ] && [ -f "$ARC" ] || { echo "Pakai: $0 <assess-xxx.tar.gz> [sha256]" >&2; exit 2; }
command -v trivy >/dev/null 2>&1 || { echo "trivy tidak ditemukan di PATH" >&2; exit 2; }
CACHE="${TRIVY_CACHE_DIR:-$HOME/.cache/trivy}"
[ -f "$CACHE/db/trivy.db" ] || { echo "Database Trivy belum ada di $CACHE/db. Jalankan: trivy image --download-db-only" >&2; exit 2; }
[ -f "$CACHE/java-db/trivy-java.db" ] || echo "PERINGATAN: Java DB belum ada ($CACHE/java-db). Jalankan: trivy image --download-java-db-only" >&2

# 1. Cocokkan SHA256 arsip
GOT=$(sha256sum "$ARC" | awk '{print $1}')
echo "SHA256 arsip : $GOT"
if [ -n "$WANT" ]; then
  [ "$GOT" = "$WANT" ] || { echo "GAGAL: SHA256 tidak cocok dengan yang dicetak assess.sh. Salin ulang arsip." >&2; exit 1; }
  echo "SHA256 cocok."
else
  echo "PERINGATAN: SHA256 pembanding tidak diberikan; cocokkan manual dengan keluaran assess.sh." >&2
fi

# 2. Tolak arsip dengan path berbahaya, lalu ekstrak ke folder baru
if tar tzf "$ARC" | grep -qE '^/|(^|/)\.\.(/|$)'; then echo "GAGAL: arsip berisi path absolut atau '..'" >&2; exit 1; fi
NAME=$(basename "$ARC" .tar.gz)
WORK=$(mktemp -d "./${NAME}.XXXXXX") || exit 1
tar xzf "$ARC" -C "$WORK" --no-same-owner --no-same-permissions || { echo "GAGAL ekstrak" >&2; exit 1; }
SRC="$WORK/$NAME"
[ -d "$SRC" ] || { echo "GAGAL: struktur arsip tidak dikenal" >&2; exit 1; }
( cd "$SRC" && sha256sum -c SHA256SUMS >/dev/null ) || { echo "GAGAL: isi arsip tidak cocok dengan SHA256SUMS" >&2; exit 1; }
echo "Isi arsip utuh (SHA256SUMS cocok)."

# 3. Jalankan Trivy tanpa jaringan
if unshare -rn true 2>/dev/null; then NONET="unshare -rn"; echo "Jaringan diputus selama pemindaian (unshare -rn)."
else NONET=""; echo "PERINGATAN: unshare -rn tidak tersedia. Putus koneksi jaringan Kali secara manual sebelum lanjut." >&2; fi
COMMON="--cache-dir $CACHE --skip-version-check --disable-telemetry --quiet"
OUTD="./${NAME}-trivy"; OUTT="./${NAME}-trivy.txt"
mkdir -p "$OUTD"
{
  echo "HASIL TRIVY untuk $NAME"
  echo "Trivy : $(trivy --version 2>/dev/null | head -n1)"
  echo "DB    : $(grep -o '"UpdatedAt":"[^"]*"' "$CACHE/db/metadata.json" 2>/dev/null)"
  echo "Waktu : $(date '+%F %T %z')"
} > "$OUTT"

RC=0
for f in "$SRC"/sbom/*.cdx.json; do
  [ -f "$f" ] || continue
  b=$(basename "$f" .cdx.json)
  echo "Memindai SBOM: $b"
  $NONET trivy sbom $COMMON --skip-db-update --skip-java-db-update --offline-scan \
      --format json --output "$OUTD/$b.json" "$f" 2> "$OUTD/$b.err" || { RC=1; echo "  gagal, lihat $OUTD/$b.err" >&2; }
  { echo; echo "===== SBOM: $b ====="
    if [ -s "$OUTD/$b.json" ]; then
      trivy convert --format table --quiet "$OUTD/$b.json" 2>> "$OUTD/$b.err"
    else echo "(tidak ada hasil)"; cat "$OUTD/$b.err"; fi
  } >> "$OUTT"
done

if [ -d "$SRC/config" ]; then
  echo "Memindai konfigurasi (Dockerfile)"
  $NONET trivy config $COMMON --skip-check-update --format json --output "$OUTD/config.json" "$SRC/config" 2> "$OUTD/config.err" || RC=1
  { echo; echo "===== CONFIG (Dockerfile/Compose) ====="
    echo "Nomor folder -> path asli di server:"; cat "$SRC/config/INDEX.txt" 2>/dev/null; echo
    $NONET trivy config $COMMON --skip-check-update --format table "$SRC/config" 2>> "$OUTD/config.err"
  } >> "$OUTT"
fi
echo >> "$OUTT"; echo "===== END =====" >> "$OUTT"

cp "$SRC/$NAME.txt" "./" 2>/dev/null
[ -n "$WORK" ] && [ -d "$WORK" ] && rm -rf -- "$WORK"
echo
echo "Selesai. Kirim DUA file ini ke analis:"
echo "  ./${NAME}.txt"
echo "  $OUTT"
echo "(JSON lengkap tersimpan di $OUTD/)"
exit $RC
