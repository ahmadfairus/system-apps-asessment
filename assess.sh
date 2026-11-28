#!/bin/bash
#==============================================================================
# assess.sh - Assessment keamanan server (READ-ONLY), SATU script SATU output
# Versi : 4.8   Target: CentOS/RHEL 7 (juga RHEL/Rocky/Alma 8-9)
# Cakupan: OS, SSH, akun, hardening, port, filesystem, Apache/Nginx, MariaDB/
#          MySQL, PostgreSQL, WildFly/JBoss, Tomcat, Spring Boot, Java lain,
#          inventaris SEMUA library Java di SELURUH disk (jar/war/ear, termasuk
#          jar di dalam jar), monitoring agent (NRPE/SNMP/NTP)
#
# Pakai : sudo bash assess.sh [opsi]
#   (tanpa opsi)          OTOMATIS: semua aplikasi yang berjalan (java path,
#                         lokasi, cara dijalankan, port) + semua aset yang TIDAK
#                         berjalan (backup, versi lama, simulator, JDK, dll)
#   -i, --interactive     (opsional) tampilkan deteksi & tanya path tambahan
#   --wildfly-home DIR    path WildFly/JBoss home   (boleh berulang / pisah koma)
#   --app-dir DIR         folder aplikasi Spring Boot / Java / Tomcat
#   --java-home DIR       path JDK/JRE yang dipakai aplikasi
#   --safe                mode paling ringan untuk run pertama di production
#                         (tanpa scan disk, tanpa request jaringan lokal,
#                         tanpa inventaris modules WildFly)
#   --skip-fs             lewati cek izin file (pencarian semua jar tetap jalan)
#   --no-net              jangan kirim request lokal (curl/openssl) ke service
#   --anonymize           samarkan hostname & IPv4 di file output
#   --anon-key KUNCI      kunci penyamaran; pakai kunci SAMA di semua server
#                         agar samaran konsisten antar server
#   --anon-terms a,b,c    kata tambahan yang disamarkan (domain, nama perusahaan)
#   --mysql-cnf FILE      file kredensial MySQL/MariaDB read-only
#   --lib-rules FILE      aturan library TAMBAHAN (CVE baru), ditambahkan ke bawaan
#   --no-exec             jangan jalankan docker exec; paket OS container dibaca
#                         dari sisi host saja (otomatis aktif pada --safe)
#   --docker-user USER    jalankan perintah docker (hanya-baca) sebagai USER,
#                         mis. Docker rootless atau root diblokir. Tanpa opsi ini
#                         user pemilik daemon/socket dicari otomatis.
#   --docker-host URI     alamat daemon, mis. unix:///run/user/1001/docker.sock
#   --lib-baseline FILE   baseline versi library yang DISETUJUI tim; library di
#                         bawah baseline ditandai "drift" (menyesuaikan patching)
#   -o DIR                folder output (default /tmp)
#
# Hasil : SATU arsip  <DIR>/assess-<host>-<waktu>.tar.gz  berisi:
#           <nama>.txt        laporan (kirim ke analis)
#           sbom/*.cdx.json   daftar komponen untuk Trivy (per host/container)
#           config/           Dockerfile/Compose, secret disamarkan
#         SHA256 arsip dicetak di akhir untuk dicocokkan setelah disalin.
# Script ini TIDAK mengubah konfigurasi, TIDAK me-restart service, TIDAK
# menginstal apa pun, dan nilai password/secret DISAMARKAN (****).
#==============================================================================
set -u
umask 077

SCRIPT_VERSION="4.8"
APACHE_MIN="2.4.71"   # versi Apache aman minimal (untuk Apache hasil kompilasi sendiri); perbarui saat ada rilis keamanan
OUTBASE="/tmp"
SKIP_FS=0
NO_NET=0
SAFE=0
ANON=0
ANON_KEY=""
ANON_TERMS=""
MYSQL_CNF="${MYSQL_DEFAULTS_FILE:-}"
INTERACTIVE=0
COLLECT_ART=0
ART_MAX_MB=0
WF_HOMES=""      # path WildFly manual
APP_DIRS=""      # folder aplikasi manual
JAVA_HOMES=""    # JDK manual
LIB_RULES=""
LIB_BASELINE=""
NO_EXEC=0
DOCKER_USER=""
DOCKER_HOST_OPT=""

usage() { awk 'NR>2 && /^#====/{exit} NR>2' "$0" | sed 's/^# \{0,1\}//'; }
need_arg() { [ -n "${2:-}" ] || { echo "Opsi $1 butuh nilai" >&2; exit 1; }; }

while [ $# -gt 0 ]; do
  case "$1" in
    -i|--interactive)    INTERACTIVE=1; shift ;;
    --wildfly-home)      need_arg "$1" "${2:-}"; WF_HOMES="$WF_HOMES ${2//,/ }"; shift 2 ;;
    --app-dir)           need_arg "$1" "${2:-}"; APP_DIRS="$APP_DIRS ${2//,/ }"; shift 2 ;;
    --java-home)         need_arg "$1" "${2:-}"; JAVA_HOMES="$JAVA_HOMES ${2//,/ }"; shift 2 ;;
    --safe)              SAFE=1; SKIP_FS=1; NO_NET=1; shift ;;
    --skip-fs)           SKIP_FS=1; shift ;;
    --no-net)            NO_NET=1; shift ;;
    --anonymize)         ANON=1; shift ;;
    --anon-key)          need_arg "$1" "${2:-}"; ANON_KEY="$2"; ANON=1; shift 2 ;;
    --anon-terms)        need_arg "$1" "${2:-}"; ANON_TERMS="$2"; ANON=1; shift 2 ;;
    --lib-rules)         need_arg "$1" "${2:-}"; LIB_RULES="$2"; shift 2 ;;
    --lib-baseline)      need_arg "$1" "${2:-}"; LIB_BASELINE="$2"; shift 2 ;;
    --no-exec)           NO_EXEC=1; shift ;;
    --docker-user)       need_arg "$1" "${2:-}"; DOCKER_USER="$2"; shift 2 ;;
    --docker-host)       need_arg "$1" "${2:-}"; DOCKER_HOST_OPT="$2"; shift 2 ;;
    -o)                  need_arg "$1" "${2:-}"; OUTBASE="$2"; shift 2 ;;
    --mysql-cnf)         need_arg "$1" "${2:-}"; MYSQL_CNF="$2"; shift 2 ;;
    -h|--help)           usage; exit 0 ;;
    *) echo "Opsi tidak dikenal: $1" >&2; usage; exit 1 ;;
  esac
done
[ "$(id -u)" -ne 0 ] && echo "PERINGATAN: jalankan dengan sudo/root agar semua cek berjalan." >&2

HOST=$(hostname -s 2>/dev/null || hostname)
TS=$(date +%Y%m%d-%H%M%S)
OUT="$OUTBASE/assess-$HOST-$TS"
RAW="$OUT/raw"
FINDINGS="$OUT/findings.csv"
ROLES=""
FW_ON=0
WF_SEEN=" "       # WildFly home yang sudah dicek
ARCH_SEEN=" "     # arsip jar/war/ear yang sudah dicek
DIR_SEEN=" "      # folder lib/aplikasi yang sudah dicek
JAVA_SEEN=" "     # binary java yang sudah dicek versinya
ART_BYTES=0
# Normalisasi path. Path di dalam container (/proc/<pid>/root/...) TIDAK boleh
# di-readlink -f karena awalan itu akan hilang dan berubah menjadi path host.
rpath() {
  case "$1" in
    /proc/[0-9]*/root|/proc/[0-9]*/root/*) printf '%s\n' "$1" | sed -E 's#/+#/#g; s#/(\./)+#/#g; s#/$##' ;;
    *) readlink -f "$1" ;;
  esac
}
run_path() { [ -n "$1" ] && rpath "$1" >> "$OUT/.running" 2>/dev/null; return 0; }
APP_PERM_DIRS=""
MAPFILE=""
ANON_HOST=""
IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1

mkdir -p "$RAW" || { echo "Gagal membuat $RAW" >&2; exit 1; }

# Jalan dengan prioritas CPU & IO paling rendah supaya tidak mengganggu production
renice -n 19 -p $$ >/dev/null 2>&1
command -v ionice >/dev/null 2>&1 && ionice -c3 -p $$ >/dev/null 2>&1

PY=$(command -v python3 || command -v python || command -v python2 || true)

#------------------------------------------------------------------------------
# FUNGSI BANTU
#------------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }
log()  { echo "[$(date +%H:%M:%S)] $*" >&2; }

# Quote 1 field CSV
csvq() {
  local s="$1"
  s=${s//$'\r'/}
  s=${s//$'\n'/ | }
  s=${s//\"/\"\"}
  printf '"%s"' "$s"
}

# finding SEVERITY CHECK_ID KATEGORI "Judul" "Bukti" "Rekomendasi"
# Menulis 1 baris temuan ke findings.csv
finding() {
  local ev="$5"
  [ ${#ev} -gt 700 ] && ev="${ev:0:700}..."
  { csvq "$HOST"; printf ','; csvq "$3"; printf ','; csvq "$2"; printf ','
    csvq "$1"; printf ','; csvq "$4"; printf ','; csvq "$ev"; printf ','
    csvq "$6"; printf '\n'; } >> "$FINDINGS"
}

# save NAMA "perintah" -> simpan output mentah ke raw/NAMA.txt
save() {
  local name="$1"; shift
  { echo "### $*"; echo; timeout 300 bash -c "$*" 2>&1; } > "$RAW/$name.txt"
}

# Samarkan nilai password/secret/token di teks konfigurasi
redact() {
  sed -E \
    -e 's#(<password>)[^<]*(</password>)#\1****\2#Ig' \
    -e 's#((clear-text|password)=")[^"]*"#\1****"#Ig' \
    -e 's/((pass(word|wd)?|pwd|secret|token|api[_-]?key|credential)[A-Za-z0-9_.-]*[[:space:]]*[=:][[:space:]]*)[^[:space:],;]+/\1****/Ig'
}

# ver_lt A B -> sukses jika versi A < B
ver_lt() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$1" ]; }

is_loopback() { case "$1" in 127.*|::1|\[::1\]|::ffff:127.*|\[::ffff:127.*) return 0 ;; esac; return 1; }

# Alamat:port yang di-listen (TCP) oleh PID tertentu
listen_of_pid() {
  local r
  r=$(ss -tlnp 2>/dev/null | awk -v p="pid=$1," 'index($0,p){print $4}' | sort -u)
  if [ -z "$r" ] && [ -r "/proc/$1/net/tcp" ] && [ "$(readlink "/proc/$1/ns/net" 2>/dev/null)" != "$(readlink /proc/1/ns/net 2>/dev/null)" ]; then
    # proses di network namespace lain: baca socket LISTEN namespace itu
    r=$(awk 'function h(x,  i,c,v){v=0; x=toupper(x); for(i=1;i<=length(x);i++){c=index("0123456789ABCDEF",substr(x,i,1))-1; v=v*16+c} return v}
      FNR>1 && $4=="0A" { split($2,a,":"); ad=a[1]; pt=h(a[2])
        if (length(ad)==8) ip=h(substr(ad,7,2)) "." h(substr(ad,5,2)) "." h(substr(ad,3,2)) "." h(substr(ad,1,2))
        else ip=(ad ~ /^0+$/) ? "[::]" : "[ipv6]"
        print ip ":" pt }' "/proc/$1/net/tcp" "/proc/$1/net/tcp6" 2>/dev/null | sort -u)
  fi
  [ -n "$r" ] && echo "$r"
  return 0
}

# Alamat target untuk request lokal berdasarkan alamat listen
target_of() {
  local h="${1%:*}"; h=${h#[}; h=${h%]}
  case "$h" in 0.0.0.0|\*|::|"") echo 127.0.0.1 ;; *:*) echo "[$h]" ;; *) echo "$h" ;; esac
}

pid_cmd()  { tr '\0' ' ' < "/proc/$1/cmdline" 2>/dev/null; }
# Semua PID proses Java (berdasarkan binary */bin/java, bukan nama proses)
java_pids() {
  local d e
  for d in /proc/[0-9]*; do
    e=$(readlink "$d/exe" 2>/dev/null) || continue
    case "$e" in */bin/java|*/bin/java\ \(deleted\)) echo "${d#/proc/}" ;; esac
  done | sort -n
}
pid_user() { ps -o user= -p "$1" 2>/dev/null | tr -d ' '; }
pid_exe()  { readlink -f "/proc/$1/exe" 2>/dev/null; }
pid_cwd()  { readlink -f "/proc/$1/cwd" 2>/dev/null; }
# Nilai argumen bentuk KEY=VALUE pada command line proses
arg_val()  { pid_cmd "$1" | tr ' ' '\n' | awk -v k="$2=" 'index($0,k)==1{print substr($0,length(k)+1); exit}'; }
# Nilai argumen bentuk "FLAG VALUE" (dipisah spasi)
arg_next() { pid_cmd "$1" | tr ' ' '\n' | awk -v k="$2" 'f{print; exit} $0==k{f=1}'; }

# Daftar isi arsip jar/war/ear dan baca 1 file di dalamnya
zip_list() {
  if have unzip; then unzip -Z1 "$1" 2>/dev/null
  elif [ -n "$PY" ]; then "$PY" -c 'import sys,zipfile; print("\n".join(zipfile.ZipFile(sys.argv[1]).namelist()))' "$1" 2>/dev/null
  fi
}
zip_cat() {
  if have unzip; then unzip -p "$1" "$2" 2>/dev/null
  elif [ -n "$PY" ]; then "$PY" -c 'import sys,zipfile; d=zipfile.ZipFile(sys.argv[1]).read(sys.argv[2]); getattr(sys.stdout,"buffer",sys.stdout).write(d)' "$1" "$2" 2>/dev/null
  fi
}

# Apakah file adalah arsip zip (jar/war/ear)?
is_zip() { [ -f "$1" ] && [ "$(head -c 2 "$1" 2>/dev/null)" = "PK" ]; }

# collect_artifact FILE LABEL [NAMA_TUJUAN]
# Menyalin jar/war/ear ke OUT/artifacts/LABEL/ untuk discan Trivy di luar server.
collect_artifact() {
  [ "$COLLECT_ART" -eq 1 ] || return 0
  local f="$1" label="$2" name="${3:-$(basename "$1")}" sz dst avail
  [ -f "$f" ] || return 0
  sz=$(stat -c %s "$f" 2>/dev/null || echo 0)
  if [ $(( (ART_BYTES + sz) / 1048576 )) -ge "$ART_MAX_MB" ]; then
    echo "DILEWATI (batas $ART_MAX_MB MB): $f" >> "$RAW/artifacts_skipped.txt"; return 0
  fi
  avail=$(df -Pk "$OUT" 2>/dev/null | awk 'NR==2{print $4}')
  if [ -n "$avail" ] && [ $(( sz / 1024 + 524288 )) -gt "$avail" ]; then
    echo "DILEWATI (disk $OUT hampir penuh): $f" >> "$RAW/artifacts_skipped.txt"; return 0
  fi
  dst="$OUT/artifacts/$(echo "$label" | tr -c 'A-Za-z0-9._\n-' '_')"
  mkdir -p "$dst"
  [ -e "$dst/$name" ] && name="$(date +%N)-$name"
  cp -p "$f" "$dst/$name" 2>/dev/null && ART_BYTES=$((ART_BYTES + sz)) && echo "$f -> artifacts/${dst##*/}/$name" >> "$RAW/artifacts_index.txt"
}

# java_version_check EXE KATEGORI LABEL -> catat versi java & temuan EOL (sekali per binary)
java_version_check() {
  local exe="$1" cat="$2" label="$3" jv jver
  [ -x "$exe" ] || return 0
  case "$JAVA_SEEN" in *" $exe "*) return 0 ;; esac
  JAVA_SEEN="$JAVA_SEEN$exe "
  jv=$(timeout 20 "$exe" -version 2>&1 | head -n3)
  { echo "== $exe ($label)"; echo "$jv"; echo; } >> "$RAW/java_versions.txt"
  jver=$(echo "$jv" | grep -oE 'version "[^"]+"' | head -n1 | tr -d '"' | awk '{print $2}')
  [ -z "$jver" ] && return 0
  local major rel="" ym now age u k
  major=${jver%%.*}; [ "$major" = 1 ] && major=$(echo "$jver" | cut -d. -f2)
  # perkiraan bulan rilis: Java 9+ tertulis di baris versi; Java 8 dari nomor update (8u401 = 2024-01, per kuartal +10)
  rel=$(echo "$jv" | head -n1 | grep -oE '20[0-9]{2}-[0-9]{2}' | head -n1)
  if [ -z "$rel" ] && [ "$major" = 8 ]; then
    u=$(echo "$jver" | sed -n 's/.*_\([0-9]*\).*/\1/p')
    if [ -n "$u" ]; then
      k=$(( (u - 401) / 10 )); [ "$u" -lt 401 ] && k=$(( (u - 410) / 10 ))
      ym=$(( 2024 * 12 + k * 3 )); rel=$(printf '%04d-%02d' $(( ym / 12 )) $(( ym % 12 + 1 )))
    fi
  fi
  if [ -n "$rel" ]; then
    now=$(( $(date +%Y) * 12 + 10#$(date +%m) - 1 ))
    age=$(( now - ( ${rel%-*} * 12 + 10#${rel#*-} - 1 ) ))
  else age=0; fi
  case "$major" in
    5|6|7) finding HIGH JAVA-EOL-01 "$cat" "Java versi lama (EOL)" "$label: Java $jver ($exe)" "Upgrade ke Java LTS yang didukung (8u terbaru/11/17/21/25)."; return 0 ;;
    9|10|12|13|14|15|16|18|19|20|22|23|24)
      finding HIGH JAVA-EOL-02 "$cat" "Java non-LTS yang sudah EOL" "$label: Java $jver ($exe)" "Pindah ke Java LTS (17/21/25) yang masih menerima update."; return 0 ;;
  esac
  if [ "$age" -gt 36 ]; then
    finding HIGH JAVA-PATCH-01 "$cat" "JDK tertinggal lebih dari 3 tahun update keamanan" "$label: Java $jver (rilis ~$rel, $exe)" \
      "Update JDK ke rilis kuartalan terbaru dari vendor yang sama (major version tetap, risiko kompatibilitas rendah)."
  elif [ "$age" -gt 12 ]; then
    finding MEDIUM JAVA-PATCH-01 "$cat" "JDK tertinggal lebih dari 1 tahun update keamanan" "$label: Java $jver (rilis ~$rel, $exe)" \
      "Update JDK ke rilis kuartalan terbaru (CPU Januari/April/Juli/Oktober)."
  else
    finding INFO JAVA-VER-01 "$cat" "Versi Java" "$label: Java $jver (rilis ~${rel:-?}, $exe)" "Pastikan update kuartalan JDK diikuti."
  fi
}

# Folder classpath (-cp / -classpath) sebuah proses java, mis. "lib/*" -> /opt/app/lib
classpath_dirs() {
  local pid="$1" cp cwd e
  cp=$(arg_next "$pid" "-cp"); [ -z "$cp" ] && cp=$(arg_next "$pid" "-classpath")
  [ -z "$cp" ] && return 0
  cwd=$(pid_cwd "$pid")
  for e in $(echo "$cp" | tr ':' ' '); do
    e=${e%/\*}; e=${e%\*}
    [ "${e#/}" = "$e" ] && e="$cwd/$e"
    if [ -d "$e" ]; then echo "$e"; elif [ -f "$e" ]; then dirname "$e"; fi
  done | sort -u
}

#------------------------------------------------------------------------------
# INVENTARIS LIBRARY JAVA (lengkap - tidak ada daftar library yang ditentukan
# di awal). Semua arsip yang ditemukan didaftarkan dengan reg_archive, lalu di
# akhir dibaca satu per satu: groupId/artifactId/versi dari pom.properties
# (bukan dari nama file), termasuk jar bertingkat (ear>war>jar) & library shaded.
# Hasil: libraries.csv. Aturan "flag cepat" dibaca dari file aturan (opsional).
#------------------------------------------------------------------------------
# reg_archive LABEL FILE
reg_archive() { [ -f "$2" ] && printf '%s\t%s\n' "$1" "$(rpath "$2")" >> "$OUT/.archives"; return 0; }

# Aturan bawaan, dipakai bila tidak ada --lib-rules / lib_rules.txt
default_lib_rules() { cat <<'RULES'
# Format : library  versi_min  versi_maks_rentan  severity  versi_perbaikan  keterangan
# library: artifactId (log4j-core) atau groupId:artifactId. "*" = semua versi. "-" = tidak ada perbaikan.
log4j-core           2.0     2.14.1  CRITICAL  2.17.1  CVE-2021-44228 Log4Shell (RCE)
log4j-core           2.15.0  2.17.0  HIGH      2.17.1  CVE-2021-45046/45105/44832
log4j:log4j          *       *       HIGH      -       Log4j 1.x EOL (CVE-2019-17571, CVE-2021-4104) - migrasi ke Log4j2/Logback/reload4j
spring-beans         *       5.2.19  HIGH      5.3.18  CVE-2022-22965 Spring4Shell (risiko tertinggi: WAR + JDK9+)
spring-beans         5.3.0   5.3.17  HIGH      5.3.18  CVE-2022-22965 Spring4Shell (risiko tertinggi: WAR + JDK9+)
commons-text         1.5     1.9     HIGH      1.10.0  CVE-2022-42889 Text4Shell
commons-collections  *       3.2.1   MEDIUM    3.2.2   CVE-2015-7501 deserialization
spring-boot-devtools *       *       MEDIUM    -       devtools tidak boleh ada di build production
fastjson             *       1.2.82  CRITICAL  1.2.83  Fastjson AutoType bypass RCE (CVE-2022-25845 dan sebelumnya); idealnya migrasi ke fastjson2
tapestry-core        *       5.3.5   CRITICAL  5.3.6   CVE-2014-1972 data form terserialisasi tanpa HMAC (RCE bila ada gadget, mis. commons-collections)
struts2-core         *       2.5.32  CRITICAL  6.3.0.2 CVE-2023-50164 dan RCE Struts2 lain
shiro-core           *       1.2.4   CRITICAL  1.13.0  CVE-2016-4437 rememberMe deserialization (kunci default)
xstream              *       1.4.19  HIGH      1.4.20  Banyak CVE RCE/DoS deserialization XStream
jackson-databind     2.0.0   2.9.10.7 HIGH     2.12.7.1 CVE polymorphic deserialization (bila default typing aktif)
snakeyaml            *       1.33    HIGH      2.0     CVE-2022-1471 RCE via Constructor default
commons-fileupload   *       1.3.2   HIGH      1.5     CVE-2016-1000031 RCE via DiskFileItem deserialization
commons-fileupload   1.3.3   1.4     MEDIUM    1.5     CVE-2023-24998 DoS (jumlah part tak terbatas)
xalan                *       2.7.2   HIGH      2.7.3   CVE-2022-34169 integer truncation pada XSLT
h2                   *       2.1.209 HIGH      2.1.210 CVE-2021-42392/CVE-2022-23221 RCE via console/JDBC URL
commons-beanutils    *       1.9.3   MEDIUM    1.9.4   CVE-2019-10086 akses class via property
commons-httpclient   *       *       MEDIUM    -       EOL, tidak memverifikasi hostname SSL (CVE-2012-5783) - ganti ke HttpClient 4.5+/5
jackson-mapper-asl   *       *       MEDIUM    -       Codehaus Jackson 1.x EOL (CVE-2019-10172 XXE) - migrasi ke com.fasterxml.jackson
RULES
}

run_lib_inventory() {
  register_disk_archives
  [ -s "$OUT/.archives" ] || return 0
  # satu path = satu baris; label dari deteksi aplikasi lebih diutamakan daripada label "disk:"
  awk -F'\t' '!seen[$2]++' "$OUT/.archives" > "$RAW/archives_list.txt"; rm -f "$OUT/.archives"
  if [ -z "$PY" ]; then
    finding INFO LIB-INV-00 Library "Inventaris library dilewati (python tidak tersedia)" "-" "Jalankan ulang di server yang punya python/python3, atau gunakan Trivy pada artefak."
    return 0
  fi
  local rules="$RAW/lib_rules_used.txt"
  default_lib_rules > "$rules"
  if [ -n "$LIB_RULES" ] && [ -f "$LIB_RULES" ]; then { echo "# --- tambahan dari $LIB_RULES"; cat "$LIB_RULES"; } >> "$rules"; fi
  log "Inventaris library Java ($(wc -l < "$RAW/archives_list.txt") arsip, termasuk jar di dalamnya)"
  sort -u "$OUT/.running" > "$RAW/running_paths.txt" 2>/dev/null; rm -f "$OUT/.running"
  timeout 3600 "$PY" - "$HOST" "$RAW/archives_list.txt" "$OUT/libraries.csv" "$rules" "$FINDINGS" "$RAW/running_paths.txt" "$RAW/jdk_installs.txt" 2>>"$RAW/libinv_errors.txt" <<'PYEOF'
# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
import sys, os, re, io, zipfile, hashlib

host, arch_list, out_csv, rules_file, find_out = sys.argv[1:6]
RUNNING = []
try:
    RUNNING = [l.strip() for l in io.open(sys.argv[6], encoding='utf-8', errors='replace') if l.strip()]
except Exception:
    pass
def active(path):
    return any(path == p or path.startswith(p.rstrip('/') + '/') for p in RUNNING)
LOWER = {'CRITICAL': 'MEDIUM', 'HIGH': 'LOW', 'MEDIUM': 'LOW', 'LOW': 'LOW', 'INFO': 'INFO'}
PY2 = sys.version_info[0] == 2
MAXDEPTH = 4
ARCH_EXT = ('.jar', '.war', '.ear', '.rar')
FN_RE = re.compile(r'^(?P<a>.+?)-(?P<v>\d[0-9A-Za-z.+_-]*)\.(jar|war|ear|rar)$')

def u(x):
    if x is None: return ''
    if PY2 and isinstance(x, bytes): return x.decode('utf-8', 'replace')
    if not PY2 and isinstance(x, bytes): return x.decode('utf-8', 'replace')
    return x if isinstance(x, type('')) else type('')(x)

def q(x): return '"' + u(x).replace('\r', '').replace('\n', ' ').replace('"', '""') + '"'

def sha1_bytes(b): return hashlib.sha1(b).hexdigest()

def sha1_file(p):
    h = hashlib.sha1()
    with open(p, 'rb') as f:
        for c in iter(lambda: f.read(1 << 20), b''):
            h.update(c)
    return h.hexdigest()

def props(data):
    d = {}
    for line in u(data).splitlines():
        line = line.strip()
        if not line or line[0] in '#!' or '=' not in line: continue
        k, v = line.split('=', 1); d[k.strip()] = v.strip()
    return d

def manifest(z):
    try: data = u(z.read('META-INF/MANIFEST.MF'))
    except Exception: return {}
    m, last = {}, None
    for line in data.splitlines():
        if line.startswith(' ') and last: m[last] += line[1:]; continue
        if ':' in line:
            k, v = line.split(':', 1); last = k.strip(); m[last] = v.strip()
    return m

rows, errors = [], []
CLS_RE = re.compile(r'-(jar|sources?|javadoc|tests?)$')

def norm_name(a):
    """spring-beans-jar -> (spring-beans, jar); commons-codec-javadoc -> (commons-codec, javadoc)"""
    m = CLS_RE.search(a)
    return (a[:m.start()], m.group(1)) if m else (a, '')

def scan(z, label, outer, inner, size, digest, depth):
    names = z.namelist()
    base = os.path.basename(inner or outer)
    nested = [n for n in names if n.lower().endswith(ARCH_EXT)]
    kind = 'app' if (depth == 0 and (nested or any(n.startswith(('BOOT-INF/', 'WEB-INF/')) for n in names))) else ('app' if base.lower().endswith(('.war', '.ear')) else 'lib')
    coords = []
    for p in sorted(n for n in names if n.startswith('META-INF/maven/') and n.endswith('/pom.properties')):
        try: d = props(z.read(p))
        except Exception: continue
        if d.get('artifactId'): coords.append((d.get('groupId', ''), d['artifactId'], d.get('version', '')))
    m = manifest(z)
    fm = FN_RE.match(base)
    primary, src = None, ''
    for c in coords:
        if base.startswith(c[1] + '-') or base == c[1] + '.jar':
            primary = c; break
    if primary is None and len(coords) == 1:
        primary = coords[0]
    if primary: src = 'pom.properties'
    elif fm: primary, src = ('', fm.group('a'), fm.group('v')), 'nama-file'
    elif m.get('Implementation-Version') or m.get('Bundle-Version'):
        primary = (m.get('Implementation-Vendor-Id', ''), m.get('Implementation-Title') or m.get('Bundle-SymbolicName') or base,
                   m.get('Implementation-Version') or m.get('Bundle-Version'))
        src = 'manifest'
    else:
        primary, src = ('', base, ''), 'tidak-diketahui'
    note = []
    nm, cls = norm_name(primary[1])
    if cls:
        note.append('nama-asli=' + primary[1] + ' klasifikasi=' + cls)
        primary = (primary[0], nm, primary[2])
    if m.get('Spring-Boot-Version'): note.append('Spring-Boot-Version=' + m['Spring-Boot-Version'])
    if m.get('Created-By'): note.append('Created-By=' + m['Created-By'])
    if nested: note.append('%d arsip di dalam' % len(nested))
    rows.append([label, outer, inner, primary[0], primary[1], primary[2], src, kind, digest, size, '; '.join(note)])
    for c in coords:
        if c == primary: continue
        rows.append([label, outer, (inner + '!' if inner else '') + '(embedded)', c[0], c[1], c[2],
                     'pom.properties(embedded)', 'embedded', '', '', 'tertanam/di-shade di dalam ' + base])
    if depth >= MAXDEPTH: return
    for n in nested:
        try:
            data = z.read(n); nz = zipfile.ZipFile(io.BytesIO(data))
        except Exception as e:
            errors.append('%s!/%s: %s' % (outer, n, e)); continue
        scan(nz, label, outer, (inner + '!/' if inner else '') + n, len(data), sha1_bytes(data), depth + 1)

seen = set()
with io.open(arch_list, encoding='utf-8', errors='replace') as f:
    for line in f:
        line = line.rstrip('\n')
        if '\t' not in line: continue
        label, path = line.split('\t', 1)
        if path in seen: continue
        seen.add(path)
        try:
            z = zipfile.ZipFile(path)
            scan(z, label, path, '', os.path.getsize(path), sha1_file(path), 0)
        except Exception as e:
            errors.append('%s: %s' % (path, e))

with io.open(out_csv, 'w', encoding='utf-8') as f:
    f.write('host,label,archive,path_in_archive,group_id,artifact_id,version,version_source,type,sha1,size,note\n')
    for r in rows:
        f.write(','.join(q(x) for x in [host] + r) + '\n')

# Ringkasan library unik: 1 baris per group:artifact:versi, dengan status dipakai proses berjalan
uniq = {}
for r in rows:
    k = (r[3], r[4], r[5])
    e = uniq.setdefault(k, [0, False, set(), set(), r[1] + ('!/' + r[2] if r[2] else '')])
    e[0] += 1
    e[1] = e[1] or active(r[1])
    e[2].add(r[0]); e[3].add(r[6])
with io.open(os.path.join(os.path.dirname(out_csv), 'libraries_unique.csv'), 'w', encoding='utf-8') as f:
    f.write('group_id,artifact_id,version,jumlah,dipakai_proses_berjalan,sumber_versi,label,contoh_lokasi\n')
    for k in sorted(uniq, key=lambda k: (k[1].lower(), k[0], k[2])):
        e = uniq[k]
        f.write(','.join(q(x) for x in [k[0], k[1], k[2], e[0], 'YA' if e[1] else 'tidak',
                                         '/'.join(sorted(e[3])), ' | '.join(sorted(e[2]))[:200], e[4][:220]]) + '\n')

# ---- aturan flag cepat (opsional) ----
def vkey(v):
    key = []
    for p in re.findall(r'\d+|[A-Za-z]+', v or ''):
        if p.isdigit(): key.append((1, int(p)))
        elif p.lower() not in ('final', 'release', 'ga', 'sp'): key.append((0, p.lower()))
    return key

rules = []
with io.open(rules_file, encoding='utf-8', errors='replace') as f:
    for i, line in enumerate(f):
        line = line.strip()
        if not line or line.startswith('#'): continue
        p = line.split(None, 5)
        if len(p) < 4: continue
        while len(p) < 6: p.append('-')
        rules.append((i,) + tuple(p))

out, done, idle_hits = [], set(), {}
for r in rows:
    g, a, v = r[3], r[4], r[5]
    for (i, lib, vmin, vmax, sev, fixed, desc) in rules:
        if ':' in lib:
            if lib != '%s:%s' % (g, a): continue
        elif lib != a: continue
        if vmin == '*' and vmax == '*': pass
        elif not v: continue
        elif (vmin != '*' and vkey(v) < vkey(vmin)) or (vmax != '*' and vkey(v) > vkey(vmax)): continue
        if not active(r[1]):
            # arsip tidak dipakai proses berjalan: dicatat untuk analisis aset, bukan temuan terpisah
            idle_hits.setdefault(r[1], []).append((sev.upper(), '%s:%s' % (a, v), desc.split(' ')[0]))
            continue
        where = r[1] + ('!/' + r[2] if r[2] else '')
        ev = '%s: %s:%s:%s di %s' % (r[0], g, a, v, where)
        if (i, ev) in done: continue
        done.add((i, ev))
        rec = ('Upgrade %s ke >= %s, rebuild & redeploy.' % (a, fixed)) if fixed != '-' else ('Ganti/keluarkan library ini: %s' % desc)
        out.append([host, 'Library', 'LIBRULE-%s-%d' % (lib.replace(':', '_'), i), sev.upper(), desc + ' [DIPAKAI aplikasi berjalan]', ev, rec])

TESTLIB = re.compile(r'^(junit|mockito-all|mockito-core|powermock-.*|hamcrest-(core|all|library)|testng|easymock|jmock.*|spring-test|assertj-core)$')
bucket = {}
for r in rows:
    if not r[2] or not active(r[1]): continue
    b = bucket.setdefault((r[0], r[1]), set())
    if TESTLIB.match(r[4] or ''): b.add(r[4])
    if 'klasifikasi=source' in r[10] or 'klasifikasi=javadoc' in r[10] or 'klasifikasi=test' in r[10]:
        b.add('*-source/javadoc/test')
for (label, outer), names in bucket.items():
    if names:
        out.append([host, 'Library', 'LIB-HYGIENE-01', 'LOW', 'Library test/source/javadoc ikut dalam artefak production',
                    '%s: %s berisi %s' % (label, os.path.basename(outer), ', '.join(sorted(names))),
                    'Keluarkan dependency scope test dan jar -source/-javadoc dari build production; menambah permukaan serangan (gadget deserialization) dan ukuran.'])

try:
    # ============================================================================
    # ANALISIS ASET YANG TIDAK BERJALAN (backup, versi lama, alat uji, sisa deploy,
    # instalasi app server / JDK yang tidak dipakai) + rekomendasi keamanan
    # ============================================================================
    import time, stat
    RANKS = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
    SECRET_KEY = re.compile(r'^\s*[A-Za-z0-9_.-]*(password|passwd|pwd|secret|token|api[-_.]?key|private[-_.]?key|credential)[A-Za-z0-9_.-]*\s*[=:]\s*(\S+)', re.I | re.M)
    NOT_SECRET_KEY = re.compile(r'(restriction|strength|policy|checker|forbidden|min|max|length|expir|valid|encoder|algorithm|class|enabled|file|path|url|uri|header|param|name|mode|type|realm|regex|pattern)', re.I)
    def secret_keys(text):
        ks = set()
        for m in SECRET_KEY.finditer(text):
            key = m.group(0).split('=')[0].split(':')[0].strip()
            val = m.group(2).strip('"\'')
            last = key.lower().replace('-', '.').replace('_', '.').split('.')[-1]
            if NOT_SECRET_KEY.search(last) and not re.search(r'(password|secret|token|key)$', last): continue
            # bagian nama SETELAH kata secret menunjukkan pengaturan, bukan nilai rahasia
            # (mis. password.restriction.strength, password-file, token.expiry)
            mw = re.search(r'(password|passwd|pwd|secret|token|api[-_.]?key|private[-_.]?key|credential)', key.lower())
            if mw and NOT_SECRET_KEY.search(key.lower()[mw.end():]): continue
            if not val or val.startswith(('${', 'ENC(', '/', 'classpath:', 'file:', 'http')) or val.lower() in ('null', 'true', 'false', '""', "''", 'none', 'changeit'):
                continue
            ks.add(key)
        return ks
    CFG_IN_ZIP = re.compile(r'^(BOOT-INF/classes/|WEB-INF/classes/)?(config/)?[^/]*\.(properties|ya?ml)$')
    def zip_secrets(path):
        ks = set()
        try:
            z = zipfile.ZipFile(path)
            for n in z.namelist():
                if CFG_IN_ZIP.match(n) and not n.startswith('META-INF/'):
                    try: ks |= secret_keys(u(z.read(n)))
                    except Exception: pass
        except Exception: pass
        return ks
    def world_readable(p):
        try: return bool(os.stat(p).st_mode & stat.S_IROTH)
        except Exception: return False
    def mtime(p):
        try: return os.path.getmtime(p)
        except Exception: return 0

    toplevel = {}
    for r in rows:
        if not r[2]: toplevel[r[1]] = r
    run_names = {}
    for p in RUNNING:
        b = os.path.basename(p.rstrip('/'))
        m = re.match(r'^(.+?)-(\d[\w.]*?)(\.(jar|war|ear))?$', b)
        if m: run_names[m.group(1).lower()] = m.group(2)
        else: run_names[b.rsplit('.', 1)[0].lower()] = ''

    units = {}
    for path, r in toplevel.items():
        if active(path): continue
        label = r[0]
        if '/tmp/vfs/' in path or '/standalone/tmp/' in path: continue
        m = re.match(r'^(.*?)/modules/', path)
        if '/modules' in label and m: key, kind = m.group(1), 'wildfly-install'
        elif r[7] == 'app' or '/deploy:' in label or '/deployments:' in label: key, kind = path, 'app'
        else: key, kind = os.path.dirname(path), 'lib-folder'
        un = units.setdefault(key, {'kind': kind, 'paths': [], 'label': label, 'hits': [], 'secrets': set(),
                                    'wr': False, 'mt': 0, 'size': 0})
        un['paths'].append(path); un['hits'] += idle_hits.get(path, [])
        un['wr'] = un['wr'] or world_readable(path); un['mt'] = max(un['mt'], mtime(path))
        try: un['size'] += os.path.getsize(path)
        except Exception: pass
        if kind == 'app': un['secrets'] |= zip_secrets(path)
    # file konfigurasi di sebelah arsip (folder unit) yang berisi secret
    for key, un in units.items():
        d = key if os.path.isdir(key) else os.path.dirname(key)
        if un['kind'] == 'wildfly-install' or not os.path.isdir(d): continue
        try: names = os.listdir(d)
        except Exception: names = []
        for n in names:
            fp = os.path.join(d, n)
            if os.path.isfile(fp) and re.search(r'\.(properties|ya?ml|conf|cfg|env|xml)([._-].*)?$', n) and os.path.getsize(fp) < 2000000:
                try: ks = secret_keys(u(io.open(fp, 'rb').read()))
                except Exception: ks = set()
                if ks:
                    un['secrets'] |= set('%s (%s)' % (k, n) for k in ks)
                    un['wr'] = un['wr'] or world_readable(fp)

    def category(key, un):
        s = (key + ' ' + un['label']).lower()
        s = re.sub(r'/data/content/[0-9a-f]{2}/[0-9a-f]{38}/', '/data/content/', s)   # buang hash konten WildFly
        b = os.path.basename(key).lower()
        if re.search(r'simulat|mock|dummy|demo|sample|example|(^|[/_-])tests?([/_.-]|$)', s): return 'alat-uji'
        if 'konten-yatim' in s or '(nonaktif)' in s: return 'sisa-deploy'
        if re.search(r'apache-maven|/maven|gradle|apache-ant|/\.m2/|/\.gradle/|jenkins|sonar|/ivy', s): return 'tool-build'
        if re.search(r'(^|[/_.-])bk([/_.-]|$)|\.(jar|war|ear|rar)[._-]\w+$', b): return 'backup'
        if re.search(r'backup|bak|bck|(^|[/_.-])old([/_.-]|$)|copy|arsip|archive|(^|[^0-9])(19|20)\d{2}[01]\d[0-3]\d([^0-9]|$)|(^|[^0-9])[0-3]\d[01]\d(19|20)\d{2}([^0-9]|$)', s): return 'backup'
        if un['kind'] == 'wildfly-install': return 'app-server-tidak-jalan'
        m = re.match(r'^(.+?)-(\d[\w.]*?)(\.(jar|war|ear))?$', b)
        if m and m.group(1).lower() in run_names:
            rv = run_names[m.group(1).lower()]
            return 'versi-lebih-baru' if rv and vkey(m.group(2)) > vkey(rv) else 'versi-lama'
        if un['kind'] == 'lib-folder': return 'folder-library'
        return 'aplikasi-tidak-jalan'

    REC = {
        'versi-lebih-baru': 'Versi LEBIH BARU dari aplikasi yang berjalan, tetapi tidak dipakai (rilis tertunda atau rollback). Putuskan: deploy versi ini setelah diuji, atau hapus. Jangan dibiarkan menggantung.',
    'tool-build': 'Build tool / repositori library (Maven, Gradle, Ant, .m2) tidak dibutuhkan di server production. Build di CI, kirim artefak jadi saja; hapus dari server.',
        'alat-uji': 'Alat uji/simulator/mock tidak boleh ada di server production. Hapus dari server (dan dari folder backup), simpan di repositori artefak bila masih dibutuhkan.',
        'backup': 'Backup di server ikut terekspos bila server dibobol dan sering berisi kredensial lama. Pindahkan ke penyimpanan backup terenkripsi di luar server, lalu hapus dari server.',
        'sisa-deploy': 'Sisa deployment WildFly (nonaktif/yatim). Undeploy dengan CLI (undeploy <nama>) agar konten ikut terhapus.',
        'app-server-tidak-jalan': 'Instalasi app server yang tidak berjalan. Bila tidak dipakai, hapus; bila cadangan, pastikan versinya sama dengan yang aktif dan izin file ketat.',
        'versi-lama': 'Versi lama dari aplikasi yang sedang berjalan. Simpan maksimal 1 versi sebelumnya untuk rollback di folder ber-permission 700; hapus sisanya.',
        'folder-library': 'Folder library yang tidak dipakai proses berjalan. Konfirmasi pemiliknya; bila tidak dipakai, arsipkan ke luar server lalu hapus.',
        'aplikasi-tidak-jalan': 'Aplikasi yang tidak sedang berjalan. Konfirmasi apakah masih dipakai (mis. dijalankan berkala/cron); bila tidak, arsipkan ke luar server lalu hapus.',
    }
    asset_rows = []
    for key, un in units.items():
        cat = category(key, un)
        vmax = max([RANKS.get(h[0], 0) for h in un['hits']] or [0])
        sev = 'LOW'
        if vmax >= 3 or un['secrets']: sev = 'MEDIUM'
        if un['secrets'] and un['wr']: sev = 'HIGH'
        if cat == 'alat-uji' and vmax >= 4: sev = 'HIGH'
        vul = sorted(set('%s %s(%s)' % (h[1], h[2], h[0]) for h in un['hits']))
        asset_rows.append((RANKS[sev], sev, cat, key, un, vul))
    asset_rows.sort(key=lambda x: (-x[0], x[2], x[3]))

    # JDK / JRE terinstal vs dipakai
    jdks = []
    try:
        for line in io.open(sys.argv[7], encoding='utf-8', errors='replace'):
            if '|' in line: jdks.append(line.rstrip('\n').split('|'))
    except Exception: pass

    with io.open(os.path.join(os.path.dirname(out_csv), 'aset_tidak_berjalan.txt'), 'w', encoding='utf-8') as f:
        f.write('ASET YANG TIDAK DIPAKAI PROSES BERJALAN (dikelompokkan, urut risiko)\n')
        f.write('kategori: alat-uji | backup | sisa-deploy | tool-build | versi-lebih-baru | app-server-tidak-jalan | versi-lama | folder-library | aplikasi-tidak-jalan\n\n')
        for _, sev, cat, key, un, vul in asset_rows:
            f.write('[%s] %-22s %s\n' % (sev, cat, key))
            f.write('    arsip: %d  ukuran: %.1f MB  terakhir diubah: %s  terbaca-semua-user: %s\n' % (
                len(un['paths']), un['size'] / 1048576.0, time.strftime('%Y-%m-%d', time.localtime(un['mt'])) if un['mt'] else '?', 'YA' if un['wr'] else 'tidak'))
            if vul: f.write('    library rentan: %s\n' % ', '.join(vul[:12]) + (' ...' if len(vul) > 12 else ''))
            if un['secrets']: f.write('    SECRET terdeteksi (nama key): %s\n' % ', '.join(sorted(un['secrets'])[:10]))
            f.write('    rekomendasi: %s\n\n' % REC[cat])
        if jdks:
            f.write('\nJDK/JRE TERINSTAL\n')
            for j in jdks: f.write('  %-45s versi=%-12s dipakai=%s\n' % (j[0], j[1], j[2]))

    per_cat = {}
    for rk, sev, cat, key, un, vul in asset_rows:
        per_cat.setdefault(cat, []).append(key)
        if rk >= 2:
            ev = '%s | %d arsip%s%s%s' % (key, len(un['paths']),
                  ('; library rentan: ' + ', '.join(vul[:6])) if vul else '',
                  ('; SECRET: ' + ', '.join(sorted(un['secrets'])[:5])) if un['secrets'] else '',
                  '; terbaca semua user' if un['wr'] else '')
            out.append([host, 'Aset tidak aktif', 'ASSET-' + cat.upper(), sev,
                        'Aset tidak berjalan (%s) berisiko' % cat, ev, REC[cat]])
    for cat, keys in per_cat.items():
        out.append([host, 'Aset tidak aktif', 'ASSET-SUM-' + cat.upper(), 'INFO',
                    '%d aset tidak berjalan kategori %s (detail: raw/aset_tidak_berjalan.txt)' % (len(keys), cat),
                    ' ; '.join(sorted(keys)[:8]) + (' ...' if len(keys) > 8 else ''), REC[cat]])
    unused = [j for j in jdks if len(j) > 2 and j[2] == 'tidak']
    if unused:
        out.append([host, 'Aset tidak aktif', 'ASSET-JDK-UNUSED', 'LOW', '%d JDK/JRE terinstal tetapi tidak dipakai aplikasi berjalan' % len(unused),
                    ' ; '.join('%s (%s)' % (j[0], j[1]) for j in unused[:8]),
                    'Hapus JDK yang tidak dipakai agar tidak terpakai tanpa sengaja (mis. lewat PATH) dan tidak menambah permukaan serangan.'])
except Exception as e:
    errors.append('analisis aset gagal (data lain tetap lengkap): %s' % e)

with io.open(find_out, 'a', encoding='utf-8') as f:
    for o in out:
        f.write(','.join(q(x) for x in o) + '\n')

for e in errors: print(e, file=sys.stderr)
print('Inventaris: %d arsip/library, %d flag aturan, %d error' % (len(rows), len(out), len(errors)), file=sys.stderr)
PYEOF
  [ -s "$OUT/libraries.csv" ] && log "  -> libraries.csv: $(($(wc -l < "$OUT/libraries.csv") - 1)) baris"
}

#------------------------------------------------------------------------------
# 0. IDENTIFIKASI OTOMATIS SEMUA APLIKASI JAVA YANG BERJALAN
#    (tanpa parameter: java path, lokasi aplikasi, cara dijalankan, port)
#------------------------------------------------------------------------------
# Cara proses dijalankan: systemd / screen / tmux / cron / sesi SSH / nohup
how_started() {
  local pid="$1" p="$1" i=0 a unit
  unit=$(grep -oE '[^/]+\.service' "/proc/$pid/cgroup" 2>/dev/null | grep -vE '^(user@|session-)' | head -n1)
  while [ "$i" -lt 10 ] && [ -n "$p" ] && [ "$p" != 1 ] && [ "$p" != 0 ]; do
    a=$(ps -o args= -p "$p" 2>/dev/null)
    case "$a" in
      SCREEN*|screen*) echo "screen: $(echo "$a" | sed -nE 's/.*-(S|R|r|dmS|dRR|RR) +([^ ]+).*/\2/p')"; return ;;
      tmux*)           echo "tmux"; return ;;
      *crond*|*CROND*) echo "cron"; return ;;
      sshd:*)          echo "manual dari sesi SSH (mati saat logout)"; return ;;
    esac
    p=$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' '); i=$((i+1))
  done
  [ -n "$unit" ] && { echo "systemd: $unit"; return; }
  echo "nohup/background (tanpa systemd)"
}

# Tipe & nama aplikasi dari command line
app_type() {
  case "$(pid_cmd "$1")" in
    *jboss-modules.jar*|*jboss.home.dir*) echo wildfly ;;
    *org.apache.catalina.startup.Bootstrap*|*-Dcatalina.base=*) echo tomcat ;;
    *org.springframework.boot*) echo springboot ;;
    *) local jar; jar=$(arg_next "$1" "-jar")
       [ -n "$jar" ] && [ "${jar#/}" = "$jar" ] && jar="$(pid_cwd "$1")/$jar"
       if [ -n "$jar" ] && [ -f "$jar" ] && zip_cat "$jar" META-INF/MANIFEST.MF | grep -qE 'Spring-Boot-Version|org\.springframework\.boot\.loader'; then
         echo springboot; else echo java; fi ;;
  esac
}
app_location() {
  local pid="$1" t="$2" jar
  case "$t" in
    wildfly) arg_val "$pid" "-Djboss.home.dir" ;;
    tomcat)  v=$(arg_val "$pid" "-Dcatalina.base"); [ -n "$v" ] && echo "$v" || arg_val "$pid" "-Dcatalina.home" ;;
    *) jar=$(arg_next "$pid" "-jar")
       if [ -n "$jar" ]; then [ "${jar#/}" = "$jar" ] && jar="$(pid_cwd "$pid")/$jar"; readlink -f "$jar" 2>/dev/null || echo "$jar"
       else echo "$(pid_cwd "$pid") (classpath: $(arg_next "$pid" -cp)$(arg_next "$pid" -classpath))"; fi ;;
  esac
}

discover_running_apps() {
  local pid t loc exe jv how user cmd ports cwd n=0 sum="" frompath="" homecwd=""
  [ -n "$(java_pids)" ] || { log "Tidak ada aplikasi Java yang berjalan"; return 0; }
  log "Identifikasi otomatis aplikasi Java yang berjalan"
  {
    echo "Daftar aplikasi Java yang SEDANG BERJALAN (terdeteksi otomatis)"
    echo "================================================================"
    for pid in $(java_pids); do
      t=$(app_type "$pid"); loc=$(app_location "$pid" "$t"); exe=$(pid_exe "$pid"); cmd=$(pid_cmd "$pid")
      if [ -n "$(pid_container "$pid")" ]; then
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null); exe=${exe% (deleted)}; jv=${exe%/bin/java}; jv=${jv%/jre}
        jv="$(sed -n 's/^JAVA_VERSION=//p' "$(pid_rootfs "$pid")$jv/release" 2>/dev/null | tr -d '"' | head -n 1) [dalam $(pid_scope "$pid")]"
      else jv=$(timeout 20 "$exe" -version 2>&1 | head -n1); fi
      how=$(how_started "$pid"); user=$(pid_user "$pid"); cwd=$(pid_cwd "$pid")
      ports=$(listen_of_pid "$pid" | tr '\n' ' ')
      n=$((n+1))
      echo
      echo "[$n] PID $pid  tipe=$t"
      echo "    aplikasi       : $loc"
      echo "    java           : $exe"
      echo "    versi java     : $jv"
      echo "    user           : $user"
      echo "    folder kerja   : $cwd"
      echo "    dijalankan via : $how"
      echo "    mulai          : $(ps -o lstart= -p "$pid" 2>/dev/null)   RAM: $(( $(ps -o rss= -p "$pid" 2>/dev/null || echo 0) / 1024 )) MB"
      echo "    port (listen)  : ${ports:--}"
      echo "    config         : $(echo "$cmd" | tr ' ' '\n' | grep -E 'config|\.properties|\.ya?ml|\.xml$|^-c$' | grep -vE '^-X' | tr '\n' ' ' | redact)"
      sum="$sum $(basename "$loc" | cut -d' ' -f1)($t:${ports:-tanpa-port})"
      case "$cmd" in java\ *|java) frompath="$frompath $(basename "$loc") (java=$exe)" ;; esac
      [ "$cwd" = "$(getent passwd "$user" | cut -d: -f6)" ] && homecwd="$homecwd $(basename "$loc")"
    done
  } > "$RAW/running_apps.txt"
  finding INFO APP-RUN-01 Aplikasi "$n aplikasi Java sedang berjalan (detail di raw/running_apps.txt)" "$sum" \
    "Pastikan setiap aplikasi tercatat di inventaris aset, punya pemilik, dan memang seharusnya berjalan di server ini."
  [ -n "$frompath" ] && finding MEDIUM OPS-JAVA-01 Operasional "Aplikasi dijalankan dengan perintah 'java' dari PATH (JDK tidak eksplisit)" "$frompath" \
    "Tulis path JDK lengkap di skrip start/unit systemd. Perintah 'java' dari PATH bisa memakai JDK lama yang tidak diinginkan."
  [ -n "$homecwd" ] && finding LOW OPS-CWD-01 Operasional "Aplikasi dijalankan dari home directory user (log/file relatif tersebar di home)" "$homecwd" \
    "Jalankan dari folder aplikasi (WorkingDirectory= di systemd) agar file log & temp berada di lokasi yang terkontrol."
}

#------------------------------------------------------------------------------
# 1. OS DASAR
#------------------------------------------------------------------------------
check_os() {
  log "Cek OS dasar"
  save os_release       "cat /etc/redhat-release /etc/os-release"
  save uname            "uname -a; echo; uptime; echo; hostname -I"
  save disk             "df -hP; echo; mount"
  save packages         "rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort"
  save rpm_last         "rpm -qa --last | head -n 60"
  save listening        "ss -tulpn"
  save services_running "systemctl list-units --type=service --state=running --no-pager --no-legend"
  save services_enabled "systemctl list-unit-files --type=service --no-pager --no-legend | grep enabled"
  save network          "ip -4 addr; echo; ip route; echo; cat /etc/resolv.conf"
  save logins           "last -n 50; echo; echo '--- gagal login (lastb) ---'; lastb -n 30"
  ps -eo user,pid,ppid,lstart,rss,args --sort=-rss 2>/dev/null | redact > "$RAW/processes.txt"
  # Unit systemd untuk service aplikasi (java/httpd/nginx/db): user, ExecStart, opsi JVM
  for u in $(systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | awk '{print $1}'); do
    if systemctl cat "$u" 2>/dev/null | grep -qiE 'java|jboss|wildfly|spring|httpd|nginx|mysql|mariadb|postgres|tomcat'; then
      { echo "##### $u"; systemctl cat "$u" 2>/dev/null | grep -vE '^\s*(#|$)' | redact; echo; } >> "$RAW/systemd_app_units.txt"
    fi
  done
  save sysctl           "sysctl -a 2>/dev/null | grep -E '^(kernel.randomize_va_space|net.ipv4.ip_forward|net.ipv4.conf.all.accept_redirects|net.ipv4.conf.all.send_redirects|net.ipv4.conf.all.accept_source_route|net.ipv4.tcp_syncookies|fs.suid_dumpable)'"
  {
    echo "### /etc/crontab"; cat /etc/crontab 2>/dev/null
    echo; echo "### /etc/cron.*"; ls -la /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
    echo; echo "### crontab per user"
    for u in $(cut -d: -f1 /etc/passwd); do
      c=$(crontab -l -u "$u" 2>/dev/null | grep -vE '^\s*(#|$)')
      [ -n "$c" ] && { echo "== $u =="; echo "$c" | redact; }
    done
  } > "$RAW/cron.txt" 2>&1

  local rel; rel=$(cat /etc/redhat-release 2>/dev/null)
  case "$rel" in
    *CentOS*release\ 6*|*CentOS*release\ 5*)
      finding CRITICAL OS-EOL-01 OS "Sistem operasi sudah End-of-Life sejak lama" "$rel" \
        "Prioritaskan migrasi ke Rocky Linux/AlmaLinux 9 atau RHEL 9. Selama transisi: isolasi jaringan, minimalkan port terbuka." ;;
    *CentOS*release\ 7*)
      finding HIGH OS-EOL-01 OS "CentOS 7 sudah End-of-Life (30 Juni 2024), tidak ada security patch" "$rel" \
        "Rencanakan migrasi ke Rocky Linux/AlmaLinux 9 atau RHEL 9 (atau RHEL 7 ELS sementara). Selama transisi: minimalkan port terbuka, perketat firewall, prioritaskan server yang terekspos." ;;
    *Red\ Hat*release\ 7*)
      finding MEDIUM OS-EOL-02 OS "RHEL 7 sudah keluar dari masa maintenance (butuh ELS)" "$rel" \
        "Pastikan langganan ELS aktif, atau rencanakan upgrade ke RHEL 9." ;;
  esac

  local run_k latest_k
  run_k=$(uname -r)
  latest_k=$(rpm -q --last kernel 2>/dev/null | head -n1 | awk '{print $1}' | sed 's/^kernel-//')
  if [ -n "$latest_k" ] && [ "$latest_k" != "$run_k" ]; then
    finding MEDIUM OS-KERNEL-01 OS "Kernel yang berjalan bukan kernel terbaru yang terinstal (butuh reboot)" \
      "berjalan: $run_k; terinstal terbaru: $latest_k" \
      "Jadwalkan reboot di maintenance window agar kernel (dan patch-nya) aktif."
  fi

  local last_epoch days
  last_epoch=$(rpm -qa --qf '%{INSTALLTIME}\n' 2>/dev/null | sort -n | tail -n1)
  if [ -n "$last_epoch" ]; then
    days=$(( ($(date +%s) - last_epoch) / 86400 ))
    echo "Hari sejak instalasi/update paket terakhir: $days" >> "$RAW/rpm_last.txt"
    if [ "$days" -gt 180 ]; then
      finding MEDIUM OS-PATCH-01 OS "Tidak ada update paket lebih dari 180 hari" "Update paket terakhir $days hari lalu" \
        "Terapkan update keamanan berkala (untuk CentOS 7: repo vault/ELS/vendor backport), atau masukkan ke rencana migrasi OS."
    fi
  fi

  local aslr; aslr=$(sysctl -n kernel.randomize_va_space 2>/dev/null)
  if [ -n "$aslr" ] && [ "$aslr" != "2" ]; then
    finding LOW OS-ASLR-01 OS "ASLR tidak penuh (kernel.randomize_va_space != 2)" "nilai: $aslr" \
      "Set kernel.randomize_va_space = 2 di /etc/sysctl.d/."
  fi
}

#------------------------------------------------------------------------------
# 2. SSH
#------------------------------------------------------------------------------
sshv() { awk -v k="$1" 'tolower($1)==k { $1=""; sub(/^ +/,""); print; exit }' "$RAW/sshd_effective.txt"; }

check_ssh() {
  local sshd_bin; sshd_bin=$(command -v sshd || echo /usr/sbin/sshd)
  [ -x "$sshd_bin" ] || return
  log "Cek SSH"
  "$sshd_bin" -T > "$RAW/sshd_effective.txt" 2>&1
  grep -qi '^port ' "$RAW/sshd_effective.txt" || { log "  sshd -T gagal (butuh root), cek SSH dilewati"; return; }
  "$sshd_bin" -V >/dev/null 2>"$RAW/sshd_version.txt"; ssh -V 2>>"$RAW/sshd_version.txt"

  local v
  v=$(sshv permitrootlogin)
  [ "$v" = "yes" ] && finding HIGH SSH-ROOT-01 SSH "Login root langsung via SSH diizinkan" "PermitRootLogin $v" \
    "Set PermitRootLogin no, login memakai user personal lalu sudo. Uji dulu dengan sesi SSH kedua tetap terbuka sebelum reload sshd."
  v=$(sshv permitemptypasswords)
  [ "$v" = "yes" ] && finding CRITICAL SSH-EMPTY-01 SSH "SSH mengizinkan password kosong" "PermitEmptyPasswords $v" \
    "Set PermitEmptyPasswords no."
  v=$(sshv passwordauthentication)
  [ "$v" = "yes" ] && finding MEDIUM SSH-PASS-01 SSH "Autentikasi password SSH aktif (rentan brute force)" "PasswordAuthentication $v" \
    "Gunakan SSH key dan set PasswordAuthentication no. Jika belum bisa: batasi SSH hanya dari jump host/IP admin dan pasang fail2ban."
  v=$(sshv x11forwarding)
  [ "$v" = "yes" ] && finding LOW SSH-X11-01 SSH "X11Forwarding aktif" "X11Forwarding $v" "Set X11Forwarding no."
  v=$(sshv maxauthtries)
  [ -n "$v" ] && [ "$v" -gt 4 ] 2>/dev/null && finding LOW SSH-TRIES-01 SSH "MaxAuthTries terlalu longgar" "MaxAuthTries $v" "Set MaxAuthTries 3-4."
  v=$(sshv ciphers)
  echo "$v" | grep -qE 'cbc|arcfour|3des' && finding MEDIUM SSH-CRYPTO-01 SSH "SSH mengizinkan cipher lemah (CBC/RC4/3DES)" "$v" \
    "Batasi Ciphers ke aes256-ctr,aes192-ctr,aes128-ctr (+ aes*-gcm@openssh.com, chacha20-poly1305@openssh.com)."
  v=$(sshv macs)
  echo "$v" | grep -qE 'hmac-md5|hmac-sha1(,|$|-etm)|umac-64' && finding LOW SSH-CRYPTO-02 SSH "SSH mengizinkan MAC lemah (MD5/SHA1/umac-64)" "$v" \
    "Batasi MACs ke hmac-sha2-512,hmac-sha2-256 (+ varian -etm@openssh.com)."
  v=$(sshv kexalgorithms)
  echo "$v" | grep -qE 'group1-sha1|group14-sha1|group-exchange-sha1' && finding LOW SSH-CRYPTO-03 SSH "SSH mengizinkan key exchange lemah (SHA1)" "$v" \
    "Hapus algoritma *-sha1 dari KexAlgorithms."
}

#------------------------------------------------------------------------------
# 3. AKUN & HAK AKSES
#------------------------------------------------------------------------------
check_accounts() {
  log "Cek akun & hak akses"
  awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1":"$3":"$6":"$7}' /etc/passwd > "$RAW/users_interactive.txt"

  local x
  x=$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd | tr '\n' ' ')
  [ -n "$x" ] && finding CRITICAL ACC-UID0-01 Akun "Ada akun selain root dengan UID 0" "$x" \
    "Investigasi segera (bisa indikasi backdoor). Ubah UID atau hapus akun bila tidak sah."

  if [ "$IS_ROOT" -eq 1 ]; then
    x=$(awk -F: '$2==""{print $1}' /etc/shadow | tr '\n' ' ')
    [ -n "$x" ] && finding CRITICAL ACC-EMPTY-01 Akun "Akun tanpa password" "$x" \
      "Kunci akun (passwd -l) atau set password kuat."
  fi

  x=$(find /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers -maxdepth 0 -perm -0002 2>/dev/null | tr '\n' ' ')
  [ -n "$x" ] && finding CRITICAL ACC-PERM-01 Akun "File akun/sudoers bisa ditulis semua user" "$x" "Perbaiki permission (passwd/group 644, shadow/gshadow 000, sudoers 440)."
  x=$(stat -c %a /etc/shadow 2>/dev/null)
  case "$x" in 0|400|600|640|"") ;; *) finding HIGH ACC-SHADOW-01 Akun "Permission /etc/shadow terlalu longgar" "mode $x" "chmod 000 /etc/shadow (default CentOS 7)." ;; esac

  if [ "$IS_ROOT" -eq 1 ]; then
    local bad v x av
    { echo "### /etc/sudoers"; grep -vE '^\s*(#|$)' /etc/sudoers 2>/dev/null
      for f in /etc/sudoers.d/*; do [ -f "$f" ] && { echo "### $f"; grep -vE '^\s*(#|$)' "$f"; }; done; } > "$RAW/sudoers.txt" 2>&1
    # Cmnd_Alias berbahaya: shell, editor, interpreter, tcpdump, chmod/chown, su ke user lain
    bad=$(awk '/^\s*Cmnd_Alias/{n=$2; sub(/^[^=]*=/,""); if ($0 ~ /(\/bin\/(ba|z|k|c|da)?sh([ ,]|$))|vi(m)? |\/vi(m)?$|nano|less|more|python|perl|ruby|tcpdump|\/chmod|\/chown|\/cp |\/tee|find |awk|\/env|\/su /) print n}' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | sort -u | tr '\n' ' ')
    for v in $bad; do
      x=$(grep -hE "^[^#]*NOPASSWD:\s*$v\b|^[^#]*NOPASSWD:[^#]*[ ,:]$v(\s*,|\s*$)" /etc/sudoers /etc/sudoers.d/* 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')
      [ -z "$x" ] && continue
      av=$(grep -hE "^\s*Cmnd_Alias\s+$v\s*=" /etc/sudoers /etc/sudoers.d/* 2>/dev/null | sed 's/.*=\s*//' | head -n1)
      if echo "$av" | grep -qE '/su ' && ! echo "$av" | grep -qE 'su root|/bin/(ba|z|k|c|da)?sh|vi|tcpdump|chmod|chown|python|perl'; then
        finding HIGH ACC-SUDO-04 Akun "Sudo NOPASSWD untuk berpindah ke akun lain ($v)" "user/alias: $x; $v = $av" \
          "Hilangkan NOPASSWD; berpindah ke akun service tanpa password menghapus jejak siapa melakukan apa. Bila akun tujuan punya sudo ke shell, ini setara root."
      else
        finding CRITICAL ACC-SUDO-02 Akun "Sudo NOPASSWD ke perintah yang bisa langsung jadi root ($v)" "user/alias: $x; $v = $av" \
          "Hapus $v dari aturan NOPASSWD. Shell/editor/tcpdump/chmod/su root via sudo = root penuh. Ganti dengan skrip pembungkus milik root (chmod 755) yang hanya melakukan tugas spesifik."
      fi
    done
    grep -hqE '^[^#]*ALL\s*=\s*!' /etc/sudoers /etc/sudoers.d/* 2>/dev/null && finding MEDIUM ACC-SUDO-03 Akun "Aturan sudo memakai daftar larangan (!CMD) yang mudah dilewati" \
      "$(grep -hE '^[^#]*ALL\s*=\s*!' /etc/sudoers /etc/sudoers.d/* | awk '{print $1}' | tr '\n' ' ')" \
      "Gunakan daftar izin (allowlist) perintah yang diperbolehkan, bukan daftar larangan; larangan bisa dilewati dengan menyalin/mengganti nama binary."
    x=$(grep -hE 'NOPASSWD:\s*ALL\s*$' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -vE '^\s*#' | tr '\n' ';')
    [ -n "$x" ] && finding MEDIUM ACC-SUDO-01 Akun "Sudo penuh tanpa password (NOPASSWD: ALL)" "$x" \
      "Batasi NOPASSWD hanya untuk perintah spesifik yang dibutuhkan (mis. untuk otomasi), dan wajibkan password untuk akses penuh."
  fi

  x=$(awk '/^PASS_MAX_DAYS/{print $2}' /etc/login.defs 2>/dev/null)
  [ "${x:-99999}" -gt 90 ] 2>/dev/null && finding LOW ACC-PWAGE-01 Akun "Kebijakan masa berlaku password tidak diatur" "PASS_MAX_DAYS ${x:-tidak diset}" \
    "Atur PASS_MAX_DAYS sesuai kebijakan perusahaan (mis. 90) dan terapkan ke akun yang ada dengan chage."

  {
    for h in $(awk -F: '{print $6}' /etc/passwd | sort -u); do
      for f in "$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2"; do
        [ -f "$f" ] && echo "$f : $(grep -cvE '^\s*(#|$)' "$f") key"
      done
    done
  } > "$RAW/ssh_authorized_keys.txt" 2>/dev/null
}

#------------------------------------------------------------------------------
# 4. HARDENING SISTEM
#------------------------------------------------------------------------------
# Firewall host: dinilai dari aturan yang BERLAKU di kernel (nftables, mencakup firewalld & iptables-nft;
# iptables-legacy untuk CentOS 7), per port yang listen: DIBLOK / DIBATASI (IP sumber) / TERBUKA UNTUK SEMUA.
check_firewall() {
  local fwd fwe nfa nfe ips ufw z zd="" ipt=0 nftc=0 res
  fwd=$(systemctl is-active firewalld 2>/dev/null); fwe=$(systemctl is-enabled firewalld 2>/dev/null)
  nfa=$(systemctl is-active nftables 2>/dev/null);  nfe=$(systemctl is-enabled nftables 2>/dev/null)
  ips=$(systemctl is-enabled iptables 2>/dev/null)
  ufw=""; command -v ufw >/dev/null 2>&1 && ufw=$(ufw status 2>/dev/null | head -n1)
  {
    echo "firewalld: ${fwd:-n/a} (${fwe:-n/a})  nftables.service: ${nfa:-n/a} (${nfe:-n/a})  iptables.service: ${ips:-n/a}  ufw: ${ufw:-n/a}"
    if [ "$fwd" = active ]; then
      echo; echo "### firewall-cmd --get-active-zones"; firewall-cmd --get-active-zones 2>&1
      echo; echo "### firewall-cmd --list-all-zones"; firewall-cmd --list-all-zones 2>&1
      for z in $(firewall-cmd --get-ipsets 2>/dev/null); do echo "ipset $z: $(firewall-cmd --info-ipset="$z" 2>/dev/null | grep -E 'entries')"; done
      echo; echo "### firewall-cmd --get-policies"; firewall-cmd --get-policies 2>&1
    fi
    if command -v nft >/dev/null 2>&1; then echo; echo "### nft list ruleset"; nft list ruleset 2>&1; fi
    echo; echo "### iptables -S"; iptables -S 2>&1
    if command -v iptables-legacy >/dev/null 2>&1; then echo; echo "### iptables-legacy -S"; iptables-legacy -S 2>&1; fi
    echo; echo "### ip6tables -S"; ip6tables -S 2>&1
    [ -n "$ufw" ] && { echo; echo "### ufw status verbose"; ufw status verbose 2>&1; }
    [ -f /etc/sysconfig/nftables.conf ] && { echo; echo "### /etc/sysconfig/nftables.conf (+ include)"; grep -vE '^\s*(#|$)' /etc/sysconfig/nftables.conf
      grep -oE 'include "[^"]+"' /etc/sysconfig/nftables.conf | cut -d'"' -f2 | while read -r z; do for f in $z; do [ -f "$f" ] && { echo "## $f"; grep -vE '^\s*(#|$)' "$f"; }; done; done; }
  } > "$RAW/firewall.txt" 2>/dev/null
  # runtime vs permanent firewalld (perubahan yang belum disimpan hilang saat reload/reboot)
  if [ "$fwd" = active ]; then
    for z in $(firewall-cmd --get-active-zones 2>/dev/null | grep -vE '^[[:space:]]'); do
      diff -q <(firewall-cmd --zone="$z" --list-all 2>/dev/null | tail -n +2 | grep -vE '^\s*interfaces:') \
              <(firewall-cmd --permanent --zone="$z" --list-all 2>/dev/null | tail -n +2 | grep -vE '^\s*interfaces:') >/dev/null 2>&1 || zd="$zd $z"
    done
  fi
  : > "$OUT/.fwports"
  command -v nft >/dev/null 2>&1 && nft -j list ruleset > "$OUT/.nft.json" 2>/dev/null
  iptables -S > "$OUT/.ipt" 2>/dev/null
  if command -v iptables-legacy >/dev/null 2>&1; then iptables-legacy -S > "$OUT/.iptl" 2>/dev/null; else : > "$OUT/.iptl"; fi
  # CentOS 7: iptables = legacy; jangan dihitung dua kali
  cmp -s "$OUT/.ipt" "$OUT/.iptl" && : > "$OUT/.iptl"
  ss -tulnpH > "$OUT/.ss" 2>/dev/null || ss -tulnp | tail -n +2 > "$OUT/.ss"
  printf 'firewalld=%s\nfirewalld_enabled=%s\nnftables=%s\nnftables_enabled=%s\niptables_svc=%s\nufw=%s\nfwd_diff=%s\nfwd_diff_zones=%s\n' \
    "${fwd:-n/a}" "${fwe:-n/a}" "${nfa:-n/a}" "${nfe:-n/a}" "${ips:-n/a}" "${ufw:-n/a}" "$([ -n "$zd" ] && echo 1 || echo 0)" "$zd" > "$OUT/.fwinfo"
  if [ -n "$PY" ]; then
    res=$(timeout 120 "$PY" - "$HOST" "$OUT/.nft.json" "$OUT/.iptl" "$OUT/.ipt" "$OUT/.ss" "$OUT/.fwinfo" "$RAW" "$FINDINGS" "$OUT/.fwports" 2>>"$RAW/firewall_analyzer_errors.txt" <<'FWEOF'
# -*- coding: utf-8 -*-
# Evaluasi aturan firewall yang BERLAKU di kernel (nftables JSON + iptables-legacy) per port yang listen.
# argv: host nft_json ipt_legacy ipt_nft ss_file fwinfo outdir findings_csv ports_out
from __future__ import print_function, unicode_literals
import sys, io, json, re, collections

host, nftf, iplf, ipnf, ssf, infof, outd, find_out, ports_out = sys.argv[1:10]
FIND = []


def fnd(sev, cid, title, ev, rec):
    FIND.append((sev, cid, 'Hardening', title, ev, rec))


def rd(p):
    try:
        return io.open(p, encoding='utf-8', errors='replace').read()
    except Exception:
        return ''


INFO = dict(l.split('=', 1) for l in rd(infof).split('\n') if '=' in l)

# ------------------------------------------------------------------ model
# rule = {'c': [cond...], 'v': verdict, 'u': bool(unknown matcher)}
# cond = (kind, neg, value); kind: proto, dport, saddr, iif, ct
# verdict = ('accept',) ('drop',) ('jump', chain) ('goto', chain) ('return',) None(counter/log)


class Ruleset(object):
    def __init__(self, name):
        self.name = name
        self.chains = collections.OrderedDict()   # key -> [rule]
        self.base = []                            # (key, policy, family)
        self.sets = {}


def port_items(v, sets, tbl):
    """Nilai dport nft -> list (lo, hi) atau None bila tidak bisa diketahui."""
    if isinstance(v, int):
        return [(v, v)]
    if isinstance(v, str):
        if v.startswith('@'):
            el = sets.get((tbl, v[1:]))
            if el is None:
                return None
            return port_items({'set': el}, sets, tbl)
        if v.isdigit():
            return [(int(v), int(v))]
        m = {'ssh': 22, 'http': 80, 'https': 443, 'domain': 53, 'snmp': 161, 'ntp': 123}.get(v)
        return [(m, m)] if m else None
    if isinstance(v, dict):
        if 'range' in v:
            a, b = v['range']
            return [(int(a), int(b))]
        if 'set' in v:
            out = []
            for x in v['set']:
                r = port_items(x, sets, tbl)
                if r is None:
                    return None
                out += r
            return out
        if 'prefix' in v:
            return None
    if isinstance(v, list):
        return port_items({'set': v}, sets, tbl)
    return None


def addr_text(v, sets, tbl):
    if isinstance(v, str):
        if v.startswith('@'):
            el = sets.get((tbl, v[1:]))
            return '%s{%s}' % (v, ','.join(addr_text(x, sets, tbl) for x in (el or [])[:8]))
        return v
    if isinstance(v, dict):
        if 'prefix' in v:
            return '%s/%s' % (v['prefix']['addr'], v['prefix']['len'])
        if 'range' in v:
            return '%s-%s' % tuple(v['range'])
        if 'set' in v:
            return ','.join(addr_text(x, sets, tbl) for x in v['set'][:8])
    return json.dumps(v)


def as_list(v):
    if isinstance(v, dict) and 'set' in v:
        return [x if isinstance(x, str) else json.dumps(x) for x in v['set']]
    if isinstance(v, list):
        return [x if isinstance(x, str) else json.dumps(x) for x in v]
    return [v if isinstance(v, str) else json.dumps(v)]


def verdict_of(e):
    for k in ('accept', 'drop', 'reject', 'return'):
        if k in e:
            return ('drop',) if k == 'reject' else (k,)
    for k in ('jump', 'goto'):
        if k in e:
            return (k, e[k]['target'])
    return None


def load_nft(p):
    try:
        d = json.loads(rd(p))['nftables']
    except Exception:
        return None
    rs = Ruleset('nftables')
    for o in d:
        if 'set' in o:
            s = o['set']
            rs.sets[(s['family'], s['table'], s['name'])] = s.get('elem', [])
        elif 'map' in o:
            s = o['map']
            rs.sets[(s['family'], s['table'], s['name'])] = s.get('elem', [])
    for o in d:
        if 'chain' in o:
            c = o['chain']
            key = (c['family'], c['table'], c['name'])
            rs.chains.setdefault(key, [])
            if c.get('hook') == 'input' and c.get('type', 'filter') == 'filter':
                rs.base.append((key, c.get('policy', 'accept'), c['family']))
    for o in d:
        if 'rule' not in o:
            continue
        r = o['rule']
        fam, tbl = r['family'], r['table']
        key = (fam, tbl, r['chain'])
        sets = dict(((t, n), v) for (f, t, n), v in rs.sets.items() if f == fam)
        conds, unk, v, extra = [], False, None, []
        for e in r.get('expr', []):
            if 'match' in e:
                m = e['match']
                left, right, op = m.get('left'), m.get('right'), m.get('op', '==')
                neg = op == '!='
                if not isinstance(left, dict):
                    unk = True
                    continue
                if 'payload' in left:
                    pl = left['payload']
                    proto, field = pl.get('protocol'), pl.get('field')
                    if field == 'dport' and proto in ('tcp', 'udp', 'th', 'sctp'):
                        if proto != 'th':
                            conds.append(('proto', False, [proto]))
                        conds.append(('dport', neg, port_items(right, sets, tbl)))
                    elif field == 'saddr' and proto in ('ip', 'ip6'):
                        conds.append(('saddr', neg, addr_text(right, sets, tbl)))
                        if proto == 'ip6':
                            conds.append(('fam6', False, None))
                    elif field == 'daddr' and proto in ('ip', 'ip6'):
                        dt = addr_text(right, sets, tbl)
                        if dt.startswith('127.') or dt == '::1':
                            conds.append(('never', False, None))
                    elif field == 'sport':
                        conds.append(('never', False, None)) if not neg else None
                    elif proto in ('icmp', 'icmpv6') or field in ('type', 'code'):
                        conds.append(('never', False, None))
                    else:
                        unk = True
                elif 'meta' in left:
                    k = left['meta'].get('key')
                    if k in ('iifname', 'iif'):
                        conds.append(('iif', neg, as_list(right)))
                    elif k == 'l4proto':
                        conds.append(('proto', neg, as_list(right)))
                    elif k == 'nfproto':
                        if 'ipv6' in as_list(right) and not neg:
                            conds.append(('fam6', False, None))
                    elif k in ('pkttype',):
                        conds.append(('never', False, None)) if 'unicast' not in as_list(right) else None
                    else:
                        unk = True
                elif 'ct' in left:
                    k = left['ct'].get('key')
                    if k == 'state':
                        conds.append(('ct', neg, as_list(right)))
                    else:
                        unk = True
                elif 'fib' in left:
                    conds.append(('never', False, None))     # rpfilter: tidak berlaku untuk paket normal
                else:
                    unk = True
            elif 'vmap' in e:
                vm = e['vmap']
                k = vm.get('key', {})
                data = vm.get('data', {})
                items = data.get('set', []) if isinstance(data, dict) else []
                if isinstance(data, str) and data.startswith('@'):
                    items = sets.get((tbl, data[1:]), [])
                if 'ct' in k and k['ct'].get('key') == 'state':
                    for it in items:
                        ks, vd = it[0], verdict_of(it[1]) if isinstance(it[1], dict) else None
                        for st in as_list(ks):
                            if st in ('new', 'untracked') and vd:
                                extra.append({'c': conds + [('ct', False, [st])], 'v': vd, 'u': unk})
                    v = None
                elif 'meta' in k and k['meta'].get('key') in ('iifname', 'iif'):
                    for it in items:
                        vd = verdict_of(it[1]) if isinstance(it[1], dict) else None
                        if vd:
                            extra.append({'c': conds + [('iif', False, as_list(it[0]))], 'v': vd, 'u': unk})
                elif 'payload' in k and k['payload'].get('field') == 'dport':
                    for it in items:
                        vd = verdict_of(it[1]) if isinstance(it[1], dict) else None
                        pi = port_items(it[0], sets, tbl)
                        if vd:
                            extra.append({'c': conds + [('dport', False, pi)], 'v': vd, 'u': unk})
                else:
                    unk = True
            else:
                vd = verdict_of(e)
                if vd:
                    v = vd
        lst = rs.chains.setdefault(key, [])
        if extra:
            lst.extend(extra)
        elif v is not None:
            lst.append({'c': conds, 'v': v, 'u': unk})
    return rs


def load_ipt(text, name):
    rs = Ruleset(name)
    pol = {}
    for ln in text.split('\n'):
        t = ln.split()
        if not t:
            continue
        if t[0] == '-P' and len(t) >= 3:
            pol[t[1]] = t[2].lower()
            rs.chains.setdefault(('ip', 'filter', t[1]), [])
            continue
        if t[0] == '-N':
            rs.chains.setdefault(('ip', 'filter', t[1]), [])
            continue
        if t[0] != '-A' or len(t) < 2:
            continue
        key = ('ip', 'filter', t[1])
        conds, unk, v, i, neg = [], False, None, 2, False
        while i < len(t):
            a = t[i]
            nx = t[i + 1] if i + 1 < len(t) else ''
            if a == '!':
                neg = True
                i += 1
                continue
            if a in ('-p', '--protocol'):
                if nx not in ('all', '0'):
                    conds.append(('proto', neg, [nx]))
                i += 2
            elif a in ('-s', '--source'):
                conds.append(('saddr', neg, nx))
                i += 2
            elif a in ('-d', '--destination'):
                if nx.startswith('127.'):
                    conds.append(('never', False, None))
                i += 2
            elif a in ('-i', '--in-interface'):
                conds.append(('iif', neg, [nx.rstrip('+')]))
                i += 2
            elif a in ('--dport', '--destination-port', '--dports', '--destination-ports'):
                items = []
                for x in nx.split(','):
                    if ':' in x:
                        lo, hi = x.split(':')
                        items.append((int(lo or 0), int(hi or 65535)))
                    elif x.isdigit():
                        items.append((int(x), int(x)))
                    else:
                        items = None
                        break
                conds.append(('dport', neg, items))
                i += 2
            elif a in ('--state', '--ctstate'):
                conds.append(('ct', neg, [x.lower() for x in nx.split(',')]))
                i += 2
            elif a == '--match-set' and i + 2 < len(t):
                if t[i + 2].startswith('src'):
                    conds.append(('saddr', neg, 'ipset:' + nx))
                else:
                    unk = True
                i += 3
            elif a in ('-j', '-g', '--jump', '--goto'):
                tg = nx.upper() if nx.upper() in ('ACCEPT', 'DROP', 'REJECT', 'RETURN') else nx
                if tg in ('ACCEPT',):
                    v = ('accept',)
                elif tg in ('DROP', 'REJECT'):
                    v = ('drop',)
                elif tg == 'RETURN':
                    v = ('return',)
                elif tg in ('LOG', 'MARK', 'CONNMARK', 'NOTRACK', 'CT', 'AUDIT', 'NFLOG'):
                    v = None
                else:
                    v = ('goto' if a in ('-g', '--goto') else 'jump', tg)
                i += 2
                # sisa argumen target (mis. --reject-with) diabaikan
                while i < len(t) and not t[i].startswith(('-j', '-g')) and t[i].startswith('--') and t[i] not in ('--dport', '--dports'):
                    i += 2
            elif a in ('-m', '--match'):
                if nx not in ('tcp', 'udp', 'state', 'conntrack', 'multiport', 'set', 'comment', 'icmp'):
                    if nx in ('addrtype', 'pkttype', 'limit', 'hashlimit', 'recent', 'mac', 'iprange', 'owner', 'string', 'mark', 'connlimit'):
                        unk = True
                if nx == 'icmp':
                    conds.append(('never', False, None))
                i += 2
            elif a in ('--comment',):
                i += 2
            elif a.startswith('--'):
                if a in ('--icmp-type', '--tcp-flags', '--syn'):
                    if a == '--tcp-flags':
                        i += 3
                        continue
                    i += 1 if a == '--syn' else 2
                    continue
                unk = True
                i += 2 if (nx and not nx.startswith('-')) else 1
            else:
                i += 1
            neg = False
        rs.chains.setdefault(key, [])
        if v is not None:
            rs.chains[key].append({'c': conds, 'v': v, 'u': unk})
    if 'INPUT' in pol or ('ip', 'filter', 'INPUT') in rs.chains:
        rs.base.append((('ip', 'filter', 'INPUT'), pol.get('INPUT', 'accept'), 'ip'))
    return rs


# ------------------------------------------------------------ evaluasi
def in_ports(items, port):
    return any(lo <= port <= hi for lo, hi in items)


def rule_match(r, proto, port):
    """'no' / 'yes' / 'src' (hanya untuk sumber tertentu) / 'unk'."""
    src = None
    for kind, neg, val in r['c']:
        if kind == 'never':
            return 'no', None
        if kind == 'fam6':
            return 'no', None
        if kind == 'proto':
            ok = proto in val or ('th' in val)
            if ok == neg:
                return 'no', None
        elif kind == 'dport':
            if val is None:
                return 'unk', None
            ok = in_ports(val, port)
            if ok == neg:
                return 'no', None
        elif kind == 'iif':
            islo = any(x in ('lo',) for x in val)
            if islo and not neg:
                return 'no', None
        elif kind == 'ct':
            ok = any(x in ('new', 'untracked') for x in val)
            if ok == neg:
                return 'no', None
        elif kind == 'saddr':
            if not neg:
                src = val
    if r['u']:
        return 'unk', src
    return ('src', src) if src else ('yes', None)


def eval_chain(rs, key, proto, port, restricted, depth=0, ctx_src=None):
    """Hasil untuk sumber umum: 'accept'/'drop'/None(lanjut) dan mengisi restricted/uncertain."""
    if depth > 30:
        return None
    for r in rs.chains.get(key, []):
        m, src = rule_match(r, proto, port)
        if m == 'no':
            continue
        if m == 'unk':
            restricted['unk'] = True
            continue
        v = r['v']
        if m == 'src' or ctx_src:
            s = src or ctx_src
            if v[0] == 'accept':
                restricted['src'].append(s)
            elif v[0] in ('jump', 'goto'):
                eval_chain(rs, (key[0], key[1], v[1]), proto, port, restricted, depth + 1, s)
            continue
        if v[0] == 'accept':
            return 'accept'
        if v[0] == 'drop':
            return 'drop'
        if v[0] == 'return':
            return None
        if v[0] in ('jump', 'goto'):
            res = eval_chain(rs, (key[0], key[1], v[1]), proto, port, restricted, depth + 1)
            if res in ('accept', 'drop'):
                return res
            if v[0] == 'goto':
                return 'end'
    return None


def eval_port(rsets, proto, port):
    """Gabungkan semua base chain input (semua tabel): drop di salah satu = diblok."""
    status, srcs, unk, any_chain = 'open', [], False, False
    for rs in rsets:
        for key, pol, fam in rs.base:
            if fam == 'ip6':
                continue
            any_chain = True
            rr = {'src': [], 'unk': False}
            res = eval_chain(rs, key, proto, port, rr)
            if res in (None, 'end'):
                res = 'accept' if pol == 'accept' else 'drop'
            unk = unk or rr['unk']
            if res == 'drop':
                if rr['src']:
                    if status != 'blocked':
                        status = 'restricted'
                    srcs += rr['src']
                else:
                    status = 'blocked'
    if not any_chain:
        return 'nofw', [], False
    return status, sorted(set(srcs)), unk


def has_filtering(rs):
    for key, pol, fam in rs.base:
        if pol == 'drop':
            return True
        stack, seen = [key], set()
        while stack:
            k = stack.pop()
            if k in seen:
                continue
            seen.add(k)
            for r in rs.chains.get(k, []):
                if r['v'][0] == 'drop':
                    return True
                if r['v'][0] in ('jump', 'goto'):
                    stack.append((k[0], k[1], r['v'][1]))
    return False


# ------------------------------------------------------------------ jalankan
rsets, used = [], []
nrs = load_nft(nftf) if nftf and rd(nftf).strip() else None
if nrs is not None and nrs.base:
    rsets.append(nrs)
    used.append('nftables (kernel, mencakup firewalld/iptables-nft)')
elif rd(ipnf).strip():
    r = load_ipt(rd(ipnf), 'iptables')
    if r.base and (r.chains.get(('ip', 'filter', 'INPUT')) or r.base[0][1] != 'accept'):
        rsets.append(r)
        used.append('iptables')
leg = rd(iplf)
if leg.strip():
    r = load_ipt(leg, 'iptables-legacy')
    if r.chains.get(('ip', 'filter', 'INPUT')) or (r.base and r.base[0][1] != 'accept'):
        rsets.append(r)
        used.append('iptables-legacy')

filt = [rs for rs in rsets if has_filtering(rs)]

# port listen
LS = []
for ln in rd(ssf).split('\n'):
    t = ln.split()
    if len(t) < 5 or t[0] not in ('tcp', 'udp'):
        continue
    loc = t[4]
    addr, _, port = loc.rpartition(':')
    if not port.isdigit():
        continue
    a = addr.strip('[]').split('%')[0]
    if a.startswith('127.') or a == '::1':
        continue
    proc = re.search(r'\(\("([^"]+)"', ln)
    LS.append((t[0], int(port), a or '*', proc.group(1) if proc else '?'))
LS = sorted(set(LS), key=lambda x: (x[0], x[1]))

rows, openp, restr, unkp = [], [], [], []
PORTS = []
for proto, port, addr, proc in LS:
    if not filt:
        st, srcs, unk = 'open', [], False
    else:
        st, srcs, unk = eval_port(filt, proto, port)
    label = {'open': 'TERBUKA UNTUK SEMUA', 'restricted': 'DIBATASI', 'blocked': 'DIBLOK', 'nofw': 'TANPA FIREWALL'}[st]
    note = (' sumber: ' + ', '.join(srcs)[:200]) if srcs else ''
    if unk:
        note += ' (ada aturan yang tidak bisa dinilai otomatis: perkiraan)'
    rows.append('%-4s %-6d %-22s %-14s %s%s' % (proto, port, addr, proc[:14], label, note))
    PORTS.append('%s %d %s' % (proto, port, st))
    if st == 'open' and filt:
        openp.append('%s/%d (%s)' % (proto, port, proc))
    elif st == 'restricted':
        restr.append('%s/%d <- %s' % (proto, port, ', '.join(srcs)[:80]))
    if unk:
        unkp.append('%s/%d' % (proto, port))

svc = ', '.join('%s=%s' % (k, INFO.get(k, '?')) for k in ('firewalld', 'firewalld_enabled', 'nftables', 'nftables_enabled', 'iptables_svc', 'ufw'))
with io.open(outd + '/firewall_analysis.txt', 'w', encoding='utf-8') as fo:
    fo.write('Analisis firewall host (aturan yang berlaku di kernel)\n')
    fo.write('Sumber aturan : %s\n' % (', '.join(used) or '(tidak ada)'))
    fo.write('Layanan       : %s\n' % svc)
    fo.write('Ada filter    : %s\n\n' % ('YA' if filt else 'TIDAK (semua lalu lintas masuk diterima)'))
    fo.write('Status port yang listen di interface jaringan (sumber umum = IP yang tidak ada di whitelist):\n')
    fo.write('\n'.join(rows) + '\n' if rows else '(tidak ada port listen non-loopback)\n')
    fo.write('\nCatatan: hanya chain input IPv4 yang dinilai; firewall jaringan (Palo Alto) di luar cakupan.\n')
with io.open(ports_out, 'w', encoding='utf-8') as fo:
    fo.write('\n'.join(PORTS) + '\n')

if not filt:
    fnd('MEDIUM', 'HRD-FW-01', 'Tidak ada host firewall yang memfilter lalu lintas masuk',
        'sumber aturan diperiksa: %s; %s' % (', '.join(used) or 'nftables/iptables kosong', svc),
        'Aktifkan firewalld (atau nftables) dengan default deny, lalu izinkan hanya port yang diperlukan dari IP sumber yang diperlukan (defense in depth di belakang Palo Alto).')
else:
    fnd('INFO', 'HRD-FW-00', 'Host firewall aktif', '%s; %d port dibatasi/diblok, %d terbuka untuk semua' % (', '.join(used), len(LS) - len(openp), len(openp)),
        'Rincian per port di raw/firewall_analysis.txt.')
    if openp:
        fnd('MEDIUM', 'HRD-FW-02', 'Firewall aktif tetapi ada port yang terbuka untuk semua IP', '; '.join(openp[:15]),
            'Batasi setiap port ke IP sumber yang membutuhkan (firewalld: rich rule source address=... port=...; hapus service/port umum dari zona; '
            'nftables: tcp dport N ip saddr {..} accept + policy drop). SSH cukup dari jump host.')
if unkp:
    fnd('INFO', 'HRD-FW-04', 'Sebagian aturan firewall tidak bisa dinilai otomatis', ', '.join(unkp[:15]),
        'Review manual raw/firewall.txt untuk port tersebut.')
pers = []
if INFO.get('firewalld') == 'active' and INFO.get('firewalld_enabled') not in ('enabled', 'static'):
    pers.append('firewalld aktif tetapi tidak enabled (mati setelah reboot)')
if INFO.get('fwd_diff') == '1':
    pers.append('konfigurasi runtime firewalld berbeda dari permanent (perubahan hilang setelah reload/reboot): zona ' + INFO.get('fwd_diff_zones', ''))
if filt and INFO.get('firewalld') != 'active' and INFO.get('nftables_enabled') != 'enabled' and INFO.get('iptables_svc') != 'enabled' and INFO.get('ufw', '').find('active') < 0:
    pers.append('aturan ada di kernel tetapi tidak ada layanan firewall yang enabled (nftables/iptables/firewalld): aturan hilang setelah reboot')
if pers:
    fnd('LOW', 'HRD-FW-03', 'Aturan firewall tidak persisten', '; '.join(pers),
        'firewalld: systemctl enable firewalld dan simpan perubahan dengan --permanent (atau firewall-cmd --runtime-to-permanent). '
        'nftables: simpan ke /etc/sysconfig/nftables.conf lalu systemctl enable nftables.')


def q(s):
    s = ('%s' % s).replace('\r', '').replace('\n', ' | ').replace('"', '""')
    return '"%s"' % (s[:700] + '...' if len(s) > 700 else s)


with io.open(find_out, 'a', encoding='utf-8') as fo:
    for sev, cid, cat, title, ev, rec in FIND:
        fo.write(','.join(q(x) for x in (host, cat, cid, sev, title, ev, rec)) + '\n')
print('fw-analyzer: %s; filter=%s; port=%d terbuka=%d dibatasi=%d' % (','.join(used) or '-', bool(filt), len(LS), len(openp), len(restr)))
FWEOF
)
    log "  $res"
    case "$res" in *filter=True*) FW_ON=1 ;; esac
    [ -s "$RAW/firewall_analyzer_errors.txt" ] || rm -f "$RAW/firewall_analyzer_errors.txt"
  else
    ipt=$( { cat "$OUT/.ipt" "$OUT/.iptl"; } | grep -cE '^-A .*-j (DROP|REJECT)|^-P INPUT DROP')
    command -v nft >/dev/null 2>&1 && nftc=$(nft list ruleset 2>/dev/null | grep -cE '\b(drop|reject)\b|policy drop')
    if [ "${ipt:-0}" -gt 0 ] || [ "${nftc:-0}" -gt 0 ]; then FW_ON=1; else
      finding MEDIUM HRD-FW-01 Hardening "Tidak ada host firewall yang memfilter lalu lintas masuk" \
        "firewalld: ${fwd:-n/a}; nftables: ${nfa:-n/a}; aturan drop/reject iptables: ${ipt:-0}, nft: ${nftc:-0}" \
        "Aktifkan firewalld (atau nftables) dengan default deny, lalu izinkan hanya port yang diperlukan dari IP sumber yang diperlukan."
    fi
  fi
  rm -f "$OUT/.nft.json" "$OUT/.ipt" "$OUT/.iptl" "$OUT/.ss" "$OUT/.fwinfo"
}

# Status firewall untuk satu port tcp (blocked/restricted/open/kosong bila tidak diketahui)
fw_port_status() { awk -v p="$1" '$1=="tcp" && $2==p {print $3; exit}' "$OUT/.fwports" 2>/dev/null; }

check_hardening() {
  log "Cek hardening sistem"
  local se; se=$(getenforce 2>/dev/null)
  case "$se" in
    Disabled)   finding MEDIUM HRD-SELINUX-01 Hardening "SELinux nonaktif" "getenforce: $se" "Aktifkan SELinux (mulai dari permissive, perbaiki denial di audit.log, lalu enforcing)." ;;
    Permissive) finding LOW HRD-SELINUX-01 Hardening "SELinux mode permissive" "getenforce: $se" "Analisis denial di audit.log lalu ubah ke enforcing." ;;
  esac

  check_firewall

  local p bad=""
  for p in telnet-server rsh-server ypserv tftp-server vsftpd xinetd talk-server; do
    rpm -q "$p" >/dev/null 2>&1 && bad="$bad $p"
  done
  [ -n "$bad" ] && finding MEDIUM HRD-SVC-01 Hardening "Paket service tidak aman terinstal" "$bad" \
    "Hapus paket yang tidak dipakai (yum remove), atau nonaktifkan service-nya."

  if [ "$(systemctl is-active rpcbind 2>/dev/null)" = active ] && ! rpm -q nfs-utils >/dev/null 2>&1; then
    finding LOW HRD-SVC-02 Hardening "rpcbind aktif tanpa NFS" "rpcbind active" "systemctl disable --now rpcbind rpcbind.socket bila tidak memakai NFS."
  fi
  if [ "$(systemctl is-active chronyd 2>/dev/null)" != active ] && [ "$(systemctl is-active ntpd 2>/dev/null)" != active ]; then
    finding LOW HRD-NTP-01 Hardening "Sinkronisasi waktu (chronyd/ntpd) tidak aktif" "-" "Aktifkan chronyd: waktu akurat penting untuk log forensik dan TLS."
  fi
  [ "$(systemctl is-active auditd 2>/dev/null)" != active ] && finding LOW HRD-AUDIT-01 Hardening "auditd tidak aktif" "-" \
    "Aktifkan auditd untuk jejak audit (login, sudo, perubahan file penting)."
  [ "$(systemctl is-active rsyslog 2>/dev/null)" != active ] && finding LOW HRD-LOG-01 Hardening "rsyslog tidak aktif" "-" \
    "Aktifkan rsyslog dan idealnya kirim log ke server log terpusat/SIEM."
}

#------------------------------------------------------------------------------
# 5. PORT TERBUKA
#------------------------------------------------------------------------------
check_network() {
  log "Cek port yang terbuka ke jaringan"
  local exposed
  exposed=$(ss -tulpn 2>/dev/null | awk 'NR>1{print $1, $5, $7}' | while read -r proto addr procinfo; do
      is_loopback "${addr%:*}" && continue
      p=$(echo "$procinfo" | sed -n 's/.*(("\([^"]*\)".*/\1/p')
      echo "$proto/${addr##*:}(${p:-?})"
    done | sort -u | tr '\n' ' ')
  [ -n "$exposed" ] && finding INFO NET-LISTEN-01 Jaringan "Port yang terbuka ke jaringan (bandingkan dengan yang seharusnya)" "$exposed" \
    "Matikan service yang tidak dipakai; batasi tiap port dengan firewall hanya dari sumber yang membutuhkan."
}

#------------------------------------------------------------------------------
# 6. FILESYSTEM
#------------------------------------------------------------------------------
# Cari SEMUA arsip Java (jar/war/ear/rar) di seluruh disk lokal -> masuk inventaris library
# Arsip dengan nama tidak standar (app.jar_bk, app.jar.bak, app.war.20261127) hanya diambil bila memang file zip
filter_archives() {
  local f
  while IFS= read -r f; do
    case "${f,,}" in
      *.jar|*.war|*.ear|*.rar) echo "$f" ;;
      *.sha1|*.sha256|*.sha512|*.md5|*.asc|*.sig|*.pom|*.lastupdated|*.properties|*.txt|*.log|*.xml|*.json|*.repositories|*.lck|*.tmp) ;;
      *) is_zip "$f" && echo "$f" ;;
    esac
  done
}

scan_disk_archives_only() {
  local mp
  log "Mencari semua arsip Java (jar/war/ear) di seluruh disk lokal"
  for mp in $(df -lP -x tmpfs -x devtmpfs 2>/dev/null | awk 'NR>1{print $6}'); do
    timeout 1200 find "$mp" -xdev \( "${PRUNE_EXPR[@]}" \) -prune -o \
      -type f \( \( \( -iname '*.jar' -o -iname '*.war' -o -iname '*.ear' -o -iname '*.rar' -o -iname '*.jar[._-]*' -o -iname '*.war[._-]*' -o -iname '*.ear[._-]*' \) -printf 'AR %p\n' \) , \
                  \( \( -name package-lock.json -o -name yarn.lock -o -name composer.lock -o -name requirements.txt \) -printf 'MF %p\n' \) , \
                  \( \( -name Dockerfile -o -name 'Dockerfile.*' -o -name '*.dockerfile' -o -name Containerfile -o -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' -o -name compose.yml -o -name compose.yaml \) -printf 'DF %p\n' \) , \
                  \( -path '*/bin/java' -printf 'JV %p\n' \) \) 2>/dev/null
  done > "$OUT/.disk"
  grep '^AR ' "$OUT/.disk" | cut -c4- | sort -u | filter_archives > "$RAW/disk_archives.txt"
  grep '^JV ' "$OUT/.disk" | cut -c4- | sort -u > "$OUT/.javabins"
  grep '^MF ' "$OUT/.disk" | cut -c4- | sort -u > "$OUT/.manifests"
  grep '^DF ' "$OUT/.disk" | cut -c4- | sort -u > "$OUT/.cfgfiles"; rm -f "$OUT/.disk"
}

# Daftar JDK/JRE terinstal: root|versi|dipakai-proses-berjalan
build_jdk_list() {
  local b root v used pid exes=""
  for pid in $(java_pids); do exes="$exes $(pid_exe "$pid")"; done
  { cat "$OUT/.javabins" 2>/dev/null; for b in $exes; do echo "$b"; done; } | sort -u | while read -r b; do
    [ -x "$b" ] || continue
    root=$(dirname "$(dirname "$b")")
    case "$root" in */jre) [ -x "$(dirname "$root")/bin/java" ] && continue ;; esac
    echo "$root"
  done | sort -u | while read -r root; do
    v=$(sed -n 's/^JAVA_VERSION="\(.*\)"/\1/p' "$root/release" 2>/dev/null)
    [ -z "$v" ] && v=$(timeout 15 "$root/bin/java" -version 2>&1 | grep -oE 'version "[^"]+"' | head -n1 | tr -d '"' | cut -d' ' -f2)
    used=tidak
    for b in $exes; do case "$b" in "$root"/*) used=YA ;; esac; done
    echo "$root|${v:-?}|$used"
  done > "$RAW/jdk_installs.txt"
  rm -f "$OUT/.javabins"
}

register_disk_archives() {
  local f n jh skipped=0 roots
  build_jdk_list
  [ -s "$RAW/disk_archives.txt" ] || return 0
  n=$(wc -l < "$RAW/disk_archives.txt")
  log "  -> $n arsip Java ditemukan di disk"
  # Instalasi WildFly/JBoss yang ditemukan di disk -> cek statis otomatis (walau tidak berjalan)
  grep '/jboss-modules\.jar$' "$RAW/disk_archives.txt" | while read -r f; do echo "$(dirname "$f")"; done > "$OUT/.wfhomes"
  while read -r jh; do
    [ -d "$jh/modules" ] || continue
    case "$WF_SEEN" in *" $(rpath "$jh") "*) continue ;; esac
    log "  -> instalasi WildFly/JBoss ditemukan (tidak berjalan): $jh"
    scan_wildfly_home "$jh"
  done < "$OUT/.wfhomes"; rm -f "$OUT/.wfhomes"
  roots=$(cut -d'|' -f1 "$RAW/jdk_installs.txt" 2>/dev/null)
  while read -r f; do
    case "$f" in */standalone/tmp/*|*/domain/tmp/*|*/work/Catalina/*) skipped=$((skipped+1)); continue ;; esac
    for jh in $roots; do case "$f" in "$jh"/*) f=""; break ;; esac; done
    [ -z "$f" ] && { skipped=$((skipped+1)); continue; }
    reg_archive "disk:$(echo "$f" | cut -d/ -f1-4)" "$f"
  done < "$RAW/disk_archives.txt"
  echo "Arsip dilewati (bagian internal JDK, folder tmp WildFly/Tomcat): $skipped" >> "$RAW/disk_archives_note.txt"
}

check_fs() {
  if [ "$SAFE" -eq 1 ]; then log "Mode --safe: scan disk (izin file & pencarian semua jar) dilewati"; return; fi
  if [ "$SKIP_FS" -eq 1 ]; then log "Lewati cek izin file (--skip-fs)"; scan_disk_archives_only; return; fi
  log "Cek filesystem (izin file, SUID/SGID, kunci) + cari semua jar/war/ear - bisa beberapa menit"
  local mp n tmp="$OUT/.fs.$$"
  : > "$tmp"
  for mp in $(df -lP -x tmpfs -x devtmpfs 2>/dev/null | awk 'NR>1{print $6}'); do
    timeout 1200 find "$mp" -xdev \( "${PRUNE_EXPR[@]}" \) -prune -o \
      \( -type f \( \
           \( \( -iname '*.jar' -o -iname '*.war' -o -iname '*.ear' -o -iname '*.rar' -o -iname '*.jar[._-]*' -o -iname '*.war[._-]*' -o -iname '*.ear[._-]*' \) -printf 'AR %p\n' \) , \
           \( -path '*/bin/java' -printf 'JV %p\n' \) , \
           \( \( -name package-lock.json -o -name yarn.lock -o -name composer.lock -o -name requirements.txt \) -printf 'MF %p\n' \) , \
           \( \( -name Dockerfile -o -name 'Dockerfile.*' -o -name '*.dockerfile' -o -name Containerfile -o -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' -o -name compose.yml -o -name compose.yaml \) -printf 'DF %p\n' \) , \
           \( -perm -0002 -printf 'WW %p\n' \) , \
           \( \( -perm -4000 -o -perm -2000 \) -printf 'SU %p\n' \) , \
           \( \( -name '*.key' -o -name '*.p12' -o -name '*.pfx' -o -name '*.jks' -o -name '*.jceks' -o -name '*.keystore' \
              -o -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' -o -name '*.env' -o -name 'passwords*' \) \
              -perm -0004 -printf 'KR %p\n' \) \
         \) \) \
      -o \( -type d -perm -0002 ! -perm -1000 -printf 'WD %p\n' \) \
      2>/dev/null >> "$tmp"
  done
  grep '^WW ' "$tmp" | cut -c4- | grep -vE '^(/tmp|/var/tmp)/' | sort -u > "$RAW/fs_world_writable.txt"
  grep '^SU ' "$tmp" | cut -c4- | sort -u > "$RAW/fs_suid_sgid.txt"
  grep '^AR ' "$tmp" | cut -c4- | sort -u | filter_archives > "$RAW/disk_archives.txt"
  grep '^JV ' "$tmp" | cut -c4- | sort -u > "$OUT/.javabins"
  grep '^MF ' "$tmp" | cut -c4- | sort -u > "$OUT/.manifests"
  grep '^DF ' "$tmp" | cut -c4- | sort -u > "$OUT/.cfgfiles"
  grep '^KR ' "$tmp" | cut -c4- | grep -vE '^/(usr/share|usr/lib|etc/pki/(ca-trust|java)|etc/ssl/certs)/|^/etc/trusted-key\.key$' | sort -u > "$RAW/fs_key_readable.txt"
  grep '^WD ' "$tmp" | cut -c4- | sort -u > "$RAW/fs_ww_dirs_nosticky.txt"
  rm -f "$tmp"
  n=$(wc -l < "$RAW/fs_key_readable.txt")
  [ "$n" -gt 0 ] && finding MEDIUM FS-KEY-01 Filesystem "$n file kunci/keystore/secret bisa dibaca semua user" \
    "$(head -n 10 "$RAW/fs_key_readable.txt" | tr '\n' ' ')" \
    "chmod 600 (owner user aplikasi) untuk private key, keystore (.p12/.jks/.jceks) dan file .env/password."
  n=$(wc -l < "$RAW/fs_ww_dirs_nosticky.txt")
  [ "$n" -gt 0 ] && finding MEDIUM FS-WWDIR-01 Filesystem "$n folder world-writable tanpa sticky bit" \
    "$(head -n 10 "$RAW/fs_ww_dirs_nosticky.txt" | tr '\n' ' ')" \
    "chmod o-w atau chmod +t; user lain bisa menghapus/mengganti file di folder ini."

  local n; n=$(wc -l < "$RAW/fs_world_writable.txt")
  [ "$n" -gt 0 ] && finding MEDIUM FS-WW-01 Filesystem "$n file bisa ditulis oleh semua user (world-writable)" \
    "$(head -n 10 "$RAW/fs_world_writable.txt" | tr '\n' ' ')" \
    "chmod o-w pada file tersebut; file world-writable yang dieksekusi root/aplikasi bisa dipakai untuk eskalasi hak akses."

  local f notrpm=""
  while read -r f; do rpm -qf "$f" >/dev/null 2>&1 || notrpm="$notrpm $f"; done < "$RAW/fs_suid_sgid.txt"
  [ -n "$notrpm" ] && finding MEDIUM FS-SUID-01 Filesystem "File SUID/SGID yang bukan berasal dari paket RPM" "$notrpm" \
    "Verifikasi asal file; hapus bit SUID/SGID (chmod u-s,g-s) bila tidak diperlukan. Bisa indikasi backdoor."
}

#------------------------------------------------------------------------------
# 7. WEB / PROXY (cek live ke service lokal: TLS, header, TRACE)
#------------------------------------------------------------------------------
web_live_checks() { # $1=label, $2=pid
  [ "$NO_NET" -eq 1 ] && return
  have curl || return
  local label="$1" pid="$2" addr port tgt hdr code weak proto miss enddate exp_epoch days
  for addr in $(listen_of_pid "$pid"); do
    port=${addr##*:}; tgt=$(target_of "$addr")
    if have openssl && echo | timeout 8 openssl s_client -connect "$tgt:$port" >/dev/null 2>&1; then
      # ---- port TLS ----
      weak=""
      for proto in ssl3 tls1 tls1_1; do
        echo | timeout 8 openssl s_client -connect "$tgt:$port" -"$proto" >/dev/null 2>&1 && weak="$weak $proto"
      done
      [ -n "$weak" ] && finding MEDIUM WEB-TLS-01 Web "Protokol TLS usang diizinkan" "$label port $port:$weak" \
        "Izinkan hanya TLSv1.2 dan TLSv1.3. Apache: SSLProtocol -all +TLSv1.2 (+TLSv1.3); Nginx: ssl_protocols TLSv1.2 TLSv1.3;"
      echo | timeout 8 openssl s_client -connect "$tgt:$port" -cipher 'RC4:DES:3DES:NULL:EXPORT:aNULL:eNULL:MD5' >/dev/null 2>&1 && \
        finding MEDIUM WEB-TLS-02 Web "Cipher TLS lemah diizinkan (RC4/DES/3DES/NULL/EXPORT)" "$label port $port" \
          "Gunakan cipher suite modern (ECDHE + AES-GCM/CHACHA20); lihat Mozilla SSL Configuration Generator profil 'intermediate'."
      enddate=$(echo | timeout 8 openssl s_client -connect "$tgt:$port" 2>/dev/null | openssl x509 -noout -enddate -subject 2>/dev/null)
      echo "$label:$port $enddate" >> "$RAW/web_certs.txt"
      exp_epoch=$(date -d "$(echo "$enddate" | sed -n 's/^notAfter=//p')" +%s 2>/dev/null)
      if [ -n "$exp_epoch" ]; then
        days=$(( (exp_epoch - $(date +%s)) / 86400 ))
        if [ "$days" -lt 0 ]; then
          finding HIGH WEB-CERT-01 Web "Sertifikat TLS sudah kedaluwarsa" "$label port $port: $enddate" "Perbarui sertifikat segera."
        elif [ "$days" -lt 30 ]; then
          finding MEDIUM WEB-CERT-02 Web "Sertifikat TLS kedaluwarsa < 30 hari" "$label port $port: sisa $days hari" "Perbarui sertifikat dan pasang monitoring masa berlaku."
        fi
      fi
      hdr=$(curl -skI -m 8 "https://$tgt:$port/" 2>/dev/null | tr -d '\r')
      code=$(curl -sk -X TRACE -m 8 -o /dev/null -w '%{http_code}' "https://$tgt:$port/" 2>/dev/null)
      miss=""
      echo "$hdr" | grep -qi '^strict-transport-security:' || miss="$miss Strict-Transport-Security"
    else
      # ---- port HTTP biasa ----
      hdr=$(curl -sI -m 8 "http://$tgt:$port/" 2>/dev/null | tr -d '\r')
      [ -z "$hdr" ] && continue
      code=$(curl -s -X TRACE -m 8 -o /dev/null -w '%{http_code}' "http://$tgt:$port/" 2>/dev/null)
      miss=""
      if ! echo "$hdr" | head -n1 | grep -qE ' (301|302|303|307|308) '; then
        finding LOW WEB-HTTP-01 Web "Port HTTP tanpa redirect ke HTTPS" "$label port $port: $(echo "$hdr" | head -n1)" \
          "Redirect semua HTTP ke HTTPS, kecuali port ini memang hanya untuk traffic internal/health check."
      fi
    fi
    { echo "== $label $tgt:$port =="; echo "$hdr"; echo "TRACE -> $code"; echo; } >> "$RAW/web_headers.txt"
    echo "$hdr" | grep -qi '^x-frame-options:' || echo "$hdr" | grep -qi 'frame-ancestors' || miss="$miss X-Frame-Options"
    echo "$hdr" | grep -qi '^x-content-type-options:' || miss="$miss X-Content-Type-Options"
    [ -n "$miss" ] && finding LOW WEB-HDR-01 Web "Security header belum lengkap" "$label port $port, tidak ada:$miss" \
      "Tambahkan di proxy, mis. Apache: Header always set X-Frame-Options SAMEORIGIN / X-Content-Type-Options nosniff / Strict-Transport-Security \"max-age=31536000\"."
    echo "$hdr" | grep -iE '^server:.*[0-9]' >/dev/null && finding LOW WEB-BANNER-01 Web "Header Server menampilkan versi software" \
      "$label port $port: $(echo "$hdr" | grep -i '^server:')" "Apache: ServerTokens Prod + ServerSignature Off; Nginx: server_tokens off;"
    echo "$hdr" | grep -qi '^x-powered-by:' && finding LOW WEB-BANNER-02 Web "Header X-Powered-By membocorkan teknologi backend" \
      "$label port $port: $(echo "$hdr" | grep -i '^x-powered-by:')" "Hapus header di proxy (Apache: Header unset X-Powered-By; Nginx: proxy_hide_header X-Powered-By)."
    [ "$code" = "200" ] && finding LOW WEB-TRACE-01 Web "Metode HTTP TRACE diizinkan" "$label port $port" \
      "Apache: TraceEnable off; Nginx: tolak metode selain yang dipakai aplikasi."
  done
}

# Daftar SEMUA file config Apache yang benar-benar dimuat (semua kedalaman & lokasi)
apache_conf_files() { # $1=bin $2=root $3=config-utama $4..=argumen instance (-d/-f)
  local bin="$1" root="$2" main="$3" out f p inc; shift 3
  out=$("$bin" "$@" -t -D DUMP_INCLUDES 2>/dev/null | sed -n 's/^[[:space:]]*([0-9*]*)[[:space:]]*\(\/.*\)$/\1/p')
  if [ -n "$out" ]; then echo "$out"; return 0; fi
  # cadangan: telusuri Include/IncludeOptional secara rekursif
  local queue=("$main") seen=" "
  while [ ${#queue[@]} -gt 0 ]; do
    f=${queue[0]}; queue=("${queue[@]:1}")
    case "$seen" in *" $f "*) continue ;; esac
    [ -f "$f" ] || continue
    seen="$seen$f "; echo "$f"
    while read -r p; do
      [ -z "$p" ] && continue
      [ "${p#/}" = "$p" ] && p="$root/$p"
      [ -d "$p" ] && p="$p/*"
      for inc in $p; do [ -f "$inc" ] && queue+=("$inc"); done
    done < <(awk 'tolower($1) ~ /^include(optional)?$/ {v=$2; gsub(/["\047]/,"",v); print v}' "$f" 2>/dev/null)
  done
}

# PID master setiap instance httpd/apache2 (bisa lebih dari satu, mis. instance custom dengan -f/-d)
apache_instances() {
  ps -eo pid=,ppid=,comm= 2>/dev/null | awk '$3=="httpd"||$3=="apache2"{c[$1]=1; p[$1]=$2} END{for(i in c) if(!(p[i] in c)) print i}' | sort -n
}

check_apache() {
  local pid bin root main sr f n=0 c="$RAW/httpd_config.txt" a_f a_d iname list ver docroots
  : > "$c"; : > "$RAW/httpd_config_full.txt"; : > "$RAW/httpd_info.txt"
  for pid in $(apache_instances); do
    n=$((n+1)); bin=$(pid_exe "$pid"); [ -x "$bin" ] || bin=/usr/sbin/httpd
    a_f=$(arg_next "$pid" -f); a_d=$(arg_next "$pid" -d)
    local args=()
    [ -n "$a_d" ] && args+=(-d "$a_d")
    [ -n "$a_f" ] && args+=(-f "$a_f")
    root=${a_d:-$("$bin" -V 2>/dev/null | sed -n 's/.*HTTPD_ROOT="\(.*\)"/\1/p')}
    if [ ! -d "$root" ]; then case "$bin" in /opt/rh/*/root/*) root="${bin%%/root/*}/root/etc/httpd" ;; *) root=/etc/httpd ;; esac; fi
    main=${a_f:-$("$bin" -V 2>/dev/null | sed -n 's/.*SERVER_CONFIG_FILE="\(.*\)"/\1/p')}
    [ -n "$main" ] && [ "${main#/}" = "$main" ] && main="$root/$main"
    sr=$(awk 'tolower($1)=="serverroot"{v=$2; gsub(/["\047]/,"",v); print v; exit}' "$main" 2>/dev/null)
    [ -n "$sr" ] && [ -d "$sr" ] && root="$sr"
    iname="httpd#$n"
    log "Cek Apache httpd instance $n: $bin (PID $pid, ServerRoot $root, config $main)"
    { echo "===== instance $n: $bin PID $pid  ServerRoot=$root  config=$main"
      "$bin" ${args[@]+"${args[@]}"} -v; echo; "$bin" ${args[@]+"${args[@]}"} -S; echo; "$bin" ${args[@]+"${args[@]}"} -M; echo; } >> "$RAW/httpd_info.txt" 2>&1
    list=$(apache_conf_files "$bin" "$root" "$main" ${args[@]+"${args[@]}"} | awk '!s[$0]++')
    [ -z "$list" ] && list=$(find "$root" -maxdepth 8 -name '*.conf' 2>/dev/null | sort)
    while read -r f; do
      [ -f "$f" ] || continue
      printf 'apache\t%s\t%s\t%s\n' "$iname" "$root" "$f" >> "$OUT/.webfiles"
      { echo "##### $f"; grep -vE '^\s*(#|$)' "$f" | redact; } >> "$c"
      { echo "##### [$iname] $f  ($(stat -c '%A %U:%G %y' "$f" 2>/dev/null | cut -c1-45))"
        awk '!/^[[:space:]]*$/{printf "%5d: %s\n", NR, $0}' "$f" | redact; echo; } >> "$RAW/httpd_config_full.txt"
    done <<< "$list"
    echo "$list" | awk -v i="$iname" 'NF{print "[" i "] " $0}' >> "$RAW/httpd_config_files.txt"
    ver=$("$bin" -v 2>/dev/null | sed -n 's#.*Apache/\([0-9][0-9.]*\).*#\1#p' | head -n1)
    finding INFO WEB-VER-01 Web "Versi Apache httpd ($iname)" "$("$bin" -v 2>/dev/null | head -n1) | $bin | $(echo "$list" | grep -c .) file config" \
      "httpd bawaan distro mendapat backport patch selama OS didukung; Apache hasil kompilasi sendiri harus di-upgrade manual."
    if ! rpm -qf "$bin" >/dev/null 2>&1 && ! dpkg -S "$bin" >/dev/null 2>&1; then
      if [ -n "$ver" ] && ver_lt "$ver" "$APACHE_MIN"; then
        finding HIGH WEB-VER-02 Web "Apache hasil kompilasi sendiri di bawah versi aman ($ver < $APACHE_MIN)" "$bin ($iname)" \
          "Build ulang ke Apache $APACHE_MIN atau lebih baru (lihat httpd.apache.org/security/vulnerabilities_24.html); matikan modul yang tidak dipakai. Apache ini tidak ikut dnf/yum update."
      else
        finding INFO WEB-VER-03 Web "Apache hasil kompilasi sendiri (tidak ikut dnf/yum update)" "$bin versi $ver ($iname)" \
          "Pantau rilis keamanan Apache dan upgrade manual."
      fi
    fi
    web_live_checks apache "$pid"
  done
  # .htaccess di DocumentRoot (aturan akses tambahan di luar file config)
  docroots=$(grep -ihE '^\s*DocumentRoot\s' "$c" | awk '{v=$2; gsub(/["\047]/,"",v); print v}' | sort -u)
  for f in $docroots; do
    [ -d "$f" ] && find "$f" -maxdepth 6 -name '.htaccess' -type f 2>/dev/null | head -n 200
  done | while read -r f; do { echo "##### $f"; redact < "$f"; echo; }; done > "$RAW/httpd_htaccess.txt"
  [ -s "$RAW/httpd_htaccess.txt" ] || rm -f "$RAW/httpd_htaccess.txt"
  grep -iE '^\s*(ProxyPass|ProxyPassMatch|ProxyPassReverse|BalancerMember|RewriteRule.*\[P|<VirtualHost|<Location|ServerName|ServerAlias|Require|SSLCertificateFile|^##### )' "$c" > "$RAW/httpd_proxy_map.txt"

  grep -qiE '^\s*ProxyRequests\s+On' "$c" && finding HIGH WEB-PROXY-01 Web "Apache aktif sebagai open forward proxy" "ProxyRequests On" \
    "Set ProxyRequests Off (reverse proxy dengan ProxyPass tidak memerlukannya)."
  if [ -z "$PY" ]; then
    grep -iE '^\s*Options\s' "$c" | grep -qiE '(^|[[:space:]+])Indexes' && finding LOW WEB-INDEX-01 Web "Directory listing (Options Indexes) aktif" \
      "$(grep -iE '^\s*Options\s' "$c" | grep -iE '(^|[[:space:]+])Indexes' | head -n3 | tr '\n' ';')" "Ganti menjadi Options -Indexes."
  fi
  grep -qiE 'SetHandler\s+server-(status|info)' "$c" && finding LOW WEB-STATUS-01 Web "mod_status/mod_info aktif" \
    "$(grep -iE 'SetHandler\s+server-(status|info)' "$c" | head -n2 | tr '\n' ';')" "Pastikan hanya bisa diakses dari IP monitoring (Require ip ...), atau nonaktifkan."
  local mods risky=""
  mods=$(grep -oE '^ [a-z0-9_]+_module' "$RAW/httpd_info.txt" | tr -d ' ' | sort -u)
  for f in dav_module dav_fs_module dav_lock_module info_module userdir_module proxy_ftp_module proxy_connect_module proxy_ajp_module \
           proxy_scgi_module proxy_fdpass_module proxy_express_module cgi_module cgid_module vhost_alias_module dumpio_module autoindex_module lbmethod_heartbeat_module; do
    echo "$mods" | grep -qx "$f" && risky="$risky ${f%_module}"
  done
  [ -n "$risky" ] && finding LOW WEB-MOD-01 Web "Modul Apache berisiko/umumnya tidak dipakai masih dimuat" "$risky" \
    "Nonaktifkan LoadModule yang tidak dipakai (uji dengan apachectl -t lalu graceful). Mengurangi permukaan serangan, mis. CVE mod_dav/mod_proxy_ftp."
  if [ "$NO_NET" -eq 1 ]; then
    grep -qiE '^\s*ServerTokens\s+Prod' "$c" || finding LOW WEB-BANNER-01 Web "ServerTokens bukan Prod" "-" "Set ServerTokens Prod dan ServerSignature Off."
    grep -qiE '^\s*TraceEnable\s+off' "$c" || finding LOW WEB-TRACE-01 Web "TraceEnable tidak dimatikan" "-" "Set TraceEnable off."
  fi
}

check_nginx() {
  local pid bin conf n=0 c="$RAW/nginx_config.txt" dump f prefix iname
  : > "$c"; : > "$RAW/nginx_info.txt"
  for pid in $(ps -eo pid=,ppid=,comm= 2>/dev/null | awk '$3=="nginx"{c[$1]=1; p[$1]=$2} END{for(i in c) if(!(p[i] in c)) print i}' | sort -n); do
    n=$((n+1)); bin=$(pid_exe "$pid"); [ -x "$bin" ] || bin=/usr/sbin/nginx
    conf=$(arg_next "$pid" -c); iname="nginx#$n"
    prefix=$("$bin" -V 2>&1 | grep -oE -- '--prefix=[^ ]+' | cut -d= -f2)
    log "Cek Nginx instance $n: $bin (PID $pid${conf:+, config $conf})"
    { echo "===== instance $n: $bin PID $pid config=${conf:-default}"; "$bin" -V; echo; } >> "$RAW/nginx_info.txt" 2>&1
    dump=$("$bin" ${conf:+-c "$conf"} -T 2>/dev/null)
    if [ -n "$dump" ]; then
      echo "$dump" | grep -vE '^\s*$' | redact >> "$c"
      echo "$dump" | sed -n 's/^# configuration file \(.*\):$/\1/p' | while read -r f; do
        [ -f "$f" ] && printf 'nginx\t%s\t%s\t%s\n' "$iname" "${prefix:-/etc/nginx}" "$f" >> "$OUT/.webfiles"
      done
    else
      for f in ${conf:-/etc/nginx/nginx.conf} /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* /etc/nginx/default.d/*.conf; do
        [ -f "$f" ] || continue
        { echo "# configuration file $f:"; grep -vE '^\s*$' "$f" | redact; } >> "$c"
        printf 'nginx\t%s\t%s\t%s\n' "$iname" "${prefix:-/etc/nginx}" "$f" >> "$OUT/.webfiles"
      done
    fi
    finding INFO WEB-VER-02 Web "Versi Nginx ($iname)" "$("$bin" -v 2>&1 | head -n1) | $bin" "Pastikan versi nginx masih menerima update keamanan."
    web_live_checks nginx "$pid"
  done
  grep -E '^\s*(proxy_pass|upstream|server_name|listen|location|allow|deny|ssl_certificate )|^# configuration file' "$c" > "$RAW/nginx_proxy_map.txt"
  if [ -z "$PY" ]; then
    grep -qE '^\s*autoindex\s+on' "$c" && finding LOW WEB-INDEX-01 Web "Directory listing (autoindex on) aktif" "nginx autoindex on" "Set autoindex off."
  fi
  if [ "$NO_NET" -eq 1 ]; then
    grep -qE '^\s*server_tokens\s+off' "$c" || finding LOW WEB-BANNER-01 Web "server_tokens tidak dimatikan" "-" "Set server_tokens off; di blok http."
  fi
}

# Lokasi log aplikasi Java (logback/log4j2, logging.file.*, WildFly, Tomcat) -> $OUT/.applogs
#   format: label<TAB>path<TAB>sumber<TAB>folder-kerja<TAB>properti(k=v;k=v)
app_log_targets() { # $1=pid $2=label [$3=file config Spring gabungan]
  local pid="$1" label="$2" cfg="${3:-}" cwd v f props envp seenf=" "
  cwd=$(pid_cwd "$pid")
  # variabel path log dari env proses & -D (nama yang mengandung LOG/DIR/PATH/HOME saja, tanpa secret)
  envp=$( { tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null; pid_cmd "$pid" | tr ' ' '\n' | sed -n 's/^-D\([A-Za-z0-9_.]*=.*\)/\1/p'; } \
          | grep -E '^[A-Za-z0-9_.]*(LOG|DIR|PATH|HOME)[A-Za-z0-9_.]*=' | grep -viE '^[^=]*(pass|secret|token|key|cred)' | sed 's/^/env:/' | tr '\n' ';')
  {
    v=$(arg_val "$pid" -Djboss.server.log.dir)
    if [ -n "$v" ]; then printf '%s\t%s/*\t-Djboss.server.log.dir\t%s\t\n' "$label" "$v" "$cwd"
    else v=$(arg_val "$pid" -Djboss.home.dir); [ -n "$v" ] && printf '%s\t%s/standalone/log/*\tjboss.home.dir\t%s\t\n' "$label" "$v" "$cwd"; fi
    v=$(arg_val "$pid" -Dcatalina.base); [ -n "$v" ] && printf '%s\t%s/logs/*\tcatalina.base\t%s\t\n' "$label" "$v" "$cwd"
    for v in "$(arg_val "$pid" -Dlogging.file.name)" "$(arg_val "$pid" --logging.file.name)"; do
      [ -n "$v" ] && printf '%s\t%s\tlogging.file.name (cmdline)\t%s\t\n' "$label" "$v" "$cwd"; done
    for v in "$(arg_val "$pid" -Dlogging.file.path)" "$(arg_val "$pid" --logging.file.path)" "$(arg_val "$pid" -DLOG_PATH)"; do
      [ -n "$v" ] && printf '%s\t%s/*\tlogging.file.path (cmdline)\t%s\t\n' "$label" "$v" "$cwd"; done
    if [ -n "$cfg" ] && [ -f "$cfg" ]; then
      grep -E '^\s*logging\.file\.name\s*[=:]' "$cfg" | sed -E 's/^[^=:]*[=:][[:space:]]*//' | while read -r v; do
        printf '%s\t%s\tlogging.file.name (config)\t%s\t\n' "$label" "$v" "$cwd"; done
      grep -E '^\s*logging\.file\.path\s*[=:]' "$cfg" | sed -E 's/^[^=:]*[=:][[:space:]]*//' | while read -r v; do
        printf '%s\t%s/*\tlogging.file.path (config)\t%s\t\n' "$label" "$v" "$cwd"; done
    fi
    for f in "$(arg_val "$pid" -Dlogging.config)" "$(arg_val "$pid" --logging.config)" "$(arg_val "$pid" -Dlogback.configurationFile)" \
             "$(arg_val "$pid" -Dlog4j.configurationFile)" "$(arg_val "$pid" -Dlog4j2.configurationFile)" "$(arg_val "$pid" -Dlog4j.configuration)" \
             "$cwd"/logback*.xml "$cwd"/log4j2*.xml "$cwd"/log4j*.properties "$cwd"/config/logback*.xml "$cwd"/config/log4j2*.xml; do
      f=${f#classpath:}; f=${f#file:}
      [ -n "$f" ] || continue
      [ "${f#/}" = "$f" ] && f="$cwd/$f"
      [ -f "$f" ] || continue
      f=$(readlink -f "$f")
      case "$seenf" in *" $f "*) continue ;; esac
      seenf="$seenf$f "
      { echo "##### $label: $f"; redact < "$f"; echo; } >> "$RAW/app_log_configs.txt"
      props=$(grep -oE '<property[^>]+name="[^"]+"[^>]+value="[^"]+"' "$f" | sed -E 's/.*name="([^"]+)".*value="([^"]+)".*/\1=\2/' | tr '\n' ';')
      props="$props$(grep -oE '<Property name="[^"]+">[^<]+' "$f" | sed -E 's/<Property name="([^"]+)">/\1=/' | tr '\n' ';')"
      { grep -oE '<(file|fileName|fileNamePattern)>[^<]+' "$f" | sed 's/^<[^>]*>//'
        grep -oiE '(fileName|filePattern)="[^"]+"' "$f" | sed 's/^[^"]*"//; s/"$//'
        grep -E '^\s*log4j\.appender\.[^.]+\.File\s*=' "$f" | sed -E 's/^[^=]*=[[:space:]]*//'; } | while read -r v; do
        printf '%s\t%s\t%s\t%s\t%s\n' "$label" "$v" "$(basename "$f")" "$cwd" "$props"; done
    done
  } 2>/dev/null | awk -F'\t' -v e="$envp" 'BEGIN{OFS="\t"} {$5 = e (NF>=5 ? $5 : ""); if (!s[$0]++) print}' >> "$OUT/.applogs"
  return 0
}

# Analisis reverse proxy (bypass whitelist), cipher/protokol per baris, lokasi & izin log,
# dan jejak serangan di access log. Input: $OUT/.webfiles, $OUT/.applogs
analyze_web_and_logs() {
  [ -s "$OUT/.webfiles" ] || [ -s "$OUT/.applogs" ] || return 0
  if [ -z "$PY" ]; then
    finding INFO WEB-ANA-00 Web "Analisis config web & log dilewati (python tidak tersedia)" "-" "Jalankan di server yang punya python3, atau review manual raw/httpd_config_full.txt."
    return 0
  fi
  local mb=40; [ "$SAFE" -eq 1 ] && mb=5
  touch "$OUT/.webfiles" "$OUT/.applogs"
  log "Analisis reverse proxy, lokasi log, dan jejak serangan di access log (maks $mb MB/file)"
  timeout 900 "$PY" - "$HOST" "$OUT/.webfiles" "$OUT/.applogs" "$RAW" "$FINDINGS" "$mb" 2>>"$RAW/web_analyzer_errors.txt" <<'PYEOF' >&2
# -*- coding: utf-8 -*-
# Analisis config web (Apache/Nginx) + lokasi log + jejak serangan di access log.
# argv: host webfiles applogs outdir findings_csv maxmb
from __future__ import print_function, unicode_literals
import sys, os, re, io, glob, time, gzip, collections

host, webfiles, applogs, outd, find_out, maxmb = sys.argv[1:7]
MAXB = int(maxmb) * 1024 * 1024
NOW = time.time()
FIND = []


def fnd(sev, cid, cat, title, ev, rec):
    FIND.append((sev, cid, cat, title, ev, rec))


def rd(p):
    try:
        return io.open(p, encoding='utf-8', errors='replace').read().split('\n')
    except Exception:
        return []


def lines_of(p):
    """(nomor_baris, teks) dengan sambungan backslash digabung."""
    out, buf, start = [], '', None
    for i, l in enumerate(rd(p), 1):
        if start is None:
            start = i
        s = l.rstrip()
        if s.endswith('\\'):
            buf += s[:-1] + ' '
            continue
        out.append((start, (buf + l).strip()))
        buf, start = '', None
    return out


def toks(s):
    r, cur, q = [], '', None
    for ch in s:
        if q:
            if ch == q:
                q = None
            else:
                cur += ch
        elif ch in '"\'':
            q = ch
        elif ch.isspace():
            if cur:
                r.append(cur)
                cur = ''
        else:
            cur += ch
    if cur:
        r.append(cur)
    return r


def url_parts(u):
    m = re.match(r'^([a-z0-9+]+)://([^/:]+)(?::(\d+))?(/.*)?$', u, re.I)
    if not m:
        return None
    sch = m.group(1).lower()
    port = m.group(3) or {'http': '80', 'https': '443', 'ajp': '8009', 'ws': '80', 'wss': '443'}.get(sch, '')
    return (sch, m.group(2).lower(), port, m.group(4) or '')


def pmatch(prefix, path):
    """Pencocokan prefix ala ProxyPass/Alias: harus berhenti di batas '/'."""
    if prefix in ('', '/'):
        return True
    if not path.startswith(prefix):
        return False
    return prefix.endswith('/') or len(path) == len(prefix) or path[len(prefix)] == '/'


def is_loop(h):
    return h in ('localhost', '::1') or h.startswith('127.')


# --------------------------------------------------------------------- parsing
inst = collections.OrderedDict()   # instance -> {'kind', 'root', 'files'}
for ln in io.open(webfiles, encoding='utf-8', errors='replace'):
    p = ln.rstrip('\n').split('\t')
    if len(p) < 4:
        continue
    kind, iname, root, f = p[:4]
    d = inst.setdefault(iname, {'kind': kind, 'root': root, 'files': []})
    if f not in d['files']:
        d['files'].append(f)

VH = []        # vhost: name, inst, file, line, locs, maps, excl
LOGS = []      # (inst, vhost, directive, value, fmt, file, line, root)
CFGL = []      # (inst, file, line, text) untuk cek per-baris
COMM = []      # (file, line, comment, next_require_ip_line)


def new_vh(name, iname, f, n):
    v = {'name': name, 'inst': iname, 'file': f, 'line': n, 'locs': [], 'maps': [], 'excl': [], 'bal': {}}
    VH.append(v)
    return v


def restricted_reqs(reqs):
    hard = [r for r in reqs if not re.match(r'(?i)^require\s+all\s+granted$', r)]
    return bool(hard), hard


def parse_apache(iname, d):
    gl = new_vh('(global)', iname, '-', 0)
    for f in d['files']:
        cur = gl
        stack = []           # (tag, loc_dict|None)
        loc = None
        pend_comment = None
        for n, t in lines_of(f):
            if not t:
                continue
            if t.startswith('#'):
                pend_comment = (f, n, t)
                continue
            CFGL.append((iname, f, n, t))
            tl = t.lower()
            m = re.match(r'^<\s*(/)?\s*([a-z]+)\s*([^>]*)>', t, re.I)
            if m:
                close, tag, arg = m.group(1), m.group(2).lower(), m.group(3).strip().strip('"\'')
                if not close:
                    if tag == 'virtualhost':
                        cur = new_vh('', iname, f, n)
                        cur['addr'] = arg
                        stack.append((tag, None))
                    elif tag in ('location', 'locationmatch'):
                        rx = tag == 'locationmatch' or arg.startswith('~')
                        loc = {'path': arg.lstrip('~ ').strip('"\''), 'rx': rx, 'reqs': [], 'file': f, 'line': n}
                        cur['locs'].append(loc)
                        stack.append((tag, loc))
                    elif tag == 'proxy' and arg.lower().startswith('balancer://'):
                        cur['_bal'] = arg.rstrip('/')
                        cur['bal'].setdefault(cur['_bal'], [])
                        stack.append((tag, None))
                    else:
                        stack.append((tag, None))
                else:
                    while stack:
                        tg, lo = stack.pop()
                        if tg == tag:
                            break
                    if tag == 'virtualhost':
                        cur = gl
                    if tag in ('location', 'locationmatch'):
                        loc = None
                        for tg, lo in reversed(stack):
                            if lo is not None:
                                loc = lo
                                break
                    if tag == 'proxy':
                        cur.pop('_bal', None)
                continue
            tk = toks(t)
            if not tk:
                continue
            dname = tk[0].lower()
            if dname in ('servername',) and len(tk) > 1 and cur is not gl and not cur['name']:
                cur['name'] = tk[1]
            elif dname in ('require', 'allow', 'deny', 'satisfy', 'authtype') and loc is not None:
                loc['reqs'].append(' '.join(tk))
                if dname == 'require' and len(tk) > 1 and tk[1].lower() == 'ip' and pend_comment:
                    COMM.append((pend_comment[0], pend_comment[1], pend_comment[2], n, ' '.join(tk[2:])))
            elif dname == 'balancermember' and len(tk) > 1 and cur.get('_bal'):
                cur['bal'][cur['_bal']].append(tk[1])
            elif dname in ('proxypass', 'proxypassmatch'):
                args = [a for a in tk[1:] if '=' not in a or a.startswith(('http', 'ajp', 'ws', 'balancer', 'fcgi', 'h2', 'unix'))]
                if loc is not None and len(args) >= 1:
                    front, back = loc['path'], args[0]
                    kind = 'ppm' if loc['rx'] else 'pp'
                elif len(args) >= 2:
                    front, back = args[0], args[1]
                    kind = 'ppm' if dname == 'proxypassmatch' else 'pp'
                else:
                    continue
                if back == '!':
                    cur['excl'].append((front, kind))
                else:
                    cur['maps'].append({'front': front, 'back': back, 'kind': kind, 'loc': loc, 'file': f, 'line': n})
            elif dname == 'rewriterule' and len(tk) >= 3 and re.search(r'\[[^\]]*\bP\b', ' '.join(tk[3:]), re.I):
                cur['maps'].append({'front': tk[1], 'back': tk[2], 'kind': 'rw', 'loc': loc, 'file': f, 'line': n})
            elif dname in ('errorlog', 'customlog', 'transferlog') and len(tk) > 1:
                LOGS.append((iname, cur['name'] or cur.get('addr', '(global)'), dname, tk[1], tk[2] if len(tk) > 2 else '', f, n, d['root']))
            if dname != 'require':
                pend_comment = None if dname not in ('require',) else pend_comment


def parse_nginx(iname, d):
    gl = new_vh('(global)', iname, '-', 0)
    for f in d['files']:
        stack = []
        cur, loc = gl, None
        pend_comment = None
        text = []
        for n, l in enumerate(rd(f), 1):
            s = l.strip()
            if s.startswith('#'):
                pend_comment = (f, n, s)
                continue
            s = re.sub(r'\s#.*$', '', s)
            if not s:
                continue
            CFGL.append((iname, f, n, s))
            # pisahkan per ; { }
            for part in re.findall(r'[^;{}]+[;{}]|[{}]', s):
                part = part.strip()
                if part == '}':
                    if stack:
                        tg, obj = stack.pop()
                        if tg == 'server':
                            cur = gl
                        if tg == 'location':
                            loc = None
                            for t2, o2 in reversed(stack):
                                if t2 == 'location':
                                    loc = o2
                                    break
                    continue
                body = part.rstrip(';{').strip()
                tk = toks(body)
                if not tk:
                    continue
                dn = tk[0].lower()
                if part.endswith('{'):
                    if dn == 'server':
                        cur = new_vh('', iname, f, n)
                        stack.append(('server', cur))
                    elif dn == 'location':
                        a = tk[1:]
                        rx = bool(a) and a[0] in ('~', '~*')
                        mod = a[0] if a and a[0] in ('=', '^~', '~', '~*') else ''
                        path = a[-1] if a else '/'
                        loc = {'path': path, 'rx': rx, 'exact': mod == '=', 'reqs': [], 'file': f, 'line': n}
                        cur['locs'].append(loc)
                        stack.append(('location', loc))
                    else:
                        stack.append((dn, None))
                    continue
                if dn == 'server_name' and len(tk) > 1 and cur is not gl and not cur['name']:
                    cur['name'] = tk[1]
                elif dn in ('allow', 'deny', 'auth_basic', 'auth_request', 'satisfy') and loc is not None:
                    if not (dn == 'auth_basic' and len(tk) > 1 and tk[1] == 'off'):
                        loc['reqs'].append(' '.join(tk))
                    if dn == 'allow' and pend_comment:
                        COMM.append((pend_comment[0], pend_comment[1], pend_comment[2], n, ' '.join(tk[1:])))
                elif dn == 'proxy_pass' and len(tk) > 1 and loc is not None:
                    kind = 'ppm' if loc['rx'] else ('exact' if loc.get('exact') else 'pp')
                    cur['maps'].append({'front': loc['path'], 'back': tk[1], 'kind': kind, 'loc': loc, 'file': f, 'line': n, 'ngx': True})
                elif dn in ('access_log', 'error_log') and len(tk) > 1:
                    LOGS.append((iname, cur['name'] or '(global)', dn, tk[1], tk[2] if len(tk) > 2 else '', f, n, d['root']))
                if dn != 'allow':
                    pend_comment = None


for iname, d in inst.items():
    (parse_apache if d['kind'] == 'apache' else parse_nginx)(iname, d)


# ------------------------------------------------------- pemetaan proxy & akses
def loc_restricted_for(v, path):
    """Location dengan pembatasan yang mencakup path (prefix ala <Location>, atau regex)."""
    for lo in v['locs']:
        r, hard = restricted_reqs(lo['reqs'])
        if not r:
            continue
        if lo['rx']:
            try:
                if re.search(lo['path'], path):
                    return lo, hard
            except re.error:
                pass
        elif lo.get('exact'):
            if path == lo['path']:
                return lo, hard
        elif path.startswith(lo['path']):
            return lo, hard
    return None, []


def excluded(v, path):
    for fr, k in v['excl']:
        if k == 'pp' and pmatch(fr, path):
            return True
        if k == 'ppm':
            try:
                if re.search(fr, path):
                    return True
            except re.error:
                pass
    return False


def backends(v, back):
    b = back.rstrip('/')
    for vv in VH:
        if vv['inst'] == v['inst'] and b in vv['bal']:
            return vv['bal'][b] or [back]
    return [back]


ROWS, PUB, RES = [], [], []
for v in VH:
    vname = v['name'] or v.get('addr', '(global)')
    for mp in v['maps']:
        lo = mp['loc']
        if lo is not None:
            r, hard = restricted_reqs(lo['reqs'])
            rl = lo if r else None
        else:
            rl, hard = loc_restricted_for(v, mp['front']) if mp['kind'] == 'pp' else (None, [])
        acc = ('DIBATASI: ' + '; '.join(hard)[:160]) if rl else 'PUBLIK'
        for b in backends(v, mp['back']):
            ROWS.append((v['inst'], vname, mp['kind'], mp['front'], b, acc, '%s:%d' % (mp['file'], mp['line'])))
            ent = dict(mp, vh=v, vname=vname, b=b, up=url_parts(b))
            if ent['up'] is None:
                continue
            (RES if rl else PUB).append(ent)


def effective(v, path):
    """Mapping pertama (urutan config) yang menangani path di vhost v."""
    best = None
    for mp in v['maps']:
        if mp['kind'] == 'pp' and pmatch(mp['front'], path):
            if mp['loc'] is not None:      # ProxyPass di dalam <Location>: prefix string
                if not path.startswith(mp['front']):
                    continue
            return mp
        if mp['kind'] == 'exact' and mp['front'] == path:
            return mp
        if mp['kind'] in ('ppm',):
            try:
                if re.search(mp['front'], path):
                    return mp
            except re.error:
                pass
    return best


def ngx_backend_path(mp, path):
    """nginx: proxy_pass dengan URI mengganti bagian location; tanpa URI meneruskan path asli."""
    up = url_parts(mp['back'])
    if not up:
        return None
    if up[3] == '':
        return path
    return up[3] + path[len(mp['front']):]


seen = set()
for r in RES:
    rs, rh, rp, rpath = r['up']
    for p in PUB:
        if p['kind'] not in ('pp',):
            continue
        ps, phh, pp_, ppath = p['up']
        if (rh, rp) != (phh, pp_):
            continue
        if p.get('ngx'):
            base = ppath if ppath else p['front']
            if not pmatch(base, rpath):
                continue
            cand = p['front'] + rpath[len(base):] if ppath else rpath
        else:
            if not pmatch(ppath, rpath):
                continue
            cand = p['front'] + rpath[len(ppath):]
        cand = re.sub(r'/{2,}', '/', cand)
        if cand == r['front'] and p['vh'] is r['vh']:
            continue
        v = p['vh']
        lo, _ = loc_restricted_for(v, cand)
        if lo is not None or excluded(v, cand):
            continue
        eff = effective(v, cand)
        if eff is not None and eff is not p and eff.get('front') != p['front']:
            continue
        key = (r['vname'], r['front'], p['vname'], cand)
        if key in seen:
            continue
        seen.add(key)
        fnd('HIGH', 'WEB-PROXY-BYPASS-01', 'Web',
            'Pembatasan akses reverse proxy bisa dilewati lewat path publik lain',
            '%s%s (publik, %s:%d) -> %s; backend yang sama di %s%s dibatasi (%s:%d)' % (
                p['vname'], cand, p['file'], p['line'], r['b'], r['vname'], r['front'], r['file'], r['line']),
            'ProxyPass memakai pencocokan prefix: sisa path ikut diteruskan ke backend. Ubah mapping publik menjadi exact '
            '(Apache: ProxyPassMatch "^/path$" url; Nginx: location = /path) dan/atau tambahkan <Location "/path/"> Require all denied. '
            'Uji dengan curl dari IP di luar whitelist: harus 403.')

pub_root = [p for p in PUB if p['kind'] == 'pp' and p['up'][3] in ('', '/') and p['front'] not in ('/',)]
for p in pub_root[:10]:
    fnd('INFO', 'WEB-PROXY-02', 'Web', 'Path publik meneruskan seluruh aplikasi backend',
        '%s%s -> %s (%s:%d)' % (p['vname'], p['front'], p['b'], p['file'], p['line']),
        'Pastikan semua endpoint di backend memang boleh publik (UI admin, actuator, callback). Batasi path sensitif dengan <Location>/location.')

plain = sorted(set('%s -> %s' % (p['front'], p['b']) for p in PUB + RES if p['up'][0] in ('http', 'ajp', 'ws') and not is_loop(p['up'][1])))
if plain:
    fnd('LOW', 'WEB-BACKEND-01', 'Web', '%d mapping proxy ke backend memakai protokol tanpa enkripsi' % len(plain),
        '; '.join(plain[:12]),
        'Gunakan https ke backend (Apache: SSLProxyEngine on + SSLProxyVerify require) atau batasi port backend dengan firewall hanya dari IP proxy.')


# ------------------------------------------------------- cek per baris config
WEAKC = re.compile(r'^(RC4|3DES|DES|NULL|EXPORT|EXP|MD5|aNULL|eNULL|ADH|AECDH|LOW|MEDIUM|ALL|DEFAULT)$|RC4|3DES|DES-CBC|NULL|EXPORT|-MD5$|^(ECDHE-(RSA|ECDSA)-|DHE-RSA-)?(AES(128|256)|CAMELLIA(128|256)|SEED|IDEA)-SHA$|^(AES|AES128|AES256|DES|CAMELLIA)(-|$)|^RSA|^(ECDHE|DHE)-(RSA|ECDSA)-AES(128|256)-SHA(256|384)$', re.I)
proto_bad, ciph_bad, idx = [], [], []
for iname, f, n, t in CFGL:
    tk = toks(t)
    if not tk:
        continue
    dn = tk[0].lower()
    if dn in ('sslciphersuite', 'ssl_ciphers'):
        val = (tk[2] if len(tk) > 2 and tk[1].lower() in ('sslv3', 'tlsv1.3') else (tk[1] if len(tk) > 1 else '')).rstrip(';')
        if len(tk) > 2 and tk[1].upper() == 'TLSV1.3':
            continue
        bad = [c for c in re.split(r'[:\s,]+', val) if c and not c.startswith(('!', '-')) and WEAKC.search(c)]
        if bad:
            ciph_bad.append('%s:%d [%s]' % (f, n, ','.join(bad[:6])))
    elif dn in ('sslprotocol', 'ssl_protocols', 'sslproxyprotocol'):
        v = ' '.join(tk[1:]).rstrip(';')
        low = v.lower()
        bad = re.search(r'(^|\s)\+?(sslv2|sslv3|tlsv1|tlsv1\.1)(\s|$)', low) or \
            (re.search(r'(^|\s)\+?all(\s|$)', low) and not (re.search(r'-tlsv1(\s|$)', low) and re.search(r'-tlsv1\.1(\s|$)', low)))
        if bad:
            proto_bad.append('%s:%d [%s]' % (f, n, v))
    elif dn == 'options' and any(re.match(r'^\+?indexes$', x, re.I) for x in tk[1:]):
        idx.append('%s:%d' % (f, n))
    elif dn == 'autoindex' and len(tk) > 1 and tk[1].lower().rstrip(';') == 'on':
        idx.append('%s:%d' % (f, n))
if ciph_bad:
    fnd('MEDIUM', 'WEB-TLSCFG-01', 'Web', 'Cipher TLS lemah di konfigurasi (CBC-SHA1 / tanpa forward secrecy / usang)',
        '; '.join(ciph_bad[:8]),
        'Pakai profil Mozilla intermediate: ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:'
        'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305. Konfirmasi dulu kompatibilitas client/partner.')
if proto_bad:
    fnd('MEDIUM', 'WEB-TLSCFG-02', 'Web', 'Protokol TLS usang diizinkan di konfigurasi',
        '; '.join(proto_bad[:8]), 'Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3; Nginx: ssl_protocols TLSv1.2 TLSv1.3;')
if idx:
    fnd('LOW', 'WEB-INDEX-01', 'Web', 'Directory listing aktif (Options Indexes / autoindex on)', '; '.join(idx[:10]),
        'Apache: Options -Indexes; Nginx: autoindex off;')
tmp_acl = [c for c in COMM if re.search(r'pentest|pen-test|sementara|temporary|\btemp\b|\btest|uji|trial|vendor', c[2], re.I)]
if tmp_acl:
    fnd('LOW', 'WEB-ACL-01', 'Web', 'IP sementara (pentest/uji/vendor) masih ada di whitelist',
        '; '.join('%s:%d %s -> %s' % (c[0], c[3], c[2][:50], c[4]) for c in tmp_acl[:10]),
        'Hapus IP sementara setelah kegiatan selesai; beri tanggal kedaluwarsa di komentar setiap entri whitelist.')

# ------------------------------------------------------------------ lokasi log
def strf_glob(p):
    g = re.sub(r'%[a-zA-Z]', '*', p)
    g = re.sub(r'\$\{[^}]*\}', '*', g)
    return g


def log_path(val, root):
    v = val.strip().strip('"\'')
    if v.startswith('|'):
        tk = toks(v[1:].strip().strip('"\''))
        c = [t for t in tk[1:] if t.startswith('/') or (not t.startswith('-') and '/' in t)]
        if not c:
            return None
        v = c[0]
    if v.lower() in ('off', '/dev/null', 'stderr') or v.startswith(('syslog', 'memory:')):
        return None
    if not v.startswith('/'):
        v = os.path.join(root or '/', v)
    return v


ALOG = []      # (label, kind[access|error|app], template)
for iname, vh, dn, val, fmt, f, n, root in LOGS:
    p = log_path(val, root)
    kind = 'error' if 'error' in dn else 'access'
    if p:
        ALOG.append(('%s %s' % (iname, vh), kind, p, fmt, '%s:%d' % (f, n)))
UNRES = []


def resolve_app(path, cwd, props):
    """${X:-def} / ${X} dari <property> logback atau properti Spring; path relatif -> folder kerja."""
    pr = {}
    for kv in props.split(';'):
        if '=' in kv:
            k, v = kv.split('=', 1)
            k = k.strip()
            if k.startswith('env:'):
                pr[k] = v.strip()
            else:
                pr.setdefault(k, v.strip())
    for k in [x for x in pr if x.startswith('env:')]:
        pr[k[4:]] = pr[k]          # env/-D mengalahkan <property> dan default
    for _ in range(5):
        m = re.search(r'\$\{([^}:]+)(:-([^}]*))?\}', path)
        if not m:
            break
        k, dflt = m.group(1), m.group(3)
        val = pr.get(k, pr.get(k.lower()))
        if val is not None and '${' + k in val:      # <property name="X" value="${X:-default}"/>
            mm = re.search(r'\$\{' + re.escape(k) + r':-([^}]*)\}', val)
            val = pr.get('env:' + k) or (mm.group(1) if mm else None)
        if val is None:
            val = pr.get('env:' + k, dflt)
        if val is None:
            return None
        path = path[:m.start()] + val + path[m.end():]
    if '${' in path:
        return None
    path = re.sub(r'%d\{[^}]*\}|%i|%d', '*', path)
    if not path.startswith('/'):
        path = os.path.join(cwd or '/', path)
    return os.path.normpath(path)


if os.path.exists(applogs):
    for ln in io.open(applogs, encoding='utf-8', errors='replace'):
        p = ln.rstrip('\n').split('\t') + ['', '', '', '']
        if not p[1].strip():
            continue
        rp = resolve_app(p[1].strip(), p[3], p[4])
        if rp is None:
            UNRES.append('%s: %s (%s)' % (p[0], p[1].strip(), p[2]))
            continue
        ALOG.append((p[0], 'app', rp, '', p[2] or '-'))

stat_out = []
ww, missing, full, common_fmt, stale, missing_app = [], [], [], [], [], []
acc_files = []
GRP = collections.OrderedDict()   # (kind, label, folder) -> template, file, sumber, format
for label, kind, tpl, fmt, src in ALOG:
    if os.path.isdir(tpl):
        g, dirn = os.path.join(tpl, '*'), tpl
    else:
        g = strf_glob(tpl)
        g = g if g != tpl else tpl + '*'
        dirn = os.path.dirname(tpl)
    e = GRP.setdefault((kind, label, dirn), {'tpl': [], 'files': set(), 'src': [], 'fmt': fmt})
    if tpl not in e['tpl']:
        e['tpl'].append(tpl)
    if src not in e['src']:
        e['src'].append(src)
    if os.path.isdir(dirn):
        e['files'].update(x for x in glob.glob(g)[:20000] if os.path.isfile(x))

for (kind, label, dirn), e in GRP.items():
    tpls = '\n              '.join(e['tpl'][:12]) + ('\n              ... (+%d)' % (len(e['tpl']) - 12) if len(e['tpl']) > 12 else '')
    if not os.path.isdir(dirn):
        (missing_app if kind == 'app' else missing).append('%s (%s, %s)' % (e['tpl'][0], label, e['src'][0]))
        stat_out.append('%-8s %s\n   folder   : %s  -> FOLDER TIDAK ADA\n   template : %s\n   sumber   : %s\n' % (
            kind, label, dirn, tpls, ', '.join(e['src'])))
        continue
    fl = sorted(e['files'])
    tot = sum(os.path.getsize(x) for x in fl)
    mt = sorted((os.path.getmtime(x), x) for x in fl)
    nww = [x for x in fl if os.stat(x).st_mode & 0o004]
    try:
        st = os.statvfs(dirn)
        used = 100 - int(100.0 * st.f_bavail / max(1, st.f_blocks))
    except Exception:
        used = -1
    try:
        ds = os.stat(dirn)
        dm = oct(ds.st_mode & 0o777)[-3:]
    except Exception:
        dm = '?'
    newest = (NOW - mt[-1][0]) / 86400 if mt else None
    oldest = (NOW - mt[0][0]) / 86400 if mt else None
    stat_out.append('%-8s %s\n   folder   : %s (mode %s, disk terpakai %s%%)\n   file     : %d, total %.1f MB, terbaru %s hari lalu, '
                    'tertua %s hari lalu, terbaca-semua-user: %d\n   template : %s\n   sumber   : %s\n' % (
                        kind, label, dirn, dm, used, len(fl), tot / 1048576.0,
                        '%.1f' % newest if newest is not None else '-', '%.0f' % oldest if oldest is not None else '-',
                        len(nww), tpls, ', '.join(e['src'])))
    if nww and not any(x.startswith(dirn + ' (') for x in ww):
        ww.append('%s (%d file)' % (dirn, len(nww)))
    if used >= 85 and not any(x.startswith(dirn + ' ') for x in full):
        full.append('%s %d%%' % (dirn, used))
    fmt = e['fmt']
    if kind == 'access' and (fmt.lower() == 'common' or (fmt and '%' in fmt and 'User-Agent' not in fmt)):
        common_fmt.append('%s (%s)' % (label, e['src'][0]))
    if kind == 'access' and newest is not None and newest > 2:
        stale.append('%s: terakhir %.0f hari lalu' % (dirn, newest))
    if kind == 'access':
        acc_files += [x for t, x in mt if NOW - t < 8 * 86400]

with io.open(os.path.join(outd, 'log_locations.txt'), 'w', encoding='utf-8') as fo:
    fo.write('Lokasi log yang dikonfigurasi (web server + aplikasi) dan kondisinya\n\n')
    fo.write('\n'.join(stat_out) if stat_out else '(tidak ada lokasi log terdeteksi)\n')
    if UNRES:
        fo.write('\nPath log aplikasi yang memakai variabel dan tidak bisa diresolve (cek manual):\n  ' + '\n  '.join(UNRES) + '\n')
if ww:
    fnd('LOW', 'LOG-PERM-01', 'Log', 'File log bisa dibaca semua user', '; '.join(ww[:10]),
        'Log bisa berisi token, nomor kartu/akun, atau data pribadi. chmod 640 (grup admin/aplikasi) dan folder 750.')
if full:
    fnd('MEDIUM', 'LOG-DISK-01', 'Log', 'Disk lokasi log hampir penuh (>= 85%)', '; '.join(full),
        'Atur rotasi & retensi (logrotate/rotatelogs), pindahkan arsip lama ke penyimpanan log terpusat. Disk penuh bisa menghentikan aplikasi dan logging.')
if missing:
    fnd('LOW', 'LOG-MISS-01', 'Log', 'Lokasi log di konfigurasi tidak ada', '; '.join(missing[:8]),
        'Perbaiki path log; tanpa log tidak ada jejak untuk investigasi insiden.')
if missing_app:
    fnd('INFO', 'LOG-MISS-02', 'Log', 'Folder log aplikasi di logback/log4j belum ada', '; '.join(missing_app[:8]),
        'Biasanya appender belum pernah menulis. Bila log itu penting (audit/transaksi), pastikan folder ada dan bisa ditulis user aplikasi.')
if common_fmt:
    fnd('LOW', 'LOG-FMT-01', 'Log', 'Access log memakai format tanpa User-Agent/Referer', '; '.join(common_fmt[:6]),
        'Pakai format combined (Apache: LogFormat combined/combined_tls) agar log berguna untuk investigasi.')
if stale:
    fnd('INFO', 'LOG-STALE-01', 'Log', 'Access log tidak bertambah > 2 hari', '; '.join(stale[:6]),
        'Pastikan logging berjalan (atau memang tidak ada traffic).')

# -------------------------------------------- jejak serangan di access log
PAT = [
    ('jndi/log4shell', r'\$\{(jndi|\$\{|lower:|upper:|env:|::-)', True),
    ('path-traversal', r'(\.\./|\.\.%2f|%2e%2e(%2f|/)|\.\.\\)', True),
    ('baca-file-sistem', r'/etc/(passwd|shadow|hosts)|win\.ini|/proc/self/', True),
    ('webshell', r'\.(jsp|jspx|php\d?|phtml|aspx?|ashx|cgi|pl|sh)\?[^ "]*\b(cmd|exec|command|shell|c|pass|pwd)=', True),
    ('perintah-os', r'(cmd|exec|command|q|arg)=[^ "&]*(whoami|uname|%20id|wget%20|curl%20|bash|/bin/sh|nc%20|powershell)', True),
    ('spring4shell/el', r'class\.module\.classLoader|\$\{T\(|%24%7BT%28|#\{.*\}', True),
    ('sqli', r'(union(\s|%20|\+|/\*\*/)+(all(\s|%20|\+))?select|sleep\(\d|benchmark\(|%27(\s|%20|\+)*or(\s|%20|\+)|information_schema)', False),
    ('xss', r'(<|%3c)(script|svg|img)[^a-z]', False),
    ('file-sensitif', r'/(\.env|\.git/|\.svn/|\.htpasswd|\.aws/|wp-config\.php|web\.config|id_rsa|\.DS_Store|backup\.(zip|tar|sql))', False),
    ('konsol-admin', r'/(manager/html|host-manager|jmx-console|web-console|invoker/|console(/|\b)|actuator|phpmyadmin|server-status|server-info|solr/|_ignition|druid/|swagger-ui|v2/api-docs|v3/api-docs|h2-console|jolokia)', False),
    ('wordpress', r'(wp-login\.php|xmlrpc\.php|/wp-admin|/wp-content)', False),
    ('scanner/tool', r'(sqlmap|nikto|nmap|masscan|zgrab|nuclei|acunetix|nessus|openvas|qualys|dirbuster|gobuster|ffuf|wpscan|feroxbuster|hydra|burp)', False),
]
CP = [(n, re.compile(r, re.I), h) for n, r, h in PAT]
LINE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3})')
stats = {n: {'n': 0, 'ok': 0, 'ip': collections.Counter(), 'okip': collections.Counter(), 'ex': []} for n, _, _ in CP}
topip, tot, scanned, first, last = collections.Counter(), 0, [], None, None
acc_files = sorted(set(acc_files), key=lambda x: -os.path.getmtime(x))[:16]


def tail_lines(p):
    try:
        if p.endswith('.gz'):
            fh = gzip.open(p, 'rb')
            data = fh.read(MAXB)
        else:
            fh = io.open(p, 'rb')
            sz = os.path.getsize(p)
            if sz > MAXB:
                fh.seek(sz - MAXB)
            data = fh.read(MAXB)
        fh.close()
        return data.decode('utf-8', 'replace').split('\n')
    except Exception:
        return []


def red(s):
    s = re.sub(r'((pass(word|wd)?|pwd|token|secret|key|auth|signature|card|pan|cvv)[^=&]*=)[^&" ]+', r'\1****', s, flags=re.I)
    return s[:220]


for p in acc_files:
    ls = tail_lines(p)
    scanned.append('%s (%d baris)' % (p, len(ls)))
    for l in ls:
        m = LINE.match(l)
        if not m:
            continue
        ip, ts, req, code = m.group(1), m.group(2), m.group(3), m.group(4)
        tot += 1
        topip[ip] += 1
        if first is None:
            first = ts
        last = ts
        rest = l[m.end():]
        for n, rx, hi in CP:
            if rx.search(req) or (n == 'scanner/tool' and rx.search(rest)):
                s = stats[n]
                s['n'] += 1
                s['ip'][ip] += 1
                if code.startswith('2'):
                    s['ok'] += 1
                    s['okip'][ip] += 1
                    if len(s['ex']) < 5:
                        s['ex'].append(red('%s [%s] "%s" %s' % (ip, ts, req, code)))
                break

with io.open(os.path.join(outd, 'web_log_ioc.txt'), 'w', encoding='utf-8') as fo:
    fo.write('Analisis jejak serangan di access log (maks %d MB terakhir per file, file 8 hari terakhir)\n' % (MAXB // 1048576))
    fo.write('File dibaca: %s\n' % ('; '.join(scanned) if scanned else '(tidak ada)'))
    fo.write('Total request terbaca: %d  rentang: %s .. %s\n\n' % (tot, first or '-', last or '-'))
    fo.write('Top 15 IP sumber:\n')
    for ip, c in topip.most_common(15):
        fo.write('  %-40s %d\n' % (ip, c))
    fo.write('\nPola serangan (jumlah / dijawab 2xx / IP teratas):\n')
    for n, _, hi in CP:
        s = stats[n]
        if not s['n']:
            continue
        fo.write('  [%s] %-18s %6d  2xx=%-5d  %s\n' % ('TINGGI' if hi else 'info', n, s['n'], s['ok'],
                                                       ', '.join('%s(%d)' % x for x in s['ip'].most_common(5))))
        for e in s['ex']:
            fo.write('        contoh 2xx: %s\n' % e)

hi_ok = [(n, stats[n]) for n, _, h in CP if h and stats[n]['ok']]
if hi_ok:
    fnd('HIGH', 'IOC-WEB-01', 'IOC', 'Request serangan berisiko tinggi di access log dijawab 2xx (perlu investigasi)',
        '; '.join('%s: %d x 2xx dari %s' % (n, s['ok'], ', '.join(ip for ip, _ in s['okip'].most_common(3))) for n, s in hi_ok),
        'Periksa contoh di raw/web_log_ioc.txt dan log aplikasi backend pada jam yang sama. Respons 2xx belum tentu berhasil '
        '(bisa halaman default), tapi wajib dipastikan. Blokir IP sumber bila bukan scanner resmi.')
att = [(n, stats[n]['n']) for n, _, _ in CP if stats[n]['n']]
if att:
    fnd('INFO', 'IOC-WEB-02', 'IOC', 'Percobaan serangan/scan di access log', ', '.join('%s=%d' % x for x in att),
        'Rincian & IP sumber di raw/web_log_ioc.txt. Pertimbangkan WAF/rate-limit bila volume tinggi.')

# ------------------------------------------------------------------- output
with io.open(os.path.join(outd, 'web_proxy_analysis.txt'), 'w', encoding='utf-8') as fo:
    fo.write('Peta reverse proxy: instance | vhost | jenis | path depan | backend | akses | lokasi config\n')
    fo.write('(pp = ProxyPass prefix, ppm = regex, exact = nginx location =, rw = RewriteRule [P])\n\n')
    for r in ROWS:
        fo.write(' | '.join(r) + '\n')


def q(s):
    s = ('%s' % s).replace('\r', '').replace('\n', ' | ').replace('"', '""')
    if len(s) > 700:
        s = s[:700] + '...'
    return '"%s"' % s


with io.open(find_out, 'a', encoding='utf-8') as fo:
    for sev, cid, cat, title, ev, rec in FIND:
        fo.write(','.join(q(x) for x in (host, cat, cid, sev, title, ev, rec)) + '\n')
print('web-analyzer: %d instance, %d vhost, %d mapping, %d lokasi log, %d temuan' % (len(inst), len(VH), len(ROWS), len(ALOG), len(FIND)))
PYEOF
  cp "$OUT/.webfiles" "$RAW/web_config_files.txt" 2>/dev/null
  cut -f1-3 "$OUT/.applogs" > "$RAW/app_log_targets.txt" 2>/dev/null
  [ -s "$RAW/web_analyzer_errors.txt" ] || rm -f "$RAW/web_analyzer_errors.txt"
  rm -f "$OUT/.webfiles" "$OUT/.applogs"
}

#------------------------------------------------------------------------------
# 8. MARIADB / MYSQL
#------------------------------------------------------------------------------
check_mariadb() {
  local pid bin ver exp="" addr MY q d
  pid=$(pgrep -o -x mysqld || pgrep -o -x mariadbd); bin=$(pid_exe "$pid")
  log "Cek MariaDB/MySQL"
  "$bin" --version > "$RAW/mysql_version.txt" 2>&1
  for f in /etc/my.cnf /etc/my.cnf.d/*.cnf /etc/mysql/my.cnf; do
    [ -f "$f" ] && { echo "##### $f"; grep -vE '^\s*(#|;|$)' "$f" | redact; }
  done > "$RAW/mysql_config.txt" 2>/dev/null

  for addr in $(listen_of_pid "$pid"); do is_loopback "${addr%:*}" || exp="$exp $addr"; done
  if [ -n "$exp" ]; then
    d=MEDIUM; st=$(fw_port_status "${exp##*:}")
    case "$st" in blocked|restricted) d=LOW ;; esac
    finding "$d" DB-LISTEN-01 MariaDB "Database listen di interface jaringan" "listen:$exp; status host firewall untuk port ini: ${st:-tidak diketahui}" \
      "Wajar jika aplikasi di server lain: pastikan port DB hanya bisa diakses dari IP server aplikasi (firewalld + Palo Alto). Jika aplikasi lokal: bind-address=127.0.0.1."
  fi

  ver=$("$bin" --version 2>/dev/null | grep -oE 'Ver [0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}')
  if "$bin" --version 2>/dev/null | grep -qi mariadb; then
    [ -n "$ver" ] && ver_lt "$ver" "10.11" && finding HIGH DB-EOL-01 MariaDB "Versi MariaDB kemungkinan sudah EOL" "MariaDB $ver" \
      "Upgrade ke rilis LTS yang masih didukung (10.11 / 11.4 / 11.8). Verifikasi jadwal di mariadb.org (maintenance policy)."
  else
    [ -n "$ver" ] && ver_lt "$ver" "8.4" && finding HIGH DB-EOL-01 MariaDB "Versi MySQL kemungkinan sudah EOL" "MySQL $ver" \
      "Upgrade ke MySQL 8.4 LTS atau versi yang masih didukung."
  fi

  if ! have mysql; then
    finding INFO DB-SKIP-01 MariaDB "Pengecekan isi database dilewati (client mysql tidak ada)" "-" "Jalankan ulang di server yang punya client mysql."
    return
  fi
  MY="mysql --connect-timeout=5 -N -B"
  [ -n "$MYSQL_CNF" ] && MY="mysql --defaults-extra-file=$MYSQL_CNF --connect-timeout=5 -N -B"
  if ! timeout 15 $MY -e 'SELECT 1' >/dev/null 2>&1; then
    finding INFO DB-SKIP-01 MariaDB "Pengecekan isi database dilewati (tidak bisa login)" "Login via socket gagal" \
      "Buat user read-only: CREATE USER 'assess'@'localhost' IDENTIFIED BY '...'; GRANT SELECT ON mysql.* TO 'assess'@'localhost'; GRANT PROCESS, SHOW DATABASES ON *.* TO 'assess'@'localhost'; lalu file /root/assess.cnf (chmod 600) berisi [client] user=assess password=... dan jalankan ulang dengan --mysql-cnf /root/assess.cnf. Hapus user & file setelah selesai."
    return
  fi
  myq()   { timeout 30 $MY -e "$1" 2>&1; }
  myvar() { myq "SHOW GLOBAL VARIABLES LIKE '$1'" | awk '{print $2}'; }

  { echo "### VERSION"; myq "SELECT VERSION()"
    echo "### USERS (user, host, plugin)"; myq "SELECT user,host,plugin FROM mysql.user"
    echo "### VARIABLES"; myq "SHOW GLOBAL VARIABLES WHERE Variable_name IN ('version','have_ssl','have_openssl','local_infile','secure_file_priv','bind_address','skip_networking','general_log','log_error','datadir','require_secure_transport')"
    echo "### DATABASES"; myq "SHOW DATABASES"; } > "$RAW/mysql_query.txt"

  q=$(myq "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE IFNULL(authentication_string,'')='' AND IFNULL(password,'')='' AND IFNULL(plugin,'') IN ('','mysql_native_password')")
  echo "$q" | grep -q '^ERROR' && q=$(myq "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE IFNULL(authentication_string,'')='' AND IFNULL(plugin,'') IN ('','mysql_native_password')")
  if [ -n "$q" ] && ! echo "$q" | grep -q '^ERROR'; then
    finding CRITICAL DB-NOPASS-01 MariaDB "User database tanpa password" "$(echo "$q" | tr '\n' ' ')" \
      "Set password kuat atau hapus user tersebut (DROP USER). Untuk root lokal bisa memakai plugin unix_socket."
  fi
  q=$(myq "SELECT CONCAT('''''@',host) FROM mysql.user WHERE user=''")
  [ -n "$q" ] && finding HIGH DB-ANON-01 MariaDB "Ada user anonim" "$(echo "$q" | tr '\n' ' ')" "Hapus user anonim (DROP USER ''@'host') - setara mysql_secure_installation."
  q=$(myq "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user='root' AND host NOT IN ('localhost','127.0.0.1','::1')")
  [ -n "$q" ] && finding HIGH DB-ROOTREM-01 MariaDB "root database bisa login dari host lain" "$(echo "$q" | tr '\n' ' ')" \
    "Hapus root selain localhost; buat user admin terpisah yang dibatasi IP jika perlu akses remote."
  q=$(myq "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE host='%'")
  [ -n "$q" ] && finding LOW DB-WILD-01 MariaDB "User database boleh login dari host mana saja ('%')" "$(echo "$q" | tr '\n' ' ')" \
    "Ganti host '%' dengan IP/subnet server aplikasi yang spesifik."
  q=$(myq "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user NOT IN ('root','mariadb.sys','mysql','mysql.sys','mysql.session','mysql.infoschema','') AND (Super_priv='Y' OR Grant_priv='Y' OR File_priv='Y' OR Shutdown_priv='Y' OR Process_priv='Y')")
  [ -n "$q" ] && ! echo "$q" | grep -q '^ERROR' && finding MEDIUM DB-PRIV-01 MariaDB "User non-root punya privilege administratif (SUPER/GRANT/FILE/...)" "$(echo "$q" | tr '\n' ' ')" \
    "Terapkan least privilege: user aplikasi cukup SELECT/INSERT/UPDATE/DELETE pada database aplikasinya saja."
  q=$(myq "SHOW DATABASES LIKE 'test'")
  [ -n "$q" ] && finding LOW DB-TEST-01 MariaDB "Database 'test' bawaan masih ada" "test" "DROP DATABASE test (jika tidak dipakai)."

  q=$(myvar have_ssl)
  if [ -n "$exp" ] && { [ "$q" = DISABLED ] || [ "$q" = NO ]; }; then
    finding MEDIUM DB-SSL-01 MariaDB "Koneksi database tidak terenkripsi (TLS nonaktif)" "have_ssl=$q" \
      "Aktifkan TLS (ssl-cert/ssl-key/ssl-ca) dan wajibkan untuk user aplikasi (REQUIRE SSL), terutama jika traffic lewat segmen jaringan bersama."
  fi
  [ "$(myvar local_infile)" = ON ] && finding LOW DB-INFILE-01 MariaDB "local_infile aktif" "local_infile=ON" "Set local_infile=0 di my.cnf bila tidak dipakai."
  if myq "SHOW GLOBAL VARIABLES LIKE 'secure_file_priv'" | grep -q secure_file_priv && [ -z "$(myvar secure_file_priv)" ]; then
    finding LOW DB-FILEPRIV-01 MariaDB "secure_file_priv kosong (LOAD/SELECT INTO OUTFILE bebas direktori)" "secure_file_priv=''" \
      "Set secure_file_priv ke direktori khusus atau NULL."
  fi
  d=$(myvar datadir)
  if [ -d "$d" ]; then
    echo "datadir: $(stat -c '%U:%G %a' "$d")" >> "$RAW/mysql_query.txt"
    [ $(( $(stat -c '%a' "$d") % 10 )) -ne 0 ] && finding MEDIUM DB-PERM-01 MariaDB "Data directory bisa dibaca user lain" "$d $(stat -c '%a' "$d")" "chmod 750/700 dan owner mysql:mysql."
  fi
}

#------------------------------------------------------------------------------
# 9. POSTGRESQL
#------------------------------------------------------------------------------
check_postgres() {
  local pid bin psql port exp="" addr numv hba q d PGH=""
  pid=$(pgrep -o -x postmaster || pgrep -o -x postgres); bin=$(pid_exe "$pid")
  log "Cek PostgreSQL"
  psql="$(dirname "$bin")/psql"; [ -x "$psql" ] || psql=$(command -v psql)
  port=$(listen_of_pid "$pid" | head -n1); port=${port##*:}; [ -z "$port" ] && port=5432

  for addr in $(listen_of_pid "$pid"); do is_loopback "${addr%:*}" || exp="$exp $addr"; done
  if [ -n "$exp" ]; then
    d=MEDIUM; st=$(fw_port_status "${exp##*:}")
    case "$st" in blocked|restricted) d=LOW ;; esac
    finding "$d" DB-LISTEN-01 PostgreSQL "Database listen di interface jaringan" "listen:$exp; status host firewall untuk port ini: ${st:-tidak diketahui}" \
      "Wajar jika aplikasi di server lain: batasi port hanya dari IP server aplikasi (firewalld + Palo Alto + pg_hba.conf). Jika lokal: listen_addresses='localhost'."
  fi

  if [ "$IS_ROOT" -ne 1 ] || [ -z "$psql" ]; then
    finding INFO DB-SKIP-02 PostgreSQL "Pengecekan isi PostgreSQL dilewati" "butuh root & psql" "Jalankan assess.sh dengan sudo."
    return
  fi
  pgq() { su -s /bin/bash postgres -c "cd /tmp && PGCONNECT_TIMEOUT=5 '$psql' -X -A -t -q -p $port $PGH -d postgres" <<< "$1" 2>&1; }
  if [ "$(pgq 'SELECT 1')" != "1" ]; then
    PGH="-h /tmp"
    if [ "$(pgq 'SELECT 1')" != "1" ]; then
      finding INFO DB-SKIP-02 PostgreSQL "Pengecekan isi PostgreSQL dilewati (gagal login sebagai postgres)" "port $port" "Cek socket/port, lalu jalankan query di bagian atas script secara manual."
      return
    fi
  fi
  pgset() { pgq "SELECT setting FROM pg_settings WHERE name='$1'"; }

  { echo "### version"; pgq "SELECT version()"
    echo "### settings"; pgq "SELECT name||' = '||setting FROM pg_settings WHERE name IN ('listen_addresses','port','ssl','password_encryption','log_connections','log_disconnections','logging_collector','log_statement','hba_file','config_file','data_directory','shared_preload_libraries') ORDER BY 1"
    echo "### roles (nama|super|login|createrole|createdb|validuntil)"; pgq "SELECT rolname||'|'||rolsuper||'|'||rolcanlogin||'|'||rolcreaterole||'|'||rolcreatedb||'|'||COALESCE(rolvaliduntil::text,'-') FROM pg_roles ORDER BY 1"
    echo "### databases"; pgq "SELECT datname FROM pg_database ORDER BY 1"; } > "$RAW/pg_query.txt"
  q=$(pgset config_file); [ -f "$q" ] && grep -vE '^\s*(#|$)' "$q" | redact > "$RAW/pg_postgresql_conf.txt"

  numv=$(pgq "SHOW server_version_num" | tr -dc '0-9')
  if [ -n "$numv" ]; then
    if [ "$numv" -lt 140000 ]; then
      finding HIGH DB-EOL-02 PostgreSQL "Versi PostgreSQL sudah EOL" "$(pgq 'SHOW server_version')" \
        "Upgrade ke PostgreSQL 16/17/18 (pg_upgrade atau dump/restore), uji dulu di staging."
    elif [ "$numv" -lt 150000 ]; then
      finding MEDIUM DB-EOL-02 PostgreSQL "PostgreSQL 14 mencapai EOL November 2026" "$(pgq 'SHOW server_version')" \
        "Rencanakan upgrade ke PostgreSQL 16+ dalam waktu dekat."
    fi
  fi
  [ -n "$exp" ] && [ "$(pgset ssl)" = off ] && finding MEDIUM DB-SSL-01 PostgreSQL "Koneksi database tidak terenkripsi (ssl=off)" "ssl=off" \
    "Aktifkan ssl=on dengan sertifikat, lalu gunakan 'hostssl' di pg_hba.conf untuk koneksi aplikasi."
  if [ "${numv:-0}" -ge 100000 ]; then
    q=$(pgset password_encryption)
    case "$q" in md5|on) finding LOW DB-PWENC-01 PostgreSQL "Hash password masih MD5" "password_encryption=$q" \
      "Set password_encryption=scram-sha-256, reset password user, lalu ubah metode pg_hba.conf ke scram-sha-256." ;; esac
  fi
  [ "$(pgset log_connections)" = off ] && finding LOW DB-LOG-01 PostgreSQL "Log koneksi nonaktif" "log_connections=off" \
    "Aktifkan log_connections & log_disconnections untuk jejak audit."

  hba=$(pgset hba_file)
  if [ -f "$hba" ]; then
    grep -vE '^\s*(#|$)' "$hba" > "$RAW/pg_hba.txt"
    hba_method() { awk '{m=""; for(i=4;i<=NF;i++) if($i~/^(trust|reject|md5|password|scram-sha-256|gss|sspi|ident|peer|pam|ldap|radius|cert)$/){m=$i;break}; print $1"|"m"|"$0}' "$RAW/pg_hba.txt"; }
    q=$(hba_method | awk -F'|' '$1 ~ /^host/ && $2=="trust"{print $3}' | tr '\n' ';')
    [ -n "$q" ] && finding CRITICAL DB-HBA-01 PostgreSQL "pg_hba.conf: koneksi jaringan dengan metode trust (tanpa password)" "$q" \
      "Ganti 'trust' dengan scram-sha-256 (atau md5 untuk versi lama) lalu reload PostgreSQL."
    q=$(hba_method | awk -F'|' '$1=="local" && $2=="trust"{print $3}' | tr '\n' ';')
    [ -n "$q" ] && finding MEDIUM DB-HBA-02 PostgreSQL "pg_hba.conf: koneksi lokal metode trust (user OS mana pun bisa login sebagai user DB apa pun)" "$q" \
      "Gunakan 'peer' untuk koneksi lokal atau metode berpassword."
    q=$(hba_method | awk -F'|' '$2=="password"{print $3}' | tr '\n' ';')
    [ -n "$q" ] && finding MEDIUM DB-HBA-03 PostgreSQL "pg_hba.conf: metode 'password' mengirim password plaintext" "$q" "Ganti dengan scram-sha-256/md5."
    q=$(hba_method | awk -F'|' '$1 ~ /^host/ && $2!="reject" && $3 ~ /(0\.0\.0\.0\/0|::\/0|[[:space:]]all[[:space:]]+[a-z-]+$)/{print $3}' | tr '\n' ';')
    [ -n "$q" ] && finding MEDIUM DB-HBA-04 PostgreSQL "pg_hba.conf: akses dari semua alamat IP" "$q" "Batasi alamat ke IP/subnet server aplikasi."
  fi
  q=$(pgq "SELECT rolname FROM pg_roles WHERE rolsuper AND rolname<>'postgres'" | tr '\n' ' ')
  [ -n "${q// /}" ] && finding MEDIUM DB-PRIV-01 PostgreSQL "Role selain postgres punya hak SUPERUSER" "$q" \
    "Cabut SUPERUSER dari role aplikasi (ALTER ROLE x NOSUPERUSER); beri hak minimal per database/schema."
  q=$(pgq "SELECT rolname FROM pg_authid WHERE rolcanlogin AND rolpassword IS NULL AND rolname<>'postgres'" | tr '\n' ' ')
  [ -n "${q// /}" ] && finding LOW DB-NOPASS-02 PostgreSQL "Role login tanpa password (aman hanya jika auth via peer/cert)" "$q" \
    "Set password untuk role yang login lewat jaringan, atau pastikan pg_hba.conf memakai peer/cert untuk role ini."
}

#------------------------------------------------------------------------------
# 10. JAVA (umum), SPRING BOOT, WILDFLY
#------------------------------------------------------------------------------
check_java_common() { # $1=pid $2=kategori $3=label
  local pid="$1" cat="$2" label="$3" user exe cmd addr exp=""
  user=$(pid_user "$pid"); exe=$(pid_exe "$pid"); cmd=$(pid_cmd "$pid")
  java_version_check "$exe" "$cat" "$label"
  { echo "PID   : $pid"; echo "User  : $user"; echo "Java  : $exe"; echo "CWD   : $(pid_cwd "$pid")"
    echo "CMDLINE:"; echo "$cmd" | redact; echo "LISTEN:"; listen_of_pid "$pid"; } > "$RAW/java_${label}_${pid}.txt"

  [ "$user" = root ] && finding HIGH JAVA-ROOT-01 "$cat" "Aplikasi Java berjalan sebagai root" "$label (PID $pid)" \
    "Jalankan dengan user khusus non-root (systemd User=appuser), perbaiki ownership direktori aplikasi/log. Jika butuh port <1024, biarkan proxy yang listen."
  echo "$cmd" | grep -q 'jmxremote.authenticate=false' && finding HIGH JAVA-JMX-01 "$cat" "JMX remote tanpa autentikasi (bisa RCE)" "$label (PID $pid)" \
    "Aktifkan jmxremote.authenticate=true + SSL, atau bind JMX hanya ke localhost."
  echo "$cmd" | grep -qE 'jdwp|-Xdebug|-Xrunjdwp' && finding HIGH JAVA-DEBUG-01 "$cat" "Remote debug (JDWP) aktif di production (bisa RCE)" "$label (PID $pid)" \
    "Hapus opsi -agentlib:jdwp/-Xdebug dari startup production."
  local fwok="" st
  for addr in $(listen_of_pid "$pid"); do
    is_loopback "${addr%:*}" && continue
    case "${addr##*:}" in 9990|9993|9999) continue ;; esac
    st=$(fw_port_status "${addr##*:}")
    case "$st" in blocked|restricted) fwok="$fwok $addr($st)"; continue ;; esac
    exp="$exp $addr"
  done
  [ -n "$fwok" ] && [ -z "$exp" ] && finding INFO JAVA-PORT-02 "$cat" "Port aplikasi listen di jaringan, tetapi sudah dibatasi host firewall" "$label:$fwok" \
    "Rincian sumber yang diizinkan di raw/firewall_analysis.txt."
  [ -n "$exp" ] && finding LOW JAVA-PORT-01 "$cat" "Port aplikasi bisa diakses langsung dari jaringan (bisa mem-bypass proxy)" "$label:$exp" \
    "Jika aplikasi diakses lewat reverse proxy, bind ke localhost/IP internal atau batasi port hanya dari IP proxy."
  [ "$cat" = SpringBoot ] || app_log_targets "$pid" "$label"
}

analyze_spring_config() { # $1=file gabungan config, $2=label
  local f="$1" label="$2" keys
  [ -s "$f" ] || return
  if grep -qiE 'management\.endpoints\.web\.exposure\.include\s*[=:]\s*["'\'']?\*' "$f" || grep -qiE '^\s*include\s*:\s*["'\'']?\*' "$f"; then
    finding HIGH SB-ACT-01 SpringBoot "Semua endpoint Actuator di-expose (exposure.include=*)" "$label" \
      "Set management.endpoints.web.exposure.include=health,info dan amankan dengan Spring Security."
  fi
  grep -qiE 'management\.security\.enabled\s*[=:]\s*false|endpoints\.sensitive\s*[=:]\s*false' "$f" && \
    finding HIGH SB-ACT-02 SpringBoot "Keamanan Actuator dimatikan (Spring Boot 1.x)" "$label" "Hapus management.security.enabled=false / endpoints.sensitive=false."
  grep -qiE 'spring\.h2\.console\.enabled\s*[=:]\s*true' "$f" && \
    finding HIGH SB-H2-01 SpringBoot "H2 console aktif di production" "$label" "Set spring.h2.console.enabled=false."
  keys=$(grep -iE '^\s*[A-Za-z0-9_.-]*(password|passwd|secret|token|api[-_]?key|private[-_]?key)[A-Za-z0-9_.-]*\s*[=:]\s*[^[:space:]]' "$f" \
        | grep -vE '[=:]\s*["'\'']?(\$\{|ENC\(|\{cipher\}|vault:)' | sed -E 's/\s*[=:].*//; s/^\s*//' | sort -u | tr '\n' ' ')
  [ -n "$keys" ] && finding MEDIUM SB-SECRET-01 SpringBoot "Password/secret tersimpan plaintext di file konfigurasi" "$label - key: $keys" \
    "Pindahkan secret ke environment variable / vault, atau enkripsi (Jasypt ENC()); permission file config 600 milik user aplikasi."
}

probe_actuator() { # $1=pid $2=label
  [ "$NO_NET" -eq 1 ] && return
  have curl || return
  local pid="$1" label="$2" addr port tgt sch code tmp="$OUT/.act.$$" eps e sens crit
  for addr in $(listen_of_pid "$pid"); do
    port=${addr##*:}; tgt=$(target_of "$addr")
    for sch in http https; do
      code=$(curl -sk -m 6 -o "$tmp" -w '%{http_code}' "$sch://$tgt:$port/actuator" 2>/dev/null)
      echo "$label $sch://$tgt:$port/actuator -> $code" >> "$RAW/sb_actuator.txt"
      if [ "$code" = 200 ] && grep -q '_links' "$tmp" 2>/dev/null; then
        eps=$(grep -oE '"[A-Za-z0-9-]+":\{"href"' "$tmp" | cut -d'"' -f2 | grep -v '^self$' | sort -u | tr '\n' ' ')
        echo "  endpoint: $eps" >> "$RAW/sb_actuator.txt"
        sens=""; crit=""
        for e in $eps; do
          case "$e" in env|heapdump|jolokia|shutdown|gateway|restart|refresh|logfile) crit="$crit $e"; sens="$sens $e" ;;
                       threaddump|configprops|loggers|mappings|beans|httptrace|httpexchanges|auditevents|sessions|trace|dump) sens="$sens $e" ;; esac
        done
        if [ -n "$crit" ]; then
          finding CRITICAL SB-ACT-03 SpringBoot "Endpoint Actuator berbahaya terbuka tanpa autentikasi" "$label $sch port $port:$crit (semua: $eps)" \
            "Batasi exposure ke health,info; lindungi /actuator dengan Spring Security; pindahkan ke management.server.port yang hanya listen di 127.0.0.1; blok /actuator di reverse proxy. heapdump/env bisa membocorkan password."
        elif [ -n "$sens" ]; then
          finding HIGH SB-ACT-04 SpringBoot "Endpoint Actuator sensitif terbuka tanpa autentikasi" "$label $sch port $port:$sens" \
            "Batasi exposure ke health,info dan lindungi dengan autentikasi."
        else
          finding LOW SB-ACT-05 SpringBoot "Actuator dapat diakses (hanya endpoint non-sensitif)" "$label $sch port $port: $eps" \
            "Pastikan /actuator tidak bisa diakses dari internet lewat proxy."
        fi
        break
      elif [ "$code" = 401 ] || [ "$code" = 403 ]; then
        break
      fi
    done
    code=$(curl -sk -m 6 -o "$tmp" -w '%{http_code}' "http://$tgt:$port/env" 2>/dev/null)
    if [ "$code" = 200 ] && grep -qE '"(profiles|systemProperties|activeProfiles)"' "$tmp" 2>/dev/null; then
      finding CRITICAL SB-ACT-03 SpringBoot "Endpoint /env (Spring Boot 1.x) terbuka tanpa autentikasi" "$label port $port" \
        "Amankan actuator (management.security.enabled=true) dan upgrade dari Spring Boot 1.x."
    fi
  done
  rm -f "$tmp"
}

sb_version_finding() { # $1=label $2=versi
  case "$2" in
    1.*) finding HIGH SB-EOL-01 SpringBoot "Spring Boot 1.x sudah lama EOL" "$1: Spring Boot $2" "Upgrade ke Spring Boot 3.x (butuh Java 17+)." ;;
    2.*) finding MEDIUM SB-EOL-02 SpringBoot "Spring Boot 2.x sudah tidak didukung komunitas (OSS)" "$1: Spring Boot $2" "Rencanakan upgrade ke Spring Boot 3.x (Java 17+), atau gunakan dukungan komersial." ;;
    "") ;;
    *) finding INFO SB-VER-01 SpringBoot "Versi Spring Boot" "$1: $2" "Cek status dukungan di spring.io/projects/spring-boot#support." ;;
  esac
}

tagof() { echo "$1" | tr -c 'A-Za-z0-9._\n-' '_'; }

# scan_app_archive FILE LABEL [FILE_AKUMULASI_CONFIG]
# Cek 1 arsip aplikasi (fat jar Spring Boot / war / ear): library, versi Spring Boot,
# config di dalam arsip, dan (opsional) salin sebagai artefak. Return 1 jika sudah pernah/ bukan zip.
scan_app_archive() {
  local f label="$2" cfg="${3:-}" rf ents libs sbver e
  rf=$(rpath "$1")
  case "$ARCH_SEEN" in *" $rf "*) return 1 ;; esac
  ARCH_SEEN="$ARCH_SEEN$rf "
  is_zip "$rf" || return 1
  ents="$RAW/app_$(tagof "$label")_$(tagof "$(basename "$rf")")_entries.txt"
  libs="${ents%_entries.txt}_libs.txt"
  zip_list "$rf" > "$ents"
  grep -E '\.jar$' "$ents" | sed 's#.*/##' > "$libs"
  reg_archive "$label" "$rf"
  if grep -qE '\.(war|ear)$' "$ents"; then
    echo "$rf berisi arsip bertingkat: $(grep -E '\.(war|ear)$' "$ents" | tr '\n' ' ') -> scan lengkap dengan Trivy" >> "$RAW/nested_archives.txt"
  fi
  sbver=$(zip_cat "$rf" META-INF/MANIFEST.MF | tr -d '\r' | sed -n 's/^Spring-Boot-Version: *//p')
  [ -z "$sbver" ] && sbver=$(grep -oE '^spring-boot-[0-9][0-9.]*[0-9]' "$libs" | head -n1 | sed 's/spring-boot-//')
  sb_version_finding "$label/$(basename "$rf")" "$sbver"
  if [ -n "$cfg" ]; then
    for e in $(grep -E '^(BOOT-INF/classes/|WEB-INF/classes/)?(config/)?(application|bootstrap)[^/]*\.(properties|ya?ml)$' "$ents"); do
      { echo "##### $rf!/$e"; zip_cat "$rf" "$e"; echo; } >> "$cfg"
    done
  fi
  collect_artifact "$rf" "$label"
  return 0
}

# scan_lib_dir DIR LABEL -> library lepas (*.jar) dalam 1 folder, mis. folder classpath "lib/"
scan_lib_dir() {
  local d label="$2" list f
  d=$(rpath "$1"); [ -d "$d" ] || return 0
  case "$DIR_SEEN" in *" $d "*) return 0 ;; esac
  DIR_SEEN="$DIR_SEEN$d "
  list="$RAW/libdir_$(tagof "$label")_$(tagof "$(basename "$d")")_libs.txt"
  find "$d" -maxdepth 1 -type f -name '*.jar' -printf '%f\n' 2>/dev/null | sort > "$list"
  [ -s "$list" ] || { rm -f "$list"; return 0; }
  while read -r f; do reg_archive "$label/$(basename "$d")" "$f"; done < <(find "$d" -maxdepth 1 -type f -name '*.jar' 2>/dev/null)
  if [ "$COLLECT_ART" -eq 1 ]; then
    while read -r f; do collect_artifact "$f" "$label/lib"; done < <(find "$d" -maxdepth 1 -type f -name '*.jar' 2>/dev/null)
  fi
}

# Konfigurasi eksternal Spring (folder kerja & spring.config.location) -> ditambahkan ke file $2
spring_external_config() { # $1=pid $2=cfg
  local pid="$1" cfg="$2" cwd e loc l
  cwd=$(pid_cwd "$pid")
  for e in "$cwd"/application*.properties "$cwd"/application*.y*ml "$cwd"/config/*.properties "$cwd"/config/*.y*ml; do
    [ -f "$e" ] && { echo "##### $e"; cat "$e"; echo; } >> "$cfg"
  done
  for loc in "$(arg_val "$pid" --spring.config.location)" "$(arg_val "$pid" -Dspring.config.location)" \
             "$(arg_val "$pid" --spring.config.additional-location)" "$(arg_val "$pid" -Dspring.config.additional-location)"; do
    for l in $(echo "$loc" | tr ',' ' '); do
      l=${l#optional:}; l=${l#file:}
      [ -f "$l" ] && { echo "##### $l"; cat "$l"; echo; } >> "$cfg"
      [ -d "$l" ] && for e in "$l"/application*; do [ -f "$e" ] && { echo "##### $e"; cat "$e"; echo; } >> "$cfg"; done
    done
  done
}

finish_spring_config() { # $1=cfg $2=label
  analyze_spring_config "$1" "$2"
  [ -s "$1" ] && redact < "$1" > "$RAW/config_$(tagof "$2").txt"
  rm -f "$1"
}

check_springboot() {
  local pid="$1" jar base cfg d
  jar=$(arg_next "$pid" "-jar")
  [ -n "$jar" ] && [ "${jar#/}" = "$jar" ] && jar="$(pid_cwd "$pid")/$jar"
  base=$(basename "${jar:-springboot-$pid}" .jar)
  log "Cek Spring Boot: $base (PID $pid)"
  ROLES="$ROLES springboot:$base"
  check_java_common "$pid" SpringBoot "$base"
  cfg="$OUT/.cfg.$$"; : > "$cfg"
  [ -f "$jar" ] && { run_path "$jar"; scan_app_archive "$jar" "$base" "$cfg"; }
  for d in $(classpath_dirs "$pid"); do run_path "$d"; scan_lib_dir "$d" "$base"; done
  spring_external_config "$pid" "$cfg"
  app_log_targets "$pid" "$base" "$cfg"
  finish_spring_config "$cfg" "$base"
  probe_actuator "$pid" "$base"
}

# wildfly_ports_check CONFIG_XML LABEL [PID]
# Memetakan socket-binding (+ port-offset) ke interface/alamat, lalu menilai port
# management, AJP, IIOP, dan port yang di-listen tapi tidak ada di konfigurasi.
wildfly_ports_check() {
  local cfg="$1" label="$2" pid="${3:-}" off="" listen="" line
  [ -n "$PY" ] || return 0
  [ -n "$pid" ] && off=$(arg_val "$pid" "-Djboss.socket.binding.port-offset")
  [ -n "$pid" ] && listen=$(listen_of_pid "$pid" | tr '\n' ',')
  "$PY" - "$cfg" "$off" "$listen" "$RAW/wildfly_${label}_ports.txt" "$(pid_cmd "${pid:-0}" 2>/dev/null)" <<'PYEOF' | while IFS=$'\t' read -r sev id title ev rec; do
from __future__ import print_function, unicode_literals
import sys, re, io
argv = [a.decode('utf-8', 'replace') if isinstance(a, bytes) else a for a in sys.argv]
cfg, off_override, listen, outp, cmdline = argv[1:6]
x = io.open(cfg, encoding='utf-8', errors='replace').read()
def dflt(v):
    m = re.match(r'^\$\{[^:}]+:([^}]*)\}$', v.strip())
    return m.group(1) if m else v.strip()
def prop(name, val):
    m = re.search(r'-D' + re.escape(name) + r'=(\S+)', cmdline)
    return m.group(1) if m else val
# -b / -bmanagement di command line
bpub = re.search(r'(?:^|\s)-b(?:=|\s+)(\S+)', cmdline)
bmgmt = re.search(r'-bmanagement(?:=|\s+)(\S+)', cmdline)
ifaces = {}
for m in re.finditer(r'<interface name="([^"]+)">(.*?)</interface>', x, re.S):
    body = m.group(2)
    a = re.search(r'<inet-address value="([^"]+)"', body)
    if a:
        raw = a.group(1); pm = re.match(r'^\$\{([^:}]+):?([^}]*)\}$', raw)
        ifaces[m.group(1)] = prop(pm.group(1), pm.group(2)) if pm else raw
    elif '<any-address' in body: ifaces[m.group(1)] = '0.0.0.0'
    elif '<loopback' in body: ifaces[m.group(1)] = '127.0.0.1'
    else: ifaces[m.group(1)] = '?'
if bpub: ifaces['public'] = bpub.group(1)
if bmgmt: ifaces['management'] = bmgmt.group(1)
g = re.search(r'<socket-binding-group[^>]*default-interface="([^"]+)"[^>]*>', x)
defif = g.group(1) if g else 'public'
om = re.search(r'port-offset="([^"]+)"', x)
offset = 0
try:
    offset = int(off_override) if off_override else int(prop('jboss.socket.binding.port-offset', dflt(om.group(1))) if om else 0)
except ValueError: offset = 0
binds = []
for m in re.finditer(r'<socket-binding ([^>]*?)/?>', x):
    at = dict(re.findall(r'(\S+?)="([^"]*)"', m.group(1)))
    if 'port' not in at: continue
    pm = re.match(r'^\$\{([^:}]+):?([^}]*)\}$', at['port'])
    try: port = int(prop(pm.group(1), pm.group(2)) if pm else at['port'])
    except ValueError: continue
    fixed = at.get('fixed-port') == 'true'
    iface = at.get('interface', defif)
    binds.append((at.get('name', '?'), iface, ifaces.get(iface, '?'), port if fixed else port + offset))
lports = set()
for a in [l for l in listen.split(',') if l]:
    try: lports.add(int(a.rsplit(':', 1)[1]))
    except ValueError: pass
with io.open(outp, 'w', encoding='utf-8') as f:
    f.write('port-offset: %d\n' % offset)
    f.write('interfaces : %s\n\n' % ', '.join('%s=%s' % kv for kv in ifaces.items()))
    f.write('%-28s %-12s %-18s %6s  %s\n' % ('socket-binding', 'interface', 'alamat', 'port', 'listen?'))
    for b in binds:
        f.write('%-28s %-12s %-18s %6d  %s\n' % (b[0], b[1], b[2], b[3], 'YA' if b[3] in lports else ('-' if lports else '?')))
    known = set(b[3] for b in binds)
    unk = sorted(p for p in lports if p not in known)
    if unk: f.write('\nPort di-listen proses WildFly tapi TIDAK ada di socket-binding: %s\n' % ', '.join(map(str, unk)))
def loop(a): return a.startswith('127.') or a in ('localhost', '::1')
agg = {}
def out(sev, cid, title, where, rec):
    if cid in agg: agg[cid][3].append(where)
    else: agg[cid] = [sev, cid, title, [where], rec]
used = set(re.findall(r'<socket-binding\s+(?:http|https)="([^"]+)"', x))
for name, iface, addr, port in binds:
    live = (port in lports) if lports else True
    if not live: continue
    if name.startswith('management') and used and name not in used: continue
    where = '%s=%s port %d (offset %d)' % (iface, addr, port, offset)
    if name.startswith('management') and not loop(addr):
        out('HIGH', 'WF-MGMT-01', 'Management console/API WildFly dapat diakses dari jaringan', where,
            'Set interface management ke 127.0.0.1 (${jboss.bind.address.management:127.0.0.1} atau -bmanagement=127.0.0.1) dan akses lewat SSH tunnel.')
    if name == 'ajp' and re.search(r'<ajp-listener', x) and not loop(addr):
        out('MEDIUM', 'WF-AJP-01', 'Listener AJP WildFly terbuka ke jaringan (AJP tanpa autentikasi)', where,
            'Matikan ajp-listener bila proxy memakai HTTP; bila dipakai (mod_jk/mod_cluster), batasi port hanya dari IP proxy dan set secret.')
    if name.startswith('iiop') and 'iiop-openjdk' in x and not loop(addr):
        out('MEDIUM', 'WF-IIOP-01', 'IIOP/CORBA WildFly aktif dan terbuka ke jaringan', where,
            'Hapus subsystem iiop-openjdk dan socket-binding iiop bila tidak dipakai (permukaan serangan deserialization).')
    if name.startswith('txn-') and not loop(addr):
        out('LOW', 'WF-TXN-01', 'Port transaction manager WildFly terbuka ke jaringan', where,
            'Batasi dengan firewall; port ini tidak perlu diakses dari luar server.')
if lports:
    unk = sorted(p for p in lports if p not in set(b[3] for b in binds))
    if unk:
        out('MEDIUM', 'WF-PORT-UNK', 'Proses WildFly membuka port yang tidak ada di konfigurasi', 'port: ' + ', '.join(map(str, unk)),
            'Identifikasi aplikasi pembuka port (mis. server socket di dalam war). Port tak terdokumentasi = permukaan serangan tersembunyi.')
for v in agg.values():
    print('\t'.join([v[0], v[1], v[2], '; '.join(v[3]), v[4]]))
if re.search(r'<subsystem xmlns="urn:wildfly:health[^"]*" security-enabled="false"', x):
    print('\t'.join(['LOW', 'WF-HEALTH-01', 'Endpoint health WildFly tanpa autentikasi', 'subsystem health security-enabled=false', 'Pastikan port management tidak terekspos, atau aktifkan security pada subsystem health.']))
PYEOF
    finding "$sev" "$id" WildFly "$title" "$label: $ev" "$rec"
  done
}

# Bagian statis WildFly (konfigurasi, versi, deployment) - dipakai deteksi otomatis & path manual
# wildfly_static JBOSS_HOME BASE_DIR [NAMA_CONFIG] [domain]
wildfly_static() {
  local jh base="$2" cfgname="${3:-}" mode="${4:-}" wpid="${5:-}" label cfg ver major n f dep d tmpl jhome
  jh=$(rpath "$1")
  case "$WF_SEEN" in *" $jh "*) return 0 ;; esac
  WF_SEEN="$WF_SEEN$jh "
  label=$(basename "$jh")
  ROLES="$ROLES wildfly:$label"
  [ -d "$base" ] || base="$jh/standalone"

  ver=$(head -n1 "$jh/version.txt" 2>/dev/null)
  [ -z "$ver" ] && ver=$(find "$jh/modules/system/layers/base/org/jboss/as/product" -name MANIFEST.MF 2>/dev/null | head -n1 | xargs -r grep -h 'JBoss-Product-Release-Version' 2>/dev/null)
  if echo "$ver" | grep -qi enterprise; then
    finding INFO WF-VER-01 WildFly "Versi JBoss EAP" "$label: $ver" "Pastikan cumulative patch terbaru dari Red Hat sudah terpasang."
  elif [ -n "$ver" ]; then
    major=$(echo "$ver" | grep -oE '[0-9]+\.[0-9]+' | head -n1 | cut -d. -f1)
    if [ -n "$major" ] && [ "$major" -le 18 ]; then
      finding HIGH WF-EOL-01 WildFly "Versi WildFly sangat lama, tidak menerima patch keamanan" "$label: $ver" "Upgrade ke WildFly terbaru (atau JBoss EAP bila butuh dukungan jangka panjang)."
    else
      finding MEDIUM WF-EOL-02 WildFly "WildFly komunitas hanya mem-patch versi terbaru" "$label: $ver" "Ikuti rilis WildFly terbaru secara berkala, atau gunakan JBoss EAP."
    fi
  fi

  # standalone.conf: JAVA_HOME & opsi JVM yang dipakai saat start
  if [ -f "$jh/bin/standalone.conf" ]; then
    grep -vE '^\s*(#|$)' "$jh/bin/standalone.conf" | redact > "$RAW/wildfly_${label}_standalone.conf.txt"
    jhome=$(sed -n 's/^\s*JAVA_HOME="\{0,1\}\([^"]*\)"\{0,1\}.*/\1/p' "$jh/bin/standalone.conf" | tail -n1)
    [ -n "$jhome" ] && java_version_check "$jhome/bin/java" WildFly "$label (JAVA_HOME standalone.conf)"
    grep -vE '^\s*#' "$jh/bin/standalone.conf" | grep -qE 'jdwp|-Xdebug' && finding HIGH JAVA-DEBUG-01 WildFly \
      "Remote debug (JDWP) diaktifkan di standalone.conf" "$label" "Hapus opsi -agentlib:jdwp/-Xdebug dari konfigurasi production."
  fi

  if [ -n "$cfgname" ]; then cfg="$base/configuration/$cfgname"
  elif [ -f "$base/configuration/standalone.xml" ]; then cfg="$base/configuration/standalone.xml"
  else cfg=$(ls "$base"/configuration/standalone*.xml 2>/dev/null | head -n1); fi
  [ "$mode" = domain ] && cfg="$jh/domain/configuration/domain.xml"
  if [ -f "$cfg" ]; then
    redact < "$cfg" > "$RAW/wildfly_${label}_$(basename "$cfg")"
    n=$(grep -ciE '<password>[^<$]|clear-text="[^$"]' "$cfg")
    [ "$n" -gt 0 ] && finding MEDIUM WF-SECRET-01 WildFly "Password tersimpan plaintext di konfigurasi WildFly" "$label: $n entri di $(basename "$cfg")" \
      "Gunakan Elytron credential store / vault atau environment variable (\${env.DB_PASS}); batasi permission file konfigurasi."
    wildfly_ports_check "$cfg" "$label" "$wpid"
    grep -q 'name="server-header"\|x-powered-by-header' "$cfg" && finding LOW WF-BANNER-01 WildFly "Header Server/X-Powered-By WildFly aktif" "$label" \
      "Hapus filter-ref server-header & x-powered-by-header di subsystem undertow."
    grep -q 'welcome-content' "$cfg" && finding LOW WF-WELCOME-01 WildFly "Halaman default WildFly (welcome-content) aktif" "$label" \
      "Hapus location name=\"/\" handler welcome-content bila tidak dipakai."
    grep -q 'ExampleDS' "$cfg" && finding LOW WF-EXDS-01 WildFly "Datasource contoh ExampleDS (H2) masih ada" "$label" "Hapus ExampleDS dan driver H2 dari konfigurasi production."
    grep -q '<https-listener' "$cfg" || finding INFO WF-TLS-01 WildFly "Tidak ada HTTPS listener (TLS kemungkinan diterminasi di proxy)" "$label" \
      "Pastikan segmen proxy-ke-WildFly terpercaya; bila lintas jaringan, pertimbangkan TLS sampai backend."
  else
    finding INFO WF-CFG-01 WildFly "File konfigurasi WildFly tidak ditemukan" "$label: ${cfg:-$base/configuration}" "Periksa base dir / nama config (-c) yang dipakai."
  fi
  for f in "$base/configuration/mgmt-users.properties" "$jh/domain/configuration/mgmt-users.properties"; do
    [ -f "$f" ] || continue
    n=$(grep -vE '^\s*(#|$)' "$f" | cut -d= -f1 | tr '\n' ' ')
    echo "$f: $n" >> "$RAW/wildfly_${label}_mgmt_users.txt"
    [ -n "$n" ] && finding INFO WF-MGMT-02 WildFly "User management console terdaftar" "$label: $n" "Pastikan password kuat, akun milik orang yang masih aktif, dan rotasi berkala."
  done

  # Library di deployment, managed content & modules
  tmpl="$RAW/wildfly_${label}_libs.txt"; : > "$tmpl"
  ls -la "$base/deployments" > "$RAW/wildfly_${label}_deployments.txt" 2>&1
  for dep in "$base"/deployments/*; do
    [ -e "$dep" ] || continue
    d=$(basename "$dep")
    case "$d" in
      *.war|*.ear|*.jar|*.rar)
        [ -n "$wpid" ] && [ -e "$dep.deployed" ] && run_path "$dep"
        if [ -f "$dep" ]; then
          zip_list "$dep" | grep -E '\.(jar|war)$' | sed "s#^#$d!/#" >> "$tmpl"
          reg_archive "$label/deployments:$d" "$dep"
          collect_artifact "$dep" "$label/deployments"
        elif [ -d "$dep" ]; then
          find "$dep" -name '*.jar' -printf "$d!/%f\n" 2>/dev/null >> "$tmpl"
          while read -r f; do reg_archive "$label/exploded-$d" "$f"; done < <(find "$dep" -name '*.jar' 2>/dev/null)
          if [ "$COLLECT_ART" -eq 1 ]; then
            for f in $(find "$dep" -name '*.jar' 2>/dev/null); do collect_artifact "$f" "$label/exploded-$d"; done
          fi
        fi ;;
    esac
  done
  # Peta deployment terdaftar (nama, aktif?, sha1 konten) dari file konfigurasi
  local depmap="$RAW/wildfly_${label}_deployment_map.txt" h dn den orphan="" disabled=""
  : > "$depmap"
  if [ -f "$cfg" ]; then
    tr '\n' ' ' < "$cfg" | grep -oE '<deployment [^>]*>[^<]*<content sha1="[0-9a-f]+"' | while read -r line; do
      dn=$(echo "$line" | sed -n 's/.*<deployment name="\([^"]*\)".*/\1/p')
      den=$(echo "$line" | grep -q 'enabled="false"' && echo tidak || echo ya)
      h=$(echo "$line" | sed -n 's/.*sha1="\([0-9a-f]*\)".*/\1/p')
      echo "$h $den $dn"
    done > "$depmap"
  fi
  if [ -d "$base/data/content" ]; then
    for f in $(find "$base/data/content" -type f -name content 2>/dev/null); do
      h=$(echo "$f" | sed -nE 's#.*/data/content/([0-9a-f]{2})/([0-9a-f]+)/content$#\1\2#p')
      dn=$(awk -v h="$h" '$1==h{print $3; exit}' "$depmap"); den=$(awk -v h="$h" '$1==h{print $2; exit}' "$depmap")
      if [ -z "$dn" ]; then dn="konten-yatim-$h"; orphan="$orphan ${h:0:12}"
      elif [ "$den" = tidak ]; then disabled="$disabled $dn"; dn="$dn(nonaktif)"
      elif [ -n "$wpid" ]; then run_path "$f"; fi
      zip_list "$f" | grep -E '\.(jar|war)$' | sed "s#^#$dn!/#" >> "$tmpl"
      reg_archive "$label/deploy:$dn" "$f"
      collect_artifact "$f" "$label/managed-content" "content-$(basename "$(dirname "$f")").war"
    done
  fi
  [ -n "$orphan" ] && finding LOW WF-CONTENT-01 WildFly "Konten deployment yatim (tidak terdaftar di konfigurasi) masih tersimpan" "$label: sha1$orphan" \
    "Bersihkan konten yang tidak terdaftar (WildFly CLI: /deployment=... remove, atau hapus folder data/content/<hash> saat server berhenti)."
  [ -n "$disabled" ] && finding LOW WF-DEP-01 WildFly "Deployment nonaktif masih tersimpan di server" "$label:$disabled" \
    "Bila tidak dipakai lagi: undeploy --name=<nama> (jangan sekadar disable) agar kode lama ikut terhapus."
  # Status deployment (hanya WildFly yang berjalan): aplikasi benar ter-deploy atau WildFly kosong?
  if [ -n "$wpid" ]; then
    local dstat="$RAW/wildfly_${label}_deploy_status.txt" ok="" bad="" mg ctx logdep logbad all logf="$base/log/server.log"
    for f in "$base"/deployments/*.deployed; do [ -e "$f" ] && ok="$ok $(basename "${f%.deployed}")"; done
    for f in "$base"/deployments/*.failed; do [ -e "$f" ] && bad="$bad $(basename "${f%.failed}")"; done
    mg=$(awk '$2=="ya"{print $3}' "$depmap" 2>/dev/null | tr '\n' ' ')
    {
      echo "Folder deployments, berhasil (.deployed) :${ok:- (tidak ada)}"
      echo "Folder deployments, gagal (.failed)      :${bad:- (tidak ada)}"
      echo "Terdaftar aktif di konfigurasi (CLI/console): ${mg:-(tidak ada)}"
      echo
      if [ -r "$logf" ]; then
        echo "server.log: baris terkait deployment (40 terakhir dari 20000 baris terakhir)"
        tail -n 20000 "$logf" 2>/dev/null | grep -E 'WFLYSRV0010|WFLYSRV0009|WFLYUT0021|WFLYSRV0025|WFLYSRV0026|WFLYCTL0013|WFLYCTL0186|Operation \("deploy"\)' | tail -n 40 | cut -c1-300 | redact
      else
        echo "server.log tidak terbaca: $logf"
      fi
    } > "$dstat" 2>/dev/null
    ctx=$(grep -oE "WFLYUT0021: Registered web context: '[^']*'" "$dstat" | sed "s/.*context: //" | sort -u | tr '\n' ' ')
    logdep=$(grep -oE 'WFLYSRV0010: Deployed "[^"]*"' "$dstat" | sed 's/.*Deployed //' | tr -d '"' | sort -u | tr '\n' ' ')
    logbad=$(grep -cE 'WFLYCTL0013|WFLYCTL0186|Operation \("deploy"\)' "$dstat" 2>/dev/null | head -n1)
    all=$(echo "$ok $mg" | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' ')
    if [ -n "$bad" ] || [ "${logbad:-0}" -gt 0 ]; then
      finding MEDIUM WF-DEPST-02 WildFly "Ada deployment yang gagal" "$label:${bad:+ gagal:$bad;} ${logbad:-0} baris error deployment di server.log" \
        "Lihat raw/wildfly_${label}_deploy_status.txt. Aplikasi yang gagal tidak berjalan dan tidak bisa dinilai; perbaiki lalu deploy ulang."
    fi
    if [ -z "$all" ]; then
      finding INFO WF-DEPST-00 WildFly "WildFly berjalan TANPA aplikasi ter-deploy" \
        "$label: folder deployments & konfigurasi kosong${logdep:+; log mencatat pernah deploy: $logdep}" \
        "Yang bisa dinilai baru platform (WildFly, Java, konfigurasi). Ulangi assessment setelah aplikasi di-deploy."
    else
      finding INFO WF-DEPST-01 WildFly "Aplikasi ter-deploy di WildFly" "$label: $all${ctx:+; context web: $ctx}" \
        "Pastikan hanya aplikasi ini yang seharusnya ada di server ini."
    fi
  fi
  find "$jh/modules" -name '*.jar' -printf 'modules!/%f\n' 2>/dev/null >> "$tmpl"
  [ "$SAFE" -eq 0 ] && while read -r f; do reg_archive "$label/modules" "$f"; done < <(find "$jh/modules" -name '*.jar' 2>/dev/null)
}

check_wildfly() {
  local pid="$1" cmd jh base cfgname label addr mode=""
  cmd=$(pid_cmd "$pid")
  jh=$(arg_val "$pid" "-Djboss.home.dir")
  base=$(arg_val "$pid" "-Djboss.server.base.dir"); [ -z "$base" ] && base="$jh/standalone"
  label=$(basename "${jh:-wildfly}")
  log "Cek WildFly: $label (PID $pid)"
  check_java_common "$pid" WildFly "$label"
  [ -d "$jh" ] || return 0
  cfgname=$(arg_next "$pid" "-c"); [ -z "$cfgname" ] && cfgname=$(arg_val "$pid" "--server-config")
  echo "$cmd" | grep -q 'Host Controller\|Process Controller' && mode=domain
  run_path "$jh/modules"; run_path "$jh/bin"; run_path "$jh/jboss-modules.jar"
  wildfly_static "$jh" "$base" "$cfgname" "$mode" "$pid"
}

check_other_java() {
  local pid="$1" jar base d
  jar=$(arg_next "$pid" "-jar")
  base=$(basename "${jar:-java-$pid}" .jar)
  log "Cek aplikasi Java lain: $base (PID $pid)"
  ROLES="$ROLES java:$base"
  check_java_common "$pid" Java "$base"
  if [ -n "$jar" ]; then
    [ "${jar#/}" = "$jar" ] && jar="$(pid_cwd "$pid")/$jar"
    [ -f "$jar" ] && { run_path "$jar"; scan_app_archive "$jar" "$base"; }
  fi
  for d in $(classpath_dirs "$pid"); do run_path "$d"; scan_lib_dir "$d" "$base"; done
}

#------------------------------------------------------------------------------
# PATH MANUAL (parameter / prompt)
#------------------------------------------------------------------------------
scan_wildfly_home() {
  local jh; jh=$(rpath "$1" 2>/dev/null)
  if [ ! -f "$jh/jboss-modules.jar" ]; then
    finding INFO PATH-WF-01 Path "Path WildFly tidak valid (jboss-modules.jar tidak ada)" "$1" "Periksa kembali path WildFly/JBoss home."
    return
  fi
  log "Cek WildFly (path manual): $jh"
  wildfly_static "$jh" "$jh/standalone"
  [ -f "$jh/domain/configuration/domain.xml" ] && [ ! -d "$jh/standalone/deployments" ] && wildfly_static "$jh" "$jh/domain" "" domain
}

scan_app_dir() {
  local d label cfg f loose n=0
  d=$(rpath "$1" 2>/dev/null)
  if [ ! -d "$d" ]; then
    finding INFO PATH-APP-01 Path "Path aplikasi tidak ditemukan" "$1" "Periksa kembali path folder aplikasi."
    return
  fi
  label=$(basename "$d")
  log "Cek folder aplikasi (path manual): $d"
  ROLES="$ROLES appdir:$label"
  cfg="$OUT/.cfg.$$"; : > "$cfg"
  loose="$RAW/appdir_$(tagof "$label")_loose_libs.txt"; : > "$loose"
  while read -r f; do
    case "$ARCH_SEEN" in *" $(rpath "$f") "*) n=$((n+1)); continue ;; esac
    if zip_list "$f" | grep -qE '^(BOOT-INF/|WEB-INF/|META-INF/application\.xml)'; then
      scan_app_archive "$f" "$label" "$cfg" && n=$((n+1))
    else
      basename "$f" >> "$loose"; reg_archive "$label/lib" "$f"; collect_artifact "$f" "$label/lib"
    fi
  done < <(find "$d" -maxdepth 4 -type f \( -name '*.jar' -o -name '*.war' -o -name '*.ear' -o -iname '*.jar[._-]*' -o -iname '*.war[._-]*' -o -iname '*.ear[._-]*' \) 2>/dev/null | filter_archives | head -n 3000)
  find "$d" -maxdepth 3 -type f \( -name 'application*.properties' -o -name 'application*.yml' -o -name 'application*.yaml' \
       -o -name 'bootstrap*.properties' -o -name 'bootstrap*.yml' \) 2>/dev/null | while read -r f; do
    echo "##### $f"; cat "$f"; echo
  done >> "$cfg"
  finish_spring_config "$cfg" "$label"
  for f in $(find "$d" -maxdepth 4 -type f -path '*/bin/java' 2>/dev/null); do java_version_check "$f" Java "$label (JRE bawaan aplikasi)"; done
  [ "$n" -eq 0 ] && [ ! -s "$loose" ] && finding INFO PATH-APP-02 Path "Tidak ada jar/war/ear di folder aplikasi" "$d" "Periksa kembali path folder aplikasi."
}

check_java_home() {
  local exe; exe="$(rpath "$1" 2>/dev/null)/bin/java"
  if [ ! -x "$exe" ]; then
    finding INFO PATH-JAVA-01 Path "Path JAVA_HOME tidak valid (bin/java tidak ada)" "$1" "Periksa kembali path JDK/JRE."
    return
  fi
  log "Cek JAVA_HOME (path manual): $1"
  java_version_check "$exe" Java "JAVA_HOME $1"
}

check_manual_paths() {
  local p
  for p in $WF_HOMES;   do scan_wildfly_home "$p"; done
  for p in $APP_DIRS;   do scan_app_dir "$p"; done
  for p in $JAVA_HOMES; do check_java_home "$p"; done
}

# Mode -i: tampilkan hasil deteksi otomatis, lalu tanya path tambahan
ask_paths() {
  [ "$INTERACTIVE" -eq 1 ] || return 0
  if ! { exec 3<>/dev/tty; } 2>/dev/null; then log "Mode interaktif butuh terminal (gunakan ssh -t), prompt dilewati"; return 0; fi
  local pid jh jar ans
  {
    echo
    echo "=== Proses Java yang sedang berjalan (otomatis dicek) ==="
    for pid in $(java_pids); do
      jh=$(arg_val "$pid" -Djboss.home.dir); jar=$(arg_next "$pid" -jar)
      echo "  PID $pid | java: $(pid_exe "$pid")${jh:+ | wildfly: $jh}${jar:+ | jar: $jar} | dir: $(pid_cwd "$pid")"
    done
    [ -n "$(java_pids)" ] || echo "  (tidak ada proses Java yang berjalan)"
    echo
    echo "Tambahkan path lain bila ada (aplikasi yang sedang mati / lokasi lain)."
    echo "Pisahkan beberapa path dengan spasi atau koma. Tekan Enter untuk melewati."
  } >&3
  printf '  Path WildFly/JBoss home           : ' >&3; read -r ans <&3; WF_HOMES="$WF_HOMES ${ans//,/ }"
  printf '  Path folder aplikasi SpringBoot/Java: ' >&3; read -r ans <&3; APP_DIRS="$APP_DIRS ${ans//,/ }"
  printf '  Path JAVA_HOME / JDK              : ' >&3; read -r ans <&3; JAVA_HOMES="$JAVA_HOMES ${ans//,/ }"
  echo >&3
  exec 3>&-
}

#------------------------------------------------------------------------------
# 11. TOMCAT (standalone)
#------------------------------------------------------------------------------
check_tomcat() {
  local pid="$1" cb ch label f n
  cb=$(arg_val "$pid" "-Dcatalina.base"); ch=$(arg_val "$pid" "-Dcatalina.home"); [ -z "$cb" ] && cb="$ch"
  label="tomcat-$(basename "${cb:-$pid}")"
  log "Cek Tomcat: $label (PID $pid)"
  ROLES="$ROLES tomcat:$label"
  check_java_common "$pid" Tomcat "$label"
  [ -d "$cb" ] || return 0
  run_path "$cb/webapps"; run_path "$cb/lib"; run_path "$ch/lib"
  [ -f "$cb/conf/server.xml" ] && grep -vE '^\s*$' "$cb/conf/server.xml" | redact > "$RAW/${label}_server.xml"
  [ -f "$cb/conf/tomcat-users.xml" ] && redact < "$cb/conf/tomcat-users.xml" | sed -E 's/(password=")[^"]*"/\1****"/g' > "$RAW/${label}_tomcat-users.xml"
  f="$cb/conf/server.xml"
  if [ -f "$f" ]; then
    grep -qE '<Server[^>]*port="8005"[^>]*shutdown="SHUTDOWN"' "$f" && finding LOW TC-SHUT-01 Tomcat "Port shutdown Tomcat 8005 dengan perintah default SHUTDOWN" "$label" \
      "Set port=\"-1\" atau ganti shutdown string ke nilai acak."
    if grep -qE '<Connector[^>]*protocol="AJP' "$f" && ! grep -qE '<Connector[^>]*protocol="AJP[^>]*(secret|requiredSecret)=' "$f"; then
      finding HIGH TC-AJP-01 Tomcat "Connector AJP tanpa secret (risiko Ghostcat CVE-2020-1938)" "$label" \
        "Matikan connector AJP bila tidak dipakai; bila dipakai set address=127.0.0.1/IP proxy + secret, dan pastikan Tomcat >= 9.0.31/8.5.51/7.0.100."
    fi
  fi
  if [ -d "$cb/webapps/manager" ] || [ -d "$cb/webapps/host-manager" ]; then
    finding MEDIUM TC-MGR-01 Tomcat "Aplikasi Tomcat Manager/Host Manager terpasang" "$label" \
      "Hapus webapps/manager & host-manager di production, atau batasi RemoteAddrValve hanya dari IP admin."
  fi
  for f in "$cb"/webapps/*.war; do [ -f "$f" ] && reg_archive "$label/webapps" "$f"; done
  while read -r f; do reg_archive "$label/webapps-exploded" "$f"; done < <(find "$cb/webapps" -path '*/WEB-INF/lib/*.jar' 2>/dev/null)
  while read -r f; do reg_archive "$label/lib" "$f"; done < <(find "$ch/lib" "$cb/lib" -maxdepth 1 -name '*.jar' 2>/dev/null | sort -u)
}

#------------------------------------------------------------------------------
# 12. TAMBAHAN: agent monitoring, kebijakan login, log terpusat, env & izin aplikasi
#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
# CONTAINER (Docker / Podman): postur keamanan + inventaris library di image
#------------------------------------------------------------------------------
check_containers() {
  local CRT="$CRT_BIN" grp sock tcp md name dir jarn n depth
  [ -n "$CRT_SRC" ] || return 0
  log "Cek container ($CRT, dibaca: $CRT_SRC, sebagai: $CRT_AS)"
  ROLES="$ROLES $CRT"

  # --- Dump info (read-only) ---
  if [ "$CRT_SRC" = cli ]; then
    { echo "### $CRT version (sebagai: $CRT_AS)"; "${CRT_CMD[@]}" version 2>&1
      echo; echo "### ps -a"; "${CRT_CMD[@]}" ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' 2>&1
      echo; echo "### images"; "${CRT_CMD[@]}" images --digests --format '{{.Repository}}:{{.Tag}}\t{{.Digest}}\t{{.CreatedSince}}\t{{.Size}}' 2>&1
      echo; echo "### info (ringkas)"; "${CRT_CMD[@]}" info 2>/dev/null | grep -iE 'Server Version|Storage Driver|Cgroup|Rootless|Security Options|seccomp|apparmor|selinux|userns' ; } > "$RAW/container_${CRT}.txt" 2>&1

  fi
  # --- Daemon / host-level ---
  # akses grup/socket/sudo ke daemon: lihat check_docker_access (DKR-*)
  # socket TCP tanpa TLS
  tcp=$(ss -tlnH 2>/dev/null | awk '{print $4}' | grep -E ':(2375|2376)$' | tr '\n' ' ')
  echo "$tcp" | grep -q 2375 && finding CRITICAL CNT-TCP-01 Container "Docker API diekspos via TCP 2375 tanpa TLS (kendali penuh daemon)" "$tcp" \
    "Matikan soket TCP tanpa TLS. Gunakan hanya soket unix, atau 2376 dengan TLS mutual (tlsverify)."
  echo "$tcp" | grep -q 2376 && finding MEDIUM CNT-TCP-02 Container "Docker API diekspos via TCP 2376" "$tcp" \
    "Pastikan 2376 memakai TLS mutual (--tlsverify) dan hanya dari IP admin via firewall."
  # permission socket
  for sock in /var/run/docker.sock /run/docker.sock /run/podman/podman.sock /run/user/*/docker.sock; do
    [ -S "$sock" ] || continue
    n=$(stat -c '%a' "$sock" 2>/dev/null)
    echo "$sock $n $(stat -c '%U:%G' "$sock" 2>/dev/null)" >> "$RAW/container_${CRT}.txt"
    [ $(( ${n:-0} % 10 )) -gt 0 ] && finding HIGH CNT-SOCK-02 Container "Socket container bisa diakses other (world)" "$sock mode $n" \
      "chmod 660 $sock, owner root:docker; akses other ke socket = kendali daemon."
  done

  # --- Per-container: inspect -> parser Python ---
  local running insp="$OUT/.cinsp.$$" det="$RAW/container_detail.txt" merged="$OUT/.cmerged.$$"
  running=$(cut -f1 "$OUT/.cmap" 2>/dev/null | tr '\n' ' ')
  if [ -z "$running" ]; then
    finding INFO CNT-NONE-01 Container "$CRT berjalan tetapi tidak ada container aktif" "-" "Tetap cek image tersimpan dengan Trivy (lihat raw/container_${CRT}.txt)."
  elif [ -z "$PY" ]; then
    finding INFO CNT-NOPY-01 Container "Postur container dilewati (python tidak tersedia)" "-" "Jalankan 'docker inspect' manual atau pasang python."
  else
    if [ "$CRT_SRC" = cli ]; then "${CRT_CMD[@]}" inspect $running > "$insp" 2>/dev/null
    else cp "$OUT/.cinsp_fs.json" "$insp" 2>/dev/null; fi
    "$PY" - "$insp" "$CRT" "$merged" "$det" "${DKR_MODE:-}" "$OUT/.cbinds" <<'PYEOF' | while IFS=$'\t' read -r sev id title ev rec; do
from __future__ import print_function
import sys, json, io, re
try:
    data = json.load(io.open(sys.argv[1], encoding='utf-8', errors='replace'))
except Exception as e:
    sys.stderr.write('inspect tidak terbaca: %s\n' % e); sys.exit(0)
merged_out = io.open(sys.argv[3], 'w', encoding='utf-8')
det = io.open(sys.argv[4], 'w', encoding='utf-8')
SENS_MOUNT = ('/', '/etc', '/root', '/home', '/var/run/docker.sock', '/run/docker.sock',
              '/var/run', '/proc', '/sys', '/boot', '/dev', '/usr', '/var/lib')
DANGER_CAP = set(['ALL','SYS_ADMIN','SYS_PTRACE','SYS_MODULE','NET_ADMIN','DAC_READ_SEARCH','SYS_RAWIO','BPF','DAC_OVERRIDE','NET_RAW'])
def out(sev, cid, title, ev, rec): print('\t'.join([sev, cid, title, ev, rec]))
MODE = sys.argv[5] if len(sys.argv) > 5 else ''
RL = 'rootless' in MODE and 'rootful' not in MODE
if isinstance(data, dict): data = [data]
for c in data:
    name = (c.get('Name') or c.get('Id', '?')[:12]).lstrip('/')
    cfg = c.get('Config') or {}; hc = c.get('HostConfig') or {}
    image = cfg.get('Image', '?'); state = (c.get('State') or {}).get('Running'); user = (cfg.get('User') or '').strip()
    det.write('== %s  image=%s  running=%s  user=%s\n' % (name, image, state, user or 'root(default)'))
    if hc.get('Privileged'):
        if RL:
            out('HIGH','CNT-PRIV-01','Container privileged (rootless: akses penuh ke semua milik user pemilik daemon, bukan root host)','%s (image %s)' % (name, image),
                'Hapus --privileged. Beri hanya capability yang dibutuhkan dan --security-opt no-new-privileges.')
        else:
            out('CRITICAL','CNT-PRIV-01','Container privileged (akses penuh ke host)','%s (image %s)' % (name, image),
                'Hapus --privileged. Beri hanya capability yang dibutuhkan dan --security-opt no-new-privileges.')
    binds = hc.get('Binds') or []; mounts = c.get('Mounts') or []
    msrc = set()
    for b in binds: msrc.add(b.split(':')[0])
    for m in mounts:
        if m.get('Source'): msrc.add(m['Source'])
    if len(sys.argv) > 6:
        try:
            bl = set()
            for m in mounts:
                if m.get('Source', '').startswith('/') and m.get('Destination') and m.get('Type', 'bind') == 'bind':
                    bl.add((m['Source'], m['Destination']))
            for b in binds:
                pp = b.split(':')
                if len(pp) >= 2 and pp[0].startswith('/'): bl.add((pp[0], pp[1]))
            bf = open(sys.argv[6], 'ab')
            for a, d in sorted(bl):
                ln = u'%s\t%s\t%s\n' % (name, a, d)
                bf.write(ln.encode('utf-8') if not isinstance(ln, bytes) else ln)
            bf.close()
        except Exception:
            pass
    for s in msrc:
        if s.rstrip('/').endswith('docker.sock'):
            if RL:
                out('HIGH','CNT-SOCK-01','Docker socket di-mount ke dalam container (rootless: kendali semua container user pemilik daemon)','%s: %s' % (name, s),
                    'Jangan mount docker.sock ke container aplikasi. Bila perlu Docker API, pakai proxy ber-otorisasi read-only.')
            else:
                out('CRITICAL','CNT-SOCK-01','Docker socket di-mount ke dalam container (setara root di host)','%s: %s' % (name, s),
                    'Jangan mount docker.sock ke container aplikasi. Bila perlu Docker API, pakai proxy ber-otorisasi read-only.')
    for s in msrc:
        sn = s.rstrip('/') or '/'
        if sn in SENS_MOUNT and not sn.endswith('docker.sock'):
            out('MEDIUM' if RL else 'HIGH','CNT-MOUNT-01','Path host sensitif di-mount ke container' + (' (rootless: terbatas pada yang bisa dibaca user pemilik daemon)' if RL else ''),'%s: %s' % (name, sn),
                'Mount hanya folder data yang diperlukan, read-only (:ro). Hindari /, /etc, /root, /var/run.')
    for key, val, cid in (('PidMode','pid','CNT-NS-PID'),('NetworkMode','net','CNT-NS-NET'),('IpcMode','ipc','CNT-NS-IPC')):
        if (hc.get(key) or '') == 'host':
            sev = 'MEDIUM' if key == 'NetworkMode' else 'HIGH'
            out(sev, cid,'Container berbagi namespace %s dengan host (--%s=host)' % (val, val), name,
                'Jalankan tanpa --%s=host kecuali perlu; namespace host melemahkan isolasi.' % val)
    caps = hc.get('CapAdd') or []
    bad = [x for x in caps if x and x.upper().replace('CAP_','') in DANGER_CAP]
    if bad:
        out('HIGH','CNT-CAP-01','Container diberi Linux capability berbahaya','%s: %s' % (name, ','.join(bad)),
            'Hapus capability ini kecuali dibutuhkan; SYS_ADMIN/SYS_PTRACE/SYS_MODULE/DAC_READ_SEARCH bisa dipakai escape ke host.')
    so = hc.get('SecurityOpt') or []; soj = ' '.join(so).lower()
    if 'seccomp=unconfined' in soj or 'seccomp:unconfined' in soj:
        out('MEDIUM','CNT-SECCOMP-01','Container berjalan dengan seccomp=unconfined', name, 'Hapus seccomp=unconfined; biarkan profil seccomp default aktif.')
    if 'apparmor=unconfined' in soj or 'apparmor:unconfined' in soj:
        out('MEDIUM','CNT-APPARMOR-01','Container berjalan dengan apparmor=unconfined', name, 'Hapus apparmor=unconfined.')
    if not any('no-new-privileges' in x.lower() for x in so):
        out('LOW','CNT-NNP-01','Container tanpa no-new-privileges', name, 'Tambah --security-opt no-new-privileges.')
    if user in ('','0','root','0:0'):
        out('LOW' if RL else 'MEDIUM','CNT-USER-01','Proses dalam container berjalan sebagai root' + (' (rootless: root container = user pemilik daemon di host)' if RL else ''),'%s (User=%s)' % (name, user or 'tidak diset'),
            'Set USER non-root di Dockerfile atau --user.')
    envn = []
    for e in (cfg.get('Env') or []):
        k = e.split('=', 1)[0]
        v = e.split('=', 1)[1] if '=' in e else ''
        if re.search(r'(PASS|PWD|SECRET|TOKEN|KEY|CRED|AUTH)', k, re.I) and v and not v.startswith('/') and not re.search(r'_FILE$', k, re.I):
            envn.append(k)
    if envn:
        out('MEDIUM','CNT-ENV-01','Secret disimpan di environment variable container (terbaca lewat docker inspect)','%s: %s (nilai tidak dicatat)' % (name, ', '.join(sorted(set(envn)))),
            'Pindahkan ke file secret yang di-mount read-only (mis. Docker secrets atau volume ber-izin 0400) dan baca lewat variabel *_FILE. Ganti nilai secret bila image/inspect pernah dibagikan.')
    ports = ((c.get('NetworkSettings') or {}).get('Ports') or {})
    for cport, b2 in ports.items():
        for b in (b2 or []):
            hip = b.get('HostIp', '')
            if hip in ('0.0.0.0','::',''):
                out('LOW','CNT-PORT-01','Port container dipublikasikan ke semua interface host','%s: %s -> %s:%s' % (name, cport, hip or '0.0.0.0', b.get('HostPort','?')),
                    'Ikat publikasi port ke 127.0.0.1 atau IP tertentu, atau batasi dengan host firewall.')
    tag = image.split('/')[-1]
    if image.endswith(':latest') or ':' not in tag:
        out('LOW','CNT-IMG-01','Image memakai tag :latest / tanpa tag versi','%s: %s' % (name, image),
            'Pin image ke tag versi + digest (image@sha256:...).')
    md = ((c.get('GraphDriver') or {}).get('Data') or {}).get('MergedDir')
    if md: merged_out.write('%s\t%s\n' % (name, md))
merged_out.close(); det.close()
PYEOF
      finding "$sev" "$id" Container "$title" "$ev" "$rec"
    done
    # Inventaris arsip Java di dalam container (lewat rootfs container, tanpa exec)
    while IFS=$'\t' read -r jarn name _i _p; do
      dir=$(ctr_root "$jarn")
      [ -n "$dir" ] && [ -d "$dir" ] || { finding INFO CNT-FS-01 Container "Filesystem container '$name' tidak terbaca dari host (inventaris library dilewati)" "${dir:-?}" \
        "Jalankan script sebagai root, atau pindai image langsung dengan Trivy."; continue; }
      n=0
      while read -r md; do
        [ -z "$md" ] && continue
        case "$md" in */lib/jvm/*|*/jre/lib/*|*/jdk*/lib/*|*/jmods/*) continue ;; esac
        reg_archive "container:$name" "$md"; run_path "$md"; n=$((n+1))
        [ "$n" -ge 3000 ] && break
      done < <(find "$dir" -xdev -type f \( -iname '*.jar' -o -iname '*.war' -o -iname '*.ear' \) 2>/dev/null)
      echo "container $name: $n arsip Java ditemukan" >> "$RAW/container_libs_note.txt"
    done < "$OUT/.cmap"
  fi
  rm -f "$insp" "$merged" 2>/dev/null
}


check_extra() {
  log "Cek tambahan: agent monitoring, kebijakan login, log, izin file aplikasi"
  local f v pid d

  # NRPE (Nagios)
  for f in /usr/local/nagios/etc/nrpe.cfg /etc/nagios/nrpe.cfg; do
    [ -f "$f" ] || continue
    { echo "##### $f"; grep -vE '^\s*(#|$)' "$f" | redact; } >> "$RAW/nrpe_cfg.txt"
    v=$(sed -n 's/^\s*dont_blame_nrpe\s*=\s*//p' "$f" | tail -n1)
    [ "$v" = 1 ] && finding HIGH MON-NRPE-01 Monitoring "NRPE menerima argumen command dari jaringan (dont_blame_nrpe=1)" "$f" \
      "Set dont_blame_nrpe=0; argumen dari client bisa dipakai untuk command injection."
    v=$(sed -n 's/^\s*allowed_hosts\s*=\s*//p' "$f" | tail -n1)
    [ -z "$v" ] && finding MEDIUM MON-NRPE-02 Monitoring "NRPE tanpa allowed_hosts (menerima dari host mana saja)" "$f" \
      "Isi allowed_hosts dengan IP server Nagios saja, dan batasi port 5666 di firewall."
    echo "allowed_hosts=$v" >> "$RAW/nrpe_cfg.txt"
  done

  # SNMP
  f=/etc/snmp/snmpd.conf
  if [ -f "$f" ]; then
    grep -vE '^\s*(#|$)' "$f" | awk '
      $1 ~ /^(ro|rw)community6?$/ { c=$2; $2=(c=="public"||c=="private")?c:"****" }
      $1 ~ /^com2sec6?$/          { c=$4; $4=(c=="public"||c=="private")?c:"****" }
      { print }' > "$RAW/snmpd_conf.txt"
    grep -qE '^\s*rwcommunity6?\s' "$f" && finding HIGH MON-SNMP-01 Monitoring "SNMP read-write community aktif" "rwcommunity di $f" \
      "Hapus rwcommunity; gunakan SNMPv3 (authPriv) read-only."
    if grep -qE '^\s*(rocommunity6?\s+(public|private)(\s|$)|com2sec6?\s+\S+\s+\S+\s+(public|private)\s*$)' "$f"; then
      finding MEDIUM MON-SNMP-02 Monitoring "SNMP memakai community default (public/private)" "$f" \
        "Ganti ke SNMPv3 (authPriv), atau minimal community acak dan batasi sumber IP + firewall UDP 161."
    fi
  fi

  # NTP
  f=/etc/ntp.conf
  if [ -f "$f" ] && pgrep -x ntpd >/dev/null 2>&1; then
    grep -E '^\s*(restrict|server|pool)' "$f" > "$RAW/ntp_conf.txt"
    grep -qE '^\s*restrict\s+(-4\s+)?default.*noquery' "$f" || finding LOW HRD-NTP-02 Hardening "ntpd tanpa 'restrict default ... noquery'" "$f" \
      "Tambahkan: restrict default nomodify notrap nopeer noquery (cegah penyalahgunaan amplifikasi NTP)."
  fi

  # Kebijakan password & penguncian akun
  { for f in /etc/security/pwquality.conf /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/login.defs; do
      [ -f "$f" ] && { echo "##### $f"; grep -vE '^\s*(#|$)' "$f"; echo; }
    done; } > "$RAW/auth_policy.txt" 2>/dev/null
  if ! grep -qE 'pam_(faillock|tally2)' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null; then
    finding LOW ACC-LOCKOUT-01 Akun "Tidak ada penguncian akun setelah gagal login berulang" "pam_faillock/pam_tally2 tidak dipakai" \
      "Aktifkan pam_faillock (deny=5 unlock_time=900) di system-auth & password-auth."
  fi
  if [ "$IS_ROOT" -eq 1 ]; then
    for v in $(awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1}' /etc/passwd); do
      echo "== $v"; chage -l "$v" 2>/dev/null
    done > "$RAW/password_age.txt"
  fi
  { echo "### hosts.allow"; grep -vE '^\s*(#|$)' /etc/hosts.allow 2>/dev/null
    echo "### hosts.deny";  grep -vE '^\s*(#|$)' /etc/hosts.deny 2>/dev/null
    echo "### /etc/hosts";  grep -vE '^\s*(#|$)' /etc/hosts 2>/dev/null; } > "$RAW/hosts_access.txt"

  # Audit & log terpusat
  have auditctl && auditctl -l > "$RAW/audit_rules.txt" 2>&1
  local siem=""
  for v in wazuh-agentd ossec-agentd filebeat fluent-bit fluentd splunkd td-agent elastic-agent nxlog vector; do
    pgrep -x "$v" >/dev/null 2>&1 && siem="$siem $v"
  done
  [ -n "$siem" ] && echo "Agen log/SIEM berjalan:$siem" >> "$RAW/audit_rules.txt"
  if [ -z "$siem" ] && ! grep -hqsE '^\s*[^#].*@@?[A-Za-z0-9.\[]|omfwd' /etc/rsyslog.conf /etc/rsyslog.d/*.conf; then
    finding LOW HRD-LOG-02 Hardening "Log tidak dikirim ke server log terpusat/SIEM" "rsyslog tanpa forwarding" \
      "Kirim log (auth, secure, aplikasi) ke server log/SIEM agar jejak tidak hilang bila server dikompromikan."
  fi

  check_containers

  # Nama environment variable proses Java (NILAI tidak diambil) + izin file aplikasi
  for pid in $(java_pids); do
    { echo "== PID $pid $(pid_cwd "$pid")"; tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | grep -aoE '^[A-Za-z_][A-Za-z0-9_]*=' | tr -d '=' | sort -u | tr '\n' ' '; echo; } >> "$RAW/java_env_names.txt"
    case "$(app_type "$pid")" in
      wildfly) d="$(arg_val "$pid" -Djboss.server.base.dir)"; [ -z "$d" ] && d="$(arg_val "$pid" -Djboss.home.dir)/standalone"; d="$d/configuration" ;;
      tomcat)  d="$(arg_val "$pid" -Dcatalina.base)/conf" ;;
      *)       d=$(app_location "$pid" java); d=$(dirname "${d%% *}") ;;
    esac
    case "$d" in /|/etc|/etc/*|/usr|/usr/*|/bin|/sbin|/lib*|/var|/root|/home|/proc*|/sys*) d="" ;; esac
    [ -n "$d" ] && APP_PERM_DIRS="$APP_PERM_DIRS $d"
  done
  for d in $(echo $APP_PERM_DIRS $APP_DIRS | tr ' ' '\n' | sort -u); do
    [ -d "$d" ] || continue
    find "$d" -maxdepth 2 -printf '%M %u:%g %8s %p\n' 2>/dev/null | head -n 300 >> "$RAW/app_dir_perms.txt"
    find "$d" -maxdepth 3 -type f \( -name '*.properties' -o -name '*.yml' -o -name '*.yaml' -o -name '*.env' -o -name '*.xml' -o -name '*.conf' \) \
      -perm -0004 2>/dev/null | while read -r f; do
        grep -qiE '^\s*[A-Za-z0-9_.-]*(password|pwd|secret|token|credential)[A-Za-z0-9_.-]*\s*[=:]\s*[^$[:space:]]' "$f" 2>/dev/null && echo "$f"
      done >> "$OUT/.permcfg"
  done
  if [ -s "$OUT/.permcfg" ]; then
    finding MEDIUM APP-PERM-01 Aplikasi "File konfigurasi berisi secret bisa dibaca semua user" "$(sort -u "$OUT/.permcfg" | head -n 10 | tr '\n' ' ')" \
      "chmod 640/600 dan owner user aplikasi; pindahkan secret ke environment/vault."
  fi
  rm -f "$OUT/.permcfg"

  # Cara aplikasi dijalankan (screen/nohup vs systemd)
  if [ -n "$(java_pids)" ] && ps -eo args | grep -qE '^(SCREEN|screen|tmux)'; then
    finding LOW OPS-RUN-01 Operasional "Aplikasi dijalankan manual dalam sesi screen/tmux (bukan systemd)" \
      "$(ps -eo args | grep -E '^(SCREEN|screen|tmux)' | head -n 5 | tr '\n' ';')" \
      "Buat unit systemd (User=, EnvironmentFile= ber-permission 600, Restart=on-failure) agar aplikasi otomatis jalan setelah reboot dan secret tidak tinggal di shell interaktif."
  fi
}

#------------------------------------------------------------------------------
# 13. ANONIMISASI & PAKET AKHIR (satu file)
#------------------------------------------------------------------------------
anonymize_output() {
  [ "$ANON" -eq 1 ] || return 0
  if [ -z "$PY" ]; then log "PERINGATAN: python tidak ada, anonimisasi DILEWATI"; ANON=0; return 0; fi
  if [ -z "$ANON_KEY" ]; then
    ANON_KEY=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
    log "PERINGATAN: --anon-key tidak diberikan -> samaran tidak konsisten antar server"
  fi
  local terms
  terms="$(hostname -s 2>/dev/null),$(hostname -f 2>/dev/null),$(hostname 2>/dev/null),$ANON_TERMS"
  terms="$terms,$(awk '!/^[[:space:]]*#/ && NF>1 {for(i=2;i<=NF;i++) print $i}' /etc/hosts 2>/dev/null | grep -vE '^(localhost|localhost[46]?\..*|ip6-.*)$' | grep -E '^.{5,}$' | tr '\n' ',')"
  MAPFILE="$OUTBASE/assess-ANONMAP-$TS.csv"
  ANON_HOST=$("$PY" - "$OUT" "$ANON_KEY" "$MAPFILE" "$terms" "$HOST" <<'PYEOF'
from __future__ import print_function, unicode_literals
import sys, os, re, io, hmac, hashlib
root, key, mapfile, terms, host = sys.argv[1:6]
key = key.encode('utf-8')
def h(s): return hmac.new(key, s.lower().encode('utf-8'), hashlib.sha256).hexdigest()
terms = sorted(set(t.strip() for t in terms.split(',') if len(t.strip()) >= 3) | set([host]), key=len, reverse=True)
mp = {}
for t in terms: mp[t.lower()] = 'host-' + h(t)[:6]
word = [(re.compile(r'(?<![A-Za-z0-9])' + re.escape(t) + r'(?![A-Za-z0-9])', re.I), mp[t.lower()]) for t in terms]
IP = re.compile(r'(?<![\w.-])((?:\d{1,3}\.){3}\d{1,3})(?![\w.-])')
KEEP = re.compile(r'^(127\.|0\.0\.0\.0$|255\.|224\.)')
ips = {}
def ip(m):
    a = m.group(1)
    if any(int(x) > 255 for x in a.split('.')) or KEEP.match(a): return a
    if a not in ips:
        d = bytearray(hmac.new(key, a.encode('utf-8'), hashlib.sha256).digest())
        ips[a] = '10.%d.%d.%d' % (d[0], d[1], d[2] or 1)
    return ips[a]
NOIP = re.compile(r'(libraries\.csv|libraries_other\.csv|libraries_unique\.csv|os_packages\.csv|\.cdx\.json|_libs\.txt|_entries\.txt|packages\.txt|rpm_last\.txt|archives_list\.txt|java_versions\.txt)$')
for dp, dn, fn in os.walk(root):
    for f in fn:
        p = os.path.join(dp, f)
        try: t = io.open(p, encoding='utf-8', errors='surrogateescape' if sys.version_info[0] > 2 else 'replace').read()
        except Exception: continue
        for rx, v in word: t = rx.sub(v, t)
        if not NOIP.search(f): t = IP.sub(ip, t)
        io.open(p, 'w', encoding='utf-8', errors='surrogateescape' if sys.version_info[0] > 2 else 'replace').write(t)
old = os.umask(0o077)
with io.open(mapfile, 'w', encoding='utf-8') as f:
    f.write('asli,samaran\n')
    for k, v in sorted(mp.items()): f.write('%s,%s\n' % (k, v))
    for k, v in sorted(ips.items()): f.write('%s,%s\n' % (k, v))
os.umask(old)
print(mp.get(host.lower(), 'host-' + h(host)[:6]))
PYEOF
)
  [ -n "$ANON_HOST" ] || ANON_HOST="anon"
}

package_output() {
  local name="assess-$HOST-$TS" bdir final txt f sum
  [ "$ANON" -eq 1 ] && name="assess-${ANON_HOST}-$TS-anon"
  bdir="$OUTBASE/$name.bundle"; final="$OUTBASE/$name.tar.gz"
  mkdir -p "$bdir/$name" || { echo "Gagal membuat $bdir" >&2; return 1; }
  txt="$bdir/$name/$name.txt"
  {
    echo "################################################################################"
    echo "# ASSESS REPORT  (assess.sh v$SCRIPT_VERSION)  -  kirim file ini ke analis"
    echo "# Bagian dipisah dengan baris:  ===== FILE: <nama> ====="
    echo "# Urutan: summary, aplikasi berjalan, aset tidak berjalan, findings,"
    echo "#         inventaris library, paket OS, data mentah"
    echo "################################################################################"
    for f in summary.txt roles.txt raw/running_apps.txt raw/running_apps_other.txt aset_tidak_berjalan.txt findings.csv \
             libraries_unique.csv libraries_other.csv libraries.csv os_packages.csv; do
      [ -f "$OUT/$f" ] && [ -s "$OUT/$f" ] && { echo; echo "===== FILE: $f ====="; cat "$OUT/$f"; }
    done
    for f in $(cd "$OUT/raw" 2>/dev/null && ls | grep -vE '^(running_apps|running_apps_other)\.txt$'); do
      [ -f "$OUT/raw/$f" ] && [ -s "$OUT/raw/$f" ] && { echo; echo "===== FILE: raw/$f ====="; cat "$OUT/raw/$f"; }
    done
    echo; echo "===== END ====="
  } > "$txt"
  [ -d "$OUT/sbom" ]   && cp -r "$OUT/sbom"   "$bdir/$name/sbom"
  [ -d "$OUT/config" ] && cp -r "$OUT/config" "$bdir/$name/config"
  {
    echo "Hasil assess.sh v$SCRIPT_VERSION"
    echo "  $name.txt        laporan lengkap -> kirim ke analis"
    echo "  sbom/*.cdx.json  daftar komponen -> trivy sbom --skip-db-update --offline-scan <file>"
    echo "  config/          Dockerfile/Compose (secret disamarkan) -> trivy config --skip-check-update config/"
    echo "  SHA256SUMS       periksa keutuhan isi: sha256sum -c SHA256SUMS"
  } > "$bdir/$name/BACA-SAYA.txt"
  if [ -d "$bdir/$name" ]; then
    ( cd "$bdir/$name" && find . -type f ! -name SHA256SUMS | sort | xargs sha256sum > SHA256SUMS 2>/dev/null )
  fi
  tar czf "$final" -C "$bdir" "$name" 2>/dev/null
  cat "$OUT/summary.txt" >&2
  [ -n "$OUT" ] && [ -d "$OUT" ] && rm -rf -- "$OUT"
  [ -n "$bdir" ] && [ -d "$bdir" ] && rm -rf -- "$bdir"
  if [ -n "${SUDO_USER:-}" ]; then chown "$SUDO_USER" "$final" 2>/dev/null; fi
  sum=$(sha256sum "$final" 2>/dev/null | awk '{print $1}')
  echo >&2
  log "Selesai. SATU arsip hasil (salin file ini): $final  ($(du -h "$final" | cut -f1))"
  log "SHA256: $sum"
  log "Cocokkan di mesin tujuan dengan: sha256sum $(basename "$final")"
  [ "$ANON" -eq 1 ] && log "Peta penyamaran (SIMPAN, JANGAN dikirim): $MAPFILE"
  echo "RESULT: $final"
  echo "SHA256: $sum"
}

#------------------------------------------------------------------------------
# DETEKSI PERAN SERVER & EKSEKUSI
#------------------------------------------------------------------------------
detect_and_check_roles() {
  { pgrep -x httpd || pgrep -x apache2; } >/dev/null 2>&1 && { ROLES="$ROLES apache"; check_apache; }
  pgrep -x nginx  >/dev/null 2>&1 && { ROLES="$ROLES nginx";  check_nginx; }
  if pgrep -x mysqld >/dev/null 2>&1 || pgrep -x mariadbd >/dev/null 2>&1; then ROLES="$ROLES mariadb"; check_mariadb; fi
  if pgrep -x postmaster >/dev/null 2>&1 || pgrep -x postgres >/dev/null 2>&1; then ROLES="$ROLES postgresql"; check_postgres; fi
  local pid cmd jar
  for pid in $(java_pids); do
    cmd=$(pid_cmd "$pid")
    if [ -n "$(pid_container "$pid")" ]; then check_container_java "$pid"; continue; fi
    case "$cmd" in
      *jboss-modules.jar*|*jboss.home.dir*) check_wildfly "$pid" ;;
      *org.apache.catalina.startup.Bootstrap*|*-Dcatalina.base=*) check_tomcat "$pid" ;;
      *org.springframework.boot*) check_springboot "$pid" ;;
      *)
        jar=$(arg_next "$pid" "-jar")
        [ -n "$jar" ] && [ "${jar#/}" = "$jar" ] && jar="$(pid_cwd "$pid")/$jar"
        if [ -n "$jar" ] && [ -f "$jar" ] && zip_cat "$jar" META-INF/MANIFEST.MF | grep -qE 'Spring-Boot-Version|org\.springframework\.boot\.loader'; then
          check_springboot "$pid"
        else
          check_other_java "$pid"
        fi ;;
    esac
  done
  analyze_web_and_logs
}

write_summary() {
  local s n
  {
    echo "Host            : $HOST"
    echo "Waktu           : $(date '+%Y-%m-%d %H:%M:%S %z')"
    echo "OS              : $(cat /etc/redhat-release 2>/dev/null || sed -n 's/^PRETTY_NAME="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' /etc/os-release 2>/dev/null | head -n1)"
    echo "Kernel          : $(uname -r)"
    echo "IP              : $(hostname -I 2>/dev/null)"
    echo "Peran terdeteksi: ${ROLES:- (tidak ada)}"
    [ -n "${WF_HOMES// /}${APP_DIRS// /}${JAVA_HOMES// /}" ] && echo "Path manual     : wildfly=[${WF_HOMES# }] app=[${APP_DIRS# }] java=[${JAVA_HOMES# }]"
    echo "Aplikasi Java   : $(grep -c '^\[[0-9]*\] PID' "$RAW/running_apps.txt" 2>/dev/null || echo 0) berjalan (raw/running_apps.txt)"
    echo "Aset tdk jalan  : $(grep -c '^\[' "$OUT/aset_tidak_berjalan.txt" 2>/dev/null || echo 0) unit (aset_tidak_berjalan.txt)"
    echo "JDK terinstal   : $(wc -l < "$RAW/jdk_installs.txt" 2>/dev/null || echo 0) (dipakai: $(grep -c '|YA$' "$RAW/jdk_installs.txt" 2>/dev/null | head -n1))"
    [ -f "$RAW/container_detail.txt" ] && echo "Container       : $(grep -c '^== ' "$RAW/container_detail.txt" 2>/dev/null || echo 0) aktif (raw/container_detail.txt)"
    n=$(awk -F'","' 'NR>1 && $3 ~ /^WF-DEPST-0[01]/' "$FINDINGS" | wc -l); [ "$n" -gt 0 ] && awk -F'","' 'NR>1 && $3 ~ /^WF-DEPST-0[01]/{print "Deployment      : " $5 " -> " $6}' "$FINDINGS"
    [ -s "$OUT/.dkrps" ] || [ -n "$CRT_SRC" ] && echo "Akses container : mode=${DKR_MODE:-?} dibaca=${CRT_SRC:-TIDAK BISA} sebagai=${CRT_AS:--} (raw/container_access.txt)"
    echo "Library Java    : $(( $(wc -l < "$OUT/libraries.csv" 2>/dev/null || echo 1) - 1 )) baris inventaris (libraries.csv)"
    [ -f "$RAW/running_apps_other.txt" ] && echo "Aplikasi lain   : $(grep -c '^\[[0-9]*\] PID' "$RAW/running_apps_other.txt" 2>/dev/null | head -n1) non-Java berjalan (raw/running_apps_other.txt)"
    [ -s "$OUT/libraries_other.csv" ] && echo "Library lain    : $(( $(wc -l < "$OUT/libraries_other.csv") - 1 )) baris (npm/pypi/composer)"
    [ -s "$OUT/os_packages.csv" ] && echo "Paket OS        : $(( $(wc -l < "$OUT/os_packages.csv") - 1 )) (host + container)"
    echo "SBOM            : $(ls "$OUT/sbom"/*.cdx.json 2>/dev/null | wc -l) file (folder sbom/)"
    [ -d "$OUT/config" ] && echo "File konfigurasi: $(wc -l < "$OUT/config/INDEX.txt" 2>/dev/null || echo 0) Dockerfile/Compose (folder config/)"
    echo "Indikasi kompromi: $(awk -F'","' 'NR>1 && $3 ~ /^IOC-/' "$FINDINGS" | wc -l) temuan (raw/ioc_detail.txt)"
    echo "assess.sh       : v$SCRIPT_VERSION (root=$IS_ROOT, safe=$SAFE, skip_fs=$SKIP_FS, no_net=$NO_NET, anonymize=$ANON)"
    echo
    echo "Jumlah temuan per severity:"
    for s in CRITICAL HIGH MEDIUM LOW INFO; do
      printf '  %-9s %s\n' "$s" "$(awk -F'","' -v s="$s" 'NR>1 && $4==s' "$FINDINGS" | wc -l)"
    done
    echo
    echo "Temuan (urut severity):"
    for s in CRITICAL HIGH MEDIUM LOW; do
      awk -F'","' -v s="$s" 'NR>1 && $4==s {print "  [" s "] " $5 "  ->  " $6}' "$FINDINGS"
    done
  } > "$OUT/summary.txt"
  echo "$ROLES" | sed 's/^ *//' > "$OUT/roles.txt"
}

#==============================================================================
# v4: CONTAINER MAP, RUNTIME NON-JAVA, PAKET OS, SBOM, KONFIGURASI, IOC
#==============================================================================
# Runtime container yang tersedia (docker/podman), kosong bila tidak ada
#------------------------------------------------------------------------------
# AKSES CONTAINER RUNTIME
#   Urutan: (1) root ke socket default (Docker biasa)
#           (2) sebagai user pemilik daemon/socket (rootless, atau root diblokir)
#           (3) root langsung ke socket rootless /run/user/<uid>/docker.sock
#           (4) tanpa CLI: baca konfigurasi container dari disk
#   Semua perintah yang dijalankan hanya membaca (ps, inspect, images, history,
#   exec untuk daftar paket).
#------------------------------------------------------------------------------
CRT_BIN=""; CRT_SRC=""; CRT_AS=""; CRT_ROOT_ERR=""; DKR_MODE=""
CRT_CMD=(); AS_CMD=()

# Proses daemon: uid pid perintah
dkr_scan_daemons() {
  ps -eo uid=,pid=,args= 2>/dev/null | awk '{c=$3; sub(/.*\//,"",c)}
    c=="dockerd" || c=="rootlesskit" || c ~ /^dockerd-rootless/ || (c=="podman" && $0 ~ /system service/)' > "$OUT/.dkrps"
}

# User non-root yang mungkin memiliki/mengakses daemon container
dkr_candidate_users() {
  local i s g gid
  {
    awk '$1!=0{print $1}' "$OUT/.dkrps" 2>/dev/null | while read -r i; do getent passwd "$i" | cut -d: -f1; done
    for s in /run/user/*/docker.sock /run/user/*/podman/podman.sock; do [ -S "$s" ] && stat -c %U "$s"; done
    for s in /var/run/docker.sock /run/docker.sock; do
      [ -S "$s" ] || continue
      g=$(stat -c %G "$s"); gid=$(stat -c %g "$s")
      getent group "$g" | cut -d: -f4 | tr ',' '\n'
      awk -F: -v g="$gid" '$4==g{print $1}' /etc/passwd
    done
  } 2>/dev/null | grep -vxE 'root|UNKNOWN|' | awk '!s[$0]++' | head -n 10
}

# Bangun AS_CMD untuk menjalankan perintah sebagai user $1 (setara: su <user>)
as_user_cmd() {
  local u="$1" uid h
  uid=$(id -u "$u" 2>/dev/null) || return 1
  h=$(getent passwd "$u" | cut -d: -f6)
  if have runuser; then AS_CMD=(runuser -u "$u" --)
  elif have sudo; then AS_CMD=(sudo -n -H -u "$u")
  else return 1; fi
  AS_CMD+=(env "HOME=${h:-/}" "XDG_RUNTIME_DIR=/run/user/$uid")
  if [ -n "$DOCKER_HOST_OPT" ]; then AS_CMD+=("DOCKER_HOST=$DOCKER_HOST_OPT")
  elif [ -S "/run/user/$uid/docker.sock" ]; then AS_CMD+=("DOCKER_HOST=unix:///run/user/$uid/docker.sock"); fi
  return 0
}

# Folder data Docker (rootful dan rootless) untuk pembacaan tanpa CLI
dkr_data_roots() {
  local r u h
  {
    r=$(sed -n 's/.*"\(data-root\|graph\)"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\2/p' /etc/docker/daemon.json 2>/dev/null | head -n1)
    echo "${r:-/var/lib/docker}"
    grep -oE -- '--(data-root|graph)[= ][^ ]+' "$OUT/.dkrps" 2>/dev/null | sed -E 's/^--(data-root|graph)[= ]//'
    for u in ${DOCKER_USER:-$(dkr_candidate_users)}; do
      h=$(getent passwd "$u" | cut -d: -f6); [ -n "$h" ] || continue
      echo "$h/.local/share/docker"
      r=$(sed -n 's/.*"\(data-root\|graph\)"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\2/p' "$h/.config/docker/daemon.json" 2>/dev/null | head -n1)
      [ -n "$r" ] && echo "$r"
    done
  } | awk '!s[$0]++' | while read -r r; do [ -d "$r/containers" ] && echo "$r"; done
}

# Peta container dari file config.v2.json + hostconfig.json (tanpa CLI)
dkr_fs_map() {
  local roots
  roots=$(dkr_data_roots)
  [ -n "$roots" ] || return 1
  # shellcheck disable=SC2086
  "$PY" - "$OUT" $roots <<'PYEOF'
from __future__ import print_function
import sys, os, io, json, glob, re
out = sys.argv[1]; roots = sys.argv[2:]
def wb(f, s):
    if not isinstance(s, bytes): s = s.encode('utf-8')
    f.write(s)
def rj(p):
    try:
        return json.load(io.open(p, encoding='utf-8', errors='replace'))
    except Exception:
        return None
cg = {}
for p in os.listdir('/proc'):
    if not p.isdigit(): continue
    try: t = io.open('/proc/%s/cgroup' % p, encoding='utf-8', errors='replace').read()
    except Exception: continue
    for m in re.findall(r'[0-9a-f]{64}', t):
        if m not in cg or int(p) < cg[m]: cg[m] = int(p)
cmap = open(os.path.join(out, '.cmap'), 'ab'); lab = open(os.path.join(out, '.clabels'), 'ab')
stp = open(os.path.join(out, '.cstopped'), 'ab'); src = open(os.path.join(out, '.cfs_source'), 'ab')
insp = []; n = 0
for r in roots:
    for d in sorted(glob.glob(os.path.join(r, 'containers', '*'))):
        c = rj(os.path.join(d, 'config.v2.json'))
        if not isinstance(c, dict): continue
        n += 1
        hc = rj(os.path.join(d, 'hostconfig.json')) or {}
        cid = c.get('ID') or os.path.basename(d); name = (c.get('Name') or cid[:12]).lstrip('/')
        cfg = c.get('Config') or {}; st = c.get('State') or {}; image = cfg.get('Image') or c.get('Image') or '?'
        labels = cfg.get('Labels') or {}
        if not st.get('Running'):
            wb(stp, u'%s (%s, berhenti)\n' % (name, image)); continue
        pid = st.get('Pid') or 0
        if cid in cg: pid = cg[cid]
        mounts = [{'Source': m.get('Source', ''), 'Destination': m.get('Destination', '')}
                  for m in (c.get('MountPoints') or {}).values() if isinstance(m, dict)]
        ns = c.get('NetworkSettings') or {}
        insp.append({'Id': cid, 'Name': '/' + name, 'Config': cfg, 'State': st, 'HostConfig': hc,
                     'Mounts': mounts, 'NetworkSettings': {'Ports': ns.get('Ports') or hc.get('PortBindings') or {}}})
        wb(cmap, u'%s\t%s\t%s\t%s\n' % (cid[:12], name, image, pid))
        wb(lab, u'%s\t%s\t%s\n' % (cid[:12], labels.get('com.docker.compose.project.config_files', ''),
                                   labels.get('com.docker.compose.project.working_dir', '')))
    wb(src, u'%s\n' % r)
f = open(os.path.join(out, '.cinsp_fs.json'), 'wb'); wb(f, json.dumps(insp)); f.close()
for x in (cmap, lab, stp, src): x.close()
sys.exit(0 if n else 1)
PYEOF
}

detect_crt() {
  local b u s err bin so
  CRT_BIN=""; CRT_SRC=""; CRT_AS=""; CRT_CMD=()
  dkr_scan_daemons
  # (1) root, socket default
  if [ -z "$DOCKER_USER" ]; then
    for b in docker podman; do
      bin=$(command -v $b 2>/dev/null) || continue
      if [ -n "$DOCKER_HOST_OPT" ] && [ "$b" = docker ]; then CRT_CMD=(env "DOCKER_HOST=$DOCKER_HOST_OPT" "$bin"); else CRT_CMD=("$bin"); fi
      if err=$(timeout 20 "${CRT_CMD[@]}" ps -q 2>&1 >/dev/null); then
        # podman root tanpa container: container bisa milik user lain, lanjut mencari
        if [ "$b" = podman ] && [ -z "$(timeout 20 "${CRT_CMD[@]}" ps -aq 2>/dev/null)" ]; then CRT_CMD=(); continue; fi
        CRT_BIN=$b; CRT_AS=root; CRT_SRC=cli; break
      fi
      CRT_CMD=()
      [ "$b" = docker ] && CRT_ROOT_ERR=$(printf '%s' "$err" | head -n1 | cut -c1-220)
    done
  fi
  # (2) sebagai user pemilik daemon / anggota grup socket
  if [ -z "$CRT_SRC" ]; then
    for u in ${DOCKER_USER:-$(dkr_candidate_users)}; do
      as_user_cmd "$u" || continue
      for b in docker podman; do
        bin=$(command -v $b 2>/dev/null) || continue
        if timeout 20 "${AS_CMD[@]}" "$bin" ps -q >/dev/null 2>&1; then
          if [ "$b" = podman ] && [ -z "$DOCKER_USER" ] && [ -z "$(timeout 20 "${AS_CMD[@]}" "$bin" ps -aq 2>/dev/null)" ]; then continue; fi
          CRT_CMD=("${AS_CMD[@]}" "$bin"); CRT_BIN=$b; CRT_AS=$u; CRT_SRC=cli; break 2
        fi
      done
    done
  fi
  # (3) root langsung ke socket rootless
  if [ -z "$CRT_SRC" ] && bin=$(command -v docker 2>/dev/null); then
    for s in /run/user/*/docker.sock; do
      [ -S "$s" ] || continue
      if timeout 20 env "DOCKER_HOST=unix://$s" "$bin" ps -q >/dev/null 2>&1; then
        CRT_CMD=(env "DOCKER_HOST=unix://$s" "$bin"); CRT_BIN=docker; CRT_AS="root ke $s"; CRT_SRC=cli; break
      fi
    done
  fi
  # (4) tanpa CLI
  if [ -z "$CRT_SRC" ] && [ -n "$PY" ] && dkr_fs_map; then CRT_SRC=fs; CRT_BIN=docker; CRT_AS="file di disk"; fi
  # mode daemon
  DKR_MODE=""
  awk '$1==0 {c=$3; sub(/.*\//,"",c); if (c=="dockerd") f=1} END{exit !f}' "$OUT/.dkrps" && DKR_MODE="rootful"
  if awk '$1!=0 {c=$3; sub(/.*\//,"",c); if (c=="dockerd") f=1} END{exit !f}' "$OUT/.dkrps"; then
    DKR_MODE="${DKR_MODE:+$DKR_MODE+}rootless"
  elif [ "$CRT_SRC" = cli ] && [ "$CRT_BIN" = docker ]; then
    so=$(timeout 20 "${CRT_CMD[@]}" info --format '{{json .SecurityOptions}}' 2>/dev/null)
    case "$so" in *rootless*) DKR_MODE="${DKR_MODE:+$DKR_MODE+}rootless" ;; esac
  fi
  return 0
}

# Peta container aktif: id12 <TAB> nama <TAB> image <TAB> pid-utama
build_container_map() {
  : > "$OUT/.cmap"; : > "$OUT/.clabels"; : > "$OUT/.cpids"; : > "$OUT/.cstopped"
  detect_crt
  if [ "$CRT_SRC" = cli ]; then
    local id
    for id in $(timeout 30 "${CRT_CMD[@]}" ps -q --no-trunc 2>/dev/null); do
      timeout 20 "${CRT_CMD[@]}" inspect -f '{{.Id}}	{{.Name}}	{{.Config.Image}}	{{.State.Pid}}	{{index .Config.Labels "com.docker.compose.project.config_files"}}	{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$id" 2>/dev/null \
        | awk -F'\t' -v CM="$OUT/.cmap" -v CL="$OUT/.clabels" '{sub(/^\//,"",$2); gsub(/<no value>/,""); i=substr($1,1,12)
            print i "\t" $2 "\t" $3 "\t" $4 >> CM; print i "\t" $5 "\t" $6 >> CL}'
    done
  fi
  [ -s "$OUT/.cmap" ] && ctr_fix_mainpid
  [ -s "$OUT/.cmap" ] && ctr_pid_tree
  [ -n "$CRT_SRC" ] && log "Container: $(wc -l < "$OUT/.cmap") aktif (dibaca: $CRT_SRC, sebagai: $CRT_AS, mode: ${DKR_MODE:-?})"
  return 0
}

# Pastikan PID utama di peta memang proses container tsb (cocokkan cgroup);
# bila tidak cocok, pakai PID terkecil yang cgroup-nya memuat id container.
ctr_fix_mainpid() {
  local id n i p q tmp="$OUT/.cmap.new"
  : > "$tmp"
  while IFS=$'\t' read -r id n i p; do
    if [ -n "$p" ] && [ "$p" != 0 ] && grep -q "$id" "/proc/$p/cgroup" 2>/dev/null; then :
    else
      q=$(grep -l "$id" /proc/[0-9]*/cgroup 2>/dev/null | sed 's#/proc/\([0-9]*\)/cgroup#\1#' | sort -n | head -n1)
      [ -n "$q" ] && p=$q
    fi
    printf '%s\t%s\t%s\t%s\n' "$id" "$n" "$i" "$p" >> "$tmp"
  done < "$OUT/.cmap"
  mv "$tmp" "$OUT/.cmap"
}

# PID utama container + semua turunannya -> id container
# (Docker rootless di cgroup v1 tidak menulis id container ke /proc/PID/cgroup)
ctr_pid_tree() {
  awk '{l=$0; sub(/.*\) /,"",l); split(l,a," "); f=FILENAME; gsub(/[^0-9]/,"",f); print f, a[2]}' /proc/[0-9]*/stat 2>/dev/null > "$OUT/.ppid"
  awk 'FNR==NR { if (NF>=4 && $4!=0) r[$4]=$1; next }
       { par[$1]=$2 }
       END { for (p in par) { q=p; n=0
               while (q!="" && q!="0" && !(q in r) && n<64) { q=par[q]; n++ }
               if (q in r) print p "\t" r[q] } }' FS='\t' "$OUT/.cmap" FS=' ' "$OUT/.ppid" > "$OUT/.cpids"
  rm -f "$OUT/.ppid"
}

# ID container (12 hex) sebuah proses; kosong = proses host
pid_container() {
  local id
  id=$(grep -oE '[0-9a-f]{64}' "/proc/$1/cgroup" 2>/dev/null | head -n1 | cut -c1-12)
  if [ -n "$id" ] && [ -s "$OUT/.cmap" ] && grep -q "^$id	" "$OUT/.cmap"; then echo "$id"; return 0; fi
  if [ -s "$OUT/.cpids" ]; then
    local c; c=$(awk -F'\t' -v p="$1" '$1==p{print $2; exit}' "$OUT/.cpids")
    [ -n "$c" ] && { echo "$c"; return 0; }
  fi
  # container yang tidak terdaftar di peta (CLI tidak bisa dipakai): daftarkan dari cgroup
  if [ -n "$id" ] && grep -qE '(docker|libpod|containerd|crio|kubepods)' "/proc/$1/cgroup" 2>/dev/null; then
    grep -q "^$id	" "$OUT/.cmap" 2>/dev/null || printf '%s\tctr-%s\t?\t%s\n' "$id" "$id" "$1" >> "$OUT/.cmap"
    echo "$id"
  fi
  return 0
}

#------------------------------------------------------------------------------
# FOLDER DATA CONTAINER (dikecualikan dari scan disk, diperiksa izinnya)
#------------------------------------------------------------------------------
PRUNE_EXPR=(-path /proc -o -path /sys -o -path /dev -o -path /run -o -path /var/lib/docker -o -path /var/lib/containers -o -path /var/lib/containerd)

ctr_storage_dirs() {
  local u h r
  {
    echo /var/lib/docker; echo /var/lib/containers; echo /var/lib/containerd
    sed -n 's/.*"\(data-root\|graph\)"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\2/p' /etc/docker/daemon.json 2>/dev/null
    grep -oE -- '--(data-root|graph)[= ][^ ]+' "$OUT/.dkrps" 2>/dev/null | sed -E 's/^--(data-root|graph)[= ]//'
    if [ "$CRT_SRC" = cli ] && [ "$CRT_BIN" = docker ]; then timeout 20 "${CRT_CMD[@]}" info --format '{{.DockerRootDir}}' 2>/dev/null; fi
    for u in $( { echo "$CRT_AS"; echo "$DOCKER_USER"; dkr_candidate_users; } | grep -vE ' |^$|^root$' | awk '!s[$0]++'); do
      h=$(getent passwd "$u" | cut -d: -f6); [ -n "$h" ] || continue
      echo "$h/.local/share/docker"; echo "$h/.local/share/containers"
      sed -n 's/.*"\(data-root\|graph\)"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\2/p' "$h/.config/docker/daemon.json" 2>/dev/null
    done
  } | sed 's#/*$##' | grep '^/' | awk '!s[$0]++' | while read -r r; do [ -d "$r" ] && rpath "$r"; done | awk '!s[$0]++'
}

build_prune_expr() {
  local d
  ctr_storage_dirs > "$RAW/container_storage_dirs.txt" 2>/dev/null
  while read -r d; do
    [ -n "$d" ] || continue
    case " ${PRUNE_EXPR[*]} " in *" $d "*) continue ;; esac
    PRUNE_EXPR+=(-o -path "$d")
  done < "$RAW/container_storage_dirs.txt"
  [ -s "$RAW/container_storage_dirs.txt" ] && log "Folder data container (tidak ikut scan disk): $(tr '\n' ' ' < "$RAW/container_storage_dirs.txt")"
  return 0
}

# File di folder host yang di-bind mount ke container dan sedang dipakai container
# -> tandai sebagai "berjalan" (bukan aset host yang menganggur)
ctr_bind_running() {
  [ -s "$OUT/.cbinds" ] || return 0
  sort -u "$OUT/.cbinds" -o "$OUT/.cbinds"
  { echo "Bind mount container (container <TAB> path host <TAB> path di container):"; cat "$OUT/.cbinds"; } > "$RAW/container_binds.txt"
  [ -s "$OUT/.running" ] || return 0
  local name src dst id pids
  while IFS=$'\t' read -r name src dst; do
    id=$(awk -F'\t' -v n="$name" '$2==n{print $1; exit}' "$OUT/.cmap" 2>/dev/null)
    [ -n "$id" ] || continue
    pids=$( { awk -F'\t' -v i="$id" '$1==i{print $4}' "$OUT/.cmap"
              awk -F'\t' -v i="$id" '$2==i{print $1}' "$OUT/.cpids" 2>/dev/null
              grep -l "$id" /proc/[0-9]*/cgroup 2>/dev/null | sed 's#/proc/\([0-9]*\)/cgroup#\1#'; } | sort -u | tr '\n' ' ')
    awk -v pids=" $pids " -v src="${src%/}" -v dst="${dst%/}" '
      match($0, /^\/proc\/[0-9]+\/root/) {
        p = substr($0, 7, RLENGTH - 11); rest = substr($0, RLENGTH + 1)
        if (index(pids, " " p " ") && (rest == dst || index(rest, dst "/") == 1)) print src substr(rest, length(dst) + 1)
      }' "$OUT/.running"
  done < "$OUT/.cbinds" > "$OUT/.running.bind"
  if [ -s "$OUT/.running.bind" ]; then
    cat "$OUT/.running.bind" >> "$OUT/.running"
    log "Bind mount: $(wc -l < "$OUT/.running.bind") path host ditandai dipakai container"
  fi
  rm -f "$OUT/.running.bind"
}

# Izin & opsi mount folder data container dan sumber bind mount
check_container_storage() {
  [ -s "$RAW/container_storage_dirs.txt" ] || [ -s "$OUT/.cbinds" ] || return 0
  log "Cek izin dan opsi mount folder data container / bind mount"
  local f="$RAW/container_storage.txt" d mode own grp opts tgt miss nomnt="" ww name
  : > "$f"
  while read -r d; do
    [ -d "$d" ] || continue
    mode=$(stat -c %a "$d"); own=$(stat -c %U "$d"); grp=$(stat -c %G "$d")
    echo "DATA  $d mode=$mode owner=$own:$grp mount=$(findmnt -n -T "$d" -o TARGET,OPTIONS 2>/dev/null | tr -s ' ')" >> "$f"
    case "$mode" in
      *[2367]) finding HIGH DKR-DATA-01 Container "Folder data container bisa ditulis semua user" "$d mode $mode ($own:$grp)" \
                 "chmod o-rwx $d. Folder ini berisi filesystem semua container dan image." ;;
      *[45])   finding MEDIUM DKR-DATA-02 Container "Folder data container bisa dibaca user lain" "$d mode $mode ($own:$grp)" \
                 "chmod o-rwx $d (Docker memakai 710). Isinya memuat filesystem container, termasuk konfigurasi dan secret aplikasi." ;;
    esac
  done < "$RAW/container_storage_dirs.txt"

  # sumber bind mount: siapa yang bisa mengubah isinya
  if [ -s "$OUT/.cbinds" ]; then
    cut -f2 "$OUT/.cbinds" | sort -u | while read -r d; do
      [ -e "$d" ] || continue
      [ -S "$d" ] && continue
      case "$d" in /proc|/proc/*|/sys|/sys/*|/dev|/dev/*|/run/*) continue ;; esac
      name=$(awk -F'\t' -v s="$d" '$2==s{print $1}' "$OUT/.cbinds" | sort -u | tr '\n' ',' | sed 's/,$//')
      mode=$(stat -c %a "$d"); own=$(stat -c %U "$d"); grp=$(stat -c %G "$d")
      echo "BIND  $d mode=$mode owner=$own:$grp container=$name mount=$(findmnt -n -T "$d" -o TARGET,OPTIONS 2>/dev/null | tr -s ' ')" >> "$f"
      ww=$(find "$d" -xdev -maxdepth 4 -perm -0002 ! -type l 2>/dev/null | head -n 5 | tr '\n' ' ')
      if [ -n "$ww" ]; then
        finding HIGH DKR-BIND-01 Container "Isi bind mount container bisa diubah semua user" "container $name: $ww" \
          "chmod -R o-w $d. Isi folder ini dipakai container; siapa pun yang bisa menulis bisa mengganti kode/konfigurasi aplikasi."
      fi
    done
  fi

  # opsi mount nosuid,nodev untuk folder data & bind mount
  { cat "$RAW/container_storage_dirs.txt"; cut -f2 "$OUT/.cbinds" 2>/dev/null; } | sort -u | while read -r d; do
    [ -d "$d" ] || continue
    case "$d" in /proc|/proc/*|/sys|/sys/*|/dev|/dev/*|/run/*) continue ;; esac
    opts=$(findmnt -n -T "$d" -o OPTIONS 2>/dev/null); tgt=$(findmnt -n -T "$d" -o TARGET 2>/dev/null)
    miss=""
    case ",$opts," in *,nosuid,*) ;; *) miss="$miss nosuid" ;; esac
    case ",$opts," in *,nodev,*) ;; *) miss="$miss nodev" ;; esac
    [ -n "$miss" ] && echo "$d (mount $tgt, tanpa$miss)"
  done > "$OUT/.nomnt"
  if [ -s "$OUT/.nomnt" ]; then
    finding LOW DKR-MNT-01 Container "Folder data/bind mount container tidak di-mount dengan nosuid,nodev" "$(head -n 6 "$OUT/.nomnt" | tr '\n' ';')" \
      "UAT (/data folder di partisi /): bind mount /data ke dirinya sendiri dengan nosuid,nodev di /etc/fstab. Produksi: partisi/LV /data dengan opsi nosuid,nodev. Cek: findmnt -T /data"
  fi
  rm -f "$OUT/.nomnt"
}

#------------------------------------------------------------------------------
# SIAPA YANG BISA MENGENDALIKAN DAEMON CONTAINER
#   Docker biasa (daemon root): akses socket = setara root host.
#   Docker rootless: akses socket = kendali semua container milik user itu.
#------------------------------------------------------------------------------
# Proses aplikasi milik user di HOST (bukan di dalam container): "comm(PID) ..."
user_host_apps() {
  local pid comm out=""
  while read -r pid comm; do
    [ -n "$pid" ] || continue
    [ -n "$(pid_container "$pid")" ] && continue
    out="$out $comm($pid)"
  done < <(ps -u "$1" -o pid=,comm= 2>/dev/null | awk '$2 ~ /^(java|node|nodejs|python[0-9.]*|php[0-9.]*|php-fpm.*|ruby|perl|httpd|nginx|gunicorn|uwsgi|beam.smp|dotnet)$/')
  echo "$out" | awk '{for(i=1;i<=NF && i<=6;i++) printf "%s ", $i; if (NF>6) printf "(+%d lagi)", NF-6}'
}

# Cara user bisa dimasuki: shell login, kunci SSH, password
user_login_info() {
  local u="$1" sh h pw r=""
  sh=$(getent passwd "$u" | cut -d: -f7); h=$(getent passwd "$u" | cut -d: -f6)
  case "$sh" in */nologin|*/false|"") r="shell=$sh(tidak bisa login)" ;; *) r="shell=$sh" ;; esac
  [ -s "$h/.ssh/authorized_keys" ] && r="$r, ada authorized_keys"
  pw=$(awk -F: -v u="$u" '$1==u{print substr($2,1,1)}' /etc/shadow 2>/dev/null)
  case "$pw" in '!'|'*'|'') r="$r, password terkunci" ;; *) r="$r, password aktif" ;; esac
  echo "$r"
}

# Baris sudoers yang menyebut kata tertentu (tanpa komentar)
sudoers_lines() {
  grep -hsE "^[[:space:]]*[^#[:space:]].*\b$1\b" /etc/sudoers /etc/sudoers.d/* 2>/dev/null | sed 's/[[:space:]]\+/ /g' | head -n 10
}

check_docker_access() {
  [ -s "$OUT/.dkrps" ] || have docker || have podman || [ -S /var/run/docker.sock ] || return 0
  log "Cek siapa yang bisa mengendalikan daemon container"
  local f="$RAW/container_access.txt" s g gid u apps login sev ev mitig="" rec via
  local rl_users dkr_users="" sd finding_title id
  {
    echo "Proses daemon (uid pid perintah):"; cat "$OUT/.dkrps"
    echo; echo "Mode daemon             : ${DKR_MODE:-tidak terdeteksi}"
    echo "Container dibaca lewat  : ${CRT_SRC:-TIDAK BISA} ${CRT_BIN:+($CRT_BIN, sebagai: $CRT_AS)}"
    [ -n "$CRT_ROOT_ERR" ] && echo "docker sebagai root     : $CRT_ROOT_ERR"
    [ -s "$OUT/.cfs_source" ] && echo "Folder data dibaca      : $(tr '\n' ' ' < "$OUT/.cfs_source")"
    echo; echo "Socket:"
    for s in /var/run/docker.sock /run/docker.sock /run/user/*/docker.sock /run/podman/podman.sock /run/user/*/podman/podman.sock; do
      [ -S "$s" ] || continue
      ls -l "$s"
      have getfacl && getfacl -p "$s" 2>/dev/null | grep -vE '^#|^$|^(user|group|other|mask)::'
    done
    echo; echo "Isi /etc/docker/daemon.json:"; grep -vE '^\s*$' /etc/docker/daemon.json 2>/dev/null || echo "(tidak ada)"
    echo; echo "sudoers yang menyebut docker/podman:"; sudoers_lines docker; sudoers_lines podman
  } > "$f" 2>/dev/null

  # mitigasi daemon root
  { grep -qs '"authorization-plugins"' /etc/docker/daemon.json || grep -q -- '--authorization-plugin' "$OUT/.dkrps"; } && mitig="$mitig plugin-otorisasi"
  { grep -qs '"userns-remap"' /etc/docker/daemon.json || grep -q -- '--userns-remap' "$OUT/.dkrps"; } && mitig="$mitig userns-remap"

  # --- Docker biasa: daemon berjalan sebagai root ---
  case "$DKR_MODE" in rootful*)
    for s in /var/run/docker.sock /run/docker.sock; do
      [ -S "$s" ] || continue
      g=$(stat -c %G "$s" 2>/dev/null); gid=$(stat -c %g "$s" 2>/dev/null)
      for u in $(getent group "$g" | cut -d: -f4 | tr ',' ' '); do dkr_users="$dkr_users $u:grup-$g"; done
      for u in $(awk -F: -v g="$gid" '$4==g{print $1}' /etc/passwd); do dkr_users="$dkr_users $u:grup-utama-$g"; done
      if have getfacl; then
        for u in $(getfacl -p "$s" 2>/dev/null | awk -F: '$1=="user" && $2!="" && $3 ~ /w/{print $2}'); do dkr_users="$dkr_users $u:ACL"; done
      fi
      break
    done
    for sd in $(sudoers_lines docker | awk '{print $1}' | grep -vxE 'root|Defaults' | sort -u); do
      case "$sd" in %*) for u in $(getent group "${sd#%}" | cut -d: -f4 | tr ',' ' '); do dkr_users="$dkr_users $u:sudo-docker"; done ;;
                     *) dkr_users="$dkr_users $sd:sudo-docker" ;; esac
    done
    for u in $(echo "$dkr_users" | tr ' ' '\n' | cut -d: -f1 | grep -vxE 'root|' | sort -u); do
      via=$(echo "$dkr_users" | tr ' ' '\n' | awk -F: -v u="$u" '$1==u{print $2}' | sort -u | tr '\n' ',' | sed 's/,$//')
      apps=$(user_host_apps "$u"); login=$(user_login_info "$u")
      if [ -n "$apps" ]; then
        sev=CRITICAL
        ev="user $u (lewat $via) menjalankan aplikasi di host: $apps; $login"
        rec="Aplikasi yang diretas (mis. webshell) langsung bisa menjadi root host lewat docker run --privileged -v /:/host. Perbaikan: (1) jalankan aplikasi host dengan user lain yang TIDAK punya akses Docker: gpasswd -d $u ${g:-docker}; (2) operasi docker hanya dari user admin terpisah; (3) sasaran jangka panjang: Docker rootless dengan user khusus; (4) pantau socket: auditctl -w /var/run/docker.sock -p rwxa -k docker-sock."
        finding_title="User aplikasi bisa mengendalikan Docker daemon yang berjalan sebagai root (aplikasi diretas = root host)"
        id=DKR-ROOTEQ-01
      else
        sev=HIGH
        ev="user $u (lewat $via); $login"
        rec="Akses ke Docker daemon root setara root host. Batasi hanya untuk admin yang memang perlu (gpasswd -d $u ${g:-docker}), wajibkan login perorangan + audit (auditctl -w /var/run/docker.sock -p rwxa -k docker-sock)."
        finding_title="User non-root bisa mengendalikan Docker daemon yang berjalan sebagai root (setara root)"
        id=DKR-ROOTEQ-02
      fi
      [ -n "$CRT_ROOT_ERR" ] && [ "$CRT_AS" = "$u" ] && ev="$ev; root ditolak menjalankan docker tetapi daemon tetap berjalan sebagai root: pemblokiran root tidak mengurangi risiko ini"
      if echo "$mitig" | grep -q plugin-otorisasi; then
        case "$sev" in CRITICAL) sev=HIGH ;; HIGH) sev=MEDIUM ;; esac
        ev="$ev; plugin otorisasi terpasang (verifikasi plugin menolak --privileged, bind mount /, --pid=host, --userns=host)"
      fi
      echo "$mitig" | grep -q userns-remap && ev="$ev; userns-remap aktif (masih bisa dilewati dengan --userns=host bila tidak dicegah plugin otorisasi)"
      finding "$sev" "$id" Container "$finding_title" "$ev" "$rec"
    done
    ;;
  esac

  # --- Docker rootless ---
  case "$DKR_MODE" in *rootless*)
    rl_users=$(awk '$1!=0 {c=$3; sub(/.*\//,"",c); if (c=="dockerd") print $1}' "$OUT/.dkrps" | sort -u | while read -r u; do getent passwd "$u" | cut -d: -f1; done)
    [ -z "$rl_users" ] && [ -n "$CRT_AS" ] && rl_users="$CRT_AS"
    for u in $rl_users; do
      s="/run/user/$(id -u "$u" 2>/dev/null)/docker.sock"
      login=$(user_login_info "$u")
      finding INFO DKR-ROOTLESS-01 Container "Docker berjalan rootless sebagai user $u (container tidak memberi jalan ke root host)" \
        "dockerd uid $(id -u "$u" 2>/dev/null); socket $(ls -l "$s" 2>/dev/null | awk '{print $1, $3}') $s; $login" \
        "Pertahankan. Pastikan socket tetap mode 660/600 milik $u dan hanya admin tertentu yang boleh su/sudo ke $u."
      apps=$(user_host_apps "$u")
      [ -n "$apps" ] && finding MEDIUM DKR-ROOTLESS-02 Container "User pemilik Docker rootless ($u) juga menjalankan aplikasi di host" \
        "$u menjalankan: $apps" \
        "Aplikasi host yang diretas bisa mengendalikan SEMUA container $u (membaca data, secret, environment). Jalankan aplikasi host dengan user lain, atau pindahkan aplikasinya ke container."
      sd=$(sudoers_lines "$u")
      [ -n "$sd" ] && echo "sudoers yang menyebut $u: $sd" >> "$f"
      if [ -n "$CRT_AS" ] && [ "$CRT_AS" != "$u" ] && [ "$CRT_SRC" = cli ]; then
        finding INFO DKR-MULTI-01 Container "Daemon rootless milik user $u tidak ikut diperiksa" "script membaca daemon $CRT_AS" "Jalankan ulang: sudo bash assess.sh --docker-user $u"
      fi
    done
    ;;
  esac

  # --- Bagian container tidak bisa diperiksa ---
  if [ -z "$CRT_SRC" ]; then
    finding MEDIUM DKR-NOACCESS-01 Container "Container runtime terpasang tetapi tidak bisa ditanya: bagian container TIDAK diperiksa" \
      "daemon: $(awk '{print "uid " $1 " " $3}' "$OUT/.dkrps" | tr '\n' ';')${CRT_ROOT_ERR:+ root: $CRT_ROOT_ERR}" \
      "Jalankan ulang dengan user yang biasa dipakai untuk docker: sudo bash assess.sh --docker-user <user>"
  elif [ "$CRT_SRC" = fs ]; then
    finding LOW DKR-FSONLY-01 Container "Container dibaca dari file konfigurasi di disk (CLI tidak bisa dipakai)" \
      "folder: $(tr '\n' ' ' < "$OUT/.cfs_source" 2>/dev/null)" \
      "Postur dan library container tetap diperiksa; image tersimpan dan riwayat build TIDAK. Untuk hasil lengkap: sudo bash assess.sh --docker-user <user>"
  fi
  return 0
}
ctr_name()    { awk -F'\t' -v i="$1" '$1==i{print $2; exit}' "$OUT/.cmap" 2>/dev/null; }
ctr_image()   { awk -F'\t' -v i="$1" '$1==i{print $3; exit}' "$OUT/.cmap" 2>/dev/null; }
ctr_mainpid() { awk -F'\t' -v i="$1" '$1==i{print $4; exit}' "$OUT/.cmap" 2>/dev/null; }
# Root filesystem container dilihat dari host (read-only, tanpa docker exec)
ctr_root() {
  local p; p=$(ctr_mainpid "$1")
  if [ -n "${ASSESS_TEST_CTR_ROOT:-}" ]; then echo "$ASSESS_TEST_CTR_ROOT/$(ctr_name "$1")"; return; fi
  [ -n "$p" ] && [ "$p" != 0 ] && echo "/proc/$p/root"
}
# Prefix rootfs untuk sebuah PID ("" bila proses host)
pid_rootfs() {
  local c; c=$(pid_container "$1")
  [ -n "$c" ] && ctr_root "$c"
  return 0
}
# Lingkup sebuah PID: "host" atau "container:<nama>"
pid_scope() {
  local c; c=$(pid_container "$1")
  if [ -n "$c" ]; then echo "container:$(ctr_name "$c")"; else echo host; fi
}

#------------------------------------------------------------------------------
# RUNTIME NON-JAVA YANG BERJALAN (Node.js, Python, PHP, lainnya) + PROSES TAK DIKENAL
#------------------------------------------------------------------------------
other_runtime_of() {
  case "$1" in
    node|nodejs)                              echo nodejs ;;
    python|python[23]|python[23].[0-9]*)      echo python ;;
    php|php-fpm|php-fpm[0-9]*|php[0-9]*|php-cgi) echo php ;;
    ruby|ruby[0-9]*)                          echo ruby ;;
    dotnet)                                   echo dotnet ;;
  esac
}

# Argumen pertama yang bukan opsi (= skrip yang dijalankan)
first_script_arg() {
  tr '\0' '\n' < "/proc/$1/cmdline" 2>/dev/null | awk 'NR>1 && $0 !~ /^-/ {print; exit}'
}

rt_eol_check() {  # runtime versi label
  local rt="$1" v="$2" label="$3" maj min
  maj=$(echo "$v" | grep -oE '[0-9]+' | sed -n 1p); min=$(echo "$v" | grep -oE '[0-9]+' | sed -n 2p)
  [ -n "$maj" ] || return 0
  case "$rt" in
    nodejs) [ "$maj" -lt 22 ] && finding HIGH RT-EOL-01 Runtime "Node.js versi sudah tidak didukung (EOL)" "$label: Node.js $v" \
              "Upgrade ke Node.js LTS yang masih didukung (22 atau 24). Versi di bawah 22 tidak lagi menerima patch keamanan." ;;
    python) if [ "$maj" -lt 3 ] || { [ "$maj" -eq 3 ] && [ "${min:-0}" -lt 11 ]; }; then
              finding HIGH RT-EOL-01 Runtime "Python versi sudah tidak didukung (EOL)" "$label: Python $v" \
              "Upgrade ke Python 3.11 atau lebih baru. Versi di bawah 3.11 tidak lagi menerima patch keamanan."; fi ;;
    php)    if [ "$maj" -lt 8 ] || { [ "$maj" -eq 8 ] && [ "${min:-0}" -lt 2 ]; }; then
              finding HIGH RT-EOL-01 Runtime "PHP versi sudah tidak didukung (EOL)" "$label: PHP $v" \
              "Upgrade ke PHP 8.3 atau lebih baru. Versi di bawah 8.2 tidak lagi menerima patch keamanan."; fi ;;
  esac
  return 0
}

discover_other_runtimes() {
  local d pid exe base rt ppid pexe scope root cwd script appdir extra ver label ports user how n=0 sum="" i x
  : > "$OUT/.otherapps"
  log "Identifikasi runtime non-Java yang berjalan (Node.js, Python, PHP, lainnya)"
  {
    echo "Aplikasi NON-JAVA yang sedang berjalan (terdeteksi otomatis)"
    echo "============================================================"
    for d in /proc/[0-9]*; do
      pid=${d#/proc/}
      exe=$(readlink "$d/exe" 2>/dev/null) || continue
      exe=${exe% (deleted)}; base=${exe##*/}
      rt=$(other_runtime_of "$base"); [ -n "$rt" ] || continue
      # lewati worker (induknya runtime yang sama)
      ppid=$(awk '/^PPid:/{print $2}' "$d/status" 2>/dev/null)
      pexe=$(readlink "/proc/$ppid/exe" 2>/dev/null); pexe=${pexe% (deleted)}
      [ -n "$(other_runtime_of "${pexe##*/}")" ] && [ "$(other_runtime_of "${pexe##*/}")" = "$rt" ] && continue
      scope=$(pid_scope "$pid"); root=$(pid_rootfs "$pid")
      cwd=$(readlink "$d/cwd" 2>/dev/null); script=$(first_script_arg "$pid")
      ports=$(listen_of_pid "$pid" | tr '\n' ' ')
      # python milik sistem (tuned, firewalld, yum, dsb) dilewati kecuali membuka port
      if [ "$rt" = python ] && [ -z "$ports" ]; then
        case "$script" in ""|/usr/*|/sbin/*|/bin/*|/var/ossec/*|/opt/rh/*) continue ;; esac
      fi
      [ -n "$script" ] && [ "${script#/}" = "$script" ] && script="$cwd/$script"
      appdir="$cwd"; extra=""
      case "$rt" in
        nodejs)
          [ -n "$script" ] && appdir=$(dirname "$script")
          i=0; x="$appdir"
          while [ "$i" -lt 5 ] && [ "$x" != "/" ] && [ ! -f "$root$x/package.json" ]; do x=$(dirname "$x"); i=$((i+1)); done
          [ -f "$root$x/package.json" ] && appdir="$x" ;;
        python)
          case "$script" in */bin/*|"") appdir="$cwd" ;; *) appdir=$(dirname "$script") ;; esac
          case "$exe" in */bin/python*) x=${exe%/bin/*}; [ -f "$root$x/pyvenv.cfg" ] && extra="$x" ;; esac ;;
      esac
      if [ -z "$root" ]; then ver=$(timeout 10 "$exe" --version 2>&1 | head -n1 | cut -c1-60); else ver="(dalam container, tidak dijalankan)"; fi
      user=$(pid_user "$pid"); how=$(how_started "$pid")
      label="$(basename "$appdir")"; [ "$scope" != host ] && label="${scope#container:}/$label"
      n=$((n+1))
      echo
      echo "[$n] PID $pid  runtime=$rt  lingkup=$scope"
      echo "    aplikasi       : $appdir"
      echo "    skrip          : ${script:--}"
      echo "    binary         : $exe"
      echo "    versi          : $ver"
      echo "    user           : $user"
      echo "    folder kerja   : $cwd"
      echo "    dijalankan via : $how"
      echo "    port (listen)  : ${ports:--}"
      printf '%s\t%s\t%s\t%s\t1\t%s\t%s\n' "$rt" "$label" "$root$appdir" "${extra:+$root$extra}" "$scope" "$root" >> "$OUT/.otherapps"
      sum="$sum $label($rt:${ports:-tanpa-port})"
      [ -z "$root" ] && rt_eol_check "$rt" "$ver" "$label"
      [ "$user" = root ] && [ "$rt" != php ] && finding HIGH RT-ROOT-01 Runtime "Aplikasi $rt berjalan sebagai root" "$label (PID $pid, $scope)" \
        "Jalankan dengan user khusus non-root (systemd User=, atau USER di Dockerfile)."
    done
  } > "$RAW/running_apps_other.txt"
  if [ "$n" -gt 0 ]; then
    finding INFO APP-RUN-02 Aplikasi "$n aplikasi non-Java sedang berjalan (detail di raw/running_apps_other.txt)" "$sum" \
      "Pastikan setiap aplikasi tercatat di inventaris aset dan punya pemilik."
  else
    rm -f "$RAW/running_apps_other.txt"
  fi

  # Manifest dependensi di disk (aplikasi yang tidak sedang berjalan)
  if [ -s "$OUT/.manifests" ]; then
    grep -vE '/(node_modules|vendor|site-packages|dist-packages|\.cache|\.npm)/|^/usr/(share|lib|lib64)/|^/opt/rh/' "$OUT/.manifests" | while read -r x; do
      d=$(dirname "$x")
      cut -f3 "$OUT/.otherapps" | grep -qxF "$d" && continue
      case "${x##*/}" in
        package-lock.json|yarn.lock) rt=nodejs ;;
        composer.lock)               rt=php ;;
        *)                           rt=python ;;
      esac
      printf '%s\t%s\t%s\t\t0\thost\t\n' "$rt" "$(basename "$d")" "$d"
    done | sort -u >> "$OUT/.otherapps"
    rm -f "$OUT/.manifests"
  fi
}

# Proses yang membuka port tetapi bukan service/runtime yang dikenali
check_unknown_listeners() {
  local line pid name exe base user scope go n=0 ev=""
  : > "$RAW/unknown_listeners.txt"
  ss -tlnpH 2>/dev/null | grep -oE 'pid=[0-9]+' | sort -u | cut -d= -f2 | while read -r pid; do
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null) || continue
    exe=${exe% (deleted)}; base=${exe##*/}
    case "$base" in
      sshd|sshd-session|java|httpd|apache2|nginx|mysqld|mariadbd|postgres|postmaster|master|nrpe|snmpd|ntpd|chronyd|rpcbind|rpc.statd|rpc.mountd|\
      dockerd|docker-proxy|containerd|containerd-shim*|conmon|systemd|systemd-resolve*|cupsd|dnsmasq|named|redis-server|mongod|haproxy|memcached|\
      sendmail|exim*|dovecot|smbd|nmbd|vsftpd|xinetd|rsyslogd|zabbix_agent*|node_exporter|wazuh-*|ossec-*|filebeat|nslcd|sssd*|crond|kubelet|kube-proxy|etcd) continue ;;
    esac
    [ -n "$(other_runtime_of "$base")" ] && continue
    user=$(pid_user "$pid"); scope=$(pid_scope "$pid"); go=""
    [ "$scope" = host ] && timeout 5 grep -aqm1 'Go buildinf:' "$exe" 2>/dev/null && go=" [binary Go]"
    echo "PID $pid | $exe$go | user=$user | $scope | port: $(listen_of_pid "$pid" | tr '\n' ' ')| cmd: $(pid_cmd "$pid" | redact | cut -c1-200)"
  done > "$RAW/unknown_listeners.txt"
  n=$(wc -l < "$RAW/unknown_listeners.txt")
  if [ "$n" -gt 0 ]; then
    finding LOW APP-UNK-01 Aplikasi "$n proses membuka port tetapi bukan service/runtime yang dikenali" \
      "$(cut -d'|' -f1-2 "$RAW/unknown_listeners.txt" | head -n 8 | tr '\n' ';')" \
      "Identifikasi tiap proses (detail di raw/unknown_listeners.txt). Binary Go/C tidak punya daftar library terpisah: pindai file binary-nya langsung dengan Trivy bila perlu."
  else
    rm -f "$RAW/unknown_listeners.txt"
  fi
}

#------------------------------------------------------------------------------
# PAKET OS: host + tiap container (docker exec; cadangan: baca rootfs dari host)
#------------------------------------------------------------------------------
# Skrip kecil yang dijalankan DI DALAM container (hanya membaca)
ctr_pkg_script() { cat <<'EOS'
cat /etc/os-release 2>/dev/null
echo "#REL $(cat /etc/centos-release /etc/redhat-release /etc/debian_version /etc/alpine-release 2>/dev/null | head -n 1)"
echo "#PKGS"
if command -v rpm >/dev/null 2>&1; then
  rpm -qa --qf 'rpm\t%{NAME}\t%|EPOCH?{%{EPOCH}}:{0}|\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n' 2>/dev/null
elif command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f 'deb\t${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n' 2>/dev/null
elif [ -f /lib/apk/db/installed ]; then
  echo "#APKDB"; cat /lib/apk/db/installed
fi
EOS
}

# Baca paket dari sebuah root filesystem (host: root="", container: /proc/PID/root)
ospk_from_root() {  # root dir_tujuan
  local root="$1" dst="$2" f
  cat "$root/etc/os-release" > "$dst/osrelease" 2>/dev/null
  cat "$root/etc/centos-release" "$root/etc/redhat-release" "$root/etc/debian_version" "$root/etc/alpine-release" 2>/dev/null | head -n 1 > "$dst/rel"
  if [ -z "$root" ] && have rpm; then
    rpm -qa --qf 'rpm\t%{NAME}\t%|EPOCH?{%{EPOCH}}:{0}|\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n' > "$dst/pkgs.tsv" 2>/dev/null
  elif [ -z "$root" ] && have dpkg-query; then
    dpkg-query -W -f 'deb\t${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n' > "$dst/pkgs.tsv" 2>/dev/null
  elif [ -f "$root/var/lib/dpkg/status" ] || [ -d "$root/var/lib/dpkg/status.d" ]; then
    { cat "$root/var/lib/dpkg/status" 2>/dev/null; echo
      for f in "$root"/var/lib/dpkg/status.d/*; do
        case "$f" in *.md5sums|*.list) continue ;; esac
        [ -f "$f" ] && { cat "$f"; echo; }
      done; } > "$dst/dpkg_status" 2>/dev/null
  elif [ -f "$root/lib/apk/db/installed" ]; then
    cat "$root/lib/apk/db/installed" > "$dst/apk_installed" 2>/dev/null
  elif [ -n "$root" ] && have rpm && [ -d "$root/var/lib/rpm" ]; then
    timeout 60 rpm --root "$root" -qa --qf 'rpm\t%{NAME}\t%|EPOCH?{%{EPOCH}}:{0}|\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n' > "$dst/pkgs.tsv" 2>/dev/null
  fi
}

collect_os_packages() {
  local base="$OUT/.ospk" d id name root ok tmp unread=""
  mkdir -p "$base/host"
  log "Kumpulkan daftar paket OS (host)"
  ospk_from_root "" "$base/host"
  [ -s "$OUT/.cmap" ] || return 0
  while IFS=$'\t' read -r id name _img _pid; do
    d="$base/container__$name"; mkdir -p "$d"; ok=0
    log "Kumpulkan daftar paket OS container: $name"
    if [ "$NO_EXEC" -eq 0 ] && [ "$SAFE" -eq 0 ] && [ "$CRT_SRC" = cli ]; then
      tmp="$d/exec.out"
      ctr_pkg_script | timeout 90 "${CRT_CMD[@]}" exec -i "$name" sh -s > "$tmp" 2>/dev/null
      if grep -q '^#PKGS' "$tmp" 2>/dev/null; then
        sed -n '1,/^#REL /p' "$tmp" | grep -v '^#REL ' > "$d/osrelease"
        sed -n 's/^#REL //p' "$tmp" | head -n 1 > "$d/rel"
        if grep -q '^#APKDB' "$tmp"; then sed -n '/^#APKDB/,$p' "$tmp" | sed 1d > "$d/apk_installed"
        else sed -n '/^#PKGS/,$p' "$tmp" | sed 1d > "$d/pkgs.tsv"; fi
        [ -s "$d/pkgs.tsv" ] || [ -s "$d/apk_installed" ] && ok=1
      fi
      rm -f "$tmp"
    fi
    if [ "$ok" -eq 0 ]; then
      root=$(ctr_root "$id")
      [ -n "$root" ] && [ -d "$root/etc" ] && ospk_from_root "$root" "$d"
      [ -s "$d/pkgs.tsv" ] || [ -s "$d/dpkg_status" ] || [ -s "$d/apk_installed" ] && ok=1
      [ "$ok" -eq 1 ] && echo "$name: paket OS dibaca dari rootfs (tanpa docker exec)" >> "$RAW/container_libs_note.txt"
    fi
    [ "$ok" -eq 0 ] && unread="$unread $name"
  done < "$OUT/.cmap"
  [ -n "$unread" ] && finding LOW CNT-OSPKG-01 Container "Daftar paket OS container tidak terbaca" "$unread" \
    "Image tanpa shell/package manager (distroless/scratch) atau format tidak dikenali. Pindai image-nya langsung: docker save lalu trivy image --input."
  return 0
}

#------------------------------------------------------------------------------
# INVENTARIS LIBRARY NON-JAVA + SBOM (CycloneDX 1.5, satu file per lingkup)
#------------------------------------------------------------------------------
build_inventory_and_sbom() {
  [ -n "$PY" ] || { finding INFO SBOM-00 SBOM "SBOM tidak dibuat (python tidak tersedia)" "-" "Pasang python/python3 di server atau jalankan di server lain."; return 0; }
  log "Inventaris library non-Java dan pembuatan SBOM"
  mkdir -p "$OUT/sbom"
  "$PY" - "$OUT" "$HOST" "$SCRIPT_VERSION" 2>>"$RAW/sbom_errors.txt" <<'PYEOF' >> "$FINDINGS"
# -*- coding: utf-8 -*-
from __future__ import print_function, unicode_literals
import sys, os, re, io, json, csv, uuid, time
PY2 = sys.version_info[0] < 3
if PY2:
    from urllib import quote as _quote
else:
    from urllib.parse import quote as _quote
argv = [a.decode('utf-8', 'replace') if isinstance(a, bytes) else a for a in sys.argv]
OUT, HOST, SVER = argv[1], argv[2], argv[3]
def U(x):
    if x is None: return ''
    if isinstance(x, bytes): return x.decode('utf-8', 'replace')
    return x
def _w(stream, text):
    b = (text + '\n').encode('utf-8')
    getattr(stream, 'buffer', stream).write(b)
def warn(*a): _w(sys.stderr, ' '.join(U(x) if not isinstance(x, Exception) else repr(x) for x in a))
def emit(line): _w(sys.stdout, line)
def q(x): return '"' + U(x).replace('\r', '').replace('\n', ' ').replace('"', '""') + '"'
def enc(s, safe=''):
    s = U(s)
    r = _quote(s.encode('utf-8'), safe=(b'.-_~' + safe.encode('ascii')) if PY2 else ('.-_~' + safe))
    return U(r)
def rtext(path, limit=20000000):
    try:
        with io.open(path, 'rb') as f: return f.read(limit).decode('utf-8', 'replace')
    except Exception: return ''
def csv_rows(path):
    if not os.path.isfile(path): return
    if PY2:
        with open(path, 'rb') as f:
            for row in csv.reader(f): yield [c.decode('utf-8', 'replace') for c in row]
    else:
        with io.open(path, encoding='utf-8', errors='replace', newline='') as f:
            for row in csv.reader(f): yield row
def wjson(path, obj):
    data = json.dumps(obj, indent=1, sort_keys=True)
    if not isinstance(data, bytes): data = data.encode('utf-8')
    with open(path, 'wb') as f: f.write(data)

# ---------------------------------------------------------------- container map
cmap = {}     # rootprefix -> name
for line in rtext(os.path.join(OUT, '.cmap')).splitlines():
    p = line.split('\t')
    if len(p) >= 4:
        cmap['/proc/%s/root' % p[3]] = p[1]
        t = os.environ.get('ASSESS_TEST_CTR_ROOT')
        if t: cmap[t.rstrip('/') + '/' + p[1]] = p[1]
def scope_of_path(path):
    for pref, name in cmap.items():
        if path == pref or path.startswith(pref + '/'): return 'container:' + name
    return 'host'

# ---------------------------------------------------------------- library non-Java
other = []    # dict(scope, runtime, eco, label, name, version, source, active, path)
def add(app, eco, name, ver, src, path):
    if not name or not ver: return
    other.append({'scope': app['scope'], 'runtime': app['rt'], 'eco': eco, 'label': app['label'], 'name': U(name).strip(),
                  'version': U(ver).strip(), 'source': src, 'active': app['active'], 'path': path})
def jload(path):
    try: return json.loads(rtext(path))
    except Exception as e: warn('json gagal', path, e); return None

def npm_lock(app, path):
    d = jload(path)
    if not isinstance(d, dict): return 0
    n = 0
    pk = d.get('packages')
    if isinstance(pk, dict):
        for k, v in pk.items():
            if not k or not isinstance(v, dict) or v.get('link'): continue
            name = v.get('name') or k.split('node_modules/')[-1]
            add(app, 'npm', name, v.get('version'), 'package-lock.json', path); n += 1
        return n
    def walk(deps, depth=0):
        c = 0
        for name, v in (deps or {}).items():
            if not isinstance(v, dict): continue
            add(app, 'npm', name, v.get('version'), 'package-lock.json', path); c += 1
            if depth < 12: c += walk(v.get('dependencies'), depth + 1)
        return c
    return walk(d.get('dependencies'))
def yarn_lock(app, path):
    n = 0; names = []
    for line in rtext(path).splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(':') and not line.startswith('#'):
            names = []
            for part in line.rstrip()[:-1].split(','):
                part = part.strip().strip('"')
                m = re.match(r'^(@?[^@]+)@', part)
                if m: names.append(m.group(1))
        else:
            m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
            if m and names:
                add(app, 'npm', names[0], m.group(1), 'yarn.lock', path); n += 1; names = []
    return n
def node_modules(app, base, depth=0, budget=None):
    if budget is None: budget = [20000]
    nm = os.path.join(base, 'node_modules')
    try: ents = os.listdir(nm)
    except Exception: return 0
    n = 0
    for e in ents:
        if e.startswith('.') or budget[0] <= 0: continue
        dirs = [os.path.join(nm, e)]
        if e.startswith('@'):
            try: dirs = [os.path.join(nm, e, x) for x in os.listdir(os.path.join(nm, e))]
            except Exception: dirs = []
        for dd in dirs:
            pj = os.path.join(dd, 'package.json')
            if os.path.isfile(pj):
                budget[0] -= 1
                d = jload(pj)
                if isinstance(d, dict): add(app, 'npm', d.get('name'), d.get('version'), 'node_modules', pj); n += 1
            if depth < 4: n += node_modules(app, dd, depth + 1, budget)
    return n
def py_site(app, sp):
    n = 0
    try: ents = os.listdir(sp)
    except Exception: return 0
    for e in ents:
        meta = None
        if e.endswith('.dist-info'): meta = os.path.join(sp, e, 'METADATA')
        elif e.endswith('.egg-info'):
            meta = os.path.join(sp, e, 'PKG-INFO')
            if os.path.isfile(os.path.join(sp, e)): meta = os.path.join(sp, e)
        if not meta or not os.path.isfile(meta): continue
        name = ver = None
        for line in rtext(meta, 20000).splitlines():
            if line.startswith('Name:') and not name: name = line[5:].strip()
            elif line.startswith('Version:') and not ver: ver = line[8:].strip()
            elif not line.strip(): break
        if name and ver: add(app, 'pypi', name, ver, 'site-packages', meta); n += 1
    return n
def find_site_packages(base, maxdepth=6):
    res = []
    base = base.rstrip('/')
    if not os.path.isdir(base): return res
    for dp, dn, fn in os.walk(base):
        depth = dp[len(base):].count(os.sep)
        if depth >= maxdepth: dn[:] = []
        dn[:] = [x for x in dn if x not in ('node_modules', '.git', '__pycache__', 'proc', 'sys')]
        for x in list(dn):
            if x in ('site-packages', 'dist-packages'):
                res.append(os.path.join(dp, x)); dn.remove(x)
    return res
def py_requirements(app, path):
    n = 0
    for line in rtext(path, 500000).splitlines():
        m = re.match(r'^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)', line)
        if m: add(app, 'pypi', m.group(1), m.group(2), 'requirements.txt', path); n += 1
    return n
def composer(app, base):
    n = 0
    lock = os.path.join(base, 'composer.lock')
    d = jload(lock) if os.path.isfile(lock) else None
    src = 'composer.lock'
    if not isinstance(d, dict):
        lock = os.path.join(base, 'vendor', 'composer', 'installed.json')
        d = jload(lock) if os.path.isfile(lock) else None
        src = 'vendor/composer/installed.json'
        if isinstance(d, list): d = {'packages': d}
    if not isinstance(d, dict): return 0
    for key in ('packages', 'packages-dev'):
        for p in (d.get(key) or []):
            if isinstance(p, dict): add(app, 'composer', p.get('name'), p.get('version'), src, lock); n += 1
    return n

apps_seen = set()
for line in rtext(os.path.join(OUT, '.otherapps')).splitlines():
    p = line.split('\t')
    if len(p) < 6: continue
    rt, label, appdir, extra, active, scope = p[0], p[1], p[2], p[3], p[4], p[5]
    root = p[6] if len(p) > 6 else ''
    if (rt, appdir) in apps_seen or not appdir: continue
    apps_seen.add((rt, appdir))
    app = {'rt': rt, 'label': label, 'active': 'YA' if active == '1' else 'tidak', 'scope': scope}
    try:
        n = 0
        if rt == 'nodejs':
            if os.path.isfile(os.path.join(appdir, 'package-lock.json')): n = npm_lock(app, os.path.join(appdir, 'package-lock.json'))
            if not n and os.path.isfile(os.path.join(appdir, 'yarn.lock')): n = yarn_lock(app, os.path.join(appdir, 'yarn.lock'))
            if not n: n = node_modules(app, appdir)
        elif rt == 'python':
            sps = []
            if extra: sps += find_site_packages(extra, 4)
            sps += find_site_packages(appdir, 5)
            if active == '1':
                for b in ('/usr/local/lib', '/usr/local/lib64'):
                    sps += find_site_packages(root + b, 2)
            for sp in sorted(set(sps)): n += py_site(app, sp)
            if not n:
                for rq in ('requirements.txt',):
                    if os.path.isfile(os.path.join(appdir, rq)): n += py_requirements(app, os.path.join(appdir, rq))
        elif rt == 'php':
            n = composer(app, appdir)
        if not n: warn('tidak ada library terbaca untuk', rt, appdir)
    except Exception as e:
        warn('inventaris gagal', rt, appdir, e)

# dedup + tulis CSV
seen = set(); rows_other = []
for o in other:
    k = (o['scope'], o['eco'], o['label'], o['name'], o['version'])
    if k in seen: continue
    seen.add(k); rows_other.append(o)
with io.open(os.path.join(OUT, 'libraries_other.csv'), 'w', encoding='utf-8') as f:
    f.write('host,scope,runtime,ecosystem,label,name,version,source,dipakai_proses_berjalan,path\n')
    for o in rows_other:
        f.write(','.join(q(x) for x in [HOST, o['scope'], o['runtime'], o['eco'], o['label'], o['name'], o['version'], o['source'], o['active'], o['path']]) + '\n')

# ---------------------------------------------------------------- paket OS
OSMAP = {'rhel': 'redhat', 'almalinux': 'alma', 'ol': 'oracle', 'amzn': 'amazon', 'opensuse-leap': 'opensuse-leap', 'sles': 'sles'}
def parse_osrelease(txt, rel):
    d = {}
    for line in txt.splitlines():
        m = re.match(r'^([A-Z_]+)=(.*)$', line.strip())
        if m: d[m.group(1)] = m.group(2).strip().strip('"').strip("'")
    oid = d.get('ID', '').lower(); ver = d.get('VERSION_ID', '')
    rel = (rel or '').strip()
    m = re.search(r'(\d+(?:\.\d+)+)', rel)
    if oid in ('centos', 'debian', 'alpine', 'rhel', 'rocky', 'almalinux') and m and (not ver or ver.count('.') < m.group(1).count('.')):
        ver = m.group(1)
    if not oid and rel:
        low = rel.lower()
        for k in ('centos', 'red hat', 'rocky', 'alma', 'alpine', 'debian'):
            if k in low: oid = {'red hat': 'rhel', 'alma': 'almalinux'}.get(k, k)
        if not oid and re.match(r'^\d+\.\d+', rel): oid = 'debian'
    return OSMAP.get(oid, oid), ver, d.get('PRETTY_NAME', rel)
def split_srcrpm(s):
    s = re.sub(r'\.(no)?src\.rpm$', '', s or '')
    p = s.rsplit('-', 2)
    return (p[0], p[1], p[2]) if len(p) == 3 else ('', '', '')
def split_deb(v):
    ep = '0'
    if ':' in v: ep, v = v.split(':', 1)
    if '-' in v: up, rev = v.rsplit('-', 1)
    else: up, rev = v, ''
    return ep, up, rev
def parse_dpkg_status(txt):
    for para in re.split(r'\n\s*\n', txt):
        d = {}
        for line in para.splitlines():
            if line[:1] in (' ', '\t') or ':' not in line: continue
            k, v = line.split(':', 1); d[k.strip()] = v.strip()
        if not d.get('Package') or not d.get('Version'): continue
        if 'Status' in d and 'installed' not in d['Status'].split()[-1:]: continue
        src, sver = d.get('Source', ''), ''
        m = re.match(r'^(\S+)\s*\(([^)]+)\)', src)
        if m: src, sver = m.group(1), m.group(2)
        yield ['deb', d['Package'], d['Version'], d.get('Architecture', ''), src or d['Package'], sver or d['Version'], 'ii']
def parse_apk(txt):
    for para in re.split(r'\n\s*\n', txt):
        d = {}
        for line in para.splitlines():
            if len(line) > 2 and line[1] == ':': d[line[0]] = line[2:].strip()
        if d.get('P') and d.get('V'): yield ['apk', d['P'], d['V'], d.get('A', ''), d.get('o', d['P'])]

scopes = {}   # scope -> dict(os=(id,ver,pretty), pkgs=[component dict], libs=[...])
def S(scope): return scopes.setdefault(scope, {'os': ('', '', ''), 'pkgs': [], 'libs': [], 'nopurl': 0})
osdir = os.path.join(OUT, '.ospk')
ospk_rows = []
if os.path.isdir(osdir):
    for ent in sorted(os.listdir(osdir)):
        d = os.path.join(osdir, ent)
        scope = 'host' if ent == 'host' else 'container:' + ent.split('__', 1)[-1]
        oid, over, pretty = parse_osrelease(rtext(os.path.join(d, 'osrelease')), rtext(os.path.join(d, 'rel')))
        sc = S(scope); sc['os'] = (oid, over, pretty)
        raw = []
        for line in rtext(os.path.join(d, 'pkgs.tsv')).splitlines():
            p = line.split('\t')
            if p and p[0] in ('rpm', 'deb'): raw.append(p)
        raw += list(parse_dpkg_status(rtext(os.path.join(d, 'dpkg_status'))))
        raw += list(parse_apk(rtext(os.path.join(d, 'apk_installed'))))
        seenp = set()
        for p in raw:
            try:
                props = []; quals = []
                if p[0] == 'rpm' and len(p) >= 7:
                    name, ep, ver, relv, arch, srpm = p[1], p[2], p[3], p[4], p[5], p[6]
                    if name == 'gpg-pubkey': continue
                    full = ver + '-' + relv
                    sn, sv, sr = split_srcrpm(srpm)
                    ptype, ns = 'rpm', (oid or 'redhat')
                    if arch and arch != '(none)': quals.append(('arch', arch))
                    if oid: quals.append(('distro', '%s-%s' % (oid, over)))
                    if ep and ep not in ('0', '(none)'): quals.append(('epoch', ep))
                    if sn: props += [('SrcName', sn), ('SrcVersion', sv), ('SrcRelease', sr)]
                    if ep and ep not in ('0', '(none)'): props.append(('SrcEpoch', ep))
                elif p[0] == 'deb' and len(p) >= 6:
                    name, fullv, arch, sn, sfull = p[1], p[2], p[3], p[4] or p[1], p[5] or p[2]
                    if len(p) > 6 and p[6].strip() and not p[6].startswith('ii'): continue
                    ep, up, rev = split_deb(fullv)
                    full = up + ('-' + rev if rev else '')
                    ptype, ns = 'deb', (oid or 'debian')
                    if arch: quals.append(('arch', arch))
                    if oid: quals.append(('distro', '%s-%s' % (oid, over)))
                    if ep != '0': quals.append(('epoch', ep))
                    sep, sup, srev = split_deb(sfull)
                    props += [('SrcName', sn), ('SrcVersion', sup)]
                    if srev: props.append(('SrcRelease', srev))
                    if sep != '0': props.append(('SrcEpoch', sep))
                elif p[0] == 'apk' and len(p) >= 5:
                    name, full, arch, sn = p[1], p[2], p[3], p[4]
                    ptype, ns = 'apk', (oid or 'alpine')
                    if arch: quals.append(('arch', arch))
                    if over: quals.append(('distro', over))
                    props += [('SrcName', sn), ('SrcVersion', full)]
                else:
                    continue
                purl = 'pkg:%s/%s/%s@%s' % (ptype, enc(ns), enc(name, '+'), enc(full, '+'))
                if quals: purl += '?' + '&'.join('%s=%s' % (k, enc(v, '+')) for k, v in sorted(quals))
                if purl in seenp: continue
                seenp.add(purl)
                props.append(('PkgType', oid or ptype))
                sc['pkgs'].append({'name': name, 'version': full, 'purl': purl, 'props': props})
                ospk_rows.append([HOST, scope, oid, over, ptype, name, full, dict(quals).get('arch', '')])
            except Exception as e:
                warn('paket dilewati', scope, p[:3], e)
with io.open(os.path.join(OUT, 'os_packages.csv'), 'w', encoding='utf-8') as f:
    f.write('host,scope,os,os_version,type,name,version,arch\n')
    for r in ospk_rows: f.write(','.join(q(x) for x in r) + '\n')

# ---------------------------------------------------------------- groupId untuk library umum
# Banyak jar (Spring, Tomcat, POI, ...) tidak menyimpan pom.properties sehingga groupId
# tidak terbaca. Tanpa groupId Trivy melewati library itu. Tabel ini hanya berisi nama
# artifact yang groupId-nya pasti di Maven Central; nama lain tetap dibiarkan kosong.
SPRING_FW = set('spring-aop spring-aspects spring-beans spring-context spring-context-indexer spring-context-support '
                'spring-core spring-expression spring-instrument spring-jcl spring-jdbc spring-jms spring-messaging '
                'spring-orm spring-oxm spring-r2dbc spring-test spring-tx spring-web spring-webflux spring-webmvc '
                'spring-websocket'.split())
EXACT_GROUP = {
    'tomcat-annotations-api': 'org.apache.tomcat', 'tomcat-jdbc': 'org.apache.tomcat', 'tomcat-juli': 'org.apache.tomcat',
    'thymeleaf': 'org.thymeleaf', 'thymeleaf-spring5': 'org.thymeleaf', 'thymeleaf-spring6': 'org.thymeleaf',
    'attoparser': 'org.attoparser', 'unbescape': 'org.unbescape',
    'poi': 'org.apache.poi', 'poi-ooxml': 'org.apache.poi', 'poi-ooxml-schemas': 'org.apache.poi',
    'poi-ooxml-lite': 'org.apache.poi', 'poi-ooxml-full': 'org.apache.poi', 'poi-scratchpad': 'org.apache.poi',
    'xmlbeans': 'org.apache.xmlbeans',
    'commons-collections': 'commons-collections', 'commons-httpclient': 'commons-httpclient',
    'commons-logging': 'commons-logging', 'commons-io': 'commons-io', 'commons-lang': 'commons-lang',
    'commons-codec': 'commons-codec', 'commons-beanutils': 'commons-beanutils', 'commons-fileupload': 'commons-fileupload',
    'commons-collections4': 'org.apache.commons', 'commons-lang3': 'org.apache.commons', 'commons-text': 'org.apache.commons',
    'commons-compress': 'org.apache.commons', 'commons-configuration2': 'org.apache.commons', 'commons-pool2': 'org.apache.commons',
    'commons-dbcp2': 'org.apache.commons', 'commons-csv': 'org.apache.commons', 'commons-math3': 'org.apache.commons',
    'velocity': 'org.apache.velocity', 'velocity-engine-core': 'org.apache.velocity',
    'freemarker': 'org.freemarker', 'gson': 'com.google.code.gson', 'guava': 'com.google.guava',
    'jasypt': 'org.jasypt', 'oro': 'oro', 'jcommander': 'com.beust', 'lombok': 'org.projectlombok',
    'reactor-core': 'io.projectreactor', 'reactive-streams': 'org.reactivestreams',
    'caffeine': 'com.github.ben-manes.caffeine', 'jspecify': 'org.jspecify', 'HikariCP': 'com.zaxxer',
    'snakeyaml': 'org.yaml', 'log4j': 'log4j', 'mariadb-java-client': 'org.mariadb.jdbc', 'postgresql': 'org.postgresql',
    'mysql-connector-java': 'mysql', 'h2': 'com.h2database', 'primefaces': 'org.primefaces',
    'primefaces-extensions': 'org.primefaces.extensions', 'mybatis': 'org.mybatis', 'mybatis-spring': 'org.mybatis',
    'ognl': 'ognl', 'javassist': 'org.javassist', 'jsoup': 'org.jsoup',
    'kafka-clients': 'org.apache.kafka', 'jna': 'net.java.dev.jna', 'jna-platform': 'net.java.dev.jna',
    'libthrift': 'org.apache.thrift', 'checker-qual': 'org.checkerframework', 'antlr': 'antlr',
}
PREFIX_GROUP = [
    ('spring-boot', 'org.springframework.boot'), ('spring-security-', 'org.springframework.security'),
    ('spring-data-', 'org.springframework.data'), ('spring-session-', 'org.springframework.session'),
    ('spring-ws-', 'org.springframework.ws'), ('spring-cloud-', 'org.springframework.cloud'),
    ('spring-batch-', 'org.springframework.batch'), ('spring-integration-', 'org.springframework.integration'),
    ('tomcat-embed-', 'org.apache.tomcat.embed'), ('thymeleaf-extras-', 'org.thymeleaf.extras'),
    ('reactor-netty', 'io.projectreactor.netty'), ('micrometer-', 'io.micrometer'),
    ('bcprov-', 'org.bouncycastle'), ('bcpkix-', 'org.bouncycastle'), ('bcutil-', 'org.bouncycastle'),
    ('log4j-', 'org.apache.logging.log4j'), ('slf4j-', 'org.slf4j'), ('logback-', 'ch.qos.logback'),
    ('netty-', 'io.netty'), ('bcmail-', 'org.bouncycastle'), ('bcpg-', 'org.bouncycastle'), ('bcjmail-', 'org.bouncycastle'),
    ('grpc-', 'io.grpc'), ('lucene-', 'org.apache.lucene'), ('opentelemetry-', 'io.opentelemetry'),
    ('elasticsearch-rest-client', 'org.elasticsearch.client'), ('jaeger-', 'io.jaegertracing'),
]
def guess_group(a, v):
    if a in SPRING_FW: return 'org.springframework'
    if a in EXACT_GROUP: return EXACT_GROUP[a]
    major = re.match(r'(\d+)', v or '')
    major = int(major.group(1)) if major else -1
    if a in ('jackson-databind', 'jackson-core', 'jackson-annotations') and major == 2: return 'com.fasterxml.jackson.core'
    if a == 'ehcache': return 'org.ehcache' if major >= 3 else 'net.sf.ehcache'
    if a == 'hibernate-core': return 'org.hibernate.orm' if major >= 6 else 'org.hibernate'
    if a in ('asm', 'asm-util', 'asm-tree', 'asm-commons', 'asm-analysis') and major >= 4: return 'org.ow2.asm'
    if a == 'dom4j': return 'org.dom4j' if major >= 2 else 'dom4j'
    for pre, g in PREFIX_GROUP:
        if a.startswith(pre): return g
    return ''

# ---------------------------------------------------------------- library Java -> komponen
hdr = None
for row in csv_rows(os.path.join(OUT, 'libraries.csv')):
    if hdr is None: hdr = row; continue
    r = dict(zip(hdr, row))
    if not r.get('artifact_id') or not r.get('version'): continue
    if r.get('type') == 'app' and not r.get('path_in_archive'): continue
    arch = r.get('archive', '')
    scope = scope_of_path(arch)
    if r.get('label', '').startswith('container:'): scope = 'container:' + r['label'].split(':', 1)[1].split('/')[0]
    sc = S(scope)
    loc = arch + ('!/' + r['path_in_archive'] if r.get('path_in_archive') else '')
    g, a, v = r.get('group_id', ''), r['artifact_id'], r['version']
    gsrc = 'jar'
    if not g:
        g = guess_group(a, v); gsrc = 'tebakan-nama-artifact'
        if g: sc['guessed'] = sc.get('guessed', 0) + 1
    if not g:
        sc['nopurl'] += 1
        sc['libs'].append({'name': a, 'version': v, 'purl': None, 'group': '', 'props': [('FilePath', loc), ('PkgType', 'jar')], 'eco': 'maven'})
        continue
    lp = [('FilePath', loc), ('PkgType', 'jar')]
    sc['libs'].append({'name': a, 'group': g, 'version': v, 'purl': 'pkg:maven/%s/%s@%s' % (enc(g), enc(a), enc(v, '+')),
                       'props': lp, 'eco': 'maven', 'gsrc': gsrc})
for o in rows_other:
    sc = S(o['scope'])
    name, v = o['name'], o['version']
    if o['eco'] == 'npm':
        if name.startswith('@') and '/' in name:
            g, n = name.split('/', 1); purl = 'pkg:npm/%s/%s@%s' % (enc(g), enc(n), enc(v, '+')); comp = {'group': g, 'name': n}
        else:
            purl = 'pkg:npm/%s@%s' % (enc(name), enc(v, '+')); comp = {'group': '', 'name': name}
        ptype = 'node-pkg'
    elif o['eco'] == 'pypi':
        nn = re.sub(r'[-_.]+', '-', name).lower()
        purl = 'pkg:pypi/%s@%s' % (enc(nn), enc(v, '+')); comp = {'group': '', 'name': name}; ptype = 'python-pkg'
    elif o['eco'] == 'composer':
        purl = 'pkg:composer/%s@%s' % ('/'.join(enc(x) for x in name.lower().split('/')), enc(v, '+')); comp = {'group': '', 'name': name}; ptype = 'composer'
    else:
        continue
    comp.update({'version': v, 'purl': purl, 'props': [('FilePath', o['path']), ('PkgType', ptype)], 'eco': o['eco']})
    sc['libs'].append(comp)

# ---------------------------------------------------------------- tulis SBOM per lingkup
def prop(k, v): return {'name': 'aquasecurity:trivy:' + k, 'value': U(v)}
summary = []
for scope in sorted(scopes):
    sc = scopes[scope]
    if not sc['pkgs'] and not sc['libs']: continue
    oid, over, pretty = sc['os']
    comps = []; deps = []; refs = set()
    def uref(base):
        r = base; i = 1
        while r in refs:
            i += 1; r = '%s#%d' % (base, i)
        refs.add(r); return r
    root_ref = str(uuid.uuid4())
    if sc['pkgs'] and oid:
        os_ref = str(uuid.uuid4())
        comps.append({'bom-ref': os_ref, 'type': 'operating-system', 'name': oid, 'version': over,
                      'properties': [prop('Class', 'os-pkgs'), prop('Type', oid)]})
        dl = []
        for p in sc['pkgs']:
            ref = uref(p['purl'])
            comps.append({'bom-ref': ref, 'type': 'library', 'name': p['name'], 'version': p['version'], 'purl': p['purl'],
                          'properties': [prop(k, v) for k, v in p['props']]})
            dl.append(ref)
        deps.append({'ref': os_ref, 'dependsOn': dl})
        deps.append({'ref': root_ref, 'dependsOn': [os_ref]})
    seenl = set()
    for l in sc['libs']:
        key = (l.get('purl') or (l['name'] + '@' + l['version']), dict(l['props']).get('FilePath', ''))
        if key in seenl: continue
        seenl.add(key)
        c = {'bom-ref': uref((l.get('purl') or 'nopurl:' + l['name'] + '@' + l['version']) + '?file=' + enc(key[1])[:300]),
             'type': 'library', 'name': l['name'], 'version': l['version'], 'properties': [prop(k, v) for k, v in l['props']]}
        if l.get('group'): c['group'] = l['group']
        if l.get('purl'): c['purl'] = l['purl']
        if l.get('gsrc') == 'tebakan-nama-artifact':
            c['properties'].append({'name': 'assess:groupIdSource', 'value': 'tebakan-nama-artifact'})
        comps.append(c)
    nlib = len(seenl)
    bom = {'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1, 'serialNumber': 'urn:uuid:' + str(uuid.uuid4()),
           'metadata': {'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                        'tools': [{'vendor': 'internal', 'name': 'assess.sh', 'version': SVER}],
                        'component': {'bom-ref': root_ref, 'type': 'container' if scope != 'host' else 'application',
                                      'name': '%s/%s' % (HOST, scope)}},
           'components': comps, 'dependencies': deps}
    fname = 'host.cdx.json' if scope == 'host' else 'container-%s.cdx.json' % re.sub(r'[^A-Za-z0-9._-]', '_', scope.split(':', 1)[1])
    wjson(os.path.join(OUT, 'sbom', fname), bom)
    summary.append('%-34s OS=%s %s | paket OS: %d | library: %d (groupId ditebak dari nama: %d; tanpa groupId, tidak bisa dicocokkan Trivy: %d)' % (
        fname, oid or '?', over, len(sc['pkgs']), nlib, sc.get('guessed', 0), sc['nopurl']))
    if sc['pkgs'] and not oid:
        emit(','.join(q(x) for x in [HOST, 'SBOM', 'SBOM-OS-01', 'INFO', 'Jenis OS tidak dikenali, paket OS tidak masuk SBOM', scope, 'Periksa /etc/os-release pada lingkup ini.']))
with io.open(os.path.join(OUT, 'sbom', 'RINGKASAN.txt'), 'w', encoding='utf-8') as f:
    f.write('SBOM CycloneDX 1.5 - satu file per lingkup (Trivy hanya menerima satu OS per SBOM)\n\n')
    f.write('\n'.join(summary) + '\n')
tot_nop = sum(sc['nopurl'] for sc in scopes.values())
emit(','.join(q(x) for x in [HOST, 'SBOM', 'SBOM-01', 'INFO', '%d file SBOM dibuat (folder sbom/)' % len(summary),
      ' ; '.join(s.split(' OS=')[0].strip() for s in summary), 'Pindai tiap file dengan: trivy sbom --skip-db-update --offline-scan <file>']))
tot_guess = sum(sc.get('guessed', 0) for sc in scopes.values())
if tot_guess:
    emit(','.join(q(x) for x in [HOST, 'SBOM', 'SBOM-03', 'INFO', '%d library Java diberi groupId dari nama artifact (mis. Spring, Tomcat, POI)' % tot_guess,
          'ditandai assess:groupIdSource=tebakan-nama-artifact di SBOM', 'Library ini sekarang ikut dicek Trivy. Bila ada hasil yang janggal, cocokkan groupId-nya dengan isi jar.']))
if tot_nop:
    emit(','.join(q(x) for x in [HOST, 'SBOM', 'SBOM-02', 'INFO', '%d library Java tanpa groupId dan tidak dikenali (mis. library internal)' % tot_nop,
          'lihat libraries.csv kolom version_source', 'Library ini tidak bisa dicocokkan Trivy lewat SBOM; dinilai manual dari inventaris.']))
warn('SBOM: %d file, %d library non-Java, %d paket OS' % (len(summary), len(rows_other), len(ospk_rows)))
PYEOF
  [ -s "$OUT/sbom/RINGKASAN.txt" ] && cp "$OUT/sbom/RINGKASAN.txt" "$RAW/sbom_ringkasan.txt"
  grep -qE 'Traceback|Error' "$RAW/sbom_errors.txt" 2>/dev/null && log "PERINGATAN: pembuatan SBOM bermasalah (lihat raw/sbom_errors.txt)"
  rm -rf "$OUT/.ospk" "$OUT/.otherapps" "$OUT/.cinsp_fs.json" "$OUT/.cfs_source"
  return 0
}

#------------------------------------------------------------------------------
# APLIKASI JAVA DI DALAM CONTAINER (dibaca lewat rootfs container, tanpa exec)
#------------------------------------------------------------------------------
check_container_java() {
  local pid="$1" cid name root cmd exe jh jar cwd label user jv cfg base x
  cid=$(pid_container "$pid"); name=$(ctr_name "$cid"); root=$(ctr_root "$cid")
  [ -z "$name" ] && name="ctr-$cid"
  if [ -z "${ASSESS_TEST_CTR_ROOT:-}" ] && { [ -z "$root" ] || [ ! -d "$root/" ]; }; then root="/proc/$pid/root"; fi
  cmd=$(pid_cmd "$pid"); exe=$(readlink "/proc/$pid/exe" 2>/dev/null); exe=${exe% (deleted)}
  cwd=$(readlink "/proc/$pid/cwd" 2>/dev/null); user=$(pid_user "$pid")
  label="container:$name"
  log "Cek aplikasi Java dalam container: $name (PID $pid)"
  ROLES="$ROLES java@$name"
  # versi Java dari file release di JAVA_HOME container
  jh=${exe%/bin/java}; jh=${jh%/jre}
  jv=$(sed -n 's/^JAVA_VERSION="\(.*\)"/\1/p' "$root$jh/release" 2>/dev/null | head -n 1)
  { echo "PID   : $pid (container $name, image $(ctr_image "$cid"))"; echo "User  : $user"; echo "Java  : $exe (versi ${jv:-?})"; echo "CWD   : $cwd"
    echo "CMDLINE:"; echo "$cmd" | redact; echo "LISTEN:"; listen_of_pid "$pid"; } > "$RAW/java_container_${name}_${pid}.txt"
  if [ -n "$jv" ]; then
    x=${jv%%.*}; [ "$x" = 1 ] && x=$(echo "$jv" | cut -d. -f2)
    case "$x" in
      5|6|7) finding HIGH JAVA-EOL-01 Container "Java versi lama (EOL) di dalam container" "$label: Java $jv" "Bangun ulang image dengan base JDK LTS yang didukung (17/21/25)." ;;
      9|10|12|13|14|15|16|18|19|20|22|23|24) finding HIGH JAVA-EOL-02 Container "Java non-LTS yang sudah EOL di dalam container" "$label: Java $jv" "Bangun ulang image dengan base JDK LTS (17/21/25)." ;;
      *) finding INFO JAVA-VER-01 Container "Versi Java dalam container" "$label: Java $jv ($exe)" "Bangun ulang image secara berkala agar mendapat update JDK terbaru." ;;
    esac
  fi
  echo "$cmd" | grep -q 'jmxremote.authenticate=false' && finding HIGH JAVA-JMX-01 Container "JMX remote tanpa autentikasi (bisa RCE)" "$label (PID $pid)" \
    "Aktifkan jmxremote.authenticate=true + SSL, atau jangan publikasikan port JMX."
  echo "$cmd" | grep -qE 'jdwp|-Xdebug|-Xrunjdwp' && finding HIGH JAVA-DEBUG-01 Container "Remote debug (JDWP) aktif di dalam container" "$label (PID $pid)" \
    "Hapus opsi -agentlib:jdwp/-Xdebug dari perintah start image."
  if [ ! -r "$root/" ] || [ -z "$(ls "$root/" 2>/dev/null)" ]; then
    finding HIGH CNT-FS-02 Container "Isi container tidak bisa dibaca dari host: library aplikasi di container ini TIDAK diperiksa" "$label (PID $pid, rootfs $root)" \
      "Jalankan ulang: sudo bash assess.sh --docker-user <user pemilik docker>. Bila tetap muncul, kirim hasil: ls -la /proc/$pid/root/"
    return 0
  fi
  case "$cmd" in
    *jboss-modules.jar*|*jboss.home.dir*)
      jh=$(arg_val "$pid" "-Djboss.home.dir"); base=$(arg_val "$pid" "-Djboss.server.base.dir"); [ -z "$base" ] && base="$jh/standalone"
      x=$(arg_next "$pid" "-c"); [ -z "$x" ] && x=$(arg_val "$pid" "--server-config")
      [ -d "$root$jh" ] && { run_path "$root$jh/modules"; wildfly_static "$root$jh" "$root$base" "$x" "" "$pid"; } ;;
    *)
      jar=$(arg_next "$pid" "-jar")
      [ -n "$jar" ] && [ "${jar#/}" = "$jar" ] && jar="$cwd/$jar"
      if [ -n "$jar" ] && [ -f "$root$jar" ]; then
        cfg="$OUT/.cfg.$$"; : > "$cfg"
        run_path "$root$jar"; scan_app_archive "$root$jar" "$label" "$cfg"
        for x in "$root$cwd"/application*.properties "$root$cwd"/application*.y*ml "$root$cwd"/config/application*; do
          [ -f "$x" ] && { echo "##### $x"; cat "$x"; echo; } >> "$cfg"
        done
        finish_spring_config "$cfg" "$name"
      fi ;;
  esac
  return 0
}

#------------------------------------------------------------------------------
# FILE KONFIGURASI CONTAINER (Dockerfile / Compose) -> folder config/, secret disamarkan
#------------------------------------------------------------------------------
redact_cfg() {
  redact | sed -E \
    -e 's/^([[:space:]]*(ENV|ARG)[[:space:]]+[A-Za-z0-9_]*(PASS|SECRET|TOKEN|KEY|CRED)[A-Za-z0-9_]*)[[:space:]]+[^[:space:]=]+[[:space:]]*$/\1 REDACTED/I' \
    -e 's/\*\*\*\*/REDACTED/g'
}

collect_container_configs() {
  local list="$OUT/.cfgfiles" f n=0 d id x sub
  : > "$list.all"
  [ -s "$list" ] && cat "$list" >> "$list.all"
  # file compose milik container yang sedang berjalan (dari label compose)
  if [ -s "$OUT/.clabels" ]; then
    while IFS=$'\t' read -r id x d; do
      echo "$x" | tr ',' '\n' | while read -r f; do
        [ -z "$f" ] && continue
        [ "${f#/}" = "$f" ] && f="$d/$f"
        echo "$f"
      done >> "$list.all"
      [ -n "$d" ] && for f in "$d"/Dockerfile* "$d"/*.dockerfile "$d"/Containerfile; do [ -f "$f" ] && echo "$f"; done >> "$list.all"
    done < "$OUT/.clabels"
  fi
  sort -u "$list.all" | grep -vE '/(node_modules|vendor|\.git|site-packages)/|^/usr/(share|lib|lib64)/|^/var/lib/(docker|containers|containerd)/|/assess-[^/]+/config/' > "$list.sorted"
  mkdir -p "$OUT/config"
  : > "$OUT/config/INDEX.txt"
  while read -r f; do
    [ -f "$f" ] || continue
    [ "$(stat -c %s "$f" 2>/dev/null || echo 0)" -gt 1048576 ] && continue
    n=$((n+1)); [ "$n" -gt 300 ] && break
    sub=$(printf '%03d' "$n")
    mkdir -p "$OUT/config/$sub"
    redact_cfg < "$f" > "$OUT/config/$sub/$(basename "$f")"
    printf '%s\t%s\n' "$sub/$(basename "$f")" "$f" >> "$OUT/config/INDEX.txt"
  done < "$list.sorted"
  rm -f "$list" "$list.all" "$list.sorted"
  if [ "$n" -eq 0 ]; then rmdir "$OUT/config" 2>/dev/null; rm -rf "$OUT/config"; return 0; fi
  cp "$OUT/config/INDEX.txt" "$RAW/config_files_index.txt"
  finding INFO CFG-01 Konfigurasi "$n file Dockerfile/Compose dikumpulkan (folder config/, secret disamarkan)" "$(cut -f2 "$OUT/config/INDEX.txt" | head -n 8 | tr '\n' ' ')" \
    "Pindai di mesin analisis: trivy config --skip-check-update config/ . Dockerfile yang hanya ada di repositori Git perlu dipindai dari repositori."
  check_compose_files
}

# Pemeriksaan sederhana file Compose (Trivy tidak punya aturan khusus Compose)
check_compose_files() {
  local idx f orig hit
  while IFS=$'\t' read -r idx orig; do
    f="$OUT/config/$idx"
    case "$(basename "$f")" in *compose*.yml|*compose*.yaml) ;; *) continue ;; esac
    hit=$(grep -nE '^\s*privileged:\s*true' "$f" | head -n 3 | tr '\n' ';')
    [ -n "$hit" ] && finding CRITICAL CMP-PRIV-01 Konfigurasi "Compose: service dijalankan privileged" "$orig: $hit" "Hapus 'privileged: true'; beri cap_add spesifik bila perlu."
    hit=$(grep -nE 'docker\.sock' "$f" | head -n 3 | tr '\n' ';')
    [ -n "$hit" ] && finding CRITICAL CMP-SOCK-01 Konfigurasi "Compose: docker.sock di-mount ke service" "$orig: $hit" "Jangan mount docker.sock ke container aplikasi (setara root di host)."
    hit=$(grep -nE '^\s*(network_mode|pid|ipc):\s*"?host"?' "$f" | head -n 3 | tr '\n' ';')
    [ -n "$hit" ] && finding HIGH CMP-NS-01 Konfigurasi "Compose: service memakai namespace host" "$orig: $hit" "Hapus network_mode/pid/ipc: host kecuali benar-benar diperlukan."
    hit=$(grep -nE '^\s*-\s*(SYS_ADMIN|ALL|SYS_PTRACE|SYS_MODULE|NET_ADMIN|DAC_READ_SEARCH)\s*$' "$f" | head -n 3 | tr '\n' ';')
    [ -n "$hit" ] && finding HIGH CMP-CAP-01 Konfigurasi "Compose: capability berbahaya ditambahkan" "$orig: $hit" "Hapus capability ini kecuali dibutuhkan."
    hit=$(awk '/^[[:space:]]*image:/{v=$2; gsub(/["\047]/,"",v); n=split(v,a,"/"); t=a[n]; if ((t !~ /:/ || t ~ /:latest$/) && v !~ /@sha256:/) print NR": "v}' "$f" | head -n 3 | tr '\n' ';')
    [ -n "$hit" ] && finding LOW CMP-IMG-01 Konfigurasi "Compose: image tanpa versi tetap (:latest / tanpa tag)" "$orig: $hit" "Pin image ke tag versi + digest."
    hit=$(grep -nE '^\s*-\s*"?(0\.0\.0\.0:)?[0-9]+:[0-9]+' "$f" | grep -v '127\.0\.0\.1' | head -n 4 | tr '\n' ';')
    [ -n "$hit" ] && finding LOW CMP-PORT-01 Konfigurasi "Compose: port dipublikasikan ke semua interface" "$orig: $hit" "Tulis 127.0.0.1:PORT:PORT bila hanya diakses reverse proxy lokal, atau batasi dengan firewall."
    hit=$(grep -ciE '(pass(word|wd)?|secret|token|api[_-]?key)[A-Za-z0-9_.-]*[[:space:]]*[=:][[:space:]]*[^$[:space:]]' "$orig" 2>/dev/null)
    [ "${hit:-0}" -gt 0 ] && finding MEDIUM CMP-SECRET-01 Konfigurasi "Compose: $hit nilai secret tertulis langsung di file" "$orig" "Pindahkan ke Docker secrets atau file env ber-permission 600 di luar repositori."
    grep -qE '^\s*user:' "$f" || finding LOW CMP-USER-01 Konfigurasi "Compose: tidak ada service yang menetapkan user non-root" "$orig" "Tambahkan 'user: UID:GID' pada tiap service, atau USER di Dockerfile."
  done < "$OUT/config/INDEX.txt"
}

# Image yang tersimpan tapi tidak dipakai, container berhenti, dan riwayat build image
check_idle_images() {
  local used all idle stopped
  if [ "$CRT_SRC" = fs ]; then
    [ -s "$OUT/.cstopped" ] && finding LOW CNT-STOP-01 Container "$(wc -l < "$OUT/.cstopped") container berhenti masih tersimpan" "$(head -n 8 "$OUT/.cstopped" | tr '\n' ';')" \
      "Hapus container yang tidak dipakai (docker rm). Container berhenti masih menyimpan filesystem dan environment variable-nya."
    return 0
  fi
  [ "$CRT_SRC" = cli ] || return 0
  "${CRT_CMD[@]}" ps -a --no-trunc --format '{{.Image}}' 2>/dev/null | sort -u > "$OUT/.imgused"
  "${CRT_CMD[@]}" ps -aq 2>/dev/null | while read -r x; do "${CRT_CMD[@]}" inspect -f '{{.Image}}' "$x" 2>/dev/null; done | sed 's/^sha256://' | cut -c1-12 | sort -u >> "$OUT/.imgused"
  "${CRT_CMD[@]}" images --format '{{.ID}}	{{.Repository}}:{{.Tag}}	{{.CreatedSince}}	{{.Size}}' 2>/dev/null > "$OUT/.imgall"
  idle=$(awk -F'\t' 'NR==FNR{u[$1]=1; next} !(substr($1,1,12) in u) && !($2 in u){print $2 " (" $3 ", " $4 ")"}' "$OUT/.imgused" "$OUT/.imgall")
  if [ -n "$idle" ]; then
    echo "$idle" > "$RAW/container_images_idle.txt"
    finding LOW CNT-IDLE-01 Container "$(echo "$idle" | wc -l) image tersimpan tetapi tidak dipakai container mana pun" "$(echo "$idle" | head -n 8 | tr '\n' ';')" \
      "Hapus image yang tidak dipakai (docker image rm / docker image prune). Image lama menyimpan library rentan dan bisa dijalankan kembali."
  fi
  stopped=$("${CRT_CMD[@]}" ps -a --filter status=exited --filter status=created --format '{{.Names}} ({{.Image}}, {{.Status}})' 2>/dev/null)
  [ -n "$stopped" ] && finding LOW CNT-STOP-01 Container "$(echo "$stopped" | wc -l) container berhenti masih tersimpan" "$(echo "$stopped" | head -n 8 | tr '\n' ';')" \
    "Hapus container yang tidak dipakai (docker rm). Container berhenti masih menyimpan filesystem dan environment variable-nya."
  # riwayat build (pengganti Dockerfile bila tidak ada di server); secret disamarkan
  cut -f2 "$OUT/.imgall" | grep -v '<none>' | sort -u | head -n 40 | while read -r x; do
    echo "##### $x"; "${CRT_CMD[@]}" history --no-trunc --format '{{.CreatedBy}}' "$x" 2>/dev/null | redact_cfg | cut -c1-400; echo
  done > "$RAW/container_image_history.txt" 2>/dev/null
  [ -s "$RAW/container_image_history.txt" ] || rm -f "$RAW/container_image_history.txt"
  rm -f "$OUT/.imgused" "$OUT/.imgall"
}

#------------------------------------------------------------------------------
# INDIKASI KOMPROMI (IOC) - semua temuan di sini PERLU DIVERIFIKASI manusia
#------------------------------------------------------------------------------
check_ioc() {
  log "Cek indikasi kompromi (IOC)"
  local f x n hit list="$RAW/ioc_detail.txt" jh base dep cls jsp content
  : > "$list"

  # 1. File SUID/SGID tersembunyi atau di lokasi tidak wajar, dan salinan shell ber-SUID
  { [ -s "$RAW/fs_suid_sgid.txt" ] && cat "$RAW/fs_suid_sgid.txt"
    find /tmp /var/tmp /dev/shm /usr/libexec /usr/local /opt /home /root /data -xdev -maxdepth 5 -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null
  } | sort -u > "$OUT/.suid"
  while read -r f; do
    [ -f "$f" ] || continue
    hit=""
    case "$(basename "$f")" in .*) hit="nama tersembunyi" ;; esac
    case "$f" in /tmp/*|/var/tmp/*|/dev/shm/*|/home/*|/root/*|/data/*) hit="${hit:+$hit, }lokasi tidak wajar" ;; esac
    for x in /bin/bash /usr/bin/bash /bin/sh /bin/dash /usr/bin/dash; do
      [ -f "$x" ] && [ "$(readlink -f "$x")" != "$(readlink -f "$f")" ] && cmp -s "$x" "$f" && { hit="${hit:+$hit, }isi identik dengan shell $x"; break; }
    done
    if [ -n "$hit" ] && ! rpm -qf "$f" >/dev/null 2>&1; then
      echo "SUID: $f | $hit | $(stat -c '%U:%G %a ubah=%y status=%z' "$f" 2>/dev/null)" >> "$list"
      finding CRITICAL IOC-SUID-01 IOC "File SUID/SGID mencurigakan ($hit)" "$f ($(stat -c '%U %a, status berubah %z' "$f" 2>/dev/null | cut -c1-60))" \
        "JANGAN dihapus dulu. Simpan salinan + hash sebagai bukti, cek asal-usulnya, lalu ikuti prosedur insiden. SUID shell tersembunyi adalah pola backdoor root."
    fi
  done < "$OUT/.suid"
  rm -f "$OUT/.suid"

  # 2. File tersembunyi di folder sementara (alat/skrip penyerang biasa ditaruh di sini)
  find /tmp /var/tmp /dev/shm -xdev -maxdepth 3 -type f -name '.*' 2>/dev/null \
    | grep -vE '/\.(X11-unix|ICE-unix|font-unix|XIM-unix|Test-unix)/|/\.(s\.PGSQL|java_pid|com_ibm|lock|X[0-9]+-lock)|/hsperfdata_' | grep -vF -- "$OUT/" > "$OUT/.hid"
  n=$(wc -l < "$OUT/.hid")
  if [ "$n" -gt 0 ]; then
    while read -r f; do echo "HIDDEN: $(stat -c '%U %a %s byte ubah=%y' "$f" 2>/dev/null | cut -c1-70) $f"; done < "$OUT/.hid" >> "$list"
    x=MEDIUM; [ "$n" -ge 5 ] && x=HIGH
    grep -qE '\.(sh|py|pl|elf|so)$' "$OUT/.hid" && x=HIGH
    finding "$x" IOC-TMP-01 IOC "$n file tersembunyi di /tmp, /var/tmp atau /dev/shm" "$(head -n 10 "$OUT/.hid" | tr '\n' ' ')" \
      "Periksa isi dan pemilik tiap file (detail di raw/ioc_detail.txt). Skrip/biner tersembunyi di folder sementara adalah pola umum pasca-eksploitasi."
  fi
  rm -f "$OUT/.hid"

  # 3. Proses berjalan dari lokasi tidak wajar / biner sudah dihapus
  for x in /proc/[0-9]*; do
    f=$(readlink "$x/exe" 2>/dev/null) || continue
    case "$f" in
      /tmp/*|/var/tmp/*|/dev/shm/*) echo "PROC: PID ${x#/proc/} berjalan dari $f | $(pid_cmd "${x#/proc/}" | redact | cut -c1-150)" >> "$list"
        finding HIGH IOC-PROC-01 IOC "Proses berjalan dari folder sementara" "PID ${x#/proc/}: $f" "Periksa proses ini segera (pemilik, induk, koneksi jaringan). Jangan di-kill sebelum buktinya diamankan." ;;
      *" (deleted)") case "$f" in /memfd:*|/tmp/*|/dev/shm/*|/var/tmp/*)
          echo "PROC: PID ${x#/proc/} biner terhapus $f" >> "$list"
          finding HIGH IOC-PROC-02 IOC "Proses berjalan dari biner yang sudah dihapus / dari memori" "PID ${x#/proc/}: $f" "Periksa proses ini segera; biner yang dihapus setelah dijalankan adalah teknik menyembunyikan jejak." ;; esac ;;
    esac
  done
  # shell/interpreter yang menjadi anak proses Java (pola webshell)
  for x in $(java_pids); do
    hit=$(ps -o pid=,comm=,args= --ppid "$x" 2>/dev/null | awk '$2 ~ /^(sh|bash|dash|nc|ncat|curl|wget|perl|python[0-9.]*)$/' | cut -c1-160 | head -n 3 | tr '\n' ';')
    if [ -n "$hit" ]; then
      echo "PROC: anak dari java PID $x: $hit" >> "$list"
      finding HIGH IOC-PROC-03 IOC "Proses Java memiliki anak proses shell/interpreter" "java PID $x -> $hit" \
        "Pastikan ini memang perilaku aplikasi. Shell yang lahir dari proses app server adalah pola webshell/RCE."
    fi
  done

  # 4. Jejak exploit di log autentikasi
  hit=$(grep -hE 'pwnkit|PWNKIT|GCONV_PATH=' /var/log/secure* /var/log/auth.log* 2>/dev/null | head -n 3 | cut -c1-200 | tr '\n' ';')
  if [ -n "$hit" ]; then
    echo "LOG: $hit" >> "$list"
    finding CRITICAL IOC-LOG-01 IOC "Jejak exploit PwnKit (CVE-2021-4034) di log" "$hit" \
      "Anggap server berpotensi sudah dikuasai root. Amankan log, periksa file SUID dan cron, ikuti prosedur insiden."
  fi

  # 5. Persistensi
  if [ -s /etc/ld.so.preload ]; then
    echo "PERSIST: /etc/ld.so.preload = $(tr '\n' ' ' < /etc/ld.so.preload)" >> "$list"
    finding HIGH IOC-PERSIST-01 IOC "/etc/ld.so.preload berisi library (dimuat ke semua proses)" "$(tr '\n' ' ' < /etc/ld.so.preload | cut -c1-200)" \
      "Verifikasi tiap library di file ini; ld.so.preload sering dipakai rootkit userland."
  fi
  hit=$(grep -rhE '(/tmp/|/dev/shm/|/var/tmp/|base64 -d|bash -i|/dev/tcp/|curl[^|]*\|\s*(ba)?sh|wget[^|]*\|\s*(ba)?sh)' /etc/crontab /etc/cron.d /var/spool/cron 2>/dev/null | grep -vE '^\s*#' | head -n 5 | cut -c1-200 | tr '\n' ';')
  if [ -n "$hit" ]; then
    echo "PERSIST: cron: $hit" >> "$list"
    finding HIGH IOC-PERSIST-02 IOC "Cron menjalankan perintah dari folder sementara / pola unduh-eksekusi" "$hit" \
      "Verifikasi tiap entri cron ini dengan pemilik sistem."
  fi
  hit=$(find /var/spool/cron /etc/cron.d /root/.ssh /home/*/.ssh -maxdepth 2 -type f -mtime -30 2>/dev/null | head -n 10 | tr '\n' ' ')
  if [ -n "$hit" ]; then
    echo "PERSIST: berubah < 30 hari: $hit" >> "$list"
    finding LOW IOC-PERSIST-03 IOC "File cron / kunci SSH berubah dalam 30 hari terakhir" "$hit" "Pastikan perubahannya sah (ada tiket/perubahan terencana)."
  fi
  hit=$(ls -d /home/*/.config/systemd/user/*.service /root/.config/systemd/user/*.service 2>/dev/null | head -n 10 | tr '\n' ' ')
  if [ -n "$hit" ]; then
    echo "PERSIST: unit systemd user: $hit" >> "$list"
    finding MEDIUM IOC-PERSIST-04 IOC "Unit systemd tingkat user ditemukan" "$hit" \
      "Verifikasi asal tiap unit. Malware (termasuk muatan insiden Trivy Maret 2026) memakai unit systemd user untuk persistensi."
  fi

  # 6. WildFly: deployment yang pernah aktif tapi tidak terdaftar, dan JSP terkompilasi yang tidak ada di paket deployment
  for jh in $(echo "$WF_SEEN" | tr ' ' '\n' | grep -v '^$'); do
    for base in "$jh/standalone"; do
      [ -d "$base" ] || continue
      f="$RAW/wildfly_$(basename "$jh")_deployment_map.txt"
      for x in "$base"/deployments/*.undeployed "$base"/deployments/*.failed; do
        [ -f "$x" ] || continue
        dep=$(basename "$x"); dep=${dep%.undeployed}; dep=${dep%.failed}
        grep -q " $dep\$" "$f" 2>/dev/null && continue
        echo "WILDFLY: penanda $x ($(stat -c %y "$x" 2>/dev/null | cut -c1-19))" >> "$list"
        finding HIGH IOC-WF-01 IOC "WildFly: ada jejak deployment yang tidak terdaftar ($dep)" "$x, $(stat -c %y "$x" 2>/dev/null | cut -c1-19)" \
          "Cari tahu siapa yang men-deploy $dep dan kapan (server.log). Deployment singkat lalu dihapus adalah pola pemasangan webshell."
      done
      hit=$(grep -hoE 'Deployed "[^"]+"' "$base"/log/server.log* 2>/dev/null | sort -u | sed 's/Deployed "//; s/"$//' | while read -r dep; do
              grep -q " $dep\$" "$f" 2>/dev/null || echo "$dep"; done | head -n 8 | tr '\n' ' ')
      if [ -n "$hit" ]; then
        echo "WILDFLY: pernah di-deploy tapi tidak terdaftar sekarang: $hit" >> "$list"
        finding MEDIUM IOC-WF-02 IOC "WildFly: deployment di log yang tidak terdaftar sekarang" "$(basename "$jh"): $hit" \
          "Pastikan tiap nama adalah rilis lama yang sah. Nama yang tidak dikenal perlu ditelusuri di server.log."
      fi
      # JSP terkompilasi vs isi paket
      for dep in "$base"/tmp/*.war "$base"/tmp/*.ear; do
        [ -d "$dep/org/apache/jsp" ] || continue
        x=$(awk -v n="$(basename "$dep")" '$3==n{print $1; exit}' "$f" 2>/dev/null)
        content="$base/data/content/${x:0:2}/${x:2}/content"
        [ -n "$x" ] && [ -f "$content" ] || continue
        zip_list "$content" > "$OUT/.wfz" 2>/dev/null
        find "$dep/org/apache/jsp" -name '*_jsp.class' 2>/dev/null | while read -r cls; do
          jsp=${cls#$dep/org/apache/jsp/}; jsp=${jsp%_jsp.class}; jsp=$(echo "$jsp" | sed 's/_005f/_/g; s/_002d/-/g; s/_002e/./g')
          grep -qF "$jsp.jsp" "$OUT/.wfz" || echo "$jsp.jsp ($(stat -c %y "$cls" 2>/dev/null | cut -c1-16))"
        done > "$OUT/.wfj"
        if [ -s "$OUT/.wfj" ]; then
          hit=$(head -n 6 "$OUT/.wfj" | tr '\n' ';')
          echo "WILDFLY: JSP terkompilasi yang tidak ada di paket $(basename "$dep"): $hit" >> "$list"
          finding CRITICAL IOC-WF-03 IOC "WildFly: JSP pernah dijalankan tetapi tidak ada di paket deployment (indikasi webshell)" "$(basename "$dep"): $hit" \
            "JANGAN restart/hapus dulu. Amankan folder standalone/tmp dan log, lalu ikuti prosedur insiden."
        fi
        rm -f "$OUT/.wfz" "$OUT/.wfj"
      done
    done
  done
  [ -s "$list" ] || { rm -f "$list"; echo "Tidak ada indikasi kompromi yang terdeteksi oleh pemeriksaan otomatis (bukan jaminan bersih)." > "$list"; }
  return 0
}

# Ganti prefix rootfs container (/proc/PID/root) dengan nama yang terbaca di semua hasil
prettify_container_paths() {
  [ -s "$OUT/.cmap" ] || return 0
  local id name _i pid f
  while IFS=$'\t' read -r id name _i pid; do
    [ -n "$pid" ] && [ "$pid" != 0 ] || continue
    for f in "$OUT"/*.csv "$OUT"/*.txt "$RAW"/*.txt "$OUT"/sbom/*.json "$OUT"/config/INDEX.txt; do
      [ -f "$f" ] && grep -q "/proc/$pid/root" "$f" 2>/dev/null && sed -i "s#/proc/$pid/root#[container:$name]#g" "$f"
    done
  done < "$OUT/.cmap"
  { echo "id	nama	image	pid"; cat "$OUT/.cmap"; } > "$RAW/container_map.txt"
  rm -f "$OUT/.cmap"
}

#------------------------------------------------------------------------------
# BASELINE VERSI LIBRARY: tandai library di bawah versi yang disetujui tim.
# Membuat assessment menyesuaikan rencana patching tanpa mengubah script.
# Format file baseline (1 baris per aturan):
#   artifactId            versi_minimum_disetujui   [severity]
#   groupId:artifactId    versi_minimum_disetujui   [severity]
#   # baris diawali # diabaikan; severity default MEDIUM
#------------------------------------------------------------------------------
check_lib_baseline() {
  [ -n "$LIB_BASELINE" ] && [ -f "$LIB_BASELINE" ] || return 0
  [ -s "$OUT/libraries.csv" ] || return 0
  [ -n "$PY" ] || { log "Baseline library dilewati (python tidak ada)"; return 0; }
  log "Bandingkan library dengan baseline versi yang disetujui: $LIB_BASELINE"
  cp "$LIB_BASELINE" "$RAW/lib_baseline_used.txt"
  "$PY" - "$OUT/libraries.csv" "$LIB_BASELINE" "$RAW/running_paths.txt" <<'PYEOF' >> "$FINDINGS"
from __future__ import print_function
import sys, csv, io, re
def vkey(v):
    k = []
    for p in re.findall(r'\d+|[A-Za-z]+', v or ''):
        if p.isdigit(): k.append((1, int(p)))
        elif p.lower() not in ('final','release','ga','sp'): k.append((0, p.lower()))
    return k
def q(x): return '"' + str(x).replace('"','""') + '"'
rules = []
for line in io.open(sys.argv[2], encoding='utf-8', errors='replace'):
    line = line.strip()
    if not line or line.startswith('#'): continue
    p = line.split()
    if len(p) < 2: continue
    rules.append((p[0], p[1], (p[2].upper() if len(p) > 2 else 'MEDIUM')))
running = []
try: running = [l.strip() for l in io.open(sys.argv[3], encoding='utf-8', errors='replace') if l.strip()]
except Exception: pass
def active(path): return any(path == r or path.startswith(r.rstrip('/')+'/') for r in running)
seen = set()
for row in csv.DictReader(io.open(sys.argv[1], encoding='utf-8', errors='replace')):
    g, a, v = row.get('group_id',''), row.get('artifact_id',''), row.get('version','')
    if not v: continue
    for (lib, minv, sev) in rules:
        if ':' in lib:
            if lib != '%s:%s' % (g, a): continue
        elif lib != a: continue
        if vkey(v) >= vkey(minv): continue
        act = active(row.get('archive',''))
        key = (a, v, row.get('label',''))
        if key in seen: continue
        seen.add(key)
        label = row.get('label','') + ('' if act else ' [arsip tidak dipakai proses berjalan]')
        s = sev if act else 'LOW'
        print(','.join(q(x) for x in [row.get('host',''), 'Library', 'LIB-DRIFT-'+a, s,
              'Library di bawah baseline versi yang disetujui (%s < %s)' % (a, minv),
              '%s: %s:%s:%s di %s' % (row.get('label',''), g, a, v, label),
              'Upgrade %s ke >= %s sesuai baseline tim, rebuild & redeploy.' % (a, minv)]))
PYEOF
}


main() {
  ask_paths
  log "Mulai assessment $HOST (assess.sh v$SCRIPT_VERSION)"
  [ "$SAFE" -eq 1 ] && log "Mode --safe: tanpa scan filesystem, tanpa request jaringan lokal, tanpa inventaris modules WildFly"
  echo 'host,category,check_id,severity,title,evidence,recommendation' > "$FINDINGS"
  build_container_map
  build_prune_expr
  check_os
  check_ssh
  check_accounts
  check_hardening
  check_network
  check_fs
  discover_running_apps
  discover_other_runtimes
  check_unknown_listeners
  check_docker_access
  detect_and_check_roles
  check_manual_paths
  check_extra
  collect_os_packages
  collect_container_configs
  check_idle_images
  check_ioc
  ctr_bind_running
  check_container_storage
  run_lib_inventory
  check_lib_baseline
  build_inventory_and_sbom
  prettify_container_paths
  write_summary
  anonymize_output
  package_output
}

main
