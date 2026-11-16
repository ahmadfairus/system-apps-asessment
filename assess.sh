#!/bin/bash
#==============================================================================
# assess.sh - Assessment keamanan server (READ-ONLY), SATU script SATU output
# Versi : 4.0   Target: CentOS/RHEL 7 (juga RHEL/Rocky/Alma 8-9)
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

SCRIPT_VERSION="4.0"
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
run_path() { [ -n "$1" ] && readlink -f "$1" >> "$OUT/.running" 2>/dev/null; return 0; }
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
listen_of_pid() { ss -tlnp 2>/dev/null | awk -v p="pid=$1," 'index($0,p){print $4}' | sort -u; }

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
reg_archive() { [ -f "$2" ] && printf '%s\t%s\n' "$1" "$(readlink -f "$2")" >> "$OUT/.archives"; return 0; }

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
    NOT_SECRET_KEY = re.compile(r'(restriction|policy|checker|forbidden|min|max|length|expir|valid|encoder|algorithm|class|enabled|file|path|url|uri|header|param|name|mode|type|realm|regex|pattern)', re.I)
    def secret_keys(text):
        ks = set()
        for m in SECRET_KEY.finditer(text):
            key = m.group(0).split('=')[0].split(':')[0].strip()
            val = m.group(2).strip('"\'')
            last = key.lower().replace('-', '.').replace('_', '.').split('.')[-1]
            if NOT_SECRET_KEY.search(last) and not re.search(r'(password|secret|token|key)$', last): continue
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
check_hardening() {
  log "Cek hardening sistem"
  local se; se=$(getenforce 2>/dev/null)
  case "$se" in
    Disabled)   finding MEDIUM HRD-SELINUX-01 Hardening "SELinux nonaktif" "getenforce: $se" "Aktifkan SELinux (mulai dari permissive, perbaiki denial di audit.log, lalu enforcing)." ;;
    Permissive) finding LOW HRD-SELINUX-01 Hardening "SELinux mode permissive" "getenforce: $se" "Analisis denial di audit.log lalu ubah ke enforcing." ;;
  esac

  local fwd ipt
  fwd=$(systemctl is-active firewalld 2>/dev/null)
  ipt=$(iptables -S 2>/dev/null | grep -cvE '^-P')
  { echo "firewalld: $fwd"; [ "$fwd" = active ] && firewall-cmd --list-all-zones 2>&1
    echo; echo "### iptables -S"; iptables -S 2>&1; echo; echo "### ip6tables -S"; ip6tables -S 2>&1; } > "$RAW/firewall.txt"
  if [ "$fwd" = active ] || [ "${ipt:-0}" -gt 0 ]; then FW_ON=1; else
    finding MEDIUM HRD-FW-01 Hardening "Tidak ada host firewall aktif" "firewalld: ${fwd:-n/a}; aturan iptables: ${ipt:-0}" \
      "Aktifkan firewalld dan izinkan hanya port yang diperlukan dari sumber yang diperlukan (defense in depth di belakang Palo Alto)."
  fi

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
scan_disk_archives_only() {
  local mp
  log "Mencari semua arsip Java (jar/war/ear) di seluruh disk lokal"
  for mp in $(df -lP -x tmpfs -x devtmpfs 2>/dev/null | awk 'NR>1{print $6}'); do
    timeout 1200 find "$mp" -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /var/lib/docker -o -path /var/lib/containers -o -path /var/lib/containerd \) -prune -o \
      -type f \( \( \( -iname '*.jar' -o -iname '*.war' -o -iname '*.ear' -o -iname '*.rar' \) -printf 'AR %p\n' \) , \
                  \( \( -name package-lock.json -o -name yarn.lock -o -name composer.lock -o -name requirements.txt \) -printf 'MF %p\n' \) , \
                  \( \( -name Dockerfile -o -name 'Dockerfile.*' -o -name '*.dockerfile' -o -name Containerfile -o -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' -o -name compose.yml -o -name compose.yaml \) -printf 'DF %p\n' \) , \
                  \( -path '*/bin/java' -printf 'JV %p\n' \) \) 2>/dev/null
  done > "$OUT/.disk"
  grep '^AR ' "$OUT/.disk" | cut -c4- | sort -u > "$RAW/disk_archives.txt"
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
    case "$WF_SEEN" in *" $(readlink -f "$jh") "*) continue ;; esac
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
    timeout 1200 find "$mp" -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /var/lib/docker -o -path /var/lib/containers -o -path /var/lib/containerd \) -prune -o \
      \( -type f \( \
           \( \( -iname '*.jar' -o -iname '*.war' -o -iname '*.ear' -o -iname '*.rar' \) -printf 'AR %p\n' \) , \
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
  grep '^AR ' "$tmp" | cut -c4- | sort -u > "$RAW/disk_archives.txt"
  grep '^JV ' "$tmp" | cut -c4- | sort -u > "$OUT/.javabins"
  grep '^MF ' "$tmp" | cut -c4- | sort -u > "$OUT/.manifests"
  grep '^DF ' "$tmp" | cut -c4- | sort -u > "$OUT/.cfgfiles"
  grep '^KR ' "$tmp" | cut -c4- | grep -vE '^/(usr/share|usr/lib|etc/pki/(ca-trust|java)|etc/ssl/certs)/' | sort -u > "$RAW/fs_key_readable.txt"
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

check_apache() {
  local pid bin root conffiles f
  pid=$(pgrep -o -x httpd); bin=$(pid_exe "$pid"); [ -x "$bin" ] || bin=/usr/sbin/httpd
  log "Cek Apache httpd ($bin)"
  root=$("$bin" -V 2>/dev/null | sed -n 's/.*HTTPD_ROOT="\(.*\)"/\1/p')
  if [ ! -d "$root" ]; then case "$bin" in /opt/rh/*/root/*) root="${bin%%/root/*}/root/etc/httpd" ;; *) root=/etc/httpd ;; esac; fi
  { "$bin" -v; echo; "$bin" -S; echo; "$bin" -M; } > "$RAW/httpd_info.txt" 2>&1
  conffiles=$(find "$root" -maxdepth 2 -name '*.conf' 2>/dev/null | sort)
  for f in $conffiles; do echo "##### $f"; grep -vE '^\s*(#|$)' "$f" | redact; done > "$RAW/httpd_config.txt" 2>/dev/null
  local c="$RAW/httpd_config.txt"
  grep -iE '^\s*(ProxyPass|ProxyPassReverse|BalancerMember|RewriteRule.*\[P|<VirtualHost|ServerName|SSLCertificateFile)' "$c" > "$RAW/httpd_proxy_map.txt"

  grep -qiE '^\s*ProxyRequests\s+On' "$c" && finding HIGH WEB-PROXY-01 Web "Apache aktif sebagai open forward proxy" "ProxyRequests On" \
    "Set ProxyRequests Off (reverse proxy dengan ProxyPass tidak memerlukannya)."
  grep -iE '^\s*Options\s' "$c" | grep -qiE '(^|[[:space:]+])Indexes' && finding LOW WEB-INDEX-01 Web "Directory listing (Options Indexes) aktif" \
    "$(grep -iE '^\s*Options\s' "$c" | grep -iE '(^|[[:space:]+])Indexes' | head -n3 | tr '\n' ';')" "Ganti menjadi Options -Indexes."
  grep -qiE 'SetHandler\s+server-(status|info)' "$c" && finding LOW WEB-STATUS-01 Web "mod_status/mod_info aktif" \
    "$(grep -iE 'SetHandler\s+server-(status|info)' "$c" | head -n2 | tr '\n' ';')" "Pastikan hanya bisa diakses dari IP monitoring (Require ip ...), atau nonaktifkan."
  if [ "$NO_NET" -eq 1 ]; then
    grep -qiE '^\s*ServerTokens\s+Prod' "$c" || finding LOW WEB-BANNER-01 Web "ServerTokens bukan Prod" "-" "Set ServerTokens Prod dan ServerSignature Off."
    grep -qiE '^\s*TraceEnable\s+off' "$c" || finding LOW WEB-TRACE-01 Web "TraceEnable tidak dimatikan" "-" "Set TraceEnable off."
  fi
  finding INFO WEB-VER-01 Web "Versi Apache httpd" "$("$bin" -v 2>/dev/null | head -n1)" \
    "httpd 2.4.6 bawaan CentOS 7 mendapat backport patch hanya selama OS masih didukung; ikut rencana migrasi OS."
  web_live_checks apache "$pid"
}

check_nginx() {
  local pid bin c="$RAW/nginx_config.txt"
  pid=$(pgrep -o -x nginx); bin=$(pid_exe "$pid"); [ -x "$bin" ] || bin=/usr/sbin/nginx
  log "Cek Nginx ($bin)"
  "$bin" -v > "$RAW/nginx_info.txt" 2>&1
  if ! "$bin" -T 2>/dev/null | grep -vE '^\s*(#|$)' | redact > "$c" || [ ! -s "$c" ]; then
    cat /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf 2>/dev/null | grep -vE '^\s*(#|$)' | redact > "$c"
  fi
  grep -E '^\s*(proxy_pass|upstream|server_name|listen|ssl_certificate )' "$c" > "$RAW/nginx_proxy_map.txt"
  grep -qE '^\s*autoindex\s+on' "$c" && finding LOW WEB-INDEX-01 Web "Directory listing (autoindex on) aktif" "nginx autoindex on" "Set autoindex off."
  if [ "$NO_NET" -eq 1 ]; then
    grep -qE '^\s*server_tokens\s+off' "$c" || finding LOW WEB-BANNER-01 Web "server_tokens tidak dimatikan" "-" "Set server_tokens off; di blok http."
  fi
  finding INFO WEB-VER-02 Web "Versi Nginx" "$(cat "$RAW/nginx_info.txt")" "Pastikan versi nginx masih menerima update keamanan."
  web_live_checks nginx "$pid"
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
    if [ "$FW_ON" -eq 1 ]; then d=LOW; else d=MEDIUM; fi
    finding "$d" DB-LISTEN-01 MariaDB "Database listen di interface jaringan" "listen:$exp; host firewall aktif=$FW_ON" \
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
    if [ "$FW_ON" -eq 1 ]; then d=LOW; else d=MEDIUM; fi
    finding "$d" DB-LISTEN-01 PostgreSQL "Database listen di interface jaringan" "listen:$exp; host firewall aktif=$FW_ON" \
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
  for addr in $(listen_of_pid "$pid"); do
    is_loopback "${addr%:*}" && continue
    case "${addr##*:}" in 9990|9993|9999) continue ;; esac
    exp="$exp $addr"
  done
  [ -n "$exp" ] && finding LOW JAVA-PORT-01 "$cat" "Port aplikasi bisa diakses langsung dari jaringan (bisa mem-bypass proxy)" "$label:$exp" \
    "Jika aplikasi diakses lewat reverse proxy, bind ke localhost/IP internal atau batasi port hanya dari IP proxy."
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
  rf=$(readlink -f "$1")
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
  d=$(readlink -f "$1"); [ -d "$d" ] || return 0
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
  jh=$(readlink -f "$1")
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
  local jh; jh=$(readlink -f "$1" 2>/dev/null)
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
  d=$(readlink -f "$1" 2>/dev/null)
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
    case "$ARCH_SEEN" in *" $(readlink -f "$f") "*) n=$((n+1)); continue ;; esac
    if zip_list "$f" | grep -qE '^(BOOT-INF/|WEB-INF/|META-INF/application\.xml)'; then
      scan_app_archive "$f" "$label" "$cfg" && n=$((n+1))
    else
      basename "$f" >> "$loose"; reg_archive "$label/lib" "$f"; collect_artifact "$f" "$label/lib"
    fi
  done < <(find "$d" -maxdepth 4 -type f \( -name '*.jar' -o -name '*.war' -o -name '*.ear' \) 2>/dev/null | head -n 3000)
  find "$d" -maxdepth 3 -type f \( -name 'application*.properties' -o -name 'application*.yml' -o -name 'application*.yaml' \
       -o -name 'bootstrap*.properties' -o -name 'bootstrap*.yml' \) 2>/dev/null | while read -r f; do
    echo "##### $f"; cat "$f"; echo
  done >> "$cfg"
  finish_spring_config "$cfg" "$label"
  for f in $(find "$d" -maxdepth 4 -type f -path '*/bin/java' 2>/dev/null); do java_version_check "$f" Java "$label (JRE bawaan aplikasi)"; done
  [ "$n" -eq 0 ] && [ ! -s "$loose" ] && finding INFO PATH-APP-02 Path "Tidak ada jar/war/ear di folder aplikasi" "$d" "Periksa kembali path folder aplikasi."
}

check_java_home() {
  local exe; exe="$(readlink -f "$1" 2>/dev/null)/bin/java"
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
  local CRT="" grp sock tcp md name dir jarn n depth
  if command -v docker >/dev/null 2>&1 && (pgrep -x dockerd >/dev/null 2>&1 || docker info >/dev/null 2>&1); then CRT=docker
  elif command -v podman >/dev/null 2>&1 && pgrep -x conmon >/dev/null 2>&1; then CRT=podman
  elif command -v docker >/dev/null 2>&1 && docker ps >/dev/null 2>&1; then CRT=docker
  else return 0; fi
  log "Cek container ($CRT)"
  ROLES="$ROLES $CRT"

  # --- Dump info (read-only) ---
  { echo "### $CRT version"; $CRT version 2>&1
    echo; echo "### ps -a"; $CRT ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' 2>&1
    echo; echo "### images"; $CRT images --digests --format '{{.Repository}}:{{.Tag}}\t{{.Digest}}\t{{.CreatedSince}}\t{{.Size}}' 2>&1
    echo; echo "### info (ringkas)"; $CRT info 2>/dev/null | grep -iE 'Server Version|Storage Driver|Cgroup|Rootless|Security Options|seccomp|apparmor|selinux|userns' ; } > "$RAW/container_${CRT}.txt" 2>&1

  # --- Daemon / host-level ---
  # grup docker = setara root
  grp=$(getent group docker 2>/dev/null | cut -d: -f4)
  [ -n "$grp" ] && finding HIGH CNT-GROUP-01 Container "Anggota grup 'docker' (setara akses root ke host)" "$grp" \
    "Batasi keanggotaan grup docker seminimal mungkin; setiap anggota bisa menjalankan container privileged = root. Pertimbangkan rootless Docker/Podman."
  # socket TCP tanpa TLS
  tcp=$(ss -tlnH 2>/dev/null | awk '{print $4}' | grep -E ':(2375|2376)$' | tr '\n' ' ')
  echo "$tcp" | grep -q 2375 && finding CRITICAL CNT-TCP-01 Container "Docker API diekspos via TCP 2375 tanpa TLS (kendali penuh daemon)" "$tcp" \
    "Matikan soket TCP tanpa TLS. Gunakan hanya soket unix, atau 2376 dengan TLS mutual (tlsverify)."
  echo "$tcp" | grep -q 2376 && finding MEDIUM CNT-TCP-02 Container "Docker API diekspos via TCP 2376" "$tcp" \
    "Pastikan 2376 memakai TLS mutual (--tlsverify) dan hanya dari IP admin via firewall."
  # permission socket
  for sock in /var/run/docker.sock /run/docker.sock /run/podman/podman.sock; do
    [ -S "$sock" ] || continue
    n=$(stat -c '%a' "$sock" 2>/dev/null)
    echo "$sock $n $(stat -c '%U:%G' "$sock" 2>/dev/null)" >> "$RAW/container_${CRT}.txt"
    [ $(( ${n:-0} % 10 )) -gt 0 ] && finding HIGH CNT-SOCK-02 Container "Socket container bisa diakses other (world)" "$sock mode $n" \
      "chmod 660 $sock, owner root:docker; akses other ke socket = kendali daemon."
  done

  # --- Per-container: inspect -> parser Python ---
  local running insp="$OUT/.cinsp.$$" det="$RAW/container_detail.txt" merged="$OUT/.cmerged.$$"
  running=$($CRT ps -q 2>/dev/null)
  if [ -z "$running" ]; then
    finding INFO CNT-NONE-01 Container "$CRT berjalan tetapi tidak ada container aktif" "-" "Tetap cek image tersimpan dengan Trivy (lihat raw/container_${CRT}.txt)."
  elif [ -z "$PY" ]; then
    finding INFO CNT-NOPY-01 Container "Postur container dilewati (python tidak tersedia)" "-" "Jalankan 'docker inspect' manual atau pasang python."
  else
    $CRT inspect $running > "$insp" 2>/dev/null
    "$PY" - "$insp" "$CRT" "$merged" "$det" <<'PYEOF' | while IFS=$'\t' read -r sev id title ev rec; do
from __future__ import print_function
import sys, json, io
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
if isinstance(data, dict): data = [data]
for c in data:
    name = (c.get('Name') or c.get('Id', '?')[:12]).lstrip('/')
    cfg = c.get('Config') or {}; hc = c.get('HostConfig') or {}
    image = cfg.get('Image', '?'); state = (c.get('State') or {}).get('Running'); user = (cfg.get('User') or '').strip()
    det.write('== %s  image=%s  running=%s  user=%s\n' % (name, image, state, user or 'root(default)'))
    if hc.get('Privileged'):
        out('CRITICAL','CNT-PRIV-01','Container privileged (akses penuh ke host)','%s (image %s)' % (name, image),
            'Hapus --privileged. Beri hanya capability yang dibutuhkan dan --security-opt no-new-privileges.')
    binds = hc.get('Binds') or []; mounts = c.get('Mounts') or []
    msrc = set()
    for b in binds: msrc.add(b.split(':')[0])
    for m in mounts:
        if m.get('Source'): msrc.add(m['Source'])
    for s in msrc:
        if s.rstrip('/').endswith('docker.sock'):
            out('CRITICAL','CNT-SOCK-01','Docker socket di-mount ke dalam container (setara root di host)','%s: %s' % (name, s),
                'Jangan mount docker.sock ke container aplikasi. Bila perlu Docker API, pakai proxy ber-otorisasi read-only.')
    for s in msrc:
        sn = s.rstrip('/') or '/'
        if sn in SENS_MOUNT and not sn.endswith('docker.sock'):
            out('HIGH','CNT-MOUNT-01','Path host sensitif di-mount ke container','%s: %s' % (name, sn),
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
        out('MEDIUM','CNT-USER-01','Proses dalam container berjalan sebagai root','%s (User=%s)' % (name, user or 'tidak diset'),
            'Set USER non-root di Dockerfile atau --user.')
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
  pgrep -x httpd  >/dev/null 2>&1 && { ROLES="$ROLES apache"; check_apache; }
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
}

write_summary() {
  local s
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
CRT_BIN=""
detect_crt() {
  if have docker && docker ps >/dev/null 2>&1; then CRT_BIN=docker
  elif have podman && podman ps >/dev/null 2>&1; then CRT_BIN=podman
  else CRT_BIN=""; fi
}

# Peta container aktif: id12 <TAB> nama <TAB> image <TAB> pid-utama
build_container_map() {
  : > "$OUT/.cmap"
  detect_crt
  [ -n "$CRT_BIN" ] || return 0
  local id
  for id in $($CRT_BIN ps -q --no-trunc 2>/dev/null); do
    $CRT_BIN inspect -f '{{.Id}}	{{.Name}}	{{.Config.Image}}	{{.State.Pid}}' "$id" 2>/dev/null \
      | awk -F'\t' '{sub(/^\//,"",$2); print substr($1,1,12) "\t" $2 "\t" $3 "\t" $4}' >> "$OUT/.cmap"
  done
}

# ID container (12 hex) dari cgroup sebuah proses; kosong = proses host
pid_container() {
  [ -s "$OUT/.cmap" ] || return 0
  local id
  id=$(grep -oE '[0-9a-f]{64}' "/proc/$1/cgroup" 2>/dev/null | head -n1 | cut -c1-12)
  [ -n "$id" ] && grep -q "^$id	" "$OUT/.cmap" && echo "$id"
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
    if [ "$NO_EXEC" -eq 0 ] && [ "$SAFE" -eq 0 ]; then
      tmp="$d/exec.out"
      ctr_pkg_script | timeout 90 $CRT_BIN exec -i "$name" sh -s > "$tmp" 2>/dev/null
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
    if not g:
        sc['nopurl'] += 1
        sc['libs'].append({'name': a, 'version': v, 'purl': None, 'group': '', 'props': [('FilePath', loc), ('PkgType', 'jar')], 'eco': 'maven'})
        continue
    sc['libs'].append({'name': a, 'group': g, 'version': v, 'purl': 'pkg:maven/%s/%s@%s' % (enc(g), enc(a), enc(v, '+')),
                       'props': [('FilePath', loc), ('PkgType', 'jar')], 'eco': 'maven'})
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
    summary.append('%-34s OS=%s %s | paket OS: %d | library: %d (tanpa groupId, tidak bisa dicocokkan Trivy: %d)' % (
        fname, oid or '?', over, len(sc['pkgs']), nlib, sc['nopurl']))
    if sc['pkgs'] and not oid:
        emit(','.join(q(x) for x in [HOST, 'SBOM', 'SBOM-OS-01', 'INFO', 'Jenis OS tidak dikenali, paket OS tidak masuk SBOM', scope, 'Periksa /etc/os-release pada lingkup ini.']))
with io.open(os.path.join(OUT, 'sbom', 'RINGKASAN.txt'), 'w', encoding='utf-8') as f:
    f.write('SBOM CycloneDX 1.5 - satu file per lingkup (Trivy hanya menerima satu OS per SBOM)\n\n')
    f.write('\n'.join(summary) + '\n')
tot_nop = sum(sc['nopurl'] for sc in scopes.values())
emit(','.join(q(x) for x in [HOST, 'SBOM', 'SBOM-01', 'INFO', '%d file SBOM dibuat (folder sbom/)' % len(summary),
      ' ; '.join(s.split(' OS=')[0].strip() for s in summary), 'Pindai tiap file dengan: trivy sbom --skip-db-update --offline-scan <file>']))
if tot_nop:
    emit(','.join(q(x) for x in [HOST, 'SBOM', 'SBOM-02', 'INFO', '%d library Java tanpa groupId (versi hanya dari nama file/manifest)' % tot_nop,
          'lihat libraries.csv kolom version_source', 'Library ini tidak bisa dicocokkan Trivy lewat SBOM; dinilai manual dari inventaris.']))
warn('SBOM: %d file, %d library non-Java, %d paket OS' % (len(summary), len(rows_other), len(ospk_rows)))
PYEOF
  [ -s "$OUT/sbom/RINGKASAN.txt" ] && cp "$OUT/sbom/RINGKASAN.txt" "$RAW/sbom_ringkasan.txt"
  grep -qE 'Traceback|Error' "$RAW/sbom_errors.txt" 2>/dev/null && log "PERINGATAN: pembuatan SBOM bermasalah (lihat raw/sbom_errors.txt)"
  rm -rf "$OUT/.ospk" "$OUT/.otherapps"
  return 0
}

#------------------------------------------------------------------------------
# APLIKASI JAVA DI DALAM CONTAINER (dibaca lewat rootfs container, tanpa exec)
#------------------------------------------------------------------------------
check_container_java() {
  local pid="$1" cid name root cmd exe jh jar cwd label user jv cfg base x
  cid=$(pid_container "$pid"); name=$(ctr_name "$cid"); root=$(ctr_root "$cid")
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
  [ -n "$root" ] && [ -d "$root" ] || return 0
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
  if [ -n "$CRT_BIN" ] && [ -s "$OUT/.cmap" ]; then
    while IFS=$'\t' read -r id _n _i _p; do
      x=$($CRT_BIN inspect -f '{{index .Config.Labels "com.docker.compose.project.config_files"}}' "$id" 2>/dev/null)
      d=$($CRT_BIN inspect -f '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$id" 2>/dev/null)
      echo "$x" | tr ',' '\n' | while read -r f; do
        [ -z "$f" ] && continue
        [ "${f#/}" = "$f" ] && f="$d/$f"
        echo "$f"
      done >> "$list.all"
      [ -n "$d" ] && for f in "$d"/Dockerfile* "$d"/*.dockerfile "$d"/Containerfile; do [ -f "$f" ] && echo "$f"; done >> "$list.all"
    done < "$OUT/.cmap"
  fi
  sort -u "$list.all" | grep -vE '/(node_modules|vendor|\.git|site-packages)/|^/usr/(share|lib|lib64)/|^/var/lib/(docker|containers|containerd)/' > "$list.sorted"
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
  [ -n "$CRT_BIN" ] || return 0
  local used all idle stopped
  $CRT_BIN ps -a --no-trunc --format '{{.Image}}' 2>/dev/null | sort -u > "$OUT/.imgused"
  $CRT_BIN ps -aq 2>/dev/null | while read -r x; do $CRT_BIN inspect -f '{{.Image}}' "$x" 2>/dev/null; done | sed 's/^sha256://' | cut -c1-12 | sort -u >> "$OUT/.imgused"
  $CRT_BIN images --format '{{.ID}}	{{.Repository}}:{{.Tag}}	{{.CreatedSince}}	{{.Size}}' 2>/dev/null > "$OUT/.imgall"
  idle=$(awk -F'\t' 'NR==FNR{u[$1]=1; next} !(substr($1,1,12) in u) && !($2 in u){print $2 " (" $3 ", " $4 ")"}' "$OUT/.imgused" "$OUT/.imgall")
  if [ -n "$idle" ]; then
    echo "$idle" > "$RAW/container_images_idle.txt"
    finding LOW CNT-IDLE-01 Container "$(echo "$idle" | wc -l) image tersimpan tetapi tidak dipakai container mana pun" "$(echo "$idle" | head -n 8 | tr '\n' ';')" \
      "Hapus image yang tidak dipakai (docker image rm / docker image prune). Image lama menyimpan library rentan dan bisa dijalankan kembali."
  fi
  stopped=$($CRT_BIN ps -a --filter status=exited --filter status=created --format '{{.Names}} ({{.Image}}, {{.Status}})' 2>/dev/null)
  [ -n "$stopped" ] && finding LOW CNT-STOP-01 Container "$(echo "$stopped" | wc -l) container berhenti masih tersimpan" "$(echo "$stopped" | head -n 8 | tr '\n' ';')" \
    "Hapus container yang tidak dipakai (docker rm). Container berhenti masih menyimpan filesystem dan environment variable-nya."
  # riwayat build (pengganti Dockerfile bila tidak ada di server); secret disamarkan
  cut -f2 "$OUT/.imgall" | grep -v '<none>' | sort -u | head -n 40 | while read -r x; do
    echo "##### $x"; $CRT_BIN history --no-trunc --format '{{.CreatedBy}}' "$x" 2>/dev/null | redact_cfg | cut -c1-400; echo
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
    | grep -vE '/\.(X11-unix|ICE-unix|font-unix|XIM-unix|Test-unix)/|/\.(s\.PGSQL|java_pid|com_ibm|lock|X[0-9]+-lock)|/hsperfdata_' > "$OUT/.hid"
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
  check_os
  check_ssh
  check_accounts
  check_hardening
  check_network
  check_fs
  discover_running_apps
  discover_other_runtimes
  check_unknown_listeners
  detect_and_check_roles
  check_manual_paths
  check_extra
  collect_os_packages
  collect_container_configs
  check_idle_images
  check_ioc
  run_lib_inventory
  check_lib_baseline
  build_inventory_and_sbom
  prettify_container_paths
  write_summary
  anonymize_output
  package_output
}

main
