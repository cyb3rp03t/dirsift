#!/usr/bin/env bash
# DirSift demo kaydedici.
# Sentetik bir acik dizin kurar, dirsift'i ona karsi calistirir, asciinema ile
# kaydeder ve istege bagli olarak GIF'e cevirir.
# Gercek bir hedefe hicbir istek gitmez: her sey 127.0.0.1 uzerinde.

set -euo pipefail

cat <<'BANNER'
   ____  _      _____ _  __ _
  |  _ \(_)_ __/ ___/(_)/ _| |_
  | | | | | '__\___ \| | |_| __|
  | |_| | | |   ___) | |  _| |_
  |____/|_|_|  |____/|_|_|  \__|

  demo recorder  ::  someone left the lights on
BANNER
echo

PORT="${PORT:-8731}"
OUTDIR="${OUTDIR:-$PWD/demo}"
FIXTURE="$(mktemp -d)"
CAST="$OUTDIR/dirsift.cast"
GIF="$OUTDIR/dirsift.gif"

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "eksik: $1  ($2)"; MISSING=1; }
}
MISSING=0
need python3 "apt install python3"
need asciinema "apt install asciinema  veya  uv tool install asciinema"
command -v dirsift >/dev/null 2>&1 || command -v uv >/dev/null 2>&1 || {
  echo "eksik: dirsift ya da uv"; MISSING=1; }
[ "$MISSING" = "1" ] && { echo; echo "Eksikleri kurup tekrar calistir."; exit 1; }

DS="dirsift"
command -v dirsift >/dev/null 2>&1 || DS="uv run dirsift"

mkdir -p "$OUTDIR"

# ---------------------------------------------------------------------------
# Sentetik acik dizin. Isimler uydurma, icerikler zararsiz metin.
# Surum ailesi (build_114x) kumeleme icin, run.bat ve panel.php giris noktasi
# skorlamasi icin, config.bak IOC cikarimi icin konuldu.
# ---------------------------------------------------------------------------
build_fixture() {
  cd "$FIXTURE"
  mkdir -p notes old
  printf 'MZ demo placeholder, not an executable\n' > build_1147.zip
  printf 'MZ demo placeholder, not an executable\n' > build_1148.zip
  printf 'MZ demo placeholder, not an executable\n' > build_1149.zip
  printf '@echo off\nstart /b build_1149.zip\n' > run.bat
  printf '<?php // demo panel placeholder ?>\n' > panel.php
  printf 'host=10.20.30.40\nport=4444\nendpoint=http://cdn.example-demo.invalid/gate.php\n' > config.bak
  printf 'internal build notes, demo fixture\n' > notes/CHANGELOG.txt
  printf 'superseded by build_1149\n' > old/build_0912.zip
  printf 'demo fixture, nothing real here\n' > readme.txt
  cd - >/dev/null
}

# ---------------------------------------------------------------------------
# Kayit sirasinda calisacak ic betik.
# ---------------------------------------------------------------------------
write_inner() {
  cat > "$FIXTURE/.demo.sh" <<INNER
#!/usr/bin/env bash
set -e
say() { printf '\033[1;33m\$ %s\033[0m\n' "\$1"; sleep 1.1; }
pause() { sleep 2.2; }

say "$DS scan http://127.0.0.1:$PORT/ --allow-private --json run.json"
$DS scan http://127.0.0.1:$PORT/ --allow-private --json run.json
pause

say "$DS report run.json"
$DS report run.json
pause

say "$DS iocs run.json"
$DS iocs run.json
pause

printf '\033[1;32mScan and analysis are separate: report and iocs re-run offline.\033[0m\n'
sleep 2.5
INNER
  chmod +x "$FIXTURE/.demo.sh"
}

cleanup() {
  [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null || true
  rm -rf "$FIXTURE"
}
trap cleanup EXIT

echo "[*] sentetik dizin kuruluyor"
build_fixture
write_inner

echo "[*] yerel sunucu :$PORT"
( cd "$FIXTURE" && python3 -m http.server "$PORT" >/dev/null 2>&1 ) &
SRV=$!
sleep 1.5

echo "[*] kayit basliyor"
rm -f "$CAST"
( cd "$FIXTURE" && asciinema rec "$CAST" \
    --cols 100 --rows 30 --idle-time-limit 2 --overwrite \
    --command "$FIXTURE/.demo.sh" )

echo "[+] kayit: $CAST"

if command -v agg >/dev/null 2>&1; then
  echo "[*] GIF'e cevriliyor"
  agg --font-size 15 --theme asciinema --speed 1.1 "$CAST" "$GIF"
  echo "[+] GIF: $GIF"
else
  echo "[!] agg kurulu degil, GIF atlandi."
  echo "    Kurulum: cargo install --git https://github.com/asciinema/agg"
  echo "    Ya da .cast dosyasini asciinema.org'a yukleyip README'ye linki koy."
fi

echo
echo "Sonraki adim: GIF'i depoya assets/dirsift-demo.gif olarak koy,"
echo "README'nin en ustune ekle:  ![DirSift](assets/dirsift-demo.gif)"
