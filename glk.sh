#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
#  GLK — рут через GhostLock (CVE-2026-43499)
#  канал: wireless debugging (adb), без Shizuku и UserService
#  бины: github.com/kmoell/glk-bins
# ============================================================
set -uo pipefail

REPO="https://raw.githubusercontent.com/kmoell/glk-bins/main"
DIR="$HOME/.glk"
LOG=""

G() { printf '\033[1;32m%s\033[0m\n' "$*"; }
B() { printf '\033[1;36m%s\033[0m\n' "$*"; }
R() { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }

# ---------- 1. зависимости ----------
command -v adb   >/dev/null 2>&1 || { B "[*] ставлю android-tools..."; pkg install -y android-tools; }
command -v curl  >/dev/null 2>&1 || { B "[*] ставлю curl..."; pkg install -y curl; }
command -v sha256sum >/dev/null 2>&1 || pkg install -y coreutils
mkdir -p "$DIR"

# ---------- 2. подключение ----------
connected() { adb get-state >/dev/null 2>&1; }

try_mdns() {
    B "[*] ищу телефон через mDNS..."
    local line host port
    while read -r line; do
        host=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+' | head -1)
        [ -z "$host" ] && host=$(echo "$line" | grep -oE 'localhost:[0-9]+' | head -1 | sed 's/localhost/127.0.0.1/')
        [ -z "$host" ] && continue
        B "    найдено: $host"
        adb connect "$host" >/dev/null 2>&1 && connected && return 0
    done < <(adb mdns services 2>/dev/null | tail -n +2)
    return 1
}

connect_phone() {
    connected && { G "[+] adb уже подключён"; return 0; }
    G "=== подключение ==="
    try_mdns && return 0

    B "1) Открой: Настройки → Для разработчиков → Отладка по Wi-Fi"
    B "2) На главном экране Отладки по Wi-Fi внизу написано IP и ПОРТ"
    read -rp "$(printf '\033[1;33m   Введи IP:ПОРТ (например 192.168.1.5:40231 или 127.0.0.1:40231): \033[0m')" ADDR
    adb connect "$ADDR" >/dev/null 2>&1
    if ! connected; then
        B ""
        B "3) Не спарено. Открой «Спарить устройство с кодом» (Pair device with pairing code)"
        B "   диалог держи открытым — сплит-скрин с Termux"
        read -rp "$(printf '\033[1;33m   IP:ПОРТ из диалога спаривания: \033[0m')" PADDR
        read -rp "$(printf '\033[1;33m   КОД из диалога: \033[0m')" PCODE
        adb pair "$PADDR" "$PCODE" 2>&1 | head -2
        read -rp "$(printf '\033[1;33m   Теперь порт с главного экрана Отладки по Wi-Fi: \033[0m')" P2
        # пробуем и 127.0.0.1 и как ввели
        adb connect "127.0.0.1:${P2##*:}" >/dev/null 2>&1 || adb connect "$P2" >/dev/null 2>&1
    fi
    connected || { R "[X] не подключилось. порт меняется при каждом включении отладки — смотри свежий."; exit 1; }
    G "[+] подключено"
}

connect_phone

# ---------- 3. определяем ядро ----------
KERN=$(adb shell uname -r 2>/dev/null | tr -d '\r\n')
[ -z "$KERN" ] && { R "[X] телефон не отвечает"; exit 1; }
G "=== телефон: ядро $KERN ==="

case "$KERN" in
    "6.6.89-android15-8-g5a0ffb447c1d-ab13771415-4k")
        BIN="6.6.89-android15-8-g5a0ffb447c1d-ab13771415-4k.bin"
        NOTE="Redmi 15C / POCO C85 · CPU 4/5 · select_stack";;
    "5.15.194-android13-8-00019-gf4321180a397-ab15212794")
        BIN="5.15.194-android13-8-00019-gf4321180a397-ab15212794.bin"
        NOTE="POCO F6 Pro (vermeer, OS3.0.304+) · multicast_waiter";;
    "6.1.145-android14-11-maybe-dirty")
        BIN="6.1.145-android14-11-maybe-dirty.bin"
        NOTE="iQOO Z9 Turbo (нужна версия 16.2.17.0!) · tcp_zerocopy";;
    *)
        R "[X] для ядра «$KERN» профиля в репо нет."
        R "    доступные: 6.6.89-...-ab13771415-4k (Redmi 15C), 5.15.194-...-ab15212794 (POCO F6 Pro), 6.1.145-...-maybe-dirty (Z9 Turbo)"
        exit 1;;
esac
B "    профиль: $BIN ($NOTE)"

# ---------- 4. качаем файлы ----------
cd "$DIR"
fetch() { # имя
    if [ ! -f "$1" ]; then
        B "[*] качаю $1..."
        curl -fsSL --retry 3 -o "$1" "$REPO/$1" || { R "[X] не скачался $1"; exit 1; }
    fi
}
fetch ghostlock
fetch "$BIN"
fetch SHA256SUMS

B "[*] сверяю sha256..."
grep -E "(ghostlock|$BIN)$" SHA256SUMS | sha256sum -c --quiet 2>/dev/null \
    || { rm -f ghostlock "$BIN" SHA256SUMS; R "[X] суммы не сошлись, качал заново при след. запуске"; exit 1; }
G "[+] файлы в порядке"

# ---------- 5. заливаем (ETXTBSY-proof) ----------
push_upd() { # локальный remote
    local want got
    want=$(sha256sum "$1" | cut -d' ' -f1)
    got=$(adb shell sha256sum "$2" 2>/dev/null | tr -d '\r' | cut -d' ' -f1)
    if [ "$want" = "$got" ]; then
        B "[*] $2 уже на месте и совпадает — не трогаю"
    else
        adb push "$1" "$2.new" >/dev/null 2>&1 || { R "[X] push $2 провалился"; exit 1; }
        adb shell "mv -f '$2.new' '$2'" || { R "[X] mv $2"; exit 1; }
    fi
}
push_upd ghostlock /data/local/tmp/ghostlock
push_upd "$BIN"     /data/local/tmp/profile.bin
adb shell chmod 755 /data/local/tmp/ghostlock
G "[+] залито: /data/local/tmp/ghostlock + profile.bin"

# ---------- 6. запуск ----------
LOG="$DIR/run-$(date +%Y%m%d-%H%M%S).log"
G "=== запуск ghostlock ==="
B "    лог: $LOG"
adb shell /data/local/tmp/ghostlock --load-prebuilt-profile /data/local/tmp/profile.bin 2>&1 | tee "$LOG"
RC=${PIPESTATUS[0]}

G ""
G "=== выход: $RC ==="
grep -q "child is root" "$LOG" && G "[+] РУТ ПОЛУЧЕН. uid 0 у ребёнка, скрипт handoff отработал."
grep -q "KernelSU module load pending" "$LOG" && B "[i] модуль KernelSU не загружен (нет приложения) — поставь KernelSU до прогона для постоянного рута"
grep -q "W2 failed" "$LOG" && B "[i] W2 промазал — телефон холодный, память свободная, попробуй ещё раз"
exit "$RC"
