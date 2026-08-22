#!/usr/bin/env bash
# Frida — installer
#
#   curl -fsSL https://raw.githubusercontent.com/the-priest/frida/main/install.sh | bash
#
# Installs into ~/.local/share/frida, puts a `frida` launcher on your PATH, and
# writes the PATH line in the syntax of YOUR login shell — including fish, which
# CachyOS ships by default and which does not understand `export`.
#
# No root. Re-run to update. `install.sh --uninstall` removes it.
set -euo pipefail

REPO_USER="the-priest"
REPO_NAME="frida"
BRANCH="main"
RAW="https://raw.githubusercontent.com/${REPO_USER}/${REPO_NAME}/${BRANCH}"

SHARE="${XDG_DATA_HOME:-$HOME/.local/share}/frida"
BIN="$HOME/.local/bin"
LAUNCHER="$BIN/frida"

BOLD=$'\033[1m'; DIM=$'\033[2m'; AMBER=$'\033[38;5;214m'
GREEN=$'\033[38;5;149m'; RED=$'\033[38;5;203m'; OFF=$'\033[0m'
if [ ! -t 1 ] || [ -n "${NO_COLOR:-}" ]; then
  BOLD=""; DIM=""; AMBER=""; GREEN=""; RED=""; OFF=""
fi

say()  { printf '%s\n' "$*" >&2; }
ok()   { printf '%s✔%s %s\n' "$GREEN" "$OFF" "$*" >&2; }
warn() { printf '%s!%s %s\n' "$AMBER" "$OFF" "$*" >&2; }
die()  { printf '%s✗%s %s\n' "$RED" "$OFF" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# --------------------------------------------------------------------------
# uninstall
# --------------------------------------------------------------------------
if [ "${1:-}" = "--uninstall" ]; then
  rm -rf "$SHARE"
  rm -f "$LAUNCHER"
  ok "Frida removed."
  say "${DIM}Tools it built are still in ~/.local/bin and ~/frida-tools — those are yours.${OFF}"
  say "${DIM}Settings and history: ~/.config/frida and ~/.local/share/frida.${OFF}"
  exit 0
fi

# --------------------------------------------------------------------------
# what distro is this
# --------------------------------------------------------------------------
DISTRO_ID=""; DISTRO_LIKE=""; PRETTY="Linux"
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  DISTRO_ID="${ID:-}"; DISTRO_LIKE="${ID_LIKE:-}"; PRETTY="${PRETTY_NAME:-Linux}"
fi

case "$DISTRO_ID $DISTRO_LIKE" in
  *cachyos*|*arch*|*manjaro*|*endeavour*) FAMILY="arch";   PKG="sudo pacman -S --needed" ;;
  *debian*|*ubuntu*|*mint*|*pop*)         FAMILY="debian"; PKG="sudo apt install -y" ;;
  *fedora*|*rhel*|*centos*)               FAMILY="fedora"; PKG="sudo dnf install -y" ;;
  *suse*|*opensuse*)                      FAMILY="suse";   PKG="sudo zypper install -y" ;;
  *)                                      FAMILY="other";  PKG="your package manager" ;;
esac

printf '\n%s%s  Frida%s %s— a toolsmith for the terminal%s\n\n' \
  "$BOLD" "$AMBER" "$OFF" "$DIM" "$OFF" >&2
say "${DIM}  $PRETTY  ·  $FAMILY family${OFF}"
say ""

# --------------------------------------------------------------------------
# requirements
# --------------------------------------------------------------------------
have python3 || die "python3 is required.  $PKG python"
PYV=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
python3 - <<'PY' || die "Frida needs Python 3.10 or newer (found $PYV)."
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PY
ok "python $PYV"

have curl || have wget || die "curl or wget is required.  $PKG curl"

fetch() {  # fetch <url> <dest>
  if have curl; then curl -fsSL "$1" -o "$2"
  else wget -qO "$2" "$1"; fi
}

# --------------------------------------------------------------------------
# install
# --------------------------------------------------------------------------
mkdir -p "$SHARE/frida" "$BIN"

# The list of modules used to be typed out here by hand, and it went stale the
# moment a new one was added: 2.0 shipped frida/commands.py, the list didn't
# mention it, and every upgraded install died on `ImportError: cannot import
# name 'commands'`. A local install now takes whatever is actually in the
# package directory, so it cannot drift again.
# The modules to fetch when installing over the network, where globbing is not
# possible. tests/test_install.sh fails if this drifts from frida/*.py.
# This must stay a plain shell variable: `curl … | bash` gives $0 as "bash",
# so anything that reads the script's own file does not exist to be read.
MODULES="__init__.py agent.py commands.py engine.py harness.py main.py prompts.py ship.py ui.py"
EXTRAS="bin/frida LICENSE README.md"

# $0 is "bash" when piped from curl, so guard the local-clone detection on a
# path that actually exists rather than on dirname of a non-file.
SELF_DIR=""
if [ -f "$0" ]; then SELF_DIR="$(cd "$(dirname "$0")" && pwd)"; fi

if [ -n "$SELF_DIR" ] && [ -f "$SELF_DIR/frida/engine.py" ]; then
  # running from a clone
  SRC="$SELF_DIR"
  say "${DIM}  installing from $SRC${OFF}"
  # Clear out any modules from a previous version that no longer exist, so a
  # deleted file can't linger and shadow something.
  rm -f "$SHARE/frida/"*.py
  for f in "$SRC"/frida/*.py; do
    [ -e "$f" ] || die "no python files found in $SRC/frida"
    cp "$f" "$SHARE/frida/$(basename "$f")"
  done
  for f in $EXTRAS; do
    mkdir -p "$SHARE/$(dirname "$f")"
    cp "$SRC/$f" "$SHARE/$f"
  done
else
  # Fetching over the network can't glob, so this list is checked by the test
  # suite against the real package directory.
  FILES=""
  for m in $MODULES; do FILES="$FILES frida/$m"; done
  FILES="$FILES $EXTRAS"
  say "${DIM}  fetching from github.com/${REPO_USER}/${REPO_NAME}${OFF}"
  for f in $FILES; do
    mkdir -p "$SHARE/$(dirname "$f")"
    fetch "$RAW/$f" "$SHARE/$f" || die "couldn't fetch $f"
  done
fi

cat > "$LAUNCHER" <<EOF
#!/usr/bin/env python3
import os, sys
sys.path.insert(0, os.path.expanduser("$SHARE"))
from frida.main import run
run()
EOF
chmod +x "$LAUNCHER"
ok "installed to $SHARE"
ok "launcher at $LAUNCHER"

# --------------------------------------------------------------------------
# PATH — in the syntax of the shell you actually use
# --------------------------------------------------------------------------
case ":$PATH:" in
  *":$BIN:"*) ok "$BIN is on your PATH" ;;
  *)
    LOGIN_SHELL="$(basename "${SHELL:-bash}")"
    case "$LOGIN_SHELL" in
      fish)
        mkdir -p "$HOME/.config/fish"
        LINE='fish_add_path ~/.local/bin'
        FILE="$HOME/.config/fish/config.fish" ;;
      zsh)
        LINE='export PATH="$HOME/.local/bin:$PATH"'
        FILE="$HOME/.zshrc" ;;
      *)
        LINE='export PATH="$HOME/.local/bin:$PATH"'
        FILE="$HOME/.bashrc" ;;
    esac
    if [ -f "$FILE" ] && grep -qF "$LINE" "$FILE" 2>/dev/null; then
      warn "$BIN is in $FILE but not in this shell — open a new terminal"
    else
      printf '\n# added by the Frida installer\n%s\n' "$LINE" >> "$FILE"
      ok "added $BIN to your PATH in $FILE"
      warn "open a new terminal, or run:  $LINE"
    fi ;;
esac

# --------------------------------------------------------------------------
# the nice-to-haves
# --------------------------------------------------------------------------
MISSING=""
have ruff || MISSING="$MISSING ruff"
have uv   || MISSING="$MISSING uv"
if [ -n "$MISSING" ]; then
  say ""
  say "${DIM}  Optional, and worth having — Frida uses them to check generated code${OFF}"
  say "${DIM}  for free before it spends a token on a fix round:${OFF}"
  case "$FAMILY" in
    arch)   say "    $PKG$MISSING" ;;
    debian) say "    pipx install${MISSING// / }  ${DIM}(or: pip install --user${MISSING})${OFF}" ;;
    *)      say "    pip install --user${MISSING}" ;;
  esac
fi

# --------------------------------------------------------------------------
# key
# --------------------------------------------------------------------------
if [ -z "${SILICONFLOW_API_KEY:-}${GROQ_API_KEY:-}${GOOGLE_API_KEY:-}${NOVITA_API_KEY:-}" ] \
   && [ ! -f "${XDG_CONFIG_HOME:-$HOME/.config}/frida/config.json" ]; then
  say ""
  warn "no API key found yet — Frida will ask for one the first time you run it"
  say "${DIM}    or set it yourself:  export SILICONFLOW_API_KEY=sk-...${OFF}"
fi

say ""
hint() { printf '  %s%-26s%s %s%s%s\n' "$AMBER" "$1" "$OFF" "$DIM" "$2" "$OFF" >&2; }
hint 'frida'                   'open the workshop'
hint 'frida "a tool that ..."' 'build one now'
hint 'frida doctor'            'check this machine'
say ""
