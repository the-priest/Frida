#!/usr/bin/env bash
# Does install.sh actually install a working Frida?
#
# 2.0.0 shipped a new module (frida/commands.py) and install.sh carried a
# hand-typed list of files that didn't mention it. Every upgraded install died
# on `ImportError: cannot import name 'commands'`. Syntax checks can't catch
# that — only running the installer can.
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
fail=0

check() { if [ "$2" = "0" ]; then echo "[PASS] $1"; else echo "[FAIL] $1"; fail=1; fi; }

bash -n install.sh
check "install.sh parses" $?

# 1. the network manifest must list exactly what is in the package
declared="$(sed -n 's/^MODULES="\(.*\)"$/\1/p' install.sh | tr ' ' '\n' | sort | tr -d '\r')"
actual="$(ls frida/*.py | xargs -n1 basename | sort)"
[ "$declared" = "$actual" ]
check "install.sh's MODULES list matches frida/*.py" $?
if [ "$declared" != "$actual" ]; then
  echo "       declared: $(echo "$declared" | tr '\n' ' ')"
  echo "       actual:   $(echo "$actual" | tr '\n' ' ')"
fi

# 2. a real install into a sandbox, then actually run the thing
SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT
HOME="$SANDBOX" bash install.sh >"$SANDBOX/log" 2>&1
check "install.sh runs to completion" $?

[ -x "$SANDBOX/.local/bin/frida" ]
check "the launcher is installed and executable" $?

# every module must have made it across
missing=""
for m in frida/*.py; do
  [ -f "$SANDBOX/.local/share/frida/$m" ] || missing="$missing $(basename "$m")"
done
[ -z "$missing" ]
check "every module was installed" $?
[ -n "$missing" ] && echo "       missing:$missing"

# 3. the real test: does it import and run?
HOME="$SANDBOX" "$SANDBOX/.local/bin/frida" --version >"$SANDBOX/ver" 2>&1
check "the installed frida runs" $?
grep -q "^frida " "$SANDBOX/ver"
check "it reports its version" $?
[ -s "$SANDBOX/ver" ] && head -3 "$SANDBOX/ver" | sed 's/^/       /'

HOME="$SANDBOX" "$SANDBOX/.local/bin/frida" doctor >/dev/null 2>&1
rc=$?
[ "$rc" -eq 0 ] || [ "$rc" -eq 1 ]
check "the installed frida can run doctor" $?

# 4. piped from curl, $0 is "bash" — nothing may read the script's own file
grep -q 'sed .*"\$0"' install.sh && piped_bug=1 || piped_bug=0
[ "$piped_bug" = "0" ]
check "nothing reads \$0 (curl | bash gives \$0 = bash)" $?

PIPED="$(mktemp -d)"
# Simulate the curl path: no argv[0] file, and no frida/ next to the "script".
( cd "$PIPED" && HOME="$PIPED" bash -c "$(cat "$ROOT/install.sh")" >"$PIPED/log" 2>&1 )
grep -qi "can't read bash\|No such file or directory" "$PIPED/log" && piped_ok=1 || piped_ok=0
[ "$piped_ok" = "0" ]
check "piped install gets past the module list" $?
[ "$piped_ok" = "1" ] && sed -n '1,12p' "$PIPED/log" | sed 's/^/       /'
rm -rf "$PIPED"

# 5. upgrading over an old install must not leave a stale module behind
echo "raise SystemExit('stale module ran')" > "$SANDBOX/.local/share/frida/frida/zombie.py"
HOME="$SANDBOX" bash install.sh >/dev/null 2>&1
[ ! -f "$SANDBOX/.local/share/frida/frida/zombie.py" ]
check "upgrading clears modules that no longer exist" $?

echo
if [ "$fail" -eq 0 ]; then echo "all good"; else echo "something failed"; fi
exit "$fail"
