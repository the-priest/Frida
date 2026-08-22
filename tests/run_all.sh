#!/usr/bin/env bash
# Every check Frida has. No network, no API key, no tokens spent.
set -uo pipefail
cd "$(dirname "$0")/.."

fail=0
echo "== compile =="
python3 -m compileall -q frida bin/frida tests || fail=1

echo
echo "== end to end =="
python3 tests/test_end_to_end.py || fail=1

echo
echo "== commands =="
python3 tests/test_commands.py 2>/dev/null || fail=1

echo
echo "== regressions =="
python3 tests/test_regressions.py 2>/dev/null || fail=1

echo
echo "== interactive =="
python3 tests/test_interactive.py 2>/dev/null || fail=1

echo
echo "== installer =="
bash tests/test_install.sh || fail=1

echo
if [ "$fail" -eq 0 ]; then echo "all good"; else echo "something failed"; fi
exit "$fail"
