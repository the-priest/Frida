#!/usr/bin/env python3
"""End-to-end proof that the loop actually works.

Runs Frida's whole pipeline against the fake gateway — intake, plan, build,
static read, real run, fix round, re-run, install — and asserts on what came out
the other end. No network, no key, no tokens.

    python3 tests/test_end_to_end.py

Exit 0 means the loop caught a broken tool, fixed it, and installed a working
one. Exit 1 means it didn't, and says which part.
"""

import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Sandbox every path Frida writes to BEFORE the engine reads them at import.
_SANDBOX = tempfile.mkdtemp(prefix="frida-e2e-")
os.environ["HOME"] = _SANDBOX
os.environ["XDG_CONFIG_HOME"] = os.path.join(_SANDBOX, ".config")
os.environ["XDG_DATA_HOME"] = os.path.join(_SANDBOX, ".local", "share")
os.environ["NO_COLOR"] = "1"

import fake_gateway                                          # noqa: E402
from frida import agent, engine, harness, ship, ui           # noqa: E402

FAILURES = []


def check(label, condition, detail=""):
    mark = "PASS" if condition else "FAIL"
    print(f"[{mark}] {label}" + (f"  —  {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(label)


def main():
    server, port = fake_gateway.start()
    url = f"http://127.0.0.1:{port}/v1"

    # Point a provider at the fake gateway.
    engine.PROVIDERS["groq"]["url"] = url + "/chat/completions"
    engine.PROVIDERS["groq"]["models_url"] = url + "/models"
    engine.PROVIDERS["groq"]["models"] = ["fake-model-pro"]
    engine.STATE["provider"] = "groq"
    engine.STATE["keys"]["groq"] = "test-key"
    engine.STATE["models"]["groq"] = "fake-model-pro"
    ship.BIN_DIR = __import__("pathlib").Path(_SANDBOX) / ".local" / "bin"

    print("\n=== the broken draft, on its own ===")
    first = harness.verify(fake_gateway.BROKEN, name="linecount", cases=[
        {"name": "counts one file", "argv": ["a.txt"], "stdin": "",
         "files": {"a.txt": "one\ntwo\nthree\n"}, "expect_exit": 0,
         "expect_stdout": "3", "why": ""},
        {"name": "missing file", "argv": ["nope.txt"], "stdin": "", "files": {},
         "expect_exit": "nonzero", "expect_stdout": "", "why": ""}])
    problems = " ".join(first["problems"]).lower()
    check("harness rejects the broken draft", not first["ok"])
    check("catches ANSI leaking into a pipe", "ansi escape codes" in problems)
    check("catches the uncaught traceback", "traceback" in problems)
    check("catches the useless --help", "epilog" in problems)

    print("\n=== the full pipeline ===")
    f = agent.Frida(provider="groq", auto=True)
    tool = f.build("a tool that counts lines in text files", install=True, ask=False)

    calls = fake_gateway.GATEWAY.calls
    check("planned before building", "plan" in calls, str(calls))
    check("wrote its own test cases", "scenario" in calls, str(calls))
    check("took a fix round", any(c.startswith("build2") for c in calls), str(calls))
    check("named the tool", tool.name == "linecount", tool.name)

    check("the delivered tool is the fixed one", "isatty" in tool.code)
    ok, report, checks = engine.smoke_test(tool.code)
    check("delivered tool passes the static read", ok, report[:200])

    final = harness.verify(tool.code, name=tool.name, cases=[
        {"name": "counts one file", "argv": ["a.txt"], "stdin": "",
         "files": {"a.txt": "one\ntwo\nthree\n"}, "expect_exit": 0,
         "expect_stdout": "3", "why": ""},
        {"name": "missing file", "argv": ["nope.txt"], "stdin": "", "files": {},
         "expect_exit": "nonzero", "expect_stdout": "", "why": ""}])
    check("delivered tool passes a real run", final["ok"], final["report"][:600])

    installed = ship.BIN_DIR / "linecount"
    check("installed as a command", installed.is_file(), str(installed))
    check("installed executable", installed.is_file() and os.access(installed, os.X_OK))

    print("\n=== it runs from the shell ===")
    import subprocess
    scratch = os.path.join(_SANDBOX, "scratch")
    os.makedirs(scratch, exist_ok=True)
    with open(os.path.join(scratch, "a.txt"), "w") as fh:
        fh.write("one\ntwo\nthree\n")
    proc = subprocess.run([str(installed), "a.txt"], cwd=scratch,
                          capture_output=True, text=True)
    check("runs and counts", proc.returncode == 0 and "3" in proc.stdout,
          repr(proc.stdout) + repr(proc.stderr))
    proc = subprocess.run([str(installed), "missing.txt"], cwd=scratch,
                          capture_output=True, text=True)
    check("fails cleanly on a missing file",
          proc.returncode == 1 and "Traceback" not in proc.stderr,
          repr(proc.stderr))
    check("no ANSI when piped", "\033[" not in proc.stdout)

    print("\n=== session state ===")
    check("session saved", bool(tool.sid))
    check("library has it", bool(engine.library_list()))
    resumed = engine.session_load(tool.sid)
    check("session reloads with code", bool(resumed and resumed.get("code")))

    print("\n=== follow-ups ===")
    issues = f.review()
    check("review returns findings", isinstance(issues, list))
    out = f.release(user="the-priest")
    check("release assembles a repo", bool(out) and "README.md" in out["files"],
          str(out and out.get("files")))
    check("release uses HTTPS remotes", bool(out) and "https://github.com/" in out["push"]
          and "git@" not in out["push"])
    install_sh = open(os.path.join(out["path"], "install.sh")).read()
    check("generated install.sh is valid bash",
          subprocess.run(["bash", "-n", os.path.join(out["path"], "install.sh")],
                         capture_output=True).returncode == 0)
    check("generated install.sh has no ssh remote", "git@github.com" not in install_sh)

    print("\n=== accounting ===")
    usage = engine.usage_summary()
    check("token usage recorded", usage["session"]["calls"] > 0, str(usage["session"]))

    server.shutdown()
    print()
    if FAILURES:
        print(f"{len(FAILURES)} failed: " + ", ".join(FAILURES))
        return 1
    print("all good")
    return 0


if __name__ == "__main__":
    sys.exit(main())
