#!/usr/bin/env python3
"""The interactive path: questions, plan approval, the REPL, its commands.

Everything Frida asks you is answered from a script here, so the whole
conversational flow runs without a human and without a model.

    python3 tests/test_interactive.py
"""

import io
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

_SANDBOX = tempfile.mkdtemp(prefix="frida-repl-")
os.environ["HOME"] = _SANDBOX
os.environ["XDG_CONFIG_HOME"] = os.path.join(_SANDBOX, ".config")
os.environ["XDG_DATA_HOME"] = os.path.join(_SANDBOX, ".local", "share")
os.environ["NO_COLOR"] = "1"

import fake_gateway                                    # noqa: E402
from frida import agent, engine, main, ship            # noqa: E402

FAILURES = []


def check(label, condition, detail=""):
    print(f"[{'PASS' if condition else 'FAIL'}] {label}" +
          (f"  —  {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(label)


SCRIPT = "\n".join([
    "a tool that counts lines in text files",   # the request
    "2",                                        # answer: recurse into directories
    "",                                         # approve the plan
    "/code",                                    # print the source
    "/test",                                    # run it again
    "/save",                                    # write a copy
    "/cost",                                    # accounting
    "/nonsense",                                # an unknown command must not crash
    "/quit",
]) + "\n"


def run():
    server, port = fake_gateway.start()
    url = f"http://127.0.0.1:{port}/v1"
    engine.PROVIDERS["groq"]["url"] = url + "/chat/completions"
    engine.PROVIDERS["groq"]["models_url"] = url + "/models"
    engine.PROVIDERS["groq"]["models"] = ["fake-model-pro"]
    engine.STATE["provider"] = "groq"
    engine.STATE["keys"]["groq"] = "test-key"
    engine.STATE["models"]["groq"] = "fake-model-pro"
    ship.BIN_DIR = __import__("pathlib").Path(_SANDBOX) / ".local" / "bin"

    sys.stdin = io.StringIO(SCRIPT)
    on_stdout, on_stderr = io.StringIO(), io.StringIO()
    real_stdout, real_stderr = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = on_stdout, on_stderr

    f = agent.Frida(provider="groq")
    try:
        code = main.repl(f)
    finally:
        sys.stdout, sys.stderr = real_stdout, real_stderr
        server.shutdown()

    printed = on_stdout.getvalue()
    chrome = on_stderr.getvalue()

    check("repl exits 0 on /quit", code == 0, str(code))
    check("the question was answered, not skipped",
          "intake" in fake_gateway.GATEWAY.calls, str(fake_gateway.GATEWAY.calls))
    check("the answer reached the build",
          any("Recurse into it" in m.get("content", "")
              for m in f.tool.messages if m.get("role") == "user"))
    check("a tool came out of it", bool(f.tool.code), "no code")
    check("it is the fixed version", "isatty" in f.tool.code)
    check("/code showed the source", "def main(" in chrome)
    check("the checklist ran", "Run it for real" in chrome)
    check("stdout stayed clean — chrome went to stderr",
          printed.strip() == "", repr(printed[:200]))
    check("an unknown command didn't kill the session", code == 0)

    copy = os.path.join(_SANDBOX, "frida-tools", "linecount.py")
    check("/save wrote a copy", os.path.isfile(copy), copy)

    print()
    if FAILURES:
        print(f"{len(FAILURES)} failed: " + ", ".join(FAILURES))
        return 1
    print("all good")
    return 0


if __name__ == "__main__":
    sys.exit(run())
