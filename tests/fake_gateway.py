#!/usr/bin/env python3
"""A stand-in for a model provider.

Speaks enough of the OpenAI chat-completions API — streaming and not — to drive
Frida's whole pipeline without spending a token. It reads the system prompt to
work out which stage is asking, and answers in character.

The first build call deliberately returns a BROKEN tool: colour written straight
to stdout, no example in --help, and an uncaught FileNotFoundError. That is the
point of the test. If Frida ships that without noticing, the harness is theatre.
"""

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BROKEN = '''#!/usr/bin/env python3
"""linecount — count lines in text files."""
import argparse
import sys


def build_parser():
    p = argparse.ArgumentParser(prog="linecount",
                                description="Count lines in text files.")
    p.add_argument("paths", nargs="+", metavar="FILE")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    total = 0
    for path in args.paths:
        n = sum(1 for _ in open(path))
        total += n
        print("\\033[36m%s\\033[0m %d" % (path, n))
    if len(args.paths) > 1:
        print("total %d" % total)
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''

FIXED = '''#!/usr/bin/env python3
"""linecount — count lines in text files."""
import argparse
import sys

__version__ = "1.0.1"


def build_parser():
    p = argparse.ArgumentParser(
        prog="linecount",
        description="Count lines in text files.",
        epilog="examples:\\n  linecount notes.txt\\n  linecount *.py",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("paths", nargs="+", metavar="FILE")
    p.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return p


def colour(text):
    if sys.stdout.isatty():
        return "\\033[36m" + text + "\\033[0m"
    return text


def main(argv=None):
    args = build_parser().parse_args(argv)
    total = 0
    try:
        for path in args.paths:
            with open(path, encoding="utf-8", errors="replace") as fh:
                n = sum(1 for _ in fh)
            total += n
            print("%s %d" % (colour(path), n))
        if len(args.paths) > 1:
            print("total %d" % total)
    except FileNotFoundError as exc:
        print("linecount: no such file: %s" % exc.filename, file=sys.stderr)
        return 1
    except IsADirectoryError as exc:
        print("linecount: not a file: %s" % exc.filename, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''

INTAKE = json.dumps({"ready": False, "questions": [
    {"q": "What should it do with a directory?",
     "why": "changes the walk logic",
     "options": [{"label": "Refuse it", "detail": "one clear error, exit 1"},
                 {"label": "Recurse into it", "detail": "count every file below"}]}]})

PLAN = json.dumps({"name": "linecount",
                   "summary": "Counts lines in one or more text files.",
                   "tasks": ["Parse arguments and validate paths",
                             "Count lines per file",
                             "Print a per-file total and a grand total",
                             "Handle missing files and Ctrl-C"],
                   "risks": []})

SCENARIOS = json.dumps({"cases": [
    {"name": "counts one file", "argv": ["a.txt"], "stdin": "",
     "files": {"a.txt": "one\ntwo\nthree\n"}, "expect_exit": 0,
     "expect_stdout": "3", "why": "the normal run"},
    {"name": "missing file", "argv": ["nope.txt"], "stdin": "", "files": {},
     "expect_exit": "nonzero", "expect_stdout": "", "why": "bad input must fail"},
    {"name": "two files", "argv": ["a.txt", "b.txt"], "stdin": "",
     "files": {"a.txt": "x\n", "b.txt": "y\nz\n"}, "expect_exit": 0,
     "expect_stdout": "total 3", "why": "grand total"},
]})

NAME = json.dumps({"name": "linecount", "title": "Line Count"})

REVIEW = json.dumps({"verdict": "Solid, with one thing worth tightening.",
                     "issues": [{"severity": "low", "line": 20,
                                 "what": "errors='replace' hides decoding problems",
                                 "fix": "warn on stderr when a file isn't valid UTF-8"}]})

RELEASE = json.dumps({"name": "linecount", "tagline": "Count lines, honestly",
                      "description": "Counts lines in text files.",
                      "usage": "linecount notes.txt", "install_notes": "",
                      "topics": ["cli", "text"]})


class Gateway:
    def __init__(self):
        self.calls = []
        self.builds = 0
        self.lock = threading.Lock()

    def answer(self, payload):
        messages = payload.get("messages") or []
        system = (messages[0].get("content") if messages else "") or ""
        user = (messages[-1].get("content") if messages else "") or ""
        with self.lock:
            if "requirements analyst" in system:
                self.calls.append("intake")
                return INTAKE
            if "Frida's planner" in system:
                self.calls.append("plan")
                return PLAN
            if "test plan for a command-line tool" in system:
                self.calls.append("scenario")
                return SCENARIOS
            if "Name this command-line tool" in system:
                self.calls.append("name")
                return NAME
            if "reviewing a single-file" in system:
                self.calls.append("review")
                return REVIEW
            if "polished public release" in system:
                self.calls.append("release")
                return RELEASE
            if "modifying an existing single-file" in system:
                # Targeted-edit request. Decline the format so Frida falls back
                # to a full rewrite — that fallback path is worth exercising.
                self.calls.append("edit")
                return "FULL_REWRITE"
            # a build turn
            self.builds += 1
            self.calls.append(f"build{self.builds}")
            if self.builds == 1 and "does not pass" not in user:
                return ("Built `linecount` — counts lines in the files you name and "
                        "prints a grand total when there is more than one.\n\n"
                        "```python\n" + BROKEN + "```\n")
            return ("Fixed all three: colour is gated behind `isatty()`, `--help` has a "
                    "worked example, and a missing file is now one line on stderr with "
                    "exit 1.\n\n```python\n" + FIXED + "```\n")


GATEWAY = Gateway()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        body = json.dumps({"data": [{"id": "fake-model-pro"}, {"id": "fake-model-flash"}]})
        raw = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        reply = GATEWAY.answer(payload)
        model = payload.get("model") or "fake-model-pro"
        if payload.get("stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            for i in range(0, len(reply), 400):
                chunk = {"choices": [{"delta": {"content": reply[i:i + 400]}}]}
                self.wfile.write(b"data: " + json.dumps(chunk).encode() + b"\n\n")
                self.wfile.flush()
            done = {"choices": [{"delta": {}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 900, "completion_tokens": len(reply) // 4}}
            self.wfile.write(b"data: " + json.dumps(done).encode() + b"\n\n")
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
            self.close_connection = True
            return
        body = json.dumps({
            "model": model,
            "choices": [{"message": {"content": reply}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 900, "completion_tokens": len(reply) // 4},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start(port=0):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]
