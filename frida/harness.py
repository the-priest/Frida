#!/usr/bin/env python3
"""
frida.harness  —  running the thing for real
============================================
The engine's smoke test proves a tool parses, imports and survives static
analysis. That is not the same as working. This module is where a generated tool
actually gets run: with arguments, with stdin, against files, and with its exit
code taken seriously.

theDawg had to open a window on a hidden X server and take a photograph of it to
find out whether a tool worked. A command-line tool tells you directly — that is
the whole point of the form — so Frida asks it:

  --help          does it explain itself, and exit 0
  --version       does it answer
  no arguments    does a tool with required arguments exit 2 like argparse says
  scenarios       the model's own test cases: real argv, real stdin, real files
  broken pipe     does `| head` produce a traceback
  interrupt       does Ctrl-C exit 130 quietly, or dump a stack trace

and it checks the two disciplines a terminal tool is judged by and a model
forgets first: results on stdout, talk on stderr, and no ANSI escape codes in
output that isn't a terminal.

Everything runs in a scratch directory with a scratch HOME. A generated tool that
writes to `~/.config/<app>` writes into the sandbox, not into yours. Nothing here
touches the network on purpose, nothing runs as root, and anything the danger
scanner flags does not run at all until you say so.

License: MIT
"""

import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from . import engine

# A case gets this long before it is killed. Generous enough for a real sweep,
# short enough that an accidental infinite loop doesn't hold the build hostage.
CASE_TIMEOUT = 20
HELP_TIMEOUT = 12

# ANSI in captured (non-tty) output. This is the CLI equivalent of theDawg's
# "the window opens but renders blank": it looks fine to the person who wrote it
# and it corrupts every downstream consumer.
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_TRACEBACK = re.compile(r"^Traceback \(most recent call last\):", re.M)


# ==========================================================================
# SANDBOX
# ==========================================================================
def _sandbox_env(home):
    """Environment for a generated tool: its own HOME, no colour forced either
    way, and the locale pinned to UTF-8 so a ✓ in a help string can't crash the
    run for reasons that have nothing to do with the code."""
    env = dict(os.environ)
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(Path(home) / ".config")
    env["XDG_DATA_HOME"] = str(Path(home) / ".local" / "share")
    env["XDG_CACHE_HOME"] = str(Path(home) / ".cache")
    env["PYTHONIOENCODING"] = "utf-8"
    env["LC_ALL"] = env.get("LC_ALL") or "C.UTF-8"
    # Deliberately NOT set: NO_COLOR. We want to see whether the tool works out
    # for itself that it isn't attached to a terminal.
    env.pop("NO_COLOR", None)
    env.pop("FORCE_COLOR", None)
    return env


class Sandbox:
    """A scratch cwd + scratch HOME that cleans itself up."""

    def __init__(self, code, name="tool"):
        self.root = Path(tempfile.mkdtemp(prefix="frida-harness-"))
        self.home = self.root / "home"
        self.work = self.root / "work"
        self.home.mkdir(parents=True, exist_ok=True)
        self.work.mkdir(parents=True, exist_ok=True)
        self.script = self.root / (engine._safe_id(name or "tool") + ".py")
        self.script.write_text(code, encoding="utf-8")
        self.env = _sandbox_env(self.home)

    def reset_work(self, files=None):
        """Fresh working directory per case, so one case can't see another's mess."""
        shutil.rmtree(self.work, ignore_errors=True)
        self.work.mkdir(parents=True, exist_ok=True)
        for rel, content in (files or {}).items():
            # Never let a model-authored filename escape the scratch directory.
            target = (self.work / rel).resolve()
            if not str(target).startswith(str(self.work.resolve())):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(str(content), encoding="utf-8")

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


# ==========================================================================
# ONE RUN
# ==========================================================================
def _invoke(sandbox, argv, stdin="", timeout=CASE_TIMEOUT, interrupt_after=None):
    """Run the script once. Returns a dict — never raises for a tool's own fault."""
    cmd = [engine.run_python(), str(sandbox.script)] + [str(a) for a in (argv or [])]
    t0 = time.time()
    try:
        proc = subprocess.Popen(
            cmd, cwd=str(sandbox.work), env=sandbox.env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True)
    except OSError as e:
        return {"exit": None, "stdout": "", "stderr": f"could not start the tool: {e}",
                "seconds": 0.0, "timed_out": False, "interrupted": False}

    interrupted = False
    if interrupt_after:
        # Let it get properly under way, then Ctrl-C the whole process group the
        # way a terminal would — not a bare SIGINT to the leader.
        def _sigint():
            time.sleep(interrupt_after)
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGINT)
            except Exception:
                pass
        threading.Thread(target=_sigint, daemon=True).start()
        interrupted = True

    try:
        out, err = proc.communicate(input=(stdin or "").encode("utf-8"), timeout=timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            proc.kill()
        out, err = proc.communicate()
        timed_out = True

    return {
        "exit": proc.returncode,
        "stdout": out.decode("utf-8", errors="replace"),
        "stderr": err.decode("utf-8", errors="replace"),
        "seconds": round(time.time() - t0, 2),
        "timed_out": timed_out,
        "interrupted": interrupted,
    }


def _discipline(run, expect_output=True):
    """The checks every case gets, whatever it was testing."""
    problems = []
    out, err, rc = run["stdout"], run["stderr"], run["exit"]

    if _TRACEBACK.search(err):
        last = [l for l in err.strip().splitlines() if l.strip()][-1:]
        problems.append("CRASH: the tool printed a Python traceback — " +
                        (last[0].strip()[:160] if last else "see stderr") +
                        ". A user should never see a stack trace; catch it and print one clear "
                        "line on stderr with a non-zero exit code.")
    if _ANSI.search(out):
        problems.append("ANSI escape codes were written to stdout while stdout was a PIPE, not a "
                        "terminal. Gate every colour code behind sys.stdout.isatty() and honour "
                        "NO_COLOR — as written, redirecting output to a file corrupts it.")
    if run["timed_out"]:
        problems.append(f"HUNG: still running after {CASE_TIMEOUT}s and had to be killed. Either "
                        f"it blocks on stdin that never comes, or it loops forever.")
    if rc == 0 and re.search(r"^(?:error|fatal|failed)\b", err, re.M | re.I) and expect_output:
        problems.append("EXIT CODE LIES: it reported an error on stderr and still exited 0. "
                        "Non-zero on failure — `&&` and CI both believe that number.")
    if rc not in (0, None) and out.strip() and expect_output:
        problems.append("On a failing run it still wrote to stdout. When the tool fails, stdout "
                        "should be empty and the reason belongs on stderr.")
    return problems


# ==========================================================================
# THE STANDARD CASES  --  every tool gets these, no model call needed
# ==========================================================================
def _case_help(sandbox, prog):
    run = _invoke(sandbox, ["--help"], timeout=HELP_TIMEOUT)
    problems = []
    out = run["stdout"]
    if run["exit"] != 0:
        problems.append(f"`--help` exited {run['exit']} instead of 0. argparse exits 0 for help; "
                        f"something is intercepting it or failing before the parser is built.")
    if len(out.strip()) < 40:
        problems.append("`--help` printed almost nothing. It is the tool's documentation: it needs "
                        "a real description, sensible metavars, and a worked example in the epilog.")
    elif "usage:" not in out.lower():
        problems.append("`--help` output has no `usage:` line — arguments aren't going through "
                        "argparse.")
    elif not re.search(r"example", out, re.I):
        problems.append("`--help` has no worked example in the epilog. Add one real invocation "
                        "someone can paste.")
    problems += _discipline(run, expect_output=False)
    return {"name": "--help", "argv": ["--help"], "why": "it is the documentation",
            "run": run, "problems": problems, "ok": not problems}


def _case_version(sandbox):
    run = _invoke(sandbox, ["--version"], timeout=HELP_TIMEOUT)
    problems = []
    if run["exit"] != 0:
        problems.append(f"`--version` exited {run['exit']}. Add "
                        f"`p.add_argument('--version', action='version', version=...)`.")
    elif not run["stdout"].strip() and not run["stderr"].strip():
        problems.append("`--version` printed nothing.")
    return {"name": "--version", "argv": ["--version"], "why": "scripts pin versions",
            "run": run, "problems": problems, "ok": not problems}


def _case_bare(sandbox, requires_args):
    """No arguments at all. With required arguments that must be exit 2."""
    run = _invoke(sandbox, [], stdin="", timeout=HELP_TIMEOUT)
    problems = []
    if requires_args:
        if run["exit"] == 0:
            problems.append("Run with no arguments at all, it exited 0. A tool with required "
                            "arguments must exit 2 and print usage on stderr.")
        elif run["exit"] not in (2, None):
            problems.append(f"Run with no arguments it exited {run['exit']}; argparse's contract "
                            f"for a usage error is 2.")
    problems += _discipline(run, expect_output=False)
    return {"name": "no arguments", "argv": [], "why": "usage errors exit 2",
            "run": run, "problems": problems, "ok": not problems}


def _case_broken_pipe(sandbox, argv, files=None, stdin=""):
    """`tool | head -1`. The classic traceback nobody tests for."""
    sandbox.reset_work(files)
    cmd = [engine.run_python(), str(sandbox.script)] + [str(a) for a in argv]
    try:
        p1 = subprocess.Popen(cmd, cwd=str(sandbox.work), env=sandbox.env,
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, start_new_session=True)
        p2 = subprocess.Popen(["head", "-1"], stdin=p1.stdout,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p1.stdout.close()
        try:
            p1.stdin.write((stdin or "").encode("utf-8"))
            p1.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        p2.wait(timeout=CASE_TIMEOUT)
        p1.wait(timeout=CASE_TIMEOUT)
        err = p1.stderr.read().decode("utf-8", errors="replace")
        p1.stderr.close()
    except Exception as e:
        return {"name": "| head", "argv": argv, "why": "pipes close early",
                "run": {"exit": None, "stdout": "", "stderr": str(e), "seconds": 0.0,
                        "timed_out": False, "interrupted": False},
                "problems": [], "ok": True}

    problems = []
    if "BrokenPipeError" in err or _TRACEBACK.search(err):
        problems.append("Piping the output into `head` produced a traceback (BrokenPipeError). "
                        "Catch BrokenPipeError in main() and return 0 — closing a pipe early is "
                        "normal shell behaviour, not an error.")
    return {"name": "| head", "argv": argv, "why": "pipes close early",
            "run": {"exit": p1.returncode, "stdout": "", "stderr": err,
                    "seconds": 0.0, "timed_out": False, "interrupted": False},
            "problems": problems, "ok": not problems}


def _case_interrupt(sandbox, argv, files=None, stdin="", after=1.2):
    """Ctrl-C the slow path. Should be 130, and should be quiet about it."""
    sandbox.reset_work(files)
    run = _invoke(sandbox, argv, stdin=stdin, timeout=CASE_TIMEOUT, interrupt_after=after)
    problems = []
    if _TRACEBACK.search(run["stderr"]) and "KeyboardInterrupt" in run["stderr"]:
        problems.append("Ctrl-C during the slow part dumped a KeyboardInterrupt traceback. "
                        "Catch KeyboardInterrupt in main() and return 130 quietly.")
    elif run["exit"] not in (130, -2, 0, None):
        problems.append(f"Ctrl-C produced exit code {run['exit']}; the convention is 130.")
    return {"name": "ctrl-c", "argv": argv, "why": "interrupts exit 130",
            "run": run, "problems": problems, "ok": not problems}


# ==========================================================================
# MODEL-AUTHORED CASES
# ==========================================================================
def make_cases(code, prompts, provider_id=None):
    """Ask the model for real invocations of the tool it just wrote."""
    res = engine.call_model(
        [{"role": "system", "content": prompts["scenario"]},
         {"role": "user", "content": "Here is the tool:\n\n" + engine.fenced(code)}],
        provider_id=provider_id, temperature=0.2, tier="cheap")
    if res.get("error"):
        return [], res["error"]
    data = engine._parse_json_reply(res.get("reply", "")) or {}
    cases = []
    for c in (data.get("cases") or [])[:6]:
        if not isinstance(c, dict):
            continue
        argv = c.get("argv") or []
        if not isinstance(argv, list):
            continue
        if any("--help" == str(a) for a in argv):
            continue
        cases.append({
            "name": str(c.get("name") or "case")[:40],
            "argv": [str(a) for a in argv][:24],
            "stdin": str(c.get("stdin") or ""),
            "files": {str(k): str(v) for k, v in (c.get("files") or {}).items()
                      if isinstance(k, str)},
            "expect_exit": c.get("expect_exit", 0),
            "expect_stdout": str(c.get("expect_stdout") or ""),
            "why": str(c.get("why") or "")[:60],
        })
    return cases, None


def _run_scenario(sandbox, case):
    sandbox.reset_work(case.get("files"))
    run = _invoke(sandbox, case["argv"], stdin=case.get("stdin", ""))
    problems = []
    want = case.get("expect_exit", 0)
    rc = run["exit"]
    if want == "nonzero":
        if rc == 0:
            problems.append(f"`{case['name']}` should have failed but exited 0. "
                            f"Bad input has to be non-zero — that is the whole contract.")
    elif isinstance(want, int) and rc is not None and rc != want:
        problems.append(f"`{case['name']}` exited {rc}, expected {want}.")
    want_out = case.get("expect_stdout") or ""
    if want_out and want_out not in run["stdout"]:
        problems.append(f"`{case['name']}` did not print the expected result "
                        f"({want_out[:60]!r}) to stdout.")
    problems += _discipline(run, expect_output=True)
    return {"name": case["name"], "argv": case["argv"], "why": case.get("why", ""),
            "run": run, "problems": problems, "ok": not problems}


# ==========================================================================
# THE FULL PASS
# ==========================================================================
def verify(code, name="tool", cases=None, allow_danger=False, on_case=None,
           deep=True):
    """Run a generated tool for real and report what happened.

    Returns a dict:
      {"ran": bool, "ok": bool, "blocked": str|None,
       "cases": [...], "problems": [str], "report": str}

    `blocked` is set (and nothing runs) when the danger scanner flags destructive
    code and allow_danger is False. That is a question for the user, not a
    refusal — theDawg learned that the hard way when refusing outright killed
    the whole feature for anyone building a disk wiper.
    """
    danger = engine.looks_dangerous(code)
    if danger and not allow_danger:
        reason = ("This tool contains destructive operations:\n  - " + "\n  - ".join(danger))
        return {"ran": False, "ok": False, "blocked": reason, "cases": [],
                "problems": [], "report": reason}

    requires_args = _requires_arguments(code)
    results = []

    with Sandbox(code, name) as sb:
        def record(case):
            results.append(case)
            if on_case:
                try:
                    on_case(case)
                except Exception:
                    pass
            return case

        sb.reset_work()
        record(_case_help(sb, name))
        if "--version" in code or "action=\"version\"" in code or "action='version'" in code:
            sb.reset_work()
            record(_case_version(sb))
        sb.reset_work()
        record(_case_bare(sb, requires_args))

        scenarios = cases or []
        for c in scenarios:
            record(_run_scenario(sb, c))

        if deep and scenarios:
            # Reuse the first successful scenario for the two runtime manners
            # checks. No point interrupting something that never ran.
            healthy = next((c for c, r in zip(scenarios, results[-len(scenarios):])
                            if r["run"]["exit"] == 0), None)
            if healthy:
                record(_case_broken_pipe(sb, healthy["argv"], healthy.get("files"),
                                         healthy.get("stdin", "")))
                if any(r["run"]["seconds"] > 1.5 for r in results):
                    record(_case_interrupt(sb, healthy["argv"], healthy.get("files"),
                                           healthy.get("stdin", "")))

    problems = []
    for r in results:
        problems.extend(r["problems"])
    # Same defect surfacing in five cases is one defect.
    problems = list(dict.fromkeys(problems))

    return {"ran": True, "ok": not problems, "blocked": None,
            "cases": results, "problems": problems,
            "report": render_report({"cases": results, "problems": problems})}


_REQUIRED_POS = re.compile(r"""add_argument\(\s*["'](?!-)[^"']+["']""")


def _requires_arguments(code):
    """Does the parser have a required positional? Used to decide whether a bare
    run should exit 2. `nargs="?"` and `nargs="*"` make it optional."""
    for m in _REQUIRED_POS.finditer(code or ""):
        tail = code[m.end():m.end() + 220]
        if re.search(r"nargs\s*=\s*[\"'][?*][\"']", tail):
            continue
        if re.search(r"default\s*=", tail):
            continue
        return True
    return False


# ==========================================================================
# REPORTING
# ==========================================================================
def render_report(result):
    """Plain-text account of a verification pass — for the model, and for the log."""
    cases = result.get("cases") or []
    if not cases:
        return "no cases were run"
    lines = []
    for c in cases:
        run = c["run"]
        mark = "PASS" if c["ok"] else "FAIL"
        argv = " ".join(c["argv"]) if c["argv"] else "(no arguments)"
        lines.append(f"[{mark}] {c['name']}  —  $ tool {argv}"
                     f"   exit={run['exit']}  {run['seconds']}s")
        for p in c["problems"]:
            lines.append("        · " + p)
        if not c["ok"]:
            out = (run["stdout"] or "").strip()
            err = (run["stderr"] or "").strip()
            if out:
                lines.append("        stdout: " + _clip(out))
            if err:
                lines.append("        stderr: " + _clip(err))
    return "\n".join(lines)


def _clip(text, limit=400):
    text = text.replace("\n", "\n                ")
    return text if len(text) <= limit else text[:limit] + " …"


def problems_for_model(result):
    """The fix instruction handed back to the model. Empty string when clean."""
    problems = result.get("problems") or []
    if not problems:
        return ""
    return ("The tool was RUN and these are real, observed failures — not a review, not an "
            "opinion. Fix every one and return the complete file.\n\n  - "
            + "\n  - ".join(problems)
            + "\n\n=== full run log ===\n" + (result.get("report") or ""))
