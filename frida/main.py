#!/usr/bin/env python3
"""
frida.main  —  the command
==========================
`frida` with no arguments opens the workshop. `frida "a thing that does X"`
builds it and gets out of the way. Everything else is a subcommand.

The front door follows the same rules Frida enforces on the tools it writes,
because a toolsmith that doesn't hold itself to its own standard is just a
lecture:

  exit codes are real          0 built, 1 failed, 2 bad usage, 130 Ctrl-C
  stdout is data               `frida code` prints the source and nothing else,
                               so `frida code | wc -l` works
  stderr is talk               every banner, spinner and checklist
  --help means something       and `--json` is there for the parts worth parsing

License: MIT
"""

import argparse
import json
import os
import shutil
import subprocess
import sys

from . import agent, engine, harness, ship, ui

__version__ = engine.__version__

HELP = """
  build <what>      describe a tool and get it, tested and installed
  run [args]        run the current tool with arguments
  test              run it again, for real — cases, pipes, exit codes
  review            a proper read-through: what's wrong and what to change
  fix               feed the last failing run back and patch it
  code              print the source to stdout
  diff              what changed in the last round
  deps              install what the tool imports
  save              write a copy to ~/frida-tools
  install           put it on your PATH as a command
  release           assemble a GitHub-ready repo
  freeze            build a single-file binary
  tools             tools you've built
  resume <id>       pick one up again
  new               start a fresh tool
  model             choose the model
  key               set an API key
  cost              tokens and spend this session
  doctor            check this machine
  quit              leave

  anything else is an instruction: "add --json", "it crashes on empty input"
"""


# ==========================================================================
# KEYS
# ==========================================================================
def inherited_keys():
    """Keys already sitting in theDawg's config, if it's installed on this box.

    Frida is theDawg's descendant and uses the same providers. Making someone
    paste a key they have already given to the same providers, on the same
    machine, for the same purpose, is a pointless bit of ceremony.
    """
    import json as _json
    from pathlib import Path as _Path
    found = {}
    legacy = (_Path(os.environ.get("XDG_CONFIG_HOME") or (_Path.home() / ".config"))
              / "thedawg" / "config.json")
    try:
        data = _json.loads(legacy.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return found, None
    for pid, key in (data.get("keys") or {}).items():
        if pid in engine.PROVIDERS and (key or "").strip():
            found[pid] = key.strip()
    return found, (data.get("provider") if data.get("provider") in found else None)


def ensure_key(interactive=True):
    """Frida needs one provider key. Find it, inherit it, or ask for it once."""
    pid = engine.STATE["provider"]
    if (engine.STATE["keys"].get(pid) or "").strip():
        return True
    for other, key in engine.STATE["keys"].items():
        if (key or "").strip():
            engine.STATE["provider"] = other
            engine.persist_state()
            ui.info(f"using {engine.PROVIDERS[other]['label']} — it's the key you have")
            return True

    legacy, preferred = inherited_keys()
    if legacy:
        labels = ", ".join(engine.PROVIDERS[p]["label"] for p in legacy)
        if not interactive or ui.confirm(f"found a {labels} key in theDawg's config — use it?",
                                         default=True):
            engine.STATE["keys"].update(legacy)
            engine.STATE["provider"] = preferred or next(iter(legacy))
            engine.persist_state()
            ui.ok(f"using your {engine.PROVIDERS[engine.STATE['provider']]['label']} key "
                  f"(copied to {engine.CONFIG_PATH})")
            return True

    if not interactive:
        ui.err("no API key. Set one: export "
               + engine.PROVIDERS[pid]["env"] + "=...")
        return False

    ui.blank()
    ui.out("  " + ui.c("cream", "Frida needs one API key to talk to a model.", bold=True))
    ui.blank()
    options = [{"label": p["label"], "detail": "environment variable " + p["env"]}
               for _, p in engine.PROVIDERS.items()]
    ids = list(engine.PROVIDERS.keys())
    choice = ui.ask("which provider?", options, allow_other=False,
                    default=ids.index(engine.DEFAULT_PROVIDER) + 1
                    if engine.DEFAULT_PROVIDER in ids else 1)
    pid = next((i for i, p in engine.PROVIDERS.items() if p["label"] == choice), ids[0])
    ui.blank()
    ui.raw(ui.c("amber", "  " + ui.G.arrow + " ") + f"paste your {engine.PROVIDERS[pid]['label']} key: ")
    try:
        key = input().strip()
    except (EOFError, KeyboardInterrupt):
        return False
    if not key:
        return False
    engine.STATE["keys"][pid] = key
    engine.STATE["provider"] = pid
    engine.persist_state()
    ui.ok(f"saved to {engine.CONFIG_PATH}")
    return True


# ==========================================================================
# DOCTOR
# ==========================================================================
def doctor(as_json=False):
    d = engine.DISTRO
    rows = []

    def check(label, present, detail="", required=False):
        rows.append({"check": label, "ok": bool(present), "detail": detail,
                     "required": bool(required)})

    check("python", True, sys.version.split()[0], required=True)
    check("machine", True, f"{d.get('pretty')} ({d.get('family')} family)")
    check("package manager", True, d.get("install") or "unknown")
    check("cachyos", engine.is_cachy(), "at home" if engine.is_cachy() else "not cachy, still fine")
    check("ruff", bool(shutil.which("ruff")),
          "fast static analysis" if shutil.which("ruff") else
          f"optional — {d.get('install')} ruff (or pip install ruff)")
    check("uv", bool(shutil.which("uv")),
          "fast installs" if shutil.which("uv") else "optional — faster dependency installs")
    check("pyinstaller", bool(engine._venv_python()),
          "managed venv ready" if engine._venv_python() else "built on first freeze")
    on_path = ship._on_path(ship.BIN_DIR)
    check("~/.local/bin on PATH", on_path, "" if on_path else ship.path_hint())

    keyed = [engine.PROVIDERS[p]["label"] for p, k in engine.STATE["keys"].items()
             if (k or "").strip()]
    # Not "required". Frida asks for a key the first time you run it and saves it,
    # so a machine without one is not a broken machine — and saying so was a lie
    # that made a working install look like a failed one.
    check("api key", bool(keyed), ", ".join(keyed) if keyed else
          "not set — Frida will ask, or: export "
          + engine.PROVIDERS[engine.STATE["provider"]]["env"] + "=sk-...")

    broken = [r for r in rows if r["required"] and not r["ok"]]
    if as_json:
        ui.data(json.dumps({"frida": __version__, "ok": not broken, "checks": rows}, indent=2))
        return 1 if broken else 0

    ui.rule("this machine")
    ui.blank()
    for r in rows:
        mark = ui.c("lime", ui.G.done) if r["ok"] else ui.c("amber", "!")
        ui.out(f"  {mark} " + ui.c("cream", r["check"].ljust(22)) + ui.c("faint", r["detail"]))
    ui.blank()
    if broken:
        ui.err("Frida can't run until that's sorted.")
        return 1
    if not keyed:
        ui.warn("no API key yet — Frida will ask for one the first time you run it")
        ui.note("or set it now:  export "
                + engine.PROVIDERS[engine.STATE["provider"]]["env"] + "=sk-...")
        ui.blank()
    if any(not r["ok"] for r in rows):
        ui.note("everything marked ! is optional — Frida runs without it, just less well")
    return 0


# ==========================================================================
# SESSION HELPERS
# ==========================================================================
def show_tools(as_json=False):
    lib = engine.library_list()
    inst = ship.installed()
    if as_json:
        ui.data(json.dumps({"library": lib, "installed": inst}, indent=2))
        return 0
    if not lib and not inst:
        ui.note("nothing built yet — try:  frida \"a tool that ...\"")
        return 0
    if lib:
        ui.rule("built")
        for r in lib:
            ui.out("  " + ui.c("amber", str(r.get("id"))[:22].ljust(24)) +
                   ui.c("cream", str(r.get("name") or "").ljust(18)) +
                   ui.c("faint", str(r.get("saved") or "")))
    if inst:
        ui.blank()
        ui.rule("on your PATH")
        for p in inst:
            ui.out("  " + ui.c("teal", os.path.basename(p)) + ui.c("faint", "  " + p))
    ui.blank()
    return 0


def pick_model(f):
    pid = engine.STATE["provider"]
    models = engine.fetch_models(pid, force=True)
    if not models:
        ui.err("couldn't fetch the model list — check the key and the network")
        return
    current = engine.STATE["models"].get(pid)
    options = [{"label": m, "detail": "current" if m == current else ""} for m in models[:12]]
    choice = ui.ask(f"which {engine.PROVIDERS[pid]['label']} model?", options, allow_other=True)
    engine.STATE["models"][pid] = choice
    engine.persist_state()
    ui.ok(f"pinned {choice}")


def show_cost():
    u = engine.usage_summary()
    s = u["session"]
    ui.rule("this session")
    ui.blank()
    ui.kv([("calls", s.get("calls", 0)),
           ("tokens in", f"{s.get('in', 0):,}"),
           ("tokens out", f"{s.get('out', 0):,}"),
           ("estimated cost", ("" if u.get("cost_complete") else "~") + f"${u['cost_usd']:.4f}")])
    if u["by_model"]:
        ui.blank()
        for model, m in u["by_model"].items():
            ui.out("  " + ui.c("faint", model[:44].ljust(46)) +
                   ui.c("grey", f"{m['in'] + m['out']:,} tok"))
    e = engine.edit_summary()
    if e.get("applied") or e.get("fallbacks"):
        ui.blank()
        ui.note(f"targeted edits: {e.get('applied', 0)} landed, "
                f"{e.get('fallbacks', 0)} fell back to a rewrite")
    ui.blank()


def run_tool(f, argv):
    if not f.tool.code:
        ui.err("no tool yet")
        return 1
    path = ship.save_copy(f.tool.code, f.tool.name)["path"]
    ui.rule(f"$ {f.tool.name} " + " ".join(argv))
    try:
        proc = subprocess.run([engine.run_python(), path] + list(argv))
        rc = proc.returncode
    except KeyboardInterrupt:
        rc = 130
    ui.rule()
    (ui.ok if rc == 0 else ui.warn)(f"exit {rc}")
    return rc


# ==========================================================================
# REPL
# ==========================================================================
def repl(f):
    ui.note("type an instruction, or /help")
    while True:
        try:
            line = ui.prompt().strip()
        except EOFError:
            ui.blank()
            return 0
        if not line:
            continue

        if line.startswith("/"):
            parts = line[1:].split()
            cmd, rest = (parts[0].lower() if parts else ""), parts[1:]
            arg = " ".join(rest)
            if cmd in ("quit", "exit", "q"):
                return 0
            if cmd in ("help", "h", "?"):
                ui.out(ui.c("faint", HELP))
                continue
            if cmd == "build":
                if not arg:
                    ui.err("say what to build")
                    continue
                f.tool = agent.Tool(f.provider)
                f.build(arg)
                continue
            if cmd == "new":
                f.tool = agent.Tool(f.provider)
                ui.ok("fresh start")
                continue
            if cmd == "code":
                if f.tool.code:
                    ui.code(f.tool.code, title=f.tool.name + ".py")
                else:
                    ui.err("no tool yet")
                continue
            if cmd == "run":
                run_tool(f, rest)
                continue
            if cmd == "test":
                if not f.tool.code:
                    ui.err("no tool yet")
                    continue
                board = ui.TaskBoard("", [agent.STEP_RUN])
                board.show()
                result = f.run_for_real(board)
                board.close()
                if result.get("blocked"):
                    ui.warn(result["blocked"])
                else:
                    ui.out(result["report"])
                continue
            if cmd == "fix":
                if not f.tool.last_run:
                    ui.err("nothing to fix from — run /test first")
                    continue
                board = ui.TaskBoard("", [agent.STEP_FIX, agent.STEP_READ, agent.STEP_RUN])
                board.show()
                f.fix_loop(board, run_result=f.tool.last_run)
                board.close()
                continue
            if cmd == "review":
                if f.tool.code:
                    f.review()
                else:
                    ui.err("no tool yet")
                continue
            if cmd == "deps":
                deps = engine.detect_deps(f.tool.code)["pip"]
                if not deps:
                    ui.ok("standard library only — nothing to install")
                    continue
                ui.info("installing: " + ", ".join(deps))
                res = engine.install_deps(deps)
                (ui.ok if res.get("ok") else ui.err)(res.get("log", "")[-800:] or "done")
                continue
            if cmd == "save":
                if f.tool.code:
                    p = ship.save_copy(f.tool.code, f.tool.name)["path"]
                    ui.file_card(p, "saved", f"python3 {p} --help")
                continue
            if cmd == "install":
                if not f.tool.code:
                    ui.err("no tool yet")
                    continue
                res = ship.install(f.tool.code, f.tool.name)
                if res.get("ok"):
                    ui.file_card(res["path"], f"{res['name']} installed",
                                 f"{res['name']} --help")
                    if not res["on_path"]:
                        ui.warn("~/.local/bin isn't on your PATH:")
                        ui.note(res["hint"])
                else:
                    ui.err(res.get("error", "failed"))
                continue
            if cmd == "release":
                if not f.tool.code:
                    ui.err("no tool yet")
                    continue
                user = arg or ui.prompt("github user ›").strip()
                f.release(user=user)
                continue
            if cmd == "freeze":
                if not f.tool.code:
                    ui.err("no tool yet")
                    continue
                ui.info("building a single-file binary — this takes a minute")
                res = ship.freeze(f.tool.code, f.tool.name)
                if res.get("ok"):
                    ui.file_card(res["path"], "binary built", res["path"])
                else:
                    ui.err((res.get("log") or "build failed")[-900:])
                continue
            if cmd in ("tools", "library", "ls"):
                show_tools()
                continue
            if cmd == "resume":
                record = engine.session_load(arg) if arg else None
                if not record:
                    sessions = engine.session_list()[:10]
                    if not sessions:
                        ui.note("nothing to resume")
                        continue
                    choice = ui.ask("resume which?",
                                    [{"label": s.get("name") or s["id"],
                                      "detail": f"{s.get('updated','')}  {s['id']}"}
                                     for s in sessions], allow_other=False)
                    record = next((engine.session_load(s["id"]) for s in sessions
                                   if (s.get("name") or s["id"]) == choice), None)
                if not record:
                    ui.err("couldn't load that")
                    continue
                f.tool = agent.Tool.restore(record, f.provider)
                ui.ok(f"resumed {f.tool.name} ({len(f.tool.code.splitlines())} lines)")
                continue
            if cmd == "model":
                pick_model(f)
                continue
            if cmd == "key":
                engine.STATE["keys"][engine.STATE["provider"]] = ""
                ensure_key()
                continue
            if cmd == "cost":
                show_cost()
                continue
            if cmd == "doctor":
                doctor()
                continue
            if cmd == "diff":
                ui.note("diff shows the last change once you've made one")
                continue
            ui.err(f"no such command: /{cmd}   (try /help)")
            continue

        # plain language
        if f.tool.code:
            f.iterate(line)
        else:
            f.build(line)


# ==========================================================================
# ENTRY
# ==========================================================================
def build_parser():
    p = argparse.ArgumentParser(
        prog="frida",
        description="Frida — describe a command-line tool, get a working one.",
        epilog=("examples:\n"
                "  frida                                  open the workshop\n"
                "  frida \"a tool that hashes every file in a directory\"\n"
                "  frida build \"csv column stats\" --yes   no questions, no prompts\n"
                "  frida doctor --json                    check this machine\n"),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("request", nargs="*", help="what you want built")
    p.add_argument("--yes", "-y", action="store_true",
                   help="don't ask questions or wait for approval")
    p.add_argument("--no-install", action="store_true",
                   help="don't put the finished tool on your PATH")
    p.add_argument("--no-verify", action="store_true",
                   help="skip running the tool for real (not recommended)")
    p.add_argument("--rounds", type=int, default=None, metavar="N",
                   help="how many fix rounds to allow (default %d)" % engine.AUTOTEST_MAX_ROUNDS)
    p.add_argument("--provider", default=None, metavar="ID",
                   help="siliconflow, groq, google, novita")
    p.add_argument("--model", default=None, metavar="ID", help="pin a model for this run")
    p.add_argument("--json", action="store_true", help="machine-readable output where it applies")
    p.add_argument("--no-banner", action="store_true", help="skip the wordmark")
    p.add_argument("--version", action="version", version="frida " + __version__)
    return p


# Words that look like subcommands but only exist inside the workshop. Without
# this, `frida test` quietly builds a tool called "test" — which is exactly the
# kind of thing that makes a CLI feel untrustworthy.
IN_SESSION_ONLY = {"run", "test", "review", "fix", "release", "freeze", "install",
                   "save", "deps", "diff", "new", "key", "model", "quit", "help"}


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.provider:
        if args.provider not in engine.PROVIDERS:
            ui.err(f"unknown provider {args.provider!r} — "
                   f"one of: {', '.join(engine.PROVIDERS)}")
            return 2
        engine.STATE["provider"] = args.provider
    if args.model:
        engine.STATE["models"][engine.STATE["provider"]] = args.model

    words = list(args.request)
    sub = words[0].lower() if words else ""
    rest = words[1:]

    # ---- subcommands that need no key ------------------------------------
    if sub == "doctor":
        return doctor(as_json=args.json)
    if sub in ("tools", "library"):
        return show_tools(as_json=args.json)

    if sub in IN_SESSION_ONLY:
        ui.err(f"`{sub}` works inside a session, not as a subcommand.")
        ui.note(f"open the workshop with  frida  and type  /{sub}")
        ui.note(f"or resume the last tool: frida resume")
        return 2

    f = agent.Frida(provider=engine.STATE["provider"], auto=args.yes,
                    rounds=args.rounds)

    if sub == "cost":
        show_cost()
        return 0

    if sub == "resume":
        record = engine.session_load(rest[0]) if rest else None
        if not record:
            sessions = engine.session_list()
            record = engine.session_load(sessions[0]["id"]) if sessions else None
        if not record:
            ui.err("nothing to resume")
            return 1
        f.tool = agent.Tool.restore(record, f.provider)
        if not args.no_banner:
            ui.banner(__version__)
        ui.ok(f"resumed {f.tool.name} — {len(f.tool.code.splitlines())} lines")
        if not ensure_key():
            return 1
        return repl(f)

    if sub == "code":
        sessions = engine.session_list()
        record = engine.session_load(sessions[0]["id"]) if sessions else None
        if not record or not record.get("code"):
            ui.err("no tool to print")
            return 1
        sys.stdout.write(record["code"])
        return 0

    # ---- everything else talks to a model --------------------------------
    if not ensure_key(interactive=sys.stdin.isatty()):
        return 1

    request = " ".join(rest if sub == "build" else words).strip()

    if request:
        if not args.no_banner:
            ui.banner(__version__)
        tool = f.build(request, install=not args.no_install,
                       ask=not args.yes)
        if not tool.code:
            return 1
        if args.json:
            ui.data(json.dumps({"name": tool.name, "version": tool.ver,
                                "lines": len(tool.code.splitlines()),
                                "session": tool.sid,
                                "installed": str(ship.BIN_DIR / tool.name)}, indent=2))
        return 0

    if not args.no_banner:
        ui.banner(__version__)
        ui.tribute()
    return repl(f)


def run():
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        ui.show_cursor()
        ui.blank()
        ui.note("stopped")
        sys.exit(130)
    except BrokenPipeError:
        sys.exit(0)


if __name__ == "__main__":
    run()
