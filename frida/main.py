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

from . import agent, commands, engine, harness, ship, ui

__version__ = engine.__version__

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


def ensure_key(interactive=True, force_prompt=False):
    """Frida needs one provider key. Find it, inherit it, or ask for it once.

    `force_prompt` is for /key, which means "let me type a key". Without it,
    /key blanked the current provider's key and then fell straight into the
    borrow-another-provider's-key branch below: no prompt ever appeared, you
    were silently moved to a different provider, and the emptied key was
    written to config.json — the old one gone for good.
    """
    pid = engine.STATE["provider"]
    if not force_prompt:
        if (engine.STATE["keys"].get(pid) or "").strip():
            return True
        for other, key in engine.STATE["keys"].items():
            if (key or "").strip():
                engine.STATE["provider"] = other
                engine.persist_state()
                ui.info(f"using {engine.PROVIDERS[other]['label']} — it's the key you have")
                return True

    legacy, preferred = inherited_keys()
    if legacy and not force_prompt:
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
    term_name, term_keys, _term_cfg = engine.terminal()
    if term_name:
        check("terminal", True, term_name)

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
    if term_keys:
        # Frida draws big with /big, but the font itself belongs to the
        # terminal — so at least say where the setting lives.
        ui.blank()
        ui.note("font too small? that's " + term_name + ", not Frida:")
        ui.note("  " + term_keys)
        if _term_cfg:
            ui.note("  " + _term_cfg)
        ui.note("  /big draws tool names and headings three rows tall")
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
    if choice is ui.CANCELLED or not str(choice).strip():
        ui.note("left on " + (current or "the default"))
        return
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
    """The workshop.

    Two kinds of input, and the distinction is the whole point of the place:
    commands, which do exactly one predictable thing to the tool you have, and
    plain language, which asks Frida to change it. Everything that is a command
    is in commands.REGISTRY, and this function does not know any of their names
    — which is why /help can no longer advertise something that doesn't work.
    """
    hist = commands.install_readline()
    commands.set_sink_for(f)          # harmless if main() already did it
    ui.note("type an instruction, or /help")
    try:
        while True:
            try:
                line = ui.prompt(status_arrow(f)).strip()
            except EOFError:
                ui.blank()
                return 0
            except ui.Quit:
                return 0
            if not line:
                continue
            try:
                if commands.dispatch(f, line) == "quit":
                    return 0
            except ui.Quit:
                return 0
            except KeyboardInterrupt:
                ui.blank()
                ui.warn("stopped")
            show_hud(f)
    finally:
        commands.save_readline(hist)
        if f.tool.code:
            f.tool.save()


def show_hud(f):
    """Where you stand, after every action."""
    u = engine.usage_summary()
    cost = ""
    if u["session"].get("calls"):
        tilde = "" if u.get("cost_complete") else "~"
        cost = "%s$%.4f" % (tilde, u["cost_usd"])
    pid = engine.STATE.get("provider")
    model = ((engine.STATE.get("models") or {}).get(pid)
             or engine.LAST_MODEL[0] or "")
    if "/" in model:
        model = model.split("/")[-1]
    ui.hud(f.tool, model=model[:28], cost=cost,
           session_versions=len(f.tool.history) + 1 if f.tool.code else 0)
    moves = ui.next_moves(f.tool)
    if moves:
        ui.chips(*moves)


def status_arrow(f):
    """The prompt carries the tool's name, so you always know what you're editing."""
    if not f.tool.code:
        return ui.G.arrow
    return ui.c("teal", f.tool.name) + ui.c("faint", " " + ui.G.arrow)


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
    p.add_argument("--theme", default=None, metavar="NAME",
                   help="ember, matrix, ice, synthwave, paper")
    p.add_argument("--big", action="store_true",
                   help="draw tool names and headings three rows tall")
    p.add_argument("--plain", action="store_true",
                   help="no animation — same output, nothing moves")
    p.add_argument("--version", action="version", version="frida " + __version__)
    return p


# Words that look like subcommands but only exist inside the workshop. Without
# this, `frida test` quietly builds a tool called "test" — which is exactly the
# kind of thing that makes a CLI feel untrustworthy.
# Commands main() handles as real subcommands (`frida code | wc -l`), plus
# their aliases. Everything else exists only inside a session, and `frida test`
# must say so rather than building a tool called "test".
_ALSO_SUBCOMMANDS = ("build", "doctor", "tools", "library", "ls", "resume",
                     "help", "code", "cost")
IN_SESSION_ONLY = frozenset(
    n for n in commands.all_names() if n not in _ALSO_SUBCOMMANDS)


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    ui.set_theme(args.theme or engine.STATE.get("theme") or "ember")
    ui.set_big(args.big or bool(engine.STATE.get("big")))
    if args.plain:
        ui.set_motion(False)
    # --theme and --model are documented "for this run". They were written into
    # STATE, which persist_state() serialises wholesale, so the next /theme or
    # key prompt quietly made them permanent.
    engine.RUN_OVERRIDES["theme"] = args.theme or ""
    if args.theme:
        engine.STATE["theme"] = args.theme

    if args.provider:
        if args.provider not in engine.PROVIDERS:
            ui.err(f"unknown provider {args.provider!r} — "
                   f"one of: {', '.join(engine.PROVIDERS)}")
            return 2
        engine.STATE["provider"] = args.provider
    if args.model:
        engine.STATE["models"][engine.STATE["provider"]] = args.model
        engine.RUN_OVERRIDES["model"] = (engine.STATE["provider"], args.model)

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
    # Point every prompt in the program at the dispatcher HERE, not inside
    # repl(). `frida "a csv tool"` also stops at a question and a plan gate,
    # and without this a /save typed there was read as plan feedback — the
    # exact bug the sink exists to prevent, still live on the one-shot path.
    commands.set_sink_for(f)

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
            ui.boot(__version__)
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
            ui.boot(__version__)
        tool = f.build(request, verify=not args.no_verify, install=not args.no_install,
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
        ui.boot(__version__)
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
