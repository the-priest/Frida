"""
Frida · the command layer.

There is exactly one list of commands in this program, and it is below. The
help text is generated from it, tab-completion is generated from it, and
dispatch reads from it. Before this file existed there were three separate
lists — a help string, an if/elif chain, and a set of names the argument
parser knew about — and they disagreed. `/help` advertised `run`, `save` and
`new`; typing them sent the words to the model, which dutifully "patched" the
tool with them. You cannot supervise a machine whose controls are decorative.

The dispatch rule, in full:

    /word ...        always a command. Unknown ones are an error, never a
                     silent fallthrough to the model.
    word             a bare word that exactly names a command IS that command.
    word --flag      a bare command word followed only by flags is that
                     command, with the flags as arguments.
    build <free text>  free-text commands take the rest of the line.
    anything else    an instruction for the model.
    > anything       forced instruction, even if it looks like a command.

The rule is deliberately conservative: "test" runs the tests, "test it with an
empty file" is an instruction. Ambiguity resolves toward the model, because a
misread instruction costs a patch you can undo, and a misread command costs
you the thing you were trying to protect.
"""

import os
import shlex
import shutil

from . import engine, ship, ui


# ==========================================================================
# THE REGISTRY
# ==========================================================================
class Command:
    __slots__ = ("name", "aliases", "arg", "blurb", "group", "handler",
                 "needs_tool", "free_text", "hidden", "keep_head")

    def __init__(self, name, blurb, handler, group="", aliases=(), arg="",
                 needs_tool=False, free_text=False, hidden=False,
                 keep_head=()):
        self.name = name
        self.aliases = tuple(aliases)
        self.arg = arg
        self.blurb = blurb
        self.group = group
        self.handler = handler
        self.needs_tool = needs_tool
        self.free_text = free_text
        self.hidden = hidden
        # Aliases that are ordinary English words and part of the sentence they
        # introduce. "why does it hang" must reach the handler whole — reading
        # it as the command `why` plus the question "does it hang" inverts what
        # was asked.
        self.keep_head = tuple(keep_head)

    @property
    def names(self):
        return (self.name,) + self.aliases

    @property
    def usage(self):
        return self.name + ((" " + self.arg) if self.arg else "")


REGISTRY = []
_BY_NAME = {}


def command(name, blurb, group="", aliases=(), arg="", needs_tool=False,
            free_text=False, hidden=False, keep_head=()):
    """Register a command. The decorated function is its handler."""
    def deco(fn):
        cmd = Command(name, blurb, fn, group, aliases, arg, needs_tool,
                      free_text, hidden, keep_head)
        REGISTRY.append(cmd)
        for n in cmd.names:
            _BY_NAME[n] = cmd
        return fn
    return deco


def lookup(word):
    return _BY_NAME.get((word or "").lower().lstrip("/"))


def all_names():
    return sorted(_BY_NAME)


# ==========================================================================
# DISPATCH
# ==========================================================================
SAY, RUN, UNKNOWN, NOTHING = "say", "run", "unknown", "nothing"


def resolve(line):
    """Work out what a line of input means.

    Returns (kind, payload, arg):
      ("run", Command, argstring) · ("say", text, "") ·
      ("unknown", word, "")       · ("nothing", "", "")
    """
    line = (line or "").strip()
    if not line:
        return NOTHING, "", ""

    # Forced instruction — the escape hatch for "run" as English.
    if line[0] in ">":
        forced = line[1:].strip()
        # A bare ">" used to reach say() as an empty instruction: two paid
        # calls, and the tool replaced by whatever came back.
        return (SAY, forced, "") if forced else (NOTHING, "", "")

    slashed = line.startswith("/")
    body = line[1:].strip() if slashed else line
    if not body:
        return NOTHING, "", ""

    head, _, tail = body.partition(" ")
    tail = tail.strip()

    # A line that is nothing but flags means "run it with these". Typing
    # `--help` at the prompt used to be sent to the model as an instruction:
    # it spent 43 seconds and real money adding a feature nobody asked for,
    # when the user just wanted to see the tool's own help.
    if (not slashed and head.startswith("-") and len(head) > 1
            and (not tail or _looks_like_argv(tail))):
        return RUN, lookup("run"), body

    cmd = lookup(head)

    if cmd and head.lower() in cmd.keep_head and tail:
        tail = body                    # the head word is part of the sentence

    if slashed:
        if not cmd:
            return UNKNOWN, head.lower(), ""
        return RUN, cmd, tail

    if not cmd:
        return SAY, line, ""

    # Bare word. Be conservative about claiming it.
    if not tail:
        return RUN, cmd, ""
    if cmd.free_text:
        return RUN, cmd, tail
    if cmd.arg and _looks_like_argv(tail):
        return RUN, cmd, tail
    return SAY, line, ""


_ARGV_CHARS = set("./=*~\\")


def _looks_like_argv(tail):
    """Is this tail command arguments, or is it English?

    'run --json out.csv' is arguments. 'run it again but with --json this time'
    is a sentence that happens to contain a flag. The test: a leading flag, or
    every token carrying something prose does not — a dash, a dot, a slash, a
    digit. It is a heuristic, and it fails toward treating input as English,
    because a misread instruction costs an undo and a misread command can cost
    the work.
    """
    tokens = tail.split()
    if not tokens:
        return False
    if tokens[0].startswith("-"):
        return True
    return all(t.startswith("-") or t[0].isdigit() or (set(t) & _ARGV_CHARS)
               for t in tokens)


def suggest(word):
    """The closest command name, for 'did you mean'."""
    import difflib
    hits = difflib.get_close_matches(word, all_names(), n=1, cutoff=0.6)
    return hits[0] if hits else ""


def dispatch(f, line):
    """Resolve and execute one line. Returns 'quit' to leave the workshop."""
    kind, payload, arg = resolve(line)

    if kind is NOTHING:
        return None
    if kind is UNKNOWN:
        near = suggest(payload)
        ui.err("no such command: /" + payload)
        ui.note(("did you mean /" + near + "?  ") if near else "" )
        ui.note("/help lists everything · or drop the slash to say it to Frida")
        return None
    if kind is SAY:
        return say(f, payload)

    cmd = payload
    # A command typed AT A GATE runs while build() is still on the stack, and
    # build() re-reads self.tool on every access. /new, /resume and /build all
    # rebind it — so the in-flight build carried on writing into, version-
    # bumping and re-installing whatever tool you had just switched to.
    if getattr(f, "busy", False) and cmd.name in ("build", "new", "resume"):
        ui.err("/" + cmd.name + " can't run while a build is in progress")
        ui.note("answer this first, or ctrl-c to stop the build")
        return None
    if cmd.needs_tool and not f.tool.code:
        ui.err("no tool yet")
        ui.note("describe one first — or /tools to pick up something you built before")
        return None
    return cmd.handler(f, arg)


def say(f, text):
    """Plain language goes to the model."""
    if f.tool.code:
        f.iterate(text)
    else:
        f.build(text)
    return None


# ==========================================================================
# HELP — generated, so it cannot drift from what dispatch actually does
# ==========================================================================
GROUPS = [
    ("make",    "make"),
    ("shape",   "shape it"),
    ("look",    "look at it"),
    ("ship",    "ship it"),
    ("session", "session"),
]


def help_text(width=None):
    w = width or ui.width()
    lines = []
    for key, title in GROUPS:
        rows = [c for c in REGISTRY if c.group == key and not c.hidden]
        if not rows:
            continue
        lines.append("")
        lines.append("  " + ui.c("amber", title, bold=True))
        pad = max(len(c.usage) for c in rows) + 3
        for c_ in rows:
            lines.append("    " + ui.c("cream", c_.usage.ljust(pad)) +
                         ui.c("grey", c_.blurb))
    lines.append("")
    lines.append("  " + ui.c("amber", "talking to Frida", bold=True))
    for text, why in [
        ("add a --json flag", "anything that isn't a command is an instruction"),
        ("it crashes on empty input", "describe the fault, she'll find it"),
        ("> run", "a leading > forces plain language"),
    ]:
        lines.append("    " + ui.c("cream", text.ljust(28)) + ui.c("grey", why))
    lines.append("")
    lines.append("  " + ui.c("faint",
                 "commands work anywhere — including at a question or a plan."))
    lines.append("  " + ui.c("faint",
                 "tab completes · ↑ recalls · ctrl-c stops the current step."))
    return "\n".join(lines)


# ==========================================================================
# HANDLERS
# ==========================================================================
def _lines(code):
    return len(code.splitlines())


# ---- make ----------------------------------------------------------------
@command("build", "describe a tool and get it, tested and installed",
         group="make", arg="<what>", free_text=True)
def h_build(f, arg):
    if not arg:
        ui.err("say what to build")
        ui.note('build a tool that renames photos by the date they were taken')
        return None
    from . import agent
    f.tool = agent.Tool(f.provider)
    f.build(arg)
    return None


@command("new", "start a fresh tool", group="make", aliases=("reset",))
def h_new(f, arg):
    from . import agent
    kept = f.tool.name if f.tool.code else ""
    if kept:
        f.tool.save()
    f.tool = agent.Tool(f.provider)
    ui.ok("fresh start")
    if kept:
        ui.note("kept " + kept + " — /tools to come back to it")
    return None


@command("tools", "everything you've built", group="make",
         aliases=("library", "ls"))
def h_tools(f, arg):
    show_tools(f)
    return None


@command("resume", "pick one up again", group="make", arg="[id]", free_text=True)
def h_resume(f, arg):
    from . import agent
    record = engine.session_load(arg.strip()) if arg.strip() else None
    if not record:
        sessions = engine.session_list()[:12]
        if not sessions:
            ui.note("nothing to resume yet")
            return None
        if arg.strip():
            hit = next((s for s in engine.session_list()
                        if (s.get("name") or "").lower() == arg.strip().lower()), None)
            record = engine.session_load(hit["id"]) if hit else None
        if not record:
            labels = ["%s  %s" % (str(i).rjust(2), s.get("name") or s["id"])
                      for i, s in enumerate(sessions, 1)]
            choice = ui.ask("resume which?",
                            [{"label": lab,
                              "detail": "%s · %s lines · %s" % (
                                  s.get("updated", ""),
                                  s.get("lines", "?"), s["id"])}
                             for lab, s in zip(labels, sessions)],
                            allow_other=False)
            if choice is ui.CANCELLED:
                ui.note("stayed on " + (f.tool.name if f.tool.code else "nothing"))
                return None
            # Match on position, not on the label: two tools with the same
            # name used to collapse and load whichever came first.
            idx = labels.index(choice) if choice in labels else -1
            record = engine.session_load(sessions[idx]["id"]) if idx >= 0 else None
    if not record:
        ui.err("couldn't load that")
        return None
    if f.tool.code:
        f.tool.save()               # never drop the tool you were holding
    f.tool = agent.Tool.restore(record, f.provider)
    ui.ok("resumed %s · %d lines · v%s" %
          (f.tool.name, _lines(f.tool.code), f.tool.ver))
    return None


# ---- shape it ------------------------------------------------------------
@command("run", "run the current tool", group="shape", arg="[args]",
         needs_tool=True)
def h_run(f, arg):
    run_tool(f, shlex.split(arg) if arg else [])
    return None


@command("test", "run it for real — cases, pipes, exit codes", group="shape",
         needs_tool=True)
def h_test(f, arg):
    from . import agent
    board = ui.TaskBoard("", [agent.STEP_RUN])
    board.show()
    try:
        result = f.run_for_real(board)
    finally:
        # Without this, ctrl-C left Live's 90ms daemon repainting over the
        # prompt for the rest of the session, with the cursor still hidden.
        board.close()
    if result.get("blocked"):
        ui.warn(result["blocked"])
    else:
        ui.out(result["report"])
    return None


@command("fix", "feed the last failing run back and patch it", group="shape",
         needs_tool=True)
def h_fix(f, arg):
    from . import agent, harness
    if not f.tool.last_run:
        ui.err("nothing to fix from")
        ui.note("run it (/run or /test) and /fix works on whatever failed")
        return None
    # A non-zero exit is not automatically a fault. A bare run that exits 2
    # because required arguments are missing is the tool behaving CORRECTLY,
    # so the harness records no problem for it — and /fix used to respond to
    # that by drawing three empty checkboxes and returning in silence.
    if not harness.problems_for_model(f.tool.last_run):
        code = f.tool.last_run.get("exit")
        ui.info("nothing to fix — that run showed correct behaviour")
        if code == 2:
            ui.note("exit 2 with no arguments is what a well-behaved CLI does")
        ui.note("to exercise it properly: /run " + (f.tool.args or "<args>"))
        ui.note("or say what you want changed and I'll change it")
        return None
    board = ui.TaskBoard("", [agent.STEP_FIX, agent.STEP_READ, agent.STEP_RUN])
    board.show()
    try:
        f.fix_loop(board, run_result=f.tool.last_run)
    finally:
        board.close()
    return None


@command("review", "a proper read-through: what's wrong and what to change",
         group="shape", needs_tool=True)
def h_review(f, arg):
    f.review()
    return None


@command("undo", "step back to the version before the last change",
         group="shape", needs_tool=True)
def h_undo(f, arg):
    snap = f.tool.undo()
    if not snap:
        ui.note("nothing to undo — this is the first version")
        return None
    ui.ok("back to v%s · %d lines" % (snap["ver"], _lines(snap["code"])))
    if snap.get("note"):
        ui.note("undid: " + snap["note"])
    f.tool.save()
    return None


@command("redo", "put back what /undo took away", group="shape",
         needs_tool=True)
def h_redo(f, arg):
    snap = f.tool.redo()
    if not snap:
        ui.note("nothing to redo")
        return None
    ui.ok("forward to v%s · %d lines" % (snap["ver"], _lines(snap["code"])))
    f.tool.save()
    return None


@command("versions", "every version of this tool, and what changed",
         group="shape", aliases=("history",), needs_tool=True)
def h_versions(f, arg):
    show_versions(f)
    return None


@command("revert", "go back to a numbered version", group="shape",
         arg="<n>", needs_tool=True)
def h_revert(f, arg):
    if not arg.strip().isdigit():
        ui.err("which one? /versions lists them by number")
        return None
    snap = f.tool.revert(int(arg.strip()))
    if not snap:
        ui.err("no version " + arg.strip())
        return None
    ui.ok("reverted to v%s · %d lines" % (snap["ver"], _lines(snap["code"])))
    f.tool.save()
    return None


@command("gui", "build this one as a window, not a terminal tool",
         group="shape", aliases=("window",))
def h_gui(f, arg):
    return _set_kind(f, "gui")


@command("cli", "back to a terminal tool", group="shape", aliases=("terminal",))
def h_cli(f, arg):
    return _set_kind(f, "cli")


def _set_kind(f, want):
    was = getattr(f.tool, "kind", "cli")
    f.tool.kind = want
    if f.tool.code:
        f.tool.save()
    if was == want:
        ui.note("already a %s tool" % ("windowed" if want == "gui" else "terminal"))
        return None
    ui.ok("this is a windowed tool now" if want == "gui"
          else "this is a terminal tool now")
    if f.tool.code:
        ui.note("say what it should look like, and it'll be rebuilt that way")
    return None


@command("rename", "give the tool a different name", group="shape",
         arg="<name>", needs_tool=True, free_text=True)
def h_rename(f, arg):
    name = engine.safe_tool_name(arg.strip()) if arg.strip() else ""
    if not name:
        ui.err("give it a name: /rename photo-sorter")
        return None
    old = f.tool.name
    if old == name:
        ui.note("already called " + name)
        return None
    f.tool.name = name
    f.tool.named = True
    f.tool.save()
    ui.ok("%s is now %s" % (old, name))
    # The old binary used to stay on PATH forever, still running the code from
    # before the rename, while every later change went to the new name.
    # installed() returns full paths, not bare names.
    if any(os.path.basename(p) == ship._clean_name(old) for p in ship.installed()):
        if ship.install(f.tool.code, name).get("ok") and ship.uninstall(old):
            ui.note("moved the installed command from %s to %s" % (old, name))
        else:
            ui.warn("%s is still on your PATH with the old code" % old)
    return None


# ---- look at it ----------------------------------------------------------
@command("ask", "ask a question about the tool — it answers, nothing changes",
         group="look", arg="<question>", aliases=("quest", "explain", "why"),
         free_text=True, needs_tool=True, keep_head=("why", "explain"))
def h_ask(f, arg):
    question = arg.strip()
    if not question:
        ui.err("ask something")
        ui.note("ask why does it hang on an empty file?")
        ui.note("ask what happens if the config is missing?")
        return None
    f.ask(question)
    return None


@command("code", "print the source", group="look", needs_tool=True)
def h_code(f, arg):
    ui.code(f.tool.code, title=f.tool.name + ".py")
    return None


@command("diff", "what changed in the last round", group="look",
         needs_tool=True)
def h_diff(f, arg):
    prev = f.tool.previous_code()
    if prev is None:
        ui.note("nothing to compare against yet — this is the first version")
        return None
    ui.diff(prev, f.tool.code, path=f.tool.name + ".py")
    return None


@command("status", "where this tool stands", group="look", aliases=("info",))
def h_status(f, arg):
    show_status(f)
    return None


@command("cost", "tokens and spend this session", group="look")
def h_cost(f, arg):
    show_cost(f)
    return None


@command("doctor", "check this machine", group="look")
def h_doctor(f, arg):
    from . import main as _main
    _main.doctor()
    return None


# ---- ship it -------------------------------------------------------------
@command("deps", "install what the tool imports", group="ship",
         needs_tool=True)
def h_deps(f, arg):
    deps = engine.detect_deps(f.tool.code)["pip"]
    if not deps:
        ui.ok("standard library only — nothing to install")
        return None
    ui.info("installing: " + ", ".join(deps))
    res = engine.install_deps(deps)
    (ui.ok if res.get("ok") else ui.err)(res.get("log", "")[-800:] or "done")
    return None


@command("save", "write a copy to ~/frida-tools", group="ship",
         needs_tool=True)
def h_save(f, arg):
    p = ship.save_copy(f.tool.code, f.tool.name)["path"]
    ui.file_card(p, "saved", "python3 %s --help" % p)
    return None


@command("install", "put it on your PATH as a command", group="ship",
         needs_tool=True)
def h_install(f, arg):
    res = ship.install(f.tool.code, f.tool.name)
    if res.get("occupied"):
        ui.warn(res["error"])
        ui.note("that file isn't one of Frida's — overwriting it may break something")
        if not ui.confirm("overwrite it?", default=False):
            ui.note("try /rename to give the tool a different command name")
            return None
        res = ship.install(f.tool.code, f.tool.name, overwrite=True)
    if not res.get("ok"):
        ui.err(res.get("error", "failed"))
        return None
    ui.file_card(res["path"], res["name"] + " installed", res["name"] + " --help")
    if not res["on_path"]:
        ui.warn("~/.local/bin isn't on your PATH:")
        ui.note(res["hint"])
    return None


@command("release", "assemble a GitHub-ready repo", group="ship",
         arg="[user]", needs_tool=True, free_text=True)
def h_release(f, arg):
    user = arg.strip() or ui.prompt("github user ›").strip()
    f.release(user=user)
    return None


@command("freeze", "build a single-file binary", group="ship", needs_tool=True)
def h_freeze(f, arg):
    ui.info("building a single-file binary — this takes a minute")
    res = ship.freeze(f.tool.code, f.tool.name)
    if res.get("ok"):
        ui.file_card(res["path"], "binary built", res["path"])
    else:
        ui.err((res.get("log") or "build failed")[-900:])
    return None


# ---- session -------------------------------------------------------------
@command("theme", "change how Frida looks", group="session", arg="[name]",
         free_text=True)
def h_theme(f, arg):
    want = arg.strip().lower()
    if want in ("", "?", "list"):
        current = ui.THEME          # the loop below repaints in each theme
        ui.blank()
        ui.rule("themes")
        ui.blank()
        for name in ui.THEMES:
            here = name == current
            ui.set_theme(name)
            mark = ui.c("lime", ui.G.done) if here else ui.c("faint", " ")
            ui.out("  %s  %s  %s   %s%s%s%s" % (
                mark,
                ui.c("amber", name.ljust(10), bold=True),
                ui.c("grey", ui.THEME_BLURB.get(name, "")[:28].ljust(29)),
                ui.c("cream", "text "), ui.c("lime", ui.G.done + " "),
                ui.c("red", ui.G.fail + " "), ui.c("teal", "tool")))
        ui.set_theme(current)   # ...and this used to "restore" the last one
        ui.blank()
        ui.note("/theme matrix   ·   it sticks between sessions")
        ui.blank()
        return None
    if not ui.set_theme(want):
        ui.err("no theme called " + want)
        ui.note("there is: " + ", ".join(ui.THEMES))
        return None
    engine.STATE["theme"] = want
    engine.persist_state()
    ui.ok("theme: " + want + "  " + ui.c("grey", ui.THEME_BLURB.get(want, "")))
    return None


@command("big", "draw headings three rows tall", group="session",
         arg="[on|off|text]", free_text=True)
def h_big(f, arg):
    want = arg.strip().lower()
    if want and want not in ("on", "off", "toggle"):
        ui.blank()
        ui.big(arg.strip())         # one-off: draw whatever you typed
        ui.blank()
        return None
    on = (want == "on") if want in ("on", "off") else not ui.BIG_MODE
    ui.set_big(on)
    engine.STATE["big"] = on
    engine.persist_state()
    if on:
        ui.blank()
        ui.big("big mode", "amber")
        ui.blank()
        ui.note("tool names and headings draw large from here on")
    else:
        ui.ok("big mode off")
    name, keys, cfg = engine.terminal()
    if on and keys:
        ui.blank()
        ui.note("to make the actual font bigger in " + name + ":")
        ui.note("  " + keys)
        if cfg:
            ui.note("  " + cfg)
    return None


@command("edit", "open the tool in $EDITOR", group="shape", needs_tool=True)
def h_edit(f, arg):
    """Hand-editing is part of perfecting something. Frida picks the change up."""
    import subprocess, tempfile
    editor = (os.environ.get("VISUAL") or os.environ.get("EDITOR") or "").strip()
    if not editor:
        for candidate in ("nvim", "vim", "nano", "micro", "vi"):
            if shutil.which(candidate):
                editor = candidate
                break
    if not editor:
        ui.err("no editor found — set $EDITOR")
        return None
    fd, path = tempfile.mkstemp(prefix=f.tool.name + "-", suffix=".py")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(f.tool.code)
        before = f.tool.code
        try:
            subprocess.call(editor.split() + [path])
        except OSError as exc:
            ui.err("couldn't start %s: %s" % (editor, exc))
            return None
        with open(path, encoding="utf-8") as fh:
            after = fh.read()
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    if after.strip() == before.strip():
        ui.note("nothing changed")
        return None
    ok, why = engine.parses(after)
    if not ok:
        ui.err("that doesn't parse: " + why)
        ui.note("nothing was changed — /edit again to fix it")
        return None
    f.tool.snapshot("edited by hand")
    f.tool.code = after
    f.tool.bump("patch")
    # The model must be told, or its next full rewrite silently reverts you.
    f.tool.messages.append({"role": "user", "content":
                            "I edited the file by hand. This is the current file now."})
    f.tool.messages.append({"role": "assistant", "content": engine.fenced(after)})
    f.tool.last_run = None
    f.tool.save()
    ui.ok("picked up your edit · v%s · %d lines"
          % (f.tool.ver, len(after.splitlines())))
    ui.note("/test to check it still works")
    return None


@command("uninstall", "take the command off your PATH", group="ship",
         arg="[name]", free_text=True)
def h_uninstall(f, arg):
    name = arg.strip() or f.tool.name
    if not name or (not arg.strip() and not f.tool.code):
        ui.err("which one? /tools lists them")
        return None
    res = ship.uninstall(name)
    if res.get("ok"):
        ui.ok("removed " + res["path"])
        ui.note("the tool itself is still saved — /install puts it back")
    else:
        ui.err(res.get("error", "couldn't remove it"))
    return None


@command("think", "how much the model may think before writing", group="session",
         arg="[off|N|auto]", free_text=True)
def h_think(f, arg):
    want = arg.strip().lower()
    current = engine.STATE.get("thinking")
    if not want:
        now = ("off" if current == 0 else
               "auto — the model decides" if current is None else "%s tokens" % current)
        ui.blank()
        ui.out("  " + ui.c("cream", "thinking: ", bold=True) + ui.c("amber", now))
        ui.blank()
        ui.note("/think off    fastest — code starts arriving immediately")
        ui.note("/think 2000   a short think, then write")
        ui.note("/think auto   let the model decide (can be tens of thousands)")
        ui.blank()
        ui.note("only some models take this; the rest ignore it")
        ui.blank()
        return None
    if want in ("auto", "default"):
        engine.STATE["thinking"] = None
    elif want in ("off", "none", "0", "no"):
        engine.STATE["thinking"] = 0
    elif want.isdigit():
        engine.STATE["thinking"] = max(0, min(64000, int(want)))
    else:
        ui.err("say: /think off, /think 2000, or /think auto")
        return None
    engine.persist_state()
    value = engine.STATE["thinking"]
    ui.ok("thinking: " + ("off" if value == 0 else
                          "auto" if value is None else "%d tokens" % value))
    return None


@command("model", "choose the model — live list from the provider",
         group="session", arg="[name or part of one]")
def h_model(f, arg):
    from . import main as _main
    _main.pick_model(f, arg)
    return None


@command("key", "set an API key", group="session")
def h_key(f, arg):
    from . import main as _main
    pid = engine.STATE["provider"]
    had = engine.STATE["keys"].get(pid) or ""
    engine.STATE["keys"][pid] = ""
    if not _main.ensure_key(force_prompt=True):
        # They backed out. Put back what was there rather than leaving the
        # provider keyless because they changed their mind.
        engine.STATE["keys"][pid] = had
        engine.STATE["provider"] = pid
        if had:
            ui.note("kept your existing " + engine.PROVIDERS[pid]["label"] + " key")
    return None


@command("help", "this list", group="session", aliases=("h", "?"))
def h_help(f, arg):
    if arg.strip():
        cmd = lookup(arg.strip())
        if not cmd:
            ui.err("no such command: " + arg.strip())
            return None
        ui.blank()
        ui.out("  " + ui.c("amber", "/" + cmd.usage, bold=True))
        ui.out("  " + ui.c("grey", cmd.blurb))
        if cmd.aliases:
            ui.out("  " + ui.c("faint", "also: " +
                               ", ".join("/" + a for a in cmd.aliases)))
        ui.blank()
        return None
    ui.out(help_text())
    ui.blank()
    return None


@command("clear", "clear the screen", group="session", aliases=("cls",))
def h_clear(f, arg):
    if ui.is_tty():
        ui.raw("\033[2J\033[H")
    return None


@command("quit", "leave", group="session", aliases=("exit", "q"))
def h_quit(f, arg):
    return "quit"


# ==========================================================================
# VIEWS used by handlers (kept here so the registry is self-contained)
# ==========================================================================
def run_tool(f, argv):
    from . import main as _main
    return _main.run_tool(f, argv)


def show_tools(f):
    from . import main as _main
    return _main.show_tools()


def show_cost(f):
    from . import main as _main
    return _main.show_cost()


def show_status(f):
    t = f.tool
    ui.blank()
    if not t.code:
        ui.out("  " + ui.c("grey", "no tool in the workshop yet."))
        ui.out("  " + ui.c("faint", "describe one, or /tools to reopen an old one"))
        ui.blank()
        return
    passed, total, good = ui.run_tally(t)
    if ui.BIG_MODE:
        ui.big(t.name, "teal")
        ui.blank()
    rows = [
        ("name", t.name),
        ("version", "v" + t.ver),
        ("lines", str(_lines(t.code))),
        ("tests", ("%d/%d passing" % (passed, total)) if total and good else
                  ("%d of %d failing" % (total - passed, total)) if total else
                  "not run yet"),
        ("versions", str(len(t.history) + 1)),
        ("deps", ", ".join(engine.detect_deps(t.code)["pip"]) or "standard library"),
    ]
    ui.rule("this tool")
    ui.blank()
    ui.kv(rows)
    ui.blank()


def show_versions(f):
    t = f.tool
    ui.blank()
    ui.rule("versions")
    ui.blank()
    snaps = t.history + [{"ver": t.ver, "code": t.code, "note": "current"}]
    width = ui.width()
    for i, s in enumerate(snaps, 1):
        current = i == len(snaps)
        mark = ui.c("lime", ui.G.done) if current else ui.c("faint", str(i).rjust(2))
        head = ui.c("cream" if current else "grey", ("v" + s["ver"]).ljust(9))
        note = (s.get("note") or "").strip().replace("\n", " ")
        room = max(20, width - 26)
        if len(note) > room:
            note = note[:room - 1] + "…"
        ui.out("  %s  %s%s  %s" % (
            mark, head, ui.c("faint", "%4d ln" % _lines(s["code"])),
            ui.c("faint" if not current else "grey", note)))
    ui.blank()
    if len(snaps) > 1:
        ui.note("/revert <n> to go back · /undo for one step")
    ui.blank()


# ==========================================================================
# READLINE — completion and history that survives the session
# ==========================================================================
def _completer(text, state):
    line = ""
    try:
        import readline
        line = readline.get_line_buffer()
    except Exception:
        pass
    stripped = line.lstrip()

    # Completing the first word: offer commands.
    if " " not in stripped:
        slash = text.startswith("/")
        stem = text.lstrip("/")
        hits = [n for n in all_names() if n.startswith(stem.lower())]
        hits = [("/" + h if slash else h) + " " for h in hits]
    else:
        head = stripped.split()[0].lstrip("/")
        hits = []
        if head in ("resume",):
            hits = [s.get("name") or s["id"] for s in engine.session_list()
                    if (s.get("name") or s["id"]).startswith(text)]
        elif head in ("help", "h", "?"):
            hits = [n + " " for n in all_names() if n.startswith(text.lower())]
    try:
        return hits[state]
    except IndexError:
        return None


def install_readline():
    """Tab completion and a history file. Silently does nothing without readline."""
    try:
        import readline
    except ImportError:
        return None
    path = os.path.join(engine.data_dir(), "history")
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        readline.read_history_file(path)
    except (OSError, ValueError):
        pass
    try:
        readline.set_history_length(2000)
        readline.set_completer(_completer)
        readline.set_completer_delims(" \t\n")
        if "libedit" in (getattr(readline, "__doc__", "") or ""):
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")
    except Exception:
        return None
    return path


def save_readline(path):
    """Write the history file, minus anything that looks like a credential.

    /key no longer goes through readline at all, but a key can still reach the
    history the ordinary way — pasted at the main prompt by mistake, or typed
    into an instruction. A shell-history file full of live API keys is a
    well-known way to leak one, and this file is ours to keep clean.
    """
    if not path:
        return
    try:
        import readline
    except ImportError:
        return
    try:
        for i in range(readline.get_current_history_length(), 0, -1):
            if ui.looks_secret(readline.get_history_item(i) or ""):
                readline.remove_history_item(i - 1)
    except Exception:
        pass
    try:
        readline.write_history_file(path)
        os.chmod(path, 0o600)
    except Exception:
        pass


def set_sink_for(f):
    """Point every prompt in the program at this dispatcher."""
    def sink(line):
        try:
            return dispatch(f, line)
        except KeyboardInterrupt:
            ui.blank()
            ui.warn("stopped")
            return None
    ui.set_command_sink(sink)
