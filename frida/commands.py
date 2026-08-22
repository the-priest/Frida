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

from . import engine, ship, ui


# ==========================================================================
# THE REGISTRY
# ==========================================================================
class Command:
    __slots__ = ("name", "aliases", "arg", "blurb", "group", "handler",
                 "needs_tool", "free_text", "hidden")

    def __init__(self, name, blurb, handler, group="", aliases=(), arg="",
                 needs_tool=False, free_text=False, hidden=False):
        self.name = name
        self.aliases = tuple(aliases)
        self.arg = arg
        self.blurb = blurb
        self.group = group
        self.handler = handler
        self.needs_tool = needs_tool
        self.free_text = free_text
        self.hidden = hidden

    @property
    def names(self):
        return (self.name,) + self.aliases

    @property
    def usage(self):
        return self.name + ((" " + self.arg) if self.arg else "")


REGISTRY = []
_BY_NAME = {}


def command(name, blurb, group="", aliases=(), arg="", needs_tool=False,
            free_text=False, hidden=False):
    """Register a command. The decorated function is its handler."""
    def deco(fn):
        cmd = Command(name, blurb, fn, group, aliases, arg, needs_tool,
                      free_text, hidden)
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
        return SAY, line[1:].strip(), ""

    slashed = line.startswith("/")
    body = line[1:].strip() if slashed else line
    if not body:
        return NOTHING, "", ""

    head, _, tail = body.partition(" ")
    tail = tail.strip()
    cmd = lookup(head)

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
            hit = next((s for s in sessions
                        if (s.get("name") or "").lower() == arg.strip().lower()), None)
            record = engine.session_load(hit["id"]) if hit else None
        if not record:
            choice = ui.ask("resume which?",
                            [{"label": s.get("name") or s["id"],
                              "detail": "%s · %s lines · %s" % (
                                  s.get("updated", ""),
                                  s.get("lines", "?"), s["id"])}
                             for s in sessions], allow_other=False)
            record = next((engine.session_load(s["id"]) for s in sessions
                           if (s.get("name") or s["id"]) == choice), None)
    if not record:
        ui.err("couldn't load that")
        return None
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
    result = f.run_for_real(board)
    board.close()
    if result.get("blocked"):
        ui.warn(result["blocked"])
    else:
        ui.out(result["report"])
    return None


@command("fix", "feed the last failing run back and patch it", group="shape",
         needs_tool=True)
def h_fix(f, arg):
    from . import agent
    if not f.tool.last_run:
        ui.err("nothing to fix from")
        ui.note("run /test first, then /fix works on what it found")
        return None
    board = ui.TaskBoard("", [agent.STEP_FIX, agent.STEP_READ, agent.STEP_RUN])
    board.show()
    f.fix_loop(board, run_result=f.tool.last_run)
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


@command("rename", "give the tool a different name", group="shape",
         arg="<name>", needs_tool=True, free_text=True)
def h_rename(f, arg):
    name = engine.safe_tool_name(arg.strip()) if arg.strip() else ""
    if not name:
        ui.err("give it a name: /rename photo-sorter")
        return None
    old, f.tool.name = f.tool.name, name
    f.tool.named = True
    f.tool.save()
    ui.ok("%s is now %s" % (old, name))
    return None


# ---- look at it ----------------------------------------------------------
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
        ui.blank()
        ui.rule("themes")
        ui.blank()
        for name in ui.THEMES:
            here = name == ui.THEME
            ui.set_theme(name)
            mark = ui.c("lime", ui.G.done) if here else ui.c("faint", " ")
            ui.out("  %s  %s  %s   %s%s%s%s" % (
                mark,
                ui.c("amber", name.ljust(10), bold=True),
                ui.c("grey", ui.THEME_BLURB.get(name, "")[:28].ljust(29)),
                ui.c("cream", "text "), ui.c("lime", ui.G.done + " "),
                ui.c("red", ui.G.fail + " "), ui.c("teal", "tool")))
        ui.set_theme(ui.THEME)
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


@command("model", "choose the model", group="session")
def h_model(f, arg):
    from . import main as _main
    _main.pick_model(f)
    return None


@command("key", "set an API key", group="session")
def h_key(f, arg):
    from . import main as _main
    engine.STATE["keys"][engine.STATE["provider"]] = ""
    _main.ensure_key()
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
    tests = t.last_run or {}
    passed, total = tests.get("passed"), tests.get("total")
    rows = [
        ("name", t.name),
        ("version", "v" + t.ver),
        ("lines", str(_lines(t.code))),
        ("tests", ("%s/%s passing" % (passed, total)) if total else "not run yet"),
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
    if not path:
        return
    try:
        import readline
        readline.write_history_file(path)
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
