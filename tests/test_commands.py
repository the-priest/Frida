#!/usr/bin/env python3
"""The command layer — dispatch, the registry, and the gate.

These are regression tests for a specific, embarrassing failure. In 1.0.1 the
help text advertised bare `run`, `save` and `new`; none of them dispatched, so
they were sent to the model as instructions and it "patched" the tool with the
word "run". At the same time `/save` typed at the plan gate was read as a plan
revision, so it built the tool instead of saving it. Every check below is one
of those two mistakes, nailed down.

    python3 tests/test_commands.py
"""

import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

_SANDBOX = tempfile.mkdtemp(prefix="frida-cmd-")
os.environ["HOME"] = _SANDBOX
os.environ["XDG_CONFIG_HOME"] = os.path.join(_SANDBOX, ".config")
os.environ["XDG_DATA_HOME"] = os.path.join(_SANDBOX, ".local", "share")
os.environ["NO_COLOR"] = "1"

from frida import agent, commands, ui                  # noqa: E402

FAILURES = []


def check(label, condition, detail=""):
    print(f"[{'PASS' if condition else 'FAIL'}] {label}" +
          (f"  —  {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(label)


def kind_of(line):
    k, payload, arg = commands.resolve(line)
    return k, (payload.name if hasattr(payload, "name") else payload), arg


print("== dispatch ==")

# The bug, exactly: these three were advertised and silently went to the model.
for word in ("run", "save", "new", "test", "deps", "code", "install", "review"):
    k, name, _ = kind_of(word)
    check(f"bare '{word}' is a command", k == commands.RUN and name == word,
          f"got {k}/{name}")

# Slashed always works.
for word in ("/run", "/save", "/new", "/quit"):
    k, _, _ = kind_of(word)
    check(f"'{word}' is a command", k == commands.RUN, f"got {k}")

# Sentences that merely start with a command word are instructions.
for line in ("test it with an empty file",
             "save it as a different name",
             "run it again but with --json this time",
             "install pandas too",
             "new idea: make it recursive"):
    k, _, _ = kind_of(line)
    check(f"instruction stays an instruction: {line!r}", k == commands.SAY,
          f"got {k}")

# Flags after an arg-taking command are arguments, not English.
k, name, arg = kind_of("run --json input.csv")
check("'run --json input.csv' is /run with args",
      k == commands.RUN and name == "run" and arg == "--json input.csv",
      f"got {k}/{name}/{arg!r}")

# Free-text commands take the rest of the line.
k, name, arg = kind_of("build a tool that renames photos")
check("'build <free text>' is /build",
      k == commands.RUN and name == "build" and arg == "a tool that renames photos")

# The escape hatch.
k, payload, _ = kind_of("> run")
check("'> run' forces an instruction", k == commands.SAY and payload == "run")

# Unknown commands are an error, never a silent fallthrough to the model.
k, payload, _ = kind_of("/frobnicate")
check("unknown /command is an error", k == commands.UNKNOWN)
check("unknown /command suggests a near miss", commands.suggest("insatll") == "install",
      commands.suggest("insatll"))

print()
print("== the registry is the only list ==")

# The original sin was three lists that disagreed. Assert there is now one.
help_body = ui.plain(commands.help_text(width=100))
listed = set()
for line in help_body.splitlines():
    line = line.strip()
    if not line or line.startswith(("talking", "make", "shape", "look", "ship",
                                    "session", "commands work", "tab completes")):
        continue
    first = line.split()[0]
    if first in commands.all_names():
        listed.add(first)

check("help lists a useful number of commands", len(listed) >= 15, str(len(listed)))
missing = [n for n in listed if not commands.lookup(n)]
check("every command in /help actually dispatches", not missing, str(missing))

visible = {c.name for c in commands.REGISTRY if not c.hidden}
unlisted = visible - listed
check("every real command appears in /help", not unlisted, str(sorted(unlisted)))

# The names the top-level argument parser refuses must be real commands too.
from frida import main as frida_main                    # noqa: E402
bogus = [n for n in frida_main.IN_SESSION_ONLY if not commands.lookup(n)]
check("argv guard only names real commands", not bogus, str(bogus))

print()
print("== commands work at a gate ==")


class FakeTool:
    code = "print('hi')"
    name = "demo"


class FakeFrida:
    def __init__(self):
        self.tool = FakeTool()
        self.saved = False


f = FakeFrida()
seen = []


def sink(line):
    seen.append(line)
    if line == "/quit":
        return "quit"
    return None


ui.set_command_sink(sink)

# The plan gate: /save must be intercepted, NOT returned as a plan revision.
import builtins                                        # noqa: E402
feed = iter(["/save", ""])
builtins.input = lambda *a: next(feed)
answer = ui.prompt("›", "enter to build it", commands=True)
check("/save at the plan gate was intercepted", seen == ["/save"], str(seen))
check("the gate still returned the real answer afterwards", answer.strip() == "",
      repr(answer))

# A question: /code must not be mistaken for an answer.
seen.clear()
feed = iter(["/code", "2"])
builtins.input = lambda *a: next(feed)
picked = ui.ask("which one?", [{"label": "first"}, {"label": "second"}],
                allow_other=False)
check("/code at a question was intercepted", seen == ["/code"], str(seen))
check("the question still got its real answer", picked == "second", picked)

# A confirm: same.
seen.clear()
feed = iter(["/status", "y"])
builtins.input = lambda *a: next(feed)
yes = ui.confirm("go ahead?", default=False)
check("/status at a confirm was intercepted", seen == ["/status"], str(seen))
check("the confirm still got its real answer", yes is True, str(yes))

# /quit at a gate leaves, rather than being swallowed.
feed = iter(["/quit"])
builtins.input = lambda *a: next(feed)
try:
    ui.prompt("›", commands=True)
    quit_worked = False
except ui.Quit:
    quit_worked = True
check("/quit at a gate raises out to the REPL", quit_worked)

# Plain text at a gate is untouched.
seen.clear()
feed = iter(["make it recursive"])
builtins.input = lambda *a: next(feed)
answer = ui.prompt("›", commands=True)
check("plain text at a gate is not a command", not seen and answer == "make it recursive")

print()
print("== history ==")

t = agent.Tool()
t.code, t.ver = "one", "1.0.0"
t.snapshot("add a flag")
t.code, t.ver = "two", "1.0.1"
t.snapshot("fix a crash")
t.code, t.ver = "three", "1.0.2"

check("history records each version", [h["ver"] for h in t.history] == ["1.0.0", "1.0.1"])
check("previous_code is the one before now", t.previous_code() == "two")
t.undo()
check("undo steps back", t.code == "two")
t.undo()
check("undo steps back again", t.code == "one")
check("undo stops at the beginning", t.undo() is None)
t.redo()
check("redo goes forward", t.code == "two")
check("a new change clears the redo stack",
      (t.snapshot("something else"), t.future == [])[1])
check("revert jumps to a numbered version", t.revert(1)["code"] == "one")
check("revert refuses a version that isn't there", t.revert(99) is None)
check("undo on a fresh tool is harmless", agent.Tool().undo() is None)

print()
print("== themes and motion ==")

for name in ui.THEMES:
    check(f"theme {name} sets every colour role",
          set(ui.THEMES[name]) == set(ui.THEMES["ember"]),
          str(set(ui.THEMES["ember"]) ^ set(ui.THEMES[name])))
    check(f"theme {name} has a blurb", bool(ui.THEME_BLURB.get(name)))

before = ui.THEME
check("set_theme swaps the palette", ui.set_theme("matrix") and ui.THEME == "matrix")
check("an unknown theme is refused", ui.set_theme("chartreuse") is False)
check("a refused theme leaves the old one alone", ui.THEME == "matrix")
ui.set_theme(before)

check("256-colour fallback stays in range",
      all(16 <= ui._rgb_to_256(*v) <= 255
          for pal in ui.THEMES.values() for v in pal.values()))

# Motion must never fire when the output isn't a terminal — a log file or a
# pipe full of cursor-movement escapes is worse than no animation at all.
real_tty = ui.is_tty
ui.is_tty = lambda: False
check("no motion when stdout isn't a tty", ui.motion_enabled() is False)
ui.is_tty = lambda: True
os.environ["FRIDA_PLAIN"] = "1"
check("FRIDA_PLAIN turns motion off", ui.motion_enabled() is False)
os.environ.pop("FRIDA_PLAIN")
ui.set_motion(False)
check("--plain turns motion off", ui.motion_enabled() is False)
ui.set_motion(True)
ui.is_tty = real_tty

print()
print("== layout ==")

import io                                              # noqa: E402
buf = io.StringIO()
ui._stream = lambda: buf
ui.blank(); ui.blank(); ui.blank()
check("blank lines collapse", buf.getvalue() == "", repr(buf.getvalue()))
buf.truncate(0), buf.seek(0)
ui.out("something"); ui.blank(); ui.blank()
check("one blank line survives after content",
      buf.getvalue() == "something\n\n", repr(buf.getvalue()))
buf.truncate(0), buf.seek(0)
ui.gap()
check("gap is a deliberate double", buf.getvalue() == "\n\n", repr(buf.getvalue()))
buf.truncate(0), buf.seek(0)
for fn in (ui.ok, ui.err, ui.warn, ui.info):
    buf.truncate(0), buf.seek(0)
    fn("x")
    line = ui.plain(buf.getvalue())
    check(f"{fn.__name__}() sits on the left margin",
          line.startswith("  ") and not line.startswith("   "), repr(line))
ui._stream = lambda: sys.stderr

print()
if FAILURES:
    print(f"something failed: {len(FAILURES)}")
    for f_ in FAILURES:
        print("  - " + f_)
    sys.exit(1)
print("all good")
