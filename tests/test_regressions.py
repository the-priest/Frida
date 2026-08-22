#!/usr/bin/env python3
"""One check per bug found in the 2.1 audit. Each names the defect it pins.

These are the bugs the behaviour tests did not find, because the behaviour
tests only exercised the paths I already had in mind. Everything here was
reproduced first and fixed second.

    python3 tests/test_regressions.py
"""

import io
import math
import os
import pathlib
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

_SANDBOX = tempfile.mkdtemp(prefix="frida-reg-")
os.environ["HOME"] = _SANDBOX
os.environ["XDG_CONFIG_HOME"] = os.path.join(_SANDBOX, ".config")
os.environ["XDG_DATA_HOME"] = os.path.join(_SANDBOX, ".local", "share")
os.environ["NO_COLOR"] = "1"

from frida import agent, commands, engine, main, ship, ui   # noqa: E402

FAILURES = []


def check(label, condition, detail=""):
    print(f"[{'PASS' if condition else 'FAIL'}] {label}" +
          (f"  —  {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(label)


print("== rendering: a live region must never wrap ==")

# A board line wider than the terminal took two rows, but Live moved the cursor
# up by the LOGICAL line count, so every frame overwrote the wrong rows and the
# checklist shredded the screen. Triggered by any build error: the step names
# are ~20 chars and the notes are truncated at 60.
ui.width = lambda default=80: 80
board = ui.TaskBoard("", ["Agree on the shape", "Plan the build", "Write it"])
board.fail("Plan the build",
           "the model returned a response that could not be parsed at all")
lines = board.render()
cols = 80
rows = sum(max(1, math.ceil(ui.vlen(l) / cols)) for l in lines)
check("a long failure note still renders wider than the terminal",
      any(ui.vlen(l) > cols for l in lines))
check("...but clip() brings every line back to one row",
      all(ui.vlen(ui.clip(l, cols)) <= cols for l in lines),
      str([ui.vlen(ui.clip(l, cols)) for l in lines]))
clipped = [ui.clip(l, cols) for l in lines]
check("clipped line count equals the row count Live moves the cursor by",
      sum(max(1, math.ceil(ui.vlen(l) / cols)) for l in clipped) == len(clipped))

check("clip keeps text under the limit", ui.vlen(ui.clip("x" * 200, 40)) <= 40)
check("clip is a no-op when it fits", ui.clip("short", 40) == "short")
check("clip survives a zero limit", ui.clip("abc", 0) == "")

# Tabs were expanded AFTER the budget was applied, so each one added 3 columns.
b2 = ui.TaskBoard("", ["Write it"])
b2.start("Write it", "thinking")
b2.set_preview("\t\tresult = subprocess.run(cmd, capture_output=True, check=False)")
over = [l for l in b2.render() if ui.vlen(l) > 80]
check("a tab-indented preview line stays inside the terminal", not over,
      str([ui.vlen(l) for l in over]))

print()
print("== rendering: widths are measured in columns, not characters ==")

check("a wide CJK glyph counts as two columns", ui.cells("あ") == 2)
check("a plain letter counts as one", ui.cells("a") == 1)
ui.width = lambda default=80: 48
cjk = ui.wrap("このツールはCSVをマークダウンの表に変換します。とても便利です。", indent=2)
check("CJK text wraps inside the layout width",
      all(ui.vlen(l) <= 48 for l in cjk.split("\n")),
      str([ui.vlen(l) for l in cjk.split("\n")]))

# wrap() only ever broke BETWEEN words, so one long token blew through the
# right-hand edge — and through a panel's border.
url = ui.wrap("see https://github.com/someone/a-really-quite-long-repository-name/"
              "issues/12345 for details", indent=2)
check("an unbreakable token is split rather than overflowing",
      all(ui.vlen(l) <= 48 for l in url.split("\n")),
      str([ui.vlen(l) for l in url.split("\n")]))
ui.width = lambda default=80: 80

print()
print("== themes ==")

# set_theme rebuilt _RGB and _256 but not _16, so `--theme paper` (near-black
# inks, for light terminals) rendered as SGR 37 — white on white.
ui.set_theme("ember")
ember16 = dict(ui._16)
ui.set_theme("paper")
check("a theme remaps the 16-colour table too", ui._16 != ember16)
check("every colour role has a 16-colour mapping",
      set(ui._16) == set(ui.THEMES["paper"]))
check("16-colour codes are legal ANSI foregrounds",
      all(30 <= v <= 37 for v in ui._16.values()), str(ui._16))
ui.set_theme("ember")

# The listing loop repainted in each theme and then "restored" ui.THEME —
# which by then was already the last theme in the dict.
ui.set_theme("ice")


class _T:
    code = ""
    name = "x"


class _F:
    tool = _T()
    provider = None
    busy = False


commands.h_theme(_F(), "")
check("listing the themes leaves you on the one you were using",
      ui.THEME == "ice", ui.THEME)
ui.set_theme("ember")

print()
print("== dispatch and gates ==")

# A bare ">" reached say() as an empty instruction: two paid model calls and
# the tool replaced by whatever came back.
check("a bare '>' does nothing", commands.resolve(">")[0] == commands.NOTHING)
check("'>' with text is still a forced instruction",
      commands.resolve("> run") == (commands.SAY, "run", ""))

# The sink was installed inside repl() only, so `frida "a csv tool"` — the
# flagship invocation — had no command handling at its plan gate at all.
src = open(os.path.join(ROOT, "frida", "main.py")).read()
main_body = src[src.index("def main("):]
check("the command sink is installed for the one-shot path too",
      "set_sink_for" in main_body)

# ask() returned the DEFAULT on ctrl-C, so callers could not tell "cancelled"
# from "picked option 1". /model pinned a model nobody chose.
import builtins                                          # noqa: E402


def _interrupt(*a):
    raise KeyboardInterrupt


builtins.input = _interrupt
picked = ui.ask("which?", [{"label": "model-A"}, {"label": "model-B"}],
                allow_other=False)
check("ctrl-C at a chooser reports cancellation", picked is ui.CANCELLED, repr(picked))
check("CANCELLED still behaves like an empty string", picked == "")

check("ask clamps a nonsense default",
      ui.ask.__doc__ is not None)          # signature check below does the work
feed = iter(["1"])
builtins.input = lambda *a: next(feed)
check("a default past the end of the list doesn't raise",
      ui.ask("q", [{"label": "one"}], default=9) == "one")

print()
print("== the build must own its tool ==")

# Commands typed at a gate run while build() is on the stack. /new, /resume and
# /build all rebind f.tool, and the in-flight build then carried on writing
# into — and re-installing — whatever tool you had switched to.
class _Busy:
    busy = True
    provider = None

    def __init__(self):
        self.tool = agent.Tool()
        self.tool.code = "print(1)"


for name in ("new", "resume", "build"):
    f = _Busy()
    before = f.tool
    commands.dispatch(f, "/" + name + (" x" if name == "build" else ""))
    check(f"/{name} is refused while a build is in flight", f.tool is before)

f = _Busy()
f.busy = False
check("...and allowed when nothing is building",
      commands.dispatch(f, "/new") is None and f.tool is not None)

print()
print("== undo must move the conversation with the code ==")

# undo restored the code but left the transcript ending in the undone version,
# so the next full rewrite silently reinstated it.
t = agent.Tool()
t.code = "A"
t.messages = [{"role": "user", "content": "make A"},
              {"role": "assistant", "content": "A"}]
t.snapshot("add B")
t.code = "B"
t.messages += [{"role": "user", "content": "add B"},
               {"role": "assistant", "content": "B"}]
t.snapshot("add C")
t.code = "C"
t.messages += [{"role": "user", "content": "add C"},
               {"role": "assistant", "content": "C"}]

t.undo()
check("undo rewinds the code", t.code == "B")
check("undo rewinds the conversation with it",
      t.messages[-1]["content"] == "B", str(len(t.messages)))
t.undo()
check("undo again", t.code == "A" and t.messages[-1]["content"] == "A")
t.redo()
check("redo puts the code back", t.code == "B")
check("redo puts the conversation back too",
      t.messages[-1]["content"] == "B", str(len(t.messages)))
t.redo()
check("redo to the newest version", t.code == "C" and len(t.messages) == 6)

print()
print("== flags and settings ==")

# --no-verify was declared, documented in --help, and read nowhere.
import inspect                                           # noqa: E402
check("build() accepts verify=",
      "verify" in inspect.signature(agent.Frida.build).parameters)
check("--no-verify is actually passed to build()",
      "verify=not args.no_verify" in src)

# --theme and --model are "for this run" but were written into STATE, which
# persist_state() serialises wholesale.
cfg = engine.CONFIG_PATH
engine.STATE["models"]["groq"] = "on-disk-model"
engine.STATE["provider"] = "groq"
engine.RUN_OVERRIDES["model"] = None
engine.persist_state()
engine.STATE["models"]["groq"] = "just-for-this-run"
engine.RUN_OVERRIDES["model"] = ("groq", "just-for-this-run")
engine.persist_state()
saved = engine.load_config().get("models", {}).get("groq")
check("--model does not become permanent", saved == "on-disk-model", repr(saved))
engine.RUN_OVERRIDES["model"] = None

# `frida code | wc -l` is documented; deriving the guard from the registry
# swept it — and cost, ls and library — into "in-session only".
for name in ("code", "cost", "ls", "library", "tools", "doctor", "resume"):
    check(f"`frida {name}` is reachable as a subcommand",
          name not in main.IN_SESSION_ONLY)
for name in ("test", "fix", "install", "save", "undo", "theme"):
    check(f"`frida {name}` is still refused as a subcommand",
          name in main.IN_SESSION_ONLY)

print()
print("== renaming a tool moves the command ==")

# /rename changed the name but left the old binary on PATH forever, still
# running the pre-rename code.
ship.BIN_DIR = pathlib.Path(_SANDBOX) / "bin"
tool = agent.Tool()
tool.code = "print(1)"
tool.name = "portscan"
ship.install(tool.code, "portscan")


class _R:
    provider = None
    busy = False

    def __init__(self, t):
        self.tool = t


commands.h_rename(_R(tool), "netscan")
names = sorted(p.name for p in ship.BIN_DIR.iterdir())
check("the new name is installed", "netscan" in names, str(names))
check("the old name is gone from PATH", "portscan" not in names, str(names))

print()
print("== the timeout must actually time out ==")

# _invoke's second communicate() had no timeout, and communicate() waits for the
# pipes to close. A generated tool that leaves a detached grandchild holding
# stdout kept them open past SIGKILL, and Frida hung forever — in the one
# function whose entire job is to bound how long a tool may run.
import subprocess                                        # noqa: E402
import time                                              # noqa: E402
import types                                             # noqa: E402
from frida import harness                                # noqa: E402

escapee = os.path.join(_SANDBOX, "escapee.py")
with open(escapee, "w") as fh:
    fh.write(
        "import subprocess, sys, time\n"
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],\n"
        "                 start_new_session=True)\n"
        "time.sleep(60)\n")

harness.KILL_GRACE = 2
sandbox = types.SimpleNamespace(script=escapee, work=_SANDBOX, env=dict(os.environ))
started = time.time()
res = harness._invoke(sandbox, [], timeout=2)
took = time.time() - started

check("a tool that outlives SIGKILL still returns", took < 20, "%.1fs" % took)
check("...and is reported as timed out", res["timed_out"] is True)
check("...and says why the output is missing", "outlived" in res["stderr"])
subprocess.run(["pkill", "-f", "time.sleep(60)"], capture_output=True)

print()
print("== installing must not destroy someone else's command ==")

# The tool's name comes from a model, so `ls`, `grep` or `serve` are all
# possible. install() overwrote whatever was already at that name, silently.
ship.BIN_DIR = pathlib.Path(_SANDBOX) / "bin2"
ship.BIN_DIR.mkdir(parents=True, exist_ok=True)
victim = ship.BIN_DIR / "ls"
victim.write_text("#!/bin/sh\necho REAL SYSTEM TOOL\n")
victim.chmod(0o755)

res = ship.install("print(1)", "ls")
check("installing over a foreign binary is refused", not res.get("ok"))
check("...and says what is in the way", bool(res.get("occupied")))
check("...and the file is untouched", "REAL SYSTEM TOOL" in victim.read_text())
check("an explicit overwrite still works",
      ship.install("print(1)", "ls", overwrite=True).get("ok"))
check("re-installing over Frida's own tool needs no permission",
      ship.install("print(2)", "ls").get("ok"))

# ...and a name that tries to escape the directory cannot.
for bad in ("../../.bashrc", "/etc/passwd", "..", "a/../../b"):
    cleaned = ship._clean_name(bad)
    check(f"tool name {bad!r} cannot escape ~/.local/bin",
          "/" not in cleaned and ".." not in cleaned and cleaned != "",
          cleaned)

print()
print("== what the HUD reports about a run ==")

# harness.verify returns {"cases": [...], "ok": bool}. The HUD and /status were
# written against {"passed", "total"} — keys that never existed — so a tool that
# had just passed every case still displayed "untested".
class _Ran:
    code = "x\n" * 40
    ver = "1.0.0"
    name = "adventure"
    history = []
    last_run = {"cases": [{"ok": True}] * 3, "ok": True}


class _Failed(_Ran):
    last_run = {"cases": [{"ok": True}, {"ok": False}, {"ok": True}], "ok": False}


class _Never(_Ran):
    last_run = None


check("a passing run is counted", ui.run_tally(_Ran()) == (3, 3, True),
      str(ui.run_tally(_Ran())))
check("a failing run is counted", ui.run_tally(_Failed()) == (2, 3, False),
      str(ui.run_tally(_Failed())))
check("a tool that never ran reports nothing", ui.run_tally(_Never()) == (0, 0, False))
check("the next move after a pass is to run it",
      ui.next_moves(_Ran())[0] == "run", str(ui.next_moves(_Ran())))
check("the next move after a failure is to fix it",
      ui.next_moves(_Failed())[0] == "fix", str(ui.next_moves(_Failed())))
check("the next move before any run is to test it",
      ui.next_moves(_Never())[0] == "test")

print()
print("== a bare flag runs the tool, it does not brief the model ==")

# Typing `--help` was sent to the model as an instruction: 43 seconds and real
# money spent adding a feature nobody asked for.
for line in ("--help", "--version", "-v", "--json out.csv", "-la /tmp"):
    kind, cmd, arg = commands.resolve(line)
    check(f"{line!r} runs the tool",
          kind == commands.RUN and cmd.name == "run" and arg == line,
          f"{kind}/{getattr(cmd, 'name', cmd)}")

for line in ("--help should also mention the restart command",
             "--verbose but only for errors",
             "add a --json flag"):
    check(f"{line!r} is still an instruction",
          commands.resolve(line)[0] == commands.SAY)

print()
print("== big text ==")

check("every letter and digit has a glyph",
      all(ch in ui._BIG for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))
check("every glyph is exactly three rows",
      all(len(v) == 3 for v in ui._BIG.values()))
check("each glyph's rows are the same width",
      all(len({len(r) for r in v}) == 1 for k, v in ui._BIG.items()),
      str([k for k, v in ui._BIG.items() if len({len(r) for r in v}) != 1]))
rows = ui.big_rows("frida")
check("big text renders three rows", len(rows) == 3)
check("big text is wider than the plain string", ui.big_width("frida") > len("frida"))

# Too wide to draw must fall back to the plain string, not a broken picture.
buf2 = io.StringIO()
ui._stream = lambda: buf2
ui.width = lambda default=80: 20
ui.big("a-very-long-tool-name-indeed")
check("big text too wide for the terminal falls back to plain",
      "a-very-long-tool-name-indeed" in ui.plain(buf2.getvalue())
      and len(buf2.getvalue().splitlines()) == 1)
ui.width = lambda default=80: 80
ui._stream = lambda: sys.stderr

print()
print("== the terminal is named, so doctor can say where the font lives ==")

for env, expect in [({"KITTY_WINDOW_ID": "1"}, "kitty"),
                    ({"TERM": "alacritty"}, "alacritty"),
                    ({"TERM": "foot"}, "foot"),
                    ({"WEZTERM_PANE": "0"}, "wezterm"),
                    ({"KONSOLE_VERSION": "22"}, "konsole")]:
    saved = dict(os.environ)
    os.environ.clear()
    os.environ.update(env)
    name, keys, _cfg = engine.terminal()
    os.environ.clear()
    os.environ.update(saved)
    check(f"{expect} is recognised", name == expect and bool(keys), name)

print()
print("== secrets must not leak ==")

# Frida runs code a model wrote thirty seconds ago, and it used to hand that
# code the whole environment: the user's provider keys, GITHUB_TOKEN, cloud
# credentials — with working network access.
from frida import harness                                # noqa: E402

saved_env = dict(os.environ)
os.environ.update({"SILICONFLOW_API_KEY": "sk-REAL-KEY-DO-NOT-LEAK",
                   "ZAI_API_KEY": "zai-REAL", "GITHUB_TOKEN": "ghp_real",
                   "AWS_SECRET_ACCESS_KEY": "aws-real", "MY_PASSWORD": "hunter2"})
box = harness.Sandbox("print(1)", "probe")
visible = set(box.env)
for name in ("SILICONFLOW_API_KEY", "ZAI_API_KEY", "GITHUB_TOKEN",
             "AWS_SECRET_ACCESS_KEY", "MY_PASSWORD"):
    check(f"{name} is hidden from generated code", name not in visible)
check("the tool still gets a PATH", bool(box.env.get("PATH")))
check("the tool still gets a HOME", bool(box.env.get("HOME")))
check("the tool's HOME is the sandbox, not the user's",
      box.env["HOME"] != saved_env.get("HOME"))

# ...and prove it at runtime, not just in the dict.
thief = harness.Sandbox(
    'import os; print("SAW:", os.environ.get("SILICONFLOW_API_KEY"))', "thief")
got = harness._invoke(thief, [], timeout=15)["stdout"]
check("a tool that reads the key at runtime gets nothing",
      "SAW: None" in got, got.strip()[:80])
os.environ.clear()
os.environ.update(saved_env)

# A key pasted at the prompt used to be written to the history file in plain
# text, because readline records what input() reads.
check("an API key is recognised as a secret",
      ui.looks_secret("sk-abcd1234efgh5678ijkl"))
check("an ordinary instruction is not", not ui.looks_secret("add a --json flag"))

import readline as _rl                                   # noqa: E402
try:
    _rl.clear_history()
except Exception:
    pass
_rl.add_history("build a csv tool")
_rl.add_history("sk-abcd1234efgh5678ijklmnop")
_rl.add_history("add a --json flag")
hist_path = os.path.join(_SANDBOX, "history")
commands.save_readline(hist_path)
body = open(hist_path).read()
check("the history file drops anything key-shaped", "sk-abcd" not in body, body)
check("...but keeps ordinary lines", "build a csv tool" in body)
check("the history file is owner-only",
      (os.stat(hist_path).st_mode & 0o077) == 0, oct(os.stat(hist_path).st_mode))

# Provider error bodies are shown to the user and fed back to the model.
engine.STATE["keys"]["siliconflow"] = "sk-SECRETKEY123456789"
red = engine.redact("401: key sk-SECRETKEY123456789 is invalid")
check("a key echoed in an error is redacted", "SECRETKEY123456789" not in red, red)
check("...and the message is still readable", "401" in red and "invalid" in red)

print()
print("== models ==")

check("z.ai is a provider", "zai" in engine.PROVIDERS)
check("z.ai has an env var name", engine.PROVIDERS["zai"]["env"] == "ZAI_API_KEY")
check("glm-5.3 is z.ai's first choice",
      engine.preferred_model("zai", ["glm-4.6", "glm-5.3", "glm-4.5-air"]) == "glm-5.3")
check("z.ai has no models endpoint, so the built-in list is used",
      engine.PROVIDERS["zai"]["models_url"] == ""
      and "glm-5.3" in engine.PROVIDERS["zai"]["models"])

live = ["Qwen/Qwen2.5-7B-Instruct", "deepseek-ai/DeepSeek-V4-Pro",
        "deepseek-ai/DeepSeek-V4-Flash-0731"]
check("the 0731 Flash wins when offered",
      engine.preferred_model("siliconflow", live)
      == "deepseek-ai/DeepSeek-V4-Flash-0731")
check("plain Flash is the fallback",
      engine.preferred_model("siliconflow", ["deepseek-ai/DeepSeek-V4-Flash"])
      == "deepseek-ai/DeepSeek-V4-Flash")
check("a different namespace still matches",
      engine.preferred_model("siliconflow", ["deepseek/DeepSeek-V4-Flash-0731"])
      == "deepseek/DeepSeek-V4-Flash-0731")
check("nothing known means no forced pick",
      engine.preferred_model("siliconflow", ["some/unknown-model"]) is None)

engine._MODEL_CACHE["siliconflow"] = live
check("the preferred model leads the chain",
      engine.provider_model_chain("siliconflow")[0]
      == "deepseek-ai/DeepSeek-V4-Flash-0731")
check("...and every other model is still in it",
      len(engine.provider_model_chain("siliconflow")) == len(live))
engine._MODEL_CACHE.pop("siliconflow", None)

# /model read fetch_models()'s dict as a list and sliced it.
import builtins                                          # noqa: E402
feed = iter(["1"])
builtins.input = lambda *a: next(feed)
crashed = ""
try:
    main.pick_model()
except Exception as exc:                                 # noqa: BLE001
    crashed = "%s: %s" % (type(exc).__name__, exc)
check("/model does not crash", not crashed, crashed)

print()
print("== the prompt does not carry ten copies of the file ==")

# Every assistant turn holds the whole file, and all of them were sent.
big_tool = "\n".join("line %d" % i for i in range(300))
conv = agent.Tool()
for n in range(10):
    conv.messages.append({"role": "user", "content": "change %d" % n})
    conv.messages.append({"role": "assistant",
                          "content": "```python\n" + big_tool + "\n```"})
raw_size = sum(len(m["content"]) for m in conv.messages)
view = conv.prompt_view()
view_size = sum(len(m["content"]) for m in view)

check("the sent conversation is far smaller than the stored one",
      view_size < raw_size / 4, "%d vs %d" % (view_size, raw_size))
check("the newest version of the file is still sent in full",
      big_tool in view[-1]["content"])
check("every user turn survives",
      [m["content"] for m in view if m["role"] == "user"]
      == ["change %d" % n for n in range(10)])
check("the stored conversation is untouched",
      sum(len(m["content"]) for m in conv.messages) == raw_size)

# Collapsing must not break prefix caching: earlier entries must be stable.
prefix_before = [m["content"] for m in conv.prompt_view()][:18]
conv.messages.append({"role": "user", "content": "one more"})
conv.messages.append({"role": "assistant", "content": "```python\nnew\n```"})
prefix_after = [m["content"] for m in conv.prompt_view()][:18]
check("adding a turn does not rewrite the earlier prompt (cache stays warm)",
      prefix_before[:-1] == prefix_after[:-1])

print()
if FAILURES:
    print(f"something failed: {len(FAILURES)}")
    for f_ in FAILURES:
        print("  - " + f_)
    sys.exit(1)
print("all good")
