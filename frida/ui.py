#!/usr/bin/env python3
"""
frida.ui  —  the terminal, treated as a display
===============================================
No curses, no Rich, no Textual, no dependencies at all: ANSI escape codes and a
careful eye on what a terminal actually guarantees. Everything degrades on
purpose — truecolour to 256 to 16 to none, live redraw to plain scrolling lines
when stdout isn't a tty, box drawing to ASCII when the locale can't carry it.

What it provides:

  banner       the wordmark
  TaskBoard    the checklist that ticks over while work happens, redrawn in place
  Live         the in-place redraw primitive underneath it
  ask()        multiple choice, answered with a number
  panel()      a titled box
  code()       Python with syntax highlighting, from tokenize
  diff()       coloured unified diff
  file_card()  what was written, where, and how to run it

The rule everywhere in here: Frida's own chrome goes to stderr, and anything you
might want to pipe goes to stdout. A tool that makes command-line tools does not
get to be sloppy about the thing it lectures the model about.

License: MIT
"""

import io
import os
import re
import shutil
import sys
import threading
import time
import tokenize

# ==========================================================================
# CAPABILITY DETECTION
# ==========================================================================
def _stream():
    return sys.stderr


def is_tty():
    try:
        return _stream().isatty()
    except Exception:
        return False


def _colour_depth():
    if os.environ.get("NO_COLOR") is not None:
        return 0
    if not is_tty():
        return 0
    term = (os.environ.get("TERM") or "").lower()
    if term in ("dumb", ""):
        return 0
    if (os.environ.get("COLORTERM") or "").lower() in ("truecolor", "24bit"):
        return 24
    if "256" in term:
        return 8
    return 4


DEPTH = _colour_depth()
UNICODE = "utf" in (os.environ.get("LC_ALL") or os.environ.get("LC_CTYPE")
                    or os.environ.get("LANG") or "utf-8").lower()


def width(default=80):
    try:
        return max(48, min(shutil.get_terminal_size((default, 24)).columns, 110))
    except Exception:
        return default


# ==========================================================================
# COLOUR
# ==========================================================================
_RGB = {
    "amber":  (232, 163,  61),
    "gold":   (247, 201, 114),
    "cream":  (238, 229, 214),
    "teal":   ( 70, 199, 212),
    "lime":   (159, 224,  74),
    "red":    (255, 107, 107),
    "violet": (199, 155, 224),
    "grey":   (128, 122, 114),
    "faint":  ( 92,  88,  82),
    "white":  (255, 255, 255),
}
_256 = {"amber": 214, "gold": 221, "cream": 223, "teal": 80, "lime": 149,
        "red": 203, "violet": 183, "grey": 244, "faint": 240, "white": 255}
_16 = {"amber": 33, "gold": 33, "cream": 37, "teal": 36, "lime": 32,
       "red": 31, "violet": 35, "grey": 90, "faint": 90, "white": 37}

RESET = "\033[0m" if DEPTH else ""
BOLD = "\033[1m" if DEPTH else ""
DIM = "\033[2m" if DEPTH else ""
ITALIC = "\033[3m" if DEPTH else ""


def c(name, text, bold=False):
    """Colour `text`. Returns it untouched when colour isn't available."""
    if not DEPTH:
        return text
    if DEPTH == 24:
        r, g, b = _RGB.get(name, _RGB["cream"])
        code = f"\033[38;2;{r};{g};{b}m"
    elif DEPTH == 8:
        code = f"\033[38;5;{_256.get(name, 250)}m"
    else:
        code = f"\033[{_16.get(name, 37)}m"
    return f"{BOLD if bold else ''}{code}{text}{RESET}"


_ANSI_RE = re.compile(r"\033\[[0-9;]*[A-Za-z]")


def plain(text):
    return _ANSI_RE.sub("", text)


def vlen(text):
    return len(plain(text))


# ==========================================================================
# GLYPHS
# ==========================================================================
class G:
    if UNICODE:
        tl, tr, bl, br, h, v = "╭", "╮", "╰", "╯", "─", "│"
        dot, done, fail, active, pending, skip = "·", "✔", "✗", "◐", "○", "—"
        arrow, bullet, paw = "›", "•", "🐾"
        rule = "─"
    else:
        tl, tr, bl, br, h, v = "+", "+", "+", "+", "-", "|"
        dot, done, fail, active, pending, skip = ".", "*", "x", ">", "o", "-"
        arrow, bullet, paw = ">", "*", ""
        rule = "-"


SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"] if UNICODE else \
          ["|", "/", "-", "\\"]


# ==========================================================================
# OUTPUT PRIMITIVES
# ==========================================================================
_LOCK = threading.RLock()


def out(text=""):
    with _LOCK:
        _stream().write(text + "\n")
        _stream().flush()


def raw(text):
    with _LOCK:
        _stream().write(text)
        _stream().flush()


def data(text):
    """The one thing that goes to stdout: output the user might pipe."""
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def info(m):    out(c("teal", G.arrow + " ") + m)
def ok(m):      out(c("lime", G.done + " ") + m)
def warn(m):    out(c("amber", "! ") + m)
def err(m):     out(c("red", G.fail + " ") + m)
def dim(m):     out(c("faint", m))
def note(m):    out(c("grey", "  " + m))


def rule(title=""):
    w = width()
    if not title:
        out(c("faint", G.rule * w))
        return
    label = f" {title} "
    left = 2
    right = max(0, w - left - vlen(label))
    out(c("faint", G.rule * left) + c("grey", label) + c("faint", G.rule * right))


def blank():
    out("")


def wrap(text, indent=0, w=None):
    """Wrap to the terminal, preserving deliberate line breaks."""
    w = (w or width()) - indent
    lines = []
    for para in (text or "").split("\n"):
        if not para.strip():
            lines.append("")
            continue
        cur = ""
        for word in para.split():
            if cur and vlen(cur) + 1 + vlen(word) > w:
                lines.append(cur)
                cur = word
            else:
                cur = (cur + " " + word) if cur else word
        if cur:
            lines.append(cur)
    pad = " " * indent
    return "\n".join(pad + l if l else "" for l in lines)


# ==========================================================================
# BANNER
# ==========================================================================
_WORDMARK = [
    "█▀▀ █▀▄ █ █▀▄ ▄▀▄",
    "█▀▀ █▀▄ █ █ █ █▀█",
    "▀   ▀ ▀ ▀ ▀▀  ▀ ▀",
]
_PAW = [
    " ●  ●  ● ",
    "●  ▄▄▄  ●",
    "   ███   ",
]
_WORDMARK_ASCII = ["  ___  ___ ___ ___   _   ", " | __|| _ \\_ _|   \\ /_\\  ",
                   " | _| |   /| || |) / _ \\ ", " |_|  |_|_\\___|___/_/ \\_\\"]


def banner(version="", subtitle="a toolsmith for the terminal"):
    if not UNICODE:
        for line in _WORDMARK_ASCII:
            out(c("amber", line, bold=True))
        out(c("grey", " " + subtitle))
        blank()
        return
    blank()
    for i, line in enumerate(_WORDMARK):
        paw = _PAW[i]
        left = c("gold", paw) if i else c("amber", paw)
        right = c("amber", line, bold=True)
        tail = ""
        if i == 0 and version:
            tail = c("faint", "   v" + version)
        if i == 2:
            tail = c("grey", "   " + subtitle)
        out("  " + left + "  " + right + tail)
    blank()


def tribute():
    out(c("faint", wrap("Named for a dog who is not here for this one. "
                        "She'd have been asleep under the desk the whole time.", indent=2)))
    blank()


# ==========================================================================
# LIVE REDRAW
# ==========================================================================
class Live:
    """Redraw a block of lines in place.

    On a tty: move the cursor up over the previous render and overwrite it. Off a
    tty (piped, logged, CI): print each state once, in order, and never move the
    cursor — a log file full of escape sequences helps nobody.
    """

    def __init__(self, interval=0.09):
        self.lines = []
        self.height = 0
        self.interval = interval
        self._stop = threading.Event()
        self._thread = None
        self._render = None
        self._last_static = None

    def _paint(self, lines):
        with _LOCK:
            s = _stream()
            if not is_tty():
                block = "\n".join(lines)
                if block != self._last_static:
                    s.write(block + "\n")
                    s.flush()
                    self._last_static = block
                return
            if self.height:
                s.write(f"\033[{self.height}A")
            for line in lines:
                s.write("\033[2K" + line[:8000] + "\n")
            # the previous render may have been taller
            extra = self.height - len(lines)
            for _ in range(max(0, extra)):
                s.write("\033[2K\n")
            if extra > 0:
                s.write(f"\033[{extra}A")
            self.height = len(lines)
            s.flush()

    def update(self, lines):
        self.lines = list(lines)
        self._paint(self.lines)

    def start(self, render):
        """Animate: `render()` is called on a timer and its lines painted."""
        self._render = render
        if not is_tty():
            self.update(render())
            return self
        self._stop.clear()

        def loop():
            while not self._stop.is_set():
                try:
                    self.update(self._render())
                except Exception:
                    pass
                self._stop.wait(self.interval)
        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()
        return self

    def stop(self, final=None):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=0.4)
            self._thread = None
        if final is not None:
            self.update(final)
        self.height = 0
        self._last_static = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.stop()


def hide_cursor():
    if is_tty():
        raw("\033[?25l")


def show_cursor():
    if is_tty():
        raw("\033[?25h")


# ==========================================================================
# THE TASK BOARD
# ==========================================================================
class TaskBoard:
    """The checklist. Cowork renders one as a widget; this is the terminal's.

    Tasks carry a status and an optional one-line note. The active task also
    carries a live stage line underneath it — what the model is doing right now,
    for how long, and how much it has written.
    """

    PENDING, ACTIVE, DONE, FAILED, SKIPPED = "pending", "active", "done", "failed", "skipped"

    def __init__(self, title="", tasks=None):
        self.title = title
        self.tasks = [{"text": t, "status": self.PENDING, "note": ""} for t in (tasks or [])]
        self.stage = ""
        self.stage_started = None
        self.detail = ""
        self._live = Live()
        self._frame = 0
        self._running = False

    # ---- mutation -------------------------------------------------------
    def add(self, text):
        self.tasks.append({"text": text, "status": self.PENDING, "note": ""})

    def _find(self, which):
        if isinstance(which, int):
            return which if 0 <= which < len(self.tasks) else None
        for i, t in enumerate(self.tasks):
            if t["text"] == which:
                return i
        return None

    def start(self, which, stage=""):
        i = self._find(which)
        if i is None:
            return
        for t in self.tasks:
            if t["status"] == self.ACTIVE:
                t["status"] = self.DONE
        self.tasks[i]["status"] = self.ACTIVE
        self.set_stage(stage or self.tasks[i]["text"])

    def finish(self, which=None, note="", status=None):
        i = self._find(which) if which is not None else self.active_index()
        if i is None:
            return
        self.tasks[i]["status"] = status or self.DONE
        self.tasks[i]["note"] = note
        self.stage = ""
        self.detail = ""

    def fail(self, which=None, note=""):
        self.finish(which, note, status=self.FAILED)

    def skip(self, which=None, note=""):
        self.finish(which, note, status=self.SKIPPED)

    def active_index(self):
        for i, t in enumerate(self.tasks):
            if t["status"] == self.ACTIVE:
                return i
        return None

    def set_stage(self, stage, detail=""):
        self.stage = stage
        self.detail = detail
        self.stage_started = time.time()

    def set_detail(self, detail):
        self.detail = detail

    # ---- rendering ------------------------------------------------------
    def _mark(self, status):
        return {
            self.DONE:    c("lime", G.done),
            self.FAILED:  c("red", G.fail),
            self.SKIPPED: c("faint", G.skip),
            self.ACTIVE:  c("amber", SPINNER[self._frame % len(SPINNER)]),
            self.PENDING: c("faint", G.pending),
        }[status]

    def render(self):
        self._frame += 1
        lines = []
        if self.title:
            lines.append("  " + c("cream", self.title, bold=True))
            lines.append("")
        for t in self.tasks:
            text = t["text"]
            if t["status"] == self.PENDING:
                text = c("faint", text)
            elif t["status"] == self.DONE:
                text = c("grey", text)
            elif t["status"] == self.ACTIVE:
                text = c("cream", text, bold=True)
            elif t["status"] == self.FAILED:
                text = c("red", text)
            else:
                text = c("faint", text)
            line = "  " + self._mark(t["status"]) + " " + text
            if t["note"]:
                line += c("faint", "  " + G.dot + " " + t["note"])
            lines.append(line)
            if t["status"] == self.ACTIVE and self.stage:
                elapsed = ""
                if self.stage_started:
                    secs = time.time() - self.stage_started
                    elapsed = c("faint", f"  {secs:.0f}s")
                sub = "    " + c("violet", G.arrow + " " + self.stage) + elapsed
                lines.append(sub)
                if self.detail:
                    lines.append("      " + c("faint", self.detail[:width() - 8]))
        return lines

    # ---- lifecycle ------------------------------------------------------
    def show(self):
        if self._running:
            return self
        self._running = True
        hide_cursor()
        self._live.start(self.render)
        return self

    def close(self):
        if not self._running:
            return
        self._running = False
        for t in self.tasks:
            if t["status"] == self.ACTIVE:
                t["status"] = self.DONE
        self.stage = ""
        self.detail = ""
        self._live.stop(final=self.render())
        show_cursor()
        blank()

    def __enter__(self):
        return self.show()

    def __exit__(self, *_):
        self.close()


# ==========================================================================
# PANELS
# ==========================================================================
def panel(body, title="", colour="teal", pad=1):
    w = width()
    inner = w - 4
    cap = f" {title} " if title else ""
    out(c("faint", G.tl + G.h) + (c(colour, cap, bold=True) if cap else "") +
        c("faint", G.h * max(0, w - 3 - len(cap)) + G.tr))
    for _ in range(pad):
        out(c("faint", G.v) + " " * (w - 2) + c("faint", G.v))
    for line in wrap(body, w=inner).split("\n"):
        out(c("faint", G.v) + " " + line + " " * max(0, inner - vlen(line)) + " " +
            c("faint", G.v))
    for _ in range(pad):
        out(c("faint", G.v) + " " * (w - 2) + c("faint", G.v))
    out(c("faint", G.bl + G.h * (w - 2) + G.br))


def say(text, who="frida"):
    """The model talking. Distinct from Frida's own chrome."""
    blank()
    out("  " + c("violet", who, bold=True))
    for line in wrap(_light_markdown(text), indent=2).split("\n"):
        out(line)
    blank()


_MD_CODE = re.compile(r"`([^`]+)`")
_MD_BOLD = re.compile(r"\*\*([^*]+)\*\*")


def _light_markdown(text):
    text = _MD_CODE.sub(lambda m: c("teal", m.group(1)), text or "")
    text = _MD_BOLD.sub(lambda m: c("cream", m.group(1), bold=True), text)
    return text


# ==========================================================================
# QUESTIONS  --  multiple choice, answered with a number
# ==========================================================================
class Quit(Exception):
    """Raised when /quit is typed somewhere that isn't the main prompt."""


_SINK = None


def set_command_sink(fn):
    """Register the dispatcher so commands work at EVERY prompt, not just the
    main one.

    This is the fix for the worst bug Frida has had: `/save` typed at the plan
    gate was read as "change the plan", so the tool got built instead of saved.
    A question is not a modal dialog you are trapped inside — it is a pause,
    and you should be able to look at your code, save it, or leave, and come
    back to the same question. Anything starting with / is handled here and the
    prompt is asked again; everything else is the answer to the question."""
    global _SINK
    _SINK = fn


def _intercept(answer):
    """True if the line was a command and has been handled."""
    if not _SINK or not answer.startswith("/"):
        return False
    if _SINK(answer) == "quit":
        raise Quit()
    return True


def ask(question, options, why="", allow_other=True, default=1):
    """Render a multiple-choice question and read the answer.

    `options` is a list of {"label", "detail"} (or bare strings). Returns the
    chosen label as a string — free text if the user typed their own.
    """
    opts = [{"label": o, "detail": ""} if isinstance(o, str) else o for o in options]
    blank()
    out("  " + c("cream", question, bold=True))
    if why:
        out("  " + c("faint", why))
    blank()
    for i, o in enumerate(opts, 1):
        num = c("amber", f"{i}", bold=True)
        line = f"    {num}  {c('cream', o['label'])}"
        out(line)
        if o.get("detail"):
            out("       " + c("faint", o["detail"]))
    if allow_other:
        out(f"    {c('faint', 'or type your own answer')}")
    blank()
    line = c("amber", "  " + G.arrow + " ") + c("faint", f"[{default}] ")
    while True:
        try:
            raw(line)
            answer = input().strip()
        except (EOFError, KeyboardInterrupt):
            blank()
            return opts[default - 1]["label"] if opts else ""
        if _intercept(answer):
            blank()
            out("  " + c("cream", question, bold=True))
            for i, o in enumerate(opts, 1):
                out("    %s  %s" % (c("amber", str(i), bold=True),
                                    c("cream", o["label"])))
            blank()
            continue
        if not answer:
            return opts[default - 1]["label"] if opts else ""
        if answer.isdigit() and 1 <= int(answer) <= len(opts):
            return opts[int(answer) - 1]["label"]
        if allow_other and answer:
            return answer
        err("pick a number from the list")


def confirm(question, default=True):
    hint = "[Y/n]" if default else "[y/N]"
    while True:
        try:
            raw(c("amber", "  " + G.arrow + " ") + question + " "
                + c("faint", hint + " "))
            answer = input().strip()
        except (EOFError, KeyboardInterrupt):
            blank()
            return False
        if _intercept(answer):
            continue
        if not answer:
            return default
        return answer.lower().startswith("y")


def prompt(label=G.arrow, hint="", commands=False):
    """An input line. With commands=True, /commands are handled here and the
    caller is only ever handed something that is genuinely an answer."""
    while True:
        if hint:
            out(c("faint", "  " + hint))
        raw(c("amber", "\n" + label + " ", bold=True))
        try:
            answer = input()
        except EOFError:
            raise
        except KeyboardInterrupt:
            blank()
            return ""
        if commands and _intercept(answer.strip()):
            continue
        return answer


# ==========================================================================
# CODE
# ==========================================================================
_KEYWORD = {
    "False", "None", "True", "and", "as", "assert", "async", "await", "break",
    "class", "continue", "def", "del", "elif", "else", "except", "finally",
    "for", "from", "global", "if", "import", "in", "is", "lambda", "nonlocal",
    "not", "or", "pass", "raise", "return", "try", "while", "with", "yield",
}
_BUILTIN = {"print", "len", "range", "open", "int", "str", "float", "list", "dict",
            "set", "tuple", "sorted", "enumerate", "zip", "sum", "min", "max", "abs",
            "isinstance", "getattr", "setattr", "hasattr", "type", "super", "repr"}


def highlight(source):
    """Colour Python with the standard library's own tokenizer.

    Regex highlighters get f-strings, nested quotes and decorators wrong. tokenize
    already knows the grammar, so use it, and fall back to plain text on a syntax
    error — half-coloured output beats a crash while showing someone their code.
    """
    if not DEPTH:
        return source
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return source
    lines = source.split("\n")
    painted = {}
    for tok in toks:
        kind, text, (r1, c1), (r2, c2), _ = tok
        if r1 != r2 or not text.strip():
            continue
        colour = None
        if kind == tokenize.COMMENT:
            colour = "faint"
        elif kind == tokenize.STRING:
            colour = "lime"
        elif kind == tokenize.NUMBER:
            colour = "gold"
        elif kind == tokenize.NAME:
            if text in _KEYWORD:
                colour = "violet"
            elif text in _BUILTIN:
                colour = "teal"
        if colour:
            painted.setdefault(r1, []).append((c1, c2, colour))
    result = []
    for i, line in enumerate(lines, 1):
        spans = sorted(painted.get(i, []), reverse=True)
        for a, b, colour in spans:
            line = line[:a] + c(colour, line[a:b]) + line[b:]
        result.append(line)
    return "\n".join(result)


def code(source, title="", numbers=True, limit=None):
    lines = source.split("\n")
    clipped = False
    if limit and len(lines) > limit:
        lines = lines[:limit]
        clipped = True
    body = highlight("\n".join(lines)).split("\n")
    if title:
        rule(title)
    gutter_w = len(str(len(body))) if numbers else 0
    for i, line in enumerate(body, 1):
        if numbers:
            out(c("faint", str(i).rjust(gutter_w) + " " + G.v + " ") + line)
        else:
            out("  " + line)
    if clipped:
        out(c("faint", f"  … {len(source.splitlines()) - len(lines)} more lines"))
    if title:
        rule()


def diff(old, new, path="tool.py", context=3):
    import difflib
    a = (old or "").splitlines()
    b = (new or "").splitlines()
    shown = 0
    for line in difflib.unified_diff(a, b, fromfile=path + " (before)",
                                     tofile=path + " (after)", lineterm="", n=context):
        shown += 1
        if line.startswith("+++") or line.startswith("---"):
            out(c("grey", line))
        elif line.startswith("@@"):
            out(c("teal", line))
        elif line.startswith("+"):
            out(c("lime", line))
        elif line.startswith("-"):
            out(c("red", line))
        else:
            out(c("faint", line))
    if not shown:
        note("nothing changed")


# ==========================================================================
# FILE CARDS
# ==========================================================================
def file_card(path, label="written", run_hint="", extra=None):
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    human = f"{size} B" if size < 1024 else f"{size / 1024:.1f} KB"
    blank()
    out("  " + c("lime", G.done) + " " + c("cream", label, bold=True) +
        c("faint", f"  {human}"))
    out("    " + c("teal", str(path)))
    if run_hint:
        out("    " + c("faint", "run it: ") + c("gold", run_hint))
    for line in (extra or []):
        out("    " + c("faint", line))
    blank()


def kv(pairs, indent=2):
    w = max((len(k) for k, _ in pairs), default=0)
    for k, v in pairs:
        out(" " * indent + c("faint", k.ljust(w) + "  ") + str(v))


def bar(label, value, total, colour="amber", cells=24):
    total = max(total, 1)
    filled = int(round(cells * min(value / total, 1.0)))
    glyph = "█" if UNICODE else "#"
    empty = "░" if UNICODE else "."
    out("  " + c("grey", label.ljust(14)) + c(colour, glyph * filled) +
        c("faint", empty * (cells - filled)) + c("faint", f"  {value}/{total}"))


# ==========================================================================
# THE HUD
# ==========================================================================
def _gradient_rule(width=None, left="amber", right="teal"):
    """A hairline that fades from one colour to the other on truecolor terminals."""
    w = (width or globals()["width"]()) - 2
    if w < 8:
        return ""
    if DEPTH < 3:
        return c("faint", G.rule * w)
    a, b = _RGB[left], _RGB[right]
    parts = []
    for i in range(w):
        t = i / max(1, w - 1)
        # Fade toward the background at both ends so it reads as a hairline,
        # not a stripe. The curve is deliberately steep in the middle third.
        fade = 0.30 + 0.70 * (1 - abs(2 * t - 1)) ** 0.8
        r = int((a[0] + (b[0] - a[0]) * t) * fade)
        g = int((a[1] + (b[1] - a[1]) * t) * fade)
        bl = int((a[2] + (b[2] - a[2]) * t) * fade)
        parts.append(f"\033[38;2;{r};{g};{bl}m{G.rule}")
    return "".join(parts) + RESET


def hairline(left="amber", right="teal"):
    out("  " + _gradient_rule(left=left, right=right))


def hud(tool=None, model="", cost="", session_versions=0):
    """One line telling you where you stand.

    A workshop you spend days in needs a status line. Not because any single
    fact here is hard to fetch, but because having to ask is what stops you
    from glancing. Version, size, whether the tests passed, what it's costing.
    """
    if not is_tty():
        return
    left = []
    if tool is not None and tool.code:
        lines_n = len(tool.code.splitlines())
        left.append(c("teal", tool.name, bold=True))
        left.append(c("faint", "v" + tool.ver))
        left.append(c("grey", "%d ln" % lines_n))
        run = tool.last_run or {}
        total = run.get("total")
        if total:
            passed = run.get("passed", 0)
            good = passed == total
            left.append((c("lime", "%d/%d " % (passed, total) + G.done) if good
                         else c("red", "%d/%d %s" % (passed, total, G.fail))))
        else:
            left.append(c("faint", "untested"))
        if session_versions > 1:
            left.append(c("faint", "%d versions" % session_versions))
    else:
        left.append(c("faint", "no tool yet"))

    right = []
    if model:
        right.append(c("faint", model))
    if cost:
        right.append(c("faint", cost))

    sep = c("faint", "  " + G.dot + "  ")
    lhs = sep.join(left)
    rhs = sep.join(right)
    room = width() - 4
    pad = room - vlen(lhs) - vlen(rhs)
    if pad < 2:
        rhs, pad = "", room - vlen(lhs)
    blank()
    hairline()
    out("  " + lhs + " " * max(1, pad) + rhs)


def chips(*moves, lead="next"):
    """The move you probably want, offered rather than remembered.

    Frida knows what state the tool is in, so making you recall which command
    comes next is a small daily tax for no reason."""
    if not moves:
        return
    shown = []
    for m in moves:
        shown.append(c("cream", "/" + m) if not m.startswith(("or ", "say"))
                     else c("faint", m))
    out("  " + c("faint", lead) + "   " + c("faint", "  ").join(shown))


def next_moves(tool):
    """What makes sense from here."""
    if tool is None or not tool.code:
        return []
    run = tool.last_run or {}
    moves = []
    if not run.get("total"):
        moves.append("test")
    elif run.get("passed") != run.get("total"):
        moves.append("fix")
    else:
        moves.append("run")
    moves.append("install")
    if tool.history:
        moves.append("diff")
    moves.append("or say what to change")
    return moves
