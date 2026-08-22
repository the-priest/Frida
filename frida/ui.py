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
import unicodedata

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
    term = (os.environ.get("TERM") or "").lower()
    # FORCE_COLOR is the convention for "I am piping this somewhere that
    # understands escapes" — `frida /code | less -R`, a CI log viewer, asciinema.
    forced = os.environ.get("FORCE_COLOR")
    if forced not in (None, "", "0"):
        return {"1": 24, "2": 8, "3": 4}.get(forced, 24)
    if not is_tty():
        return 0
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


# ==========================================================================
# THEMES
# ==========================================================================
# A theme is a full remapping of the ten semantic colour names. Because every
# call site asks for a role ("amber" = the accent, "lime" = something worked)
# rather than a colour, swapping the palette re-skins the entire program and no
# other line of code has to know.
THEMES = {
    "ember": {   # Frida's own: warm amber on a dark room, teal for what's live
        "amber": (232, 163,  61), "gold":   (247, 201, 114),
        "cream": (238, 229, 214), "teal":   ( 70, 199, 212),
        "lime":  (159, 224,  74), "red":    (255, 107, 107),
        "violet":(199, 155, 224), "grey":   (128, 122, 114),
        "faint": ( 92,  88,  82), "white":  (255, 255, 255),
    },
    "matrix": {  # green phosphor, the way a VT220 never actually looked
        "amber": ( 64, 255, 128), "gold":   (140, 255, 170),
        "cream": (198, 255, 214), "teal":   (  0, 214, 150),
        "lime":  (110, 255, 110), "red":    (255,  92,  92),
        "violet":( 96, 230, 170), "grey":   ( 78, 130,  98),
        "faint": ( 48,  86,  64), "white":  (235, 255, 240),
    },
    "ice": {     # cold blues, easiest on the eyes for a long night
        "amber": ( 96, 214, 255), "gold":   (150, 226, 255),
        "cream": (219, 234, 254), "teal":   (122, 162, 247),
        "lime":  ( 94, 234, 212), "red":    (255, 122, 144),
        "violet":(167, 160, 255), "grey":   ( 96, 118, 144),
        "faint": ( 62,  78,  98), "white":  (245, 250, 255),
    },
    "synthwave": {  # the loud one. you will not want it every day
        "amber": (255,  46, 151), "gold":   (255, 154, 210),
        "cream": (248, 230, 255), "teal":   (  0, 229, 255),
        "lime":  (124, 247, 196), "red":    (255,  67, 101),
        "violet":(185, 103, 255), "grey":   (139,  99, 152),
        "faint": ( 84,  56,  96), "white":  (255, 255, 255),
    },
    "paper": {   # for light terminals — inks, not glows
        "amber": (176,  86,   0), "gold":   (140,  92,  10),
        "cream": ( 36,  34,  32), "teal":   (  0, 110, 130),
        "lime":  ( 42, 120,  40), "red":    (176,  32,  48),
        "violet":(108,  64, 150), "grey":   (100,  96,  92),
        "faint": (150, 146, 140), "white":  (  0,   0,   0),
    },
}
THEME_BLURB = {
    "ember": "warm amber · the default",
    "matrix": "green phosphor",
    "ice": "cold blues · easiest at 3am",
    "synthwave": "loud. gloriously loud",
    "paper": "for light terminals",
}
THEME = "ember"


def _rgb_to_256(r, g, b):
    """Nearest xterm-256 index, so themes survive a terminal without truecolor."""
    if abs(r - g) < 12 and abs(g - b) < 12:          # grey ramp
        if r < 8:
            return 16
        if r > 248:
            return 231
        return 232 + round((r - 8) / 247 * 23)
    return (16 + 36 * round(r / 255 * 5)
            + 6 * round(g / 255 * 5) + round(b / 255 * 5))


def set_theme(name):
    """Swap the palette. Unknown names leave it alone."""
    global THEME
    pal = THEMES.get(name)
    if not pal:
        return False
    THEME = name
    _RGB.clear()
    _RGB.update(pal)
    _256.clear()
    _256.update({k: _rgb_to_256(*v) for k, v in pal.items()})
    # ...and the 16-colour table, or `--theme paper` renders its near-black
    # inks as SGR 37 (white) — invisible on the light terminal it exists for.
    _16.clear()
    _16.update({k: _rgb_to_16(*v) for k, v in pal.items()})
    return True


def _rgb_to_16(r, g, b):
    """Nearest of the 8 ANSI foreground colours (30-37), by hue and lightness."""
    lo, hi = min(r, g, b), max(r, g, b)
    if hi - lo < 40:                       # greyish
        return 37 if hi > 150 else (30 if hi < 60 else 37)
    bit = (1 if r > (lo + hi) / 2 else 0) | (2 if g > (lo + hi) / 2 else 0) \
        | (4 if b > (lo + hi) / 2 else 0)
    return 30 + {1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 0: 7}[bit]


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


def cells(text):
    """How many terminal columns `text` occupies. Wide CJK glyphs take two."""
    n = 0
    for ch in text:
        if unicodedata.combining(ch):
            continue
        n += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return n


def vlen(text):
    return cells(plain(text))


def clip(text, limit):
    """Truncate to `limit` columns, keeping colour codes intact.

    Every in-place redraw in this program assumes one rendered line occupies
    one terminal row. A line wider than the terminal silently occupies two, the
    cursor-up count then undershoots, and the display shreds itself — so
    nothing may reach a live region without passing through here first."""
    if limit <= 0:
        return ""
    if vlen(text) <= limit:
        return text
    out_chars, used, i = [], 0, 0
    while i < len(text):
        m = _ANSI_RE.match(text, i)
        if m:                                  # escapes cost no columns
            out_chars.append(m.group(0))
            i = m.end()
            continue
        ch = text[i]
        w = 0 if unicodedata.combining(ch) else (
            2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1)
        if used + w > limit - 1:
            break
        out_chars.append(ch)
        used += w
        i += 1
    return "".join(out_chars) + (RESET if DEPTH else "") + "…"


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


# Frida's whole layout hangs off one left margin. Every status line, rule, task
# and card starts at the same column, so the eye has a single edge to follow
# down a long session instead of a ragged one.
MARGIN = "  "

_LAST_BLANK = [True]


def out(text=""):
    with _LOCK:
        _LAST_BLANK[0] = not plain(text).strip()
        _stream().write(text + "\n")
        _stream().flush()


def raw(text):
    with _LOCK:
        if text and not text.endswith("\n"):
            _LAST_BLANK[0] = False
        _stream().write(text)
        _stream().flush()


def data(text):
    """The one thing that goes to stdout: output the user might pipe."""
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def info(m):    out(MARGIN + c("teal", G.arrow + " ") + m)
def ok(m):      out(MARGIN + c("lime", G.done + " ") + m)
def warn(m):    out(MARGIN + c("amber", "! ") + m)
def err(m):     out(MARGIN + c("red", G.fail + " ") + m)
def dim(m):     out(MARGIN + c("faint", m))
def note(m):    out(MARGIN + c("grey", "  " + m))


def rule(title=""):
    w = width()
    if not title:
        out(c("faint", G.rule * w))
        return
    label = f" {title} "
    left = 2
    right = max(0, w - left - vlen(label))
    out(c("faint", G.rule * left) + c("grey", label) + c("faint", G.rule * right))


def blank(collapse=True):
    """A blank line, but never two in a row by accident.

    Sections each end with their own blank and the next one opens with another,
    which used to produce a random mix of one- and two-line gaps down the
    screen. Collapsing them gives the page a steady rhythm — which is most of
    what makes a dense terminal feel calm rather than cramped."""
    if collapse and _LAST_BLANK[0]:
        return
    out("")


def gap():
    """A deliberate double gap, for the seam between major sections."""
    out("")
    out("")


def wrap(text, indent=0, w=None):
    """Wrap to the terminal, preserving deliberate line breaks."""
    w = max(8, (w or width()) - indent)
    lines = []
    for para in (text or "").split("\n"):
        if not para.strip():
            lines.append("")
            continue
        cur = ""
        for word in para.split():
            # An unbreakable token — a URL, a long path — used to be emitted
            # whole, pushing the line past the terminal and, inside a panel,
            # straight through its own border. Split it instead.
            while vlen(word) > w:
                head = ""
                for ch in word:
                    if vlen(head + ch) > w:
                        break
                    head += ch
                if not head:                 # pathological: a single wide glyph
                    head, word = word[0], word[1:]
                else:
                    word = word[len(head):]
                if cur:
                    lines.append(cur)
                    cur = ""
                lines.append(head)
            if not word:
                continue
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
            # The real terminal, not width()'s clamped layout figure: a line
            # that wraps here costs a row the cursor arithmetic doesn't know
            # about, and the whole board starts overwriting itself.
            cols = shutil.get_terminal_size((80, 24)).columns
            for line in lines:
                s.write("\033[2K" + clip(line, cols) + "\n")
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
        self.preview = []
        self.preview_label = ""
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
        self.clear_preview()          # last step's code must not bleed into this one
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

    def set_preview(self, text, keep=8, label=""):
        """The tail of what the model is writing, shown as it arrives.

        This is the one piece of theatre that is also load-bearing. A spinner
        for ninety seconds tells you nothing; watching the last few lines of
        your tool appear tells you it understood the request, and lets you hit
        ctrl-c at second four instead of second ninety."""
        rows = [ln for ln in (text or "").splitlines() if ln.strip()]
        self.preview = rows[-keep:]
        self.preview_label = label

    def clear_preview(self):
        self.preview = []
        self.preview_label = ""

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
                if self.preview:
                    room = max(24, width() - 12)
                    rail = c("faint", G.v)
                    if self.preview_label:
                        lines.append("      " + rail + c("faint", " " + self.preview_label))
                    for pl in self.preview:
                        body = pl.rstrip().replace("\t", "    ")[:room]
                        lines.append("      " + rail + " " + c("grey", body))
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
        self.preview = []
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
    rendered = wrap(_light_markdown(text), indent=2).split("\n")
    if motion_enabled() and sum(len(x) for x in rendered) < 400:
        for line in rendered:
            _type_line(line)
    else:
        for line in rendered:
            out(line)
    blank()


def _type_line(line, cps=1400):
    """One line, arriving. Keeps existing colour codes intact by typing the
    plain text and repainting the whole line at the end."""
    bare = plain(line)
    # `\r\033[2K` only clears the row the cursor is on. If the line wraps, the
    # earlier rows survive and every frame leaves another copy behind.
    if not bare.strip() or cells(bare) >= shutil.get_terminal_size((80, 24)).columns:
        out(line)
        return
    delay = 1.0 / cps
    step = 2
    hide_cursor()
    try:
        for i in range(0, len(bare), step):
            raw("\r\033[2K" + c("cream", bare[:i + step]))
            time.sleep(delay * step)
    except KeyboardInterrupt:
        # Swallowing this per line meant say() ate one ctrl-C per line of the
        # reply and returned as though nothing had happened.
        set_motion(False)
    finally:
        show_cursor()
        raw("\r\033[2K")
    out(line)


_MD_CODE = re.compile(r"`([^`]+)`")
_MD_BOLD = re.compile(r"\*\*([^*]+)\*\*")


def _light_markdown(text):
    text = _MD_CODE.sub(lambda m: c("teal", m.group(1)), text or "")
    text = _MD_BOLD.sub(lambda m: c("cream", m.group(1), bold=True), text)
    return text


# ==========================================================================
# QUESTIONS  --  multiple choice, answered with a number
# ==========================================================================
class _Cancelled(str):
    """Returned by ask() when the user interrupts.

    It subclasses str (and equals "") so a caller that ignores it degrades to
    "empty answer" rather than crashing — but `is ui.CANCELLED` distinguishes
    "they pressed ctrl-C" from "they chose option 1", which callers used to be
    unable to tell apart. /model pinned a model nobody picked; /resume loaded
    the top session over your work."""
    __slots__ = ()


CANCELLED = _Cancelled()


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
    try:
        if _SINK(answer) == "quit":
            raise Quit()
    except Quit:
        raise
    except Exception as exc:                    # noqa: BLE001
        # The prompt is the user's way out. A handler blowing up must not take
        # the question down with it — report and re-ask.
        err("that command failed: %s" % exc)
    return True


def ask(question, options, why="", allow_other=True, default=1):
    """Render a multiple-choice question and read the answer.

    `options` is a list of {"label", "detail"} (or bare strings). Returns the
    chosen label as a string — free text if the user typed their own.
    """
    opts = [{"label": o, "detail": ""} if isinstance(o, str) else o for o in options]
    default = min(max(1, default), len(opts)) if opts else 1
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
            return CANCELLED
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
        if answer.isdecimal() and 1 <= int(answer) <= len(opts):
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
        except EOFError:
            blank()
            return default          # ask() returns its default at EOF too
        except KeyboardInterrupt:
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
    if DEPTH < 8:
        # DEPTH is only ever 0, 4, 8 or 24 — the old `< 3` test caught nothing
        # but "no colour", so 16-colour terminals were sent 24-bit escapes.
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
        parts.append(_paint(G.rule, (r, g, bl)))
    return "".join(parts) + RESET


def hairline(left="amber", right="teal"):
    out("  " + _gradient_rule(left=left, right=right))


def run_tally(tool):
    """(passed, total, all_good) from the last run — or (0, 0, False).

    harness.verify returns {"cases": [...], "ok": bool}. The HUD was written
    against {"passed", "total"}, which never existed, so a tool that had just
    passed every case still reported "untested".
    """
    run = getattr(tool, "last_run", None) or {}
    cases = run.get("cases")
    if not isinstance(cases, list) or not cases:
        return 0, 0, False
    passed = sum(1 for case in cases if case.get("ok"))
    return passed, len(cases), bool(run.get("ok"))


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
        passed, total, good = run_tally(tool)
        if total:
            left.append(c("lime", "%d/%d %s" % (passed, total, G.done)) if good
                        else c("red", "%d/%d %s" % (passed, total, G.fail)))
        elif (tool.last_run or {}).get("blocked"):
            left.append(c("amber", "not run"))
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
    passed, total, good = run_tally(tool)
    moves = []
    if not total:
        moves.append("test")
    elif not good:
        moves.append("fix")
    else:
        moves.append("run")
    moves.append("install")
    if tool.history:
        moves.append("diff")
    moves.append("or say what to change")
    return moves


# ==========================================================================
# MOTION
# ==========================================================================
# The rule for every animation in this program: it plays on something that
# happens rarely, or it does not play. A flourish you see once a session is
# delight; the same flourish on every keystroke is a tax you pay all day. So
# the wordmark shimmers at startup and a tool sweeps once when it lands, and
# the things you do a hundred times a day stay perfectly still.
MOTION = True


def motion_enabled():
    return (MOTION and is_tty() and DEPTH >= 8
            and os.environ.get("FRIDA_PLAIN") in (None, "", "0"))


def set_motion(on):
    global MOTION
    MOTION = bool(on)


def _shade(rgb, level):
    """`level` 0..1 — 1 is the colour, 0 is very nearly the background."""
    r, g, b = rgb
    level = max(0.0, min(1.0, level))
    return (int(r * level), int(g * level), int(b * level))


def _paint(ch, rgb):
    if DEPTH >= 24:
        return "\033[38;2;%d;%d;%dm%s" % (rgb[0], rgb[1], rgb[2], ch)
    return "\033[38;5;%dm%s" % (_rgb_to_256(*rgb), ch)


def boot(version="", subtitle="a toolsmith for the terminal"):
    """The wordmark, with a light sweeping across it once.

    Startup is the one moment in a CLI where a little theatre costs nothing:
    you are not waiting on it, you asked for it, and you will see it once.
    """
    rows = [(_PAW[i], _WORDMARK[i]) for i in range(3)]
    needed = 2 + len(rows[0][0]) + 2 + len(rows[0][1])
    if (not UNICODE or not motion_enabled()
            or shutil.get_terminal_size((80, 24)).columns < needed + 2):
        # Too narrow and every row wraps, so cursor-up-3 lands mid-block and
        # all 23 frames print below the last.
        banner(version, subtitle)
        return

    body = _RGB["amber"]
    accent = _RGB["cream"]
    span = len(rows[0][0]) + 2 + len(rows[0][1])

    blank()
    for _ in rows:
        out("")
    hide_cursor()
    try:
        frames = 22
        for fnum in range(frames + 1):
            # the highlight travels a little past the end so it exits cleanly
            head = -6 + (span + 12) * (fnum / frames)
            raw("\033[%dA" % len(rows))
            for paw, word in rows:
                line = paw + "  " + word
                buf = []
                for x, ch in enumerate(line):
                    if ch == " ":
                        buf.append(" ")
                        continue
                    d = abs(x - head)
                    if d < 3.2:
                        mix = 1 - (d / 3.2)
                        rgb = tuple(int(body[k] + (accent[k] - body[k]) * mix)
                                    for k in range(3))
                        buf.append(_paint(ch, rgb))
                    else:
                        # everything behind the sweep has already arrived
                        lit = 1.0 if x < head else 0.34
                        buf.append(_paint(ch, _shade(body, lit)))
                raw("\033[2K  " + BOLD + "".join(buf) + RESET + "\n")
            time.sleep(0.016)
    finally:
        show_cursor()

    # settle into the static banner so the final frame is the real thing
    raw("\033[%dA" % len(rows))
    for i, (paw, word) in enumerate(rows):
        tail = ""
        if i == 0 and version:
            tail = c("faint", "   v" + version)
        if i == 2:
            tail = c("grey", "   " + subtitle)
        raw("\033[2K  " + c("gold" if i else "amber", paw) + "  "
            + c("amber", word, bold=True) + tail + "\n")
    blank()


def sweep(text, colour="lime", passes=1):
    """One bright pass across a finished line. Used when a tool lands."""
    if not motion_enabled():
        out(text)
        return
    base = _RGB[colour]
    bare = plain(text)
    hide_cursor()
    try:
        for _ in range(passes):
            for fnum in range(0, len(bare) + 10, 2):
                buf = []
                for x, ch in enumerate(bare):
                    d = abs(x - fnum)
                    lit = 1.0 if d > 4 else 1.0 + (1 - d / 4) * 0.9
                    rgb = tuple(min(255, int(v * lit)) for v in base)
                    buf.append(_paint(ch, rgb))
                raw("\r\033[2K" + "".join(buf) + RESET)
                time.sleep(0.012)
    finally:
        raw("\r\033[2K")
        show_cursor()
    out(text)


def typewriter(text, colour="cream", cps=900):
    """Frida's prose, arriving rather than appearing.

    Fast enough that reading is never delayed — the effect is that the room
    feels alive, not that you are waiting for a machine to finish talking."""
    if (not motion_enabled() or len(text) > 1200
            or cells(plain(text)) >= shutil.get_terminal_size((80, 24)).columns):
        out(c(colour, text))
        return
    delay = 1.0 / max(120, cps)
    chunk = 3
    shown = ""
    hide_cursor()
    try:
        for i in range(0, len(text), chunk):
            shown += text[i:i + chunk]
            raw("\r\033[2K" + c(colour, shown))
            time.sleep(delay * chunk)
    except KeyboardInterrupt:
        pass
    finally:
        show_cursor()
        raw("\r\033[2K")
    out(c(colour, text))

# ==========================================================================
# BIG TEXT
# ==========================================================================
# Frida cannot change your font — that belongs to the terminal emulator, and a
# program that claims otherwise is lying. What it can do is draw at three times
# the height using the same block idiom as the wordmark, so the things worth
# seeing across the room are actually visible from there.
_BIG = {
    "A": ("▄▀▄", "█▀█", "▀ ▀"), "B": ("█▀▄", "█▀▄", "▀▀ "),
    "C": ("▄▀▀", "█  ", "▀▀▀"), "D": ("█▀▄", "█ █", "▀▀ "),
    "E": ("█▀▀", "█▀▀", "▀▀▀"), "F": ("█▀▀", "█▀▀", "▀  "),
    "G": ("▄▀▀", "█ ▄", "▀▀▀"), "H": ("█ █", "█▀█", "▀ ▀"),
    "I": ("▀█▀", " █ ", "▀▀▀"), "J": ("  █", "▄ █", "▀▀ "),
    "K": ("█ ▄", "█▀▄", "▀ ▀"), "L": ("█  ", "█  ", "▀▀▀"),
    "M": ("█▄▄▄█", "█ ▀ █", "▀   ▀"), "N": ("█▄ █", "█ ▀█", "▀  ▀"),
    "O": ("▄▀▄", "█ █", "▀▀▀"), "P": ("█▀▄", "█▀▀", "▀  "),
    "Q": ("▄▀▄", "█ █", "▀▀▄"), "R": ("█▀▄", "█▀▄", "▀ ▀"),
    "S": ("▄▀▀", "▀▀▄", "▀▀ "), "T": ("▀█▀", " █ ", " ▀ "),
    "U": ("█ █", "█ █", "▀▀▀"), "V": ("█ █", "█ █", " ▀ "),
    "W": ("█   █", "█ ▄ █", "▀▀ ▀▀"), "X": ("▀▄▀", "▄▀▄", "▀ ▀"),
    "Y": ("█ █", "▀█▀", " ▀ "), "Z": ("▀▀█", "▄▀ ", "▀▀▀"),
    "0": ("▄▀▄", "█ █", "▀▀▀"), "1": (" █ ", " █ ", " ▀ "),
    "2": ("▀▀▄", "▄▀ ", "▀▀▀"), "3": ("▀▀▄", " ▀▄", "▀▀ "),
    "4": ("█ █", "▀▀█", "  ▀"), "5": ("█▀▀", "▀▀▄", "▀▀ "),
    "6": ("▄▀▀", "█▀▄", "▀▀▀"), "7": ("▀▀█", "  █", "  ▀"),
    "8": ("▄▀▄", "▄▀▄", "▀▀▀"), "9": ("▄▀▄", "▀▀█", "▀▀▀"),
    "-": ("   ", "▀▀▀", "   "), "_": ("   ", "   ", "▀▀▀"),
    ".": ("   ", "   ", " ▀ "), ",": ("   ", "   ", " ▄ "),
    "!": (" █ ", " █ ", " ▀ "), "?": ("▀▀▄", " ▀ ", " ▀ "),
    ":": (" ▄ ", "   ", " ▀ "), "/": ("  ▄", " ▀ ", "▄  "),
    "+": ("   ", "▄█▄", " ▀ "), "*": ("▄▀▄", "▀▄▀", "   "),
    "%": ("█ ▄", " ▀ ", "▄ ▀"), "#": ("█▄█", "█▄█", "▀ ▀"),
    " ": ("  ", "  ", "  "),
}

BIG_MODE = False


def set_big(on):
    global BIG_MODE
    BIG_MODE = bool(on)


def big_rows(text):
    """The three rows of `text` drawn large. Unknown characters become spaces."""
    rows = ["", "", ""]
    for ch in str(text).upper():
        glyph = _BIG.get(ch, _BIG[" "])
        for i in range(3):
            rows[i] += glyph[i] + " "
    return [r.rstrip() for r in rows]


def big_width(text):
    return max((cells(r) for r in big_rows(text)), default=0)


def big(text, colour="amber", indent=2, fade=True):
    """Draw `text` three rows tall, fading top to bottom on truecolor."""
    rows = big_rows(text)
    room = width() - indent
    if not rows or big_width(text) > room:
        # Too wide to draw large — say it small rather than draw it broken.
        out(" " * indent + c(colour, str(text), bold=True))
        return
    base = _RGB.get(colour, _RGB["amber"])
    for i, row in enumerate(rows):
        if fade and DEPTH >= 24:
            level = (1.0, 0.86, 0.66)[i]
            rgb = tuple(int(v * level) for v in base)
            out(" " * indent + BOLD + _paint(row, rgb) + RESET)
        else:
            out(" " * indent + c(colour, row, bold=True))


def headline(text, colour="amber", sub=""):
    """A heading, large when big mode is on and quiet when it isn't."""
    blank()
    if BIG_MODE:
        big(text, colour)
        if sub:
            out("  " + c("grey", sub))
    else:
        out("  " + c(colour, str(text), bold=True)
            + (("  " + c("grey", sub)) if sub else ""))
    blank()
