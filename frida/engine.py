#!/usr/bin/env python3
"""
frida.engine  —  the forge
==========================
Everything Frida knows how to do that isn't talking to you: reaching the model,
reading the machine it's running on, tearing generated code apart to see whether
it holds, patching it, installing what it needs, freezing it into a binary.

There is no window in this file and no window anywhere in Frida. No HTTP server,
no browser, no toolkit, no display. Frida is a terminal program that makes
terminal programs, and the whole way down it stays that way.

What lives here:

  machine     distro / package-manager detection, so a generated tool that needs
              a system package names it in *your* package manager - `pacman -S`
              on CachyOS, not `apt install`
  providers   SiliconFlow first, Groq behind it; live model lists; a retry
              policy that treats a busy gateway as weather, not as failure
  transport   streamed responses, so the timeout is idle-time and a model that
              thinks for three minutes is not mistaken for a hang
  budget      per-model context trimming, usage and cost accounting
  reading     ruff + a purpose-built AST pass that finds wrong-arity calls,
              undefined names and unassigned attributes for free, locally,
              before a single paid fix round is spent
  patching    SEARCH/REPLACE edit blocks applied on this machine, so changing one
              line costs one line instead of a whole file
  shipping    a managed venv, dependency install, PyInstaller builds

Inherited from theDawg, which built windows. Frida doesn't.

License: MIT
"""

import os
import ast

import re

import sys

import json

import time

import shlex

import shutil

import signal

import socket

import platform

import tempfile

import threading

import subprocess

import urllib.request

import urllib.error

from pathlib import Path

import http.client            # IncompleteRead / RemoteDisconnected are retryable

__version__ = "2.7.1"

HERE = os.path.dirname(os.path.abspath(__file__))

# --------------------------------------------------------------------------
# PLATFORM DETECTION  -- every cross-platform branch in this file reads these
# --------------------------------------------------------------------------
IS_WIN = platform.system() == "Windows"

IS_MAC = platform.system() == "Darwin"

IS_LINUX = not IS_WIN and not IS_MAC

# --------------------------------------------------------------------------
# DISTRO DETECTION  -- so every package hint Frida prints (and every hint it
# TEACHES the model to print) is correct for the machine it is actually on.
# CachyOS is the reference target: Arch-based, pacman, KDE Plasma 6 on Wayland,
# x86-64-v3/v4 optimised packages. Debian/Fedora/SUSE stay supported.
# --------------------------------------------------------------------------
_OSREL = None

def _os_release():
    """Parse /etc/os-release once. Returns a dict (empty on non-Linux)."""
    global _OSREL
    if _OSREL is not None:
        return _OSREL
    data = {}
    for p in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, _, v = line.partition("=")
                    data[k.strip()] = v.strip().strip('"').strip("'")
            break
        except Exception:
            continue
    _OSREL = data
    return data

# logical name -> per-family package name. None = "not a separate package here".
# Frida builds terminal tools, so this table holds what a terminal tool or Frida
# itself might actually need. Everything to do with windows — gtk4, libadwaita,
# webkitgtk, PyQt, PySide, tk, Xvfb, xdotool, ImageMagick — came out with the GUI.
PKG_TABLE = {
    #                 arch                     debian              fedora                    suse
    "python":        ("python",                "python3",          "python3",                "python3"),
    "pip":           ("python-pip",            "python3-pip",      "python3-pip",            "python3-pip"),
    "ruff":          ("ruff",                  "ruff",             "ruff",                   "ruff"),
    "uv":            ("uv",                    "uv",               "uv",                     "uv"),
    "pyinstaller":   ("pyinstaller",           "pyinstaller",      "pyinstaller",            "pyinstaller"),
    "git":           ("git",                   "git",              "git",                    "git"),
    "curl":          ("curl",                  "curl",             "curl",                   "curl"),
    "jq":            ("jq",                    "jq",               "jq",                     "jq"),
    "pillow":        ("python-pillow",         "python3-pil",      "python3-pillow",         "python3-Pillow"),
}

_FAM_IDX = {"arch": 0, "debian": 1, "fedora": 2, "suse": 3}

# how each family installs things
_INSTALL_CMD = {
    "arch":   "sudo pacman -S --needed",
    "debian": "sudo apt install",
    "fedora": "sudo dnf install",
    "suse":   "sudo zypper install",
}

def detect_distro():
    """Classify the running Linux distribution.

    Returns {"id","like","family","name","pretty","cachy","install","update"} where
    family is one of arch|debian|fedora|suse|other and `install` is the literal
    command prefix used to install a package on this box.
    """
    if not IS_LINUX:
        return {"id": "", "like": "", "family": "other", "name": platform.system(),
                "pretty": platform.system(), "cachy": False,
                "install": "", "update": ""}
    d = _os_release()
    did = (d.get("ID") or "").lower()
    like = (d.get("ID_LIKE") or "").lower()
    blob = did + " " + like
    if any(k in blob for k in ("cachyos", "arch", "manjaro", "endeavouros", "garuda", "artix")):
        fam = "arch"
    elif any(k in blob for k in ("debian", "ubuntu", "kali", "linuxmint", "mint", "raspbian", "pop")):
        fam = "debian"
    elif any(k in blob for k in ("fedora", "rhel", "centos", "nobara", "bazzite")):
        fam = "fedora"
    elif any(k in blob for k in ("suse", "opensuse")):
        fam = "suse"
    else:
        fam = "other"
    return {
        "id": did,
        "like": like,
        "family": fam,
        "name": d.get("NAME", "Linux"),
        "pretty": d.get("PRETTY_NAME", d.get("NAME", "Linux")),
        "cachy": did == "cachyos" or "cachyos" in blob,
        "install": _INSTALL_CMD.get(fam, ""),
        "update": {"arch": "sudo pacman -Syu", "debian": "sudo apt update && sudo apt upgrade",
                   "fedora": "sudo dnf upgrade", "suse": "sudo zypper up"}.get(fam, ""),
    }

DISTRO = detect_distro()

def pkg(*logical):
    """Package names for this distro family. Unknown/absent entries are dropped."""
    idx = _FAM_IDX.get(DISTRO["family"])
    out = []
    for name in logical:
        row = PKG_TABLE.get(name)
        if not row:
            continue
        val = row[idx] if idx is not None else row[0]
        if val:
            out.append(val)
    return out

def install_line(*logical):
    """A copy-pasteable install command for this distro, e.g.
    `sudo pacman -S --needed ruff uv` on CachyOS, `sudo apt install -y ruff uv`
    on Debian. Falls back to a neutral phrasing on unknown distros."""
    names = pkg(*logical)
    if not names:
        return ""
    if not DISTRO["install"]:
        return "install with your package manager: " + " ".join(names)
    return f"{DISTRO['install']} {' '.join(names)}"

def is_cachy():
    return bool(DISTRO.get("cachy"))

def cpu_threads():
    """Usable parallelism, honouring cgroup/affinity limits rather than raw core count."""
    try:
        return max(1, len(os.sched_getaffinity(0)))
    except Exception:
        return max(1, os.cpu_count() or 1)

def app_data_dir():
    """Per-OS app data dir (writes that should persist + survive)."""
    if IS_WIN:
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "Frida"
    if IS_MAC:
        return Path.home() / "Library" / "Application Support" / "Frida"
    return Path.home() / ".local" / "share" / "frida"

def parses(code):
    """(ok, reason). A cheap syntax gate for code that didn't come from a model."""
    import ast as _a
    try:
        _a.parse(code or "")
        return True, ""
    except SyntaxError as e:
        return False, "line %s: %s" % (e.lineno, e.msg)
    except (ValueError, MemoryError, RecursionError) as e:
        return False, str(e)


def terminal():
    """Identify the terminal emulator and how to change its font size.

    Frida cannot make your font bigger — font size belongs to the terminal, not
    to the program drawing inside it. What it can do is stop you having to go
    and look it up.
    """
    env = os.environ
    def has(*names):
        return any(env.get(n) for n in names)

    term = (env.get("TERM") or "").lower()
    prog = (env.get("TERM_PROGRAM") or "").lower()

    if has("KITTY_WINDOW_ID") or "kitty" in term:
        return ("kitty", "ctrl + shift + =   (ctrl+shift+- smaller, "
                "ctrl+shift+0 to reset)", "~/.config/kitty/kitty.conf: font_size 16")
    if has("ALACRITTY_WINDOW_ID", "ALACRITTY_SOCKET") or "alacritty" in term:
        return ("alacritty", "ctrl + =   (ctrl+- smaller, ctrl+0 to reset)",
                "~/.config/alacritty/alacritty.toml: [font] size = 16")
    if "foot" in term:
        return ("foot", "ctrl + =   (ctrl+- smaller, ctrl+0 to reset)",
                "~/.config/foot/foot.ini: font=monospace:size=16")
    if has("WEZTERM_PANE", "WEZTERM_EXECUTABLE"):
        return ("wezterm", "ctrl + =   (ctrl+- smaller, ctrl+0 to reset)",
                "~/.wezterm.lua: config.font_size = 16")
    if has("KONSOLE_VERSION", "KONSOLE_DBUS_SESSION"):
        return ("konsole", "ctrl + =   (or Settings → Edit Current Profile → "
                "Appearance → Font)", "")
    if has("GNOME_TERMINAL_SCREEN") or prog == "gnome-terminal":
        return ("gnome-terminal", "ctrl + +   (ctrl+- smaller, ctrl+0 to reset)",
                "Preferences → your profile → Text → Custom font")
    if prog == "vscode":
        return ("vs code", "settings: terminal.integrated.fontSize", "")
    if has("VTE_VERSION"):
        return ("a vte terminal", "ctrl + +   (ctrl+- smaller)", "")
    if term.startswith("xterm"):
        return ("xterm", "ctrl + right-click → choose a larger font",
                "~/.Xresources: XTerm*faceSize: 16")
    return ("", "", "")


def data_dir():
    """Where Frida keeps things that should outlive a session (history, sessions)."""
    return str(app_data_dir())


_NAME_OK = "abcdefghijklmnopqrstuvwxyz0123456789-_"


def safe_tool_name(raw, fallback="tool"):
    """A name that is safe as a filename and legal as a shell command.

    Tools get installed onto PATH, so a name is a public thing: no spaces, no
    slashes, no leading dash (which argparse and getopt would read as a flag).
    """
    raw = (raw or "").strip().lower().replace(" ", "-").replace("_", "-")
    out = "".join(ch for ch in raw if ch in _NAME_OK).strip("-")
    while "--" in out:
        out = out.replace("--", "-")
    return out[:48] or fallback


def config_dir():
    """Per-OS config dir (small settings file)."""
    if IS_WIN:
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "Frida"
    if IS_MAC:
        return Path.home() / "Library" / "Application Support" / "Frida"
    return Path.home() / ".config" / "frida"

def tools_dir():
    """Where built/saved tools live, under the user's home (visible, not hidden)."""
    return Path.home() / "frida-tools"

# ==========================================================================
# CONFIG  -- yours to edit
# ==========================================================================

# --------------------------------------------------------------------------
# PROVIDERS
# --------------------------------------------------------------------------
# Frida can call several providers. You pick one per session in the UI; if a
# call fails it falls through that provider's own model chain (biggest first).
# Keys are read from env vars (below) or pasted in Settings. Nothing is sent to
# the browser; keys persist to an owner-only config file.
#
# The "models" lists below are only FALLBACKS. Frida fetches each provider's
# live catalog from its OpenAI-compatible /models endpoint ("models_url") using
# your key, so the dropdown shows exactly what your account can actually call —
# no more guessing at names that 404 with "model unavailable on your plan".
PROVIDERS = {
    "groq": {
        "label": "Groq",
        "url": "https://api.groq.com/openai/v1/chat/completions",
        "models_url": "https://api.groq.com/openai/v1/models",
        "env": "GROQ_API_KEY",
        "kind": "openai",
        "models": [
            "llama-3.3-70b-versatile",
            "openai/gpt-oss-120b",
            "openai/gpt-oss-20b",
            "gemma2-9b-it",
            "llama-3.1-8b-instant",
        ],
    },
    "siliconflow": {
        "label": "SiliconFlow",
        # SiliconFlow runs TWO separate platforms whose keys are NOT interchangeable:
        #   - International: cloud.siliconflow.COM  -> api.siliconflow.com
        #   - China:         cloud.siliconflow.CN   -> api.siliconflow.cn
        # A key made on one returns 401 on the other. We target .com because that's
        # where cloud.siliconflow.com keys are issued. If your key is from the .cn
        # site instead, change both URLs below back to .cn.
        "url": "https://api.siliconflow.com/v1/chat/completions",
        "models_url": "https://api.siliconflow.com/v1/models?sub_type=chat",
        "env": "SILICONFLOW_API_KEY",
        "kind": "openai",
        # V4 Pro first — the primary. 1.6T MoE (49B active), 1M context, and the
        # strongest coding model on this provider (93.5% LiveCodeBench). Flash sits
        # right behind it and does all the cheap auxiliary work: see MODEL_TIERS.
        "models": [
            "deepseek-ai/DeepSeek-V4-Flash",
            "deepseek-ai/DeepSeek-V4-Flash-0731",
            "deepseek-ai/DeepSeek-V4-Pro",
            "deepseek-ai/DeepSeek-V3",
            "Qwen/Qwen2.5-72B-Instruct",
            "Qwen/Qwen2.5-Coder-32B-Instruct",
            "Qwen/Qwen2.5-7B-Instruct",
        ],
    },
    "google": {
        "label": "Google AI Studio",
        "url": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        "models_url": "https://generativelanguage.googleapis.com/v1beta/openai/models",
        "env": "GOOGLE_API_KEY",
        "kind": "openai",   # google exposes an OpenAI-compatible endpoint
        "models": [
            "gemini-2.5-pro",
            "gemini-2.5-flash",
            "gemini-2.0-flash",
            "gemini-1.5-pro",
            "gemini-1.5-flash",
        ],
    },
    "zai": {
        "label": "Z.ai",
        # Z.ai's OpenAI-compatible surface. There is no documented /models
        # listing endpoint, so the list below is the source of truth rather
        # than a fallback — fetch_models degrades to it cleanly.
        "url": "https://api.z.ai/api/paas/v4/chat/completions",
        "models_url": "",
        "env": "ZAI_API_KEY",
        "kind": "openai",
        "models": [
            "glm-5.3",
            "glm-5",
            "glm-4.6",
            "glm-4.5-air",
        ],
    },
    "novita": {
        "label": "Novita AI",
        "url": "https://api.novita.ai/v3/openai/chat/completions",
        "models_url": "https://api.novita.ai/v3/openai/models",
        "env": "NOVITA_API_KEY",
        "kind": "openai",
        "models": [
            "deepseek/deepseek-v3",
            "qwen/qwen-2.5-72b-instruct",
            "meta-llama/llama-3.1-70b-instruct",
            "openai/gpt-oss-120b",
            "meta-llama/llama-3.1-8b-instruct",
        ],
    },
}

# default provider on first launch: SiliconFlow primary, Groq is the fallback.
DEFAULT_PROVIDER = "siliconflow"

# when no model is explicitly chosen, prefer this one on the default provider.
DEFAULT_MODEL_BY_PROVIDER = {
    "siliconflow": "deepseek-ai/DeepSeek-V4-Flash",
}

# ==========================================================================
# TASK TIERS  --  the single biggest lever on both code quality AND spend.
#
# Not every call needs a 1.6-trillion-parameter model. Writing and repairing a
# tool is where mistakes actually hurt, so that goes to V4 Pro with reasoning
# turned on. Naming a file, turning a question into buttons, drafting a README —
# those are clerical, and Flash does them for a fraction of the price.
#
# Routing this way is why "better code" and "cheaper" aren't in tension here:
# the expensive model runs on fewer, more important calls.
# ==========================================================================
# Flash is the default on both tiers now — it's a strong model, it's ~5x cheaper
# than Pro, and it's what gets picked in Settings. Someone who wants Pro for the
# harder build work just picks it there and, as of this version, that choice
# actually sticks. (Google/Groq unchanged — different model families.)
MODEL_TIERS = {
    "siliconflow": {"build": "deepseek-ai/DeepSeek-V4-Flash",
                    "cheap": "deepseek-ai/DeepSeek-V4-Flash"},
    "novita":      {"build": "deepseek/deepseek-v4-flash",
                    "cheap": "deepseek/deepseek-v4-flash"},
    "google":      {"build": "gemini-2.5-pro", "cheap": "gemini-2.5-flash"},
    "zai":         {"build": "glm-5.3", "cheap": "glm-4.5-air"},
    "groq":        {"build": None, "cheap": None},     # use whatever the chain gives
}

# What Frida wants, in order, when nothing is pinned. Matched against the models
# the provider actually lists, so a renamed or retired id degrades to the next
# choice instead of 404-ing every call.
#
# On SiliconFlow the 0731 Flash is the one to want: same architecture as the
# original V4 Flash, re-post-trained for agentic work, which is exactly what
# this program does all day — read a file, patch it, read the failure, patch
# again. Pro is stronger in the abstract and roughly 5x the price; Flash 0731
# beats it on the tight edit loop that dominates Frida's token spend.
PREFERRED = {
    # Plain Flash first, deliberately. The 0731 revision is re-post-trained for
    # agentic work and is genuinely better at planning — but it is a REASONING
    # model: it spends tens of thousands of tokens thinking before it emits a
    # character of code. For a workshop you sit in front of, watching the file
    # get written is most of the feedback, and a minute of silence before it
    # starts is a worse tool even when the output is marginally better.
    # /think turns it on for people who want it.
    "siliconflow": [
        "deepseek-ai/DeepSeek-V4-Flash",
        "deepseek-ai/DeepSeek-V4-Flash-0731",
        "deepseek-ai/DeepSeek-V4-Pro",
        "deepseek-ai/DeepSeek-V3",
    ],
    "zai": ["glm-5.3", "glm-5", "glm-4.6"],
    "novita": ["deepseek/deepseek-v4-flash", "deepseek/deepseek-v3"],
    "google": ["gemini-2.5-pro", "gemini-2.5-flash"],
    "groq": ["openai/gpt-oss-120b", "llama-3.3-70b-versatile"],
}


def preferred_model(provider_id, available=None):
    """The best model Frida knows of that this provider actually offers.

    `available` is the live list when we have one. Matching is exact first, then
    case-insensitive, then by suffix — providers disagree about namespacing the
    same model ("deepseek-ai/X" vs "deepseek/X" vs "X").
    """
    wants = PREFERRED.get(provider_id) or []
    have = list(available or [])
    if not have:
        return wants[0] if wants else None
    lower = {m.lower(): m for m in have}
    tails = {}
    for m in have:
        tails.setdefault(m.rsplit("/", 1)[-1].lower(), m)
    for want in wants:
        if want in have:
            return want
        hit = lower.get(want.lower()) or tails.get(want.rsplit("/", 1)[-1].lower())
        if hit:
            return hit
    return None

# Ceilings on the reply. Without one, a model that starts rambling bills you for
# every token of it. A 2000-line tool is about 25k tokens, so 32k is generous.
MAX_TOKENS = {"build": 32000, "cheap": 2000}

# DeepSeek V4 exposes graded reasoning effort. On the build path it's worth
# paying for — it's the difference between code that runs and code that nearly
# runs. Everywhere else it's off.
#
# SPEED LEVER: "high" is the dominant wall-clock cost of a build (the model burns
# a large hidden reasoning budget before it writes a line). Drop it without
# touching source by exporting FRIDA_REASONING=medium (or low / none) — medium
# is typically ~2x faster to first token and still writes solid single-file tools;
# high stays the default so nobody's build quality changes unless they ask for it.
_REASON = (os.environ.get("FRIDA_REASONING") or "high").strip().lower()

if _REASON in ("none", "off", ""):
    _REASON = None
elif _REASON not in ("low", "medium", "high"):
    _REASON = "high"

REASONING_EFFORT = {"build": _REASON, "cheap": None}

# Fields some gateways reject outright. Once a (provider, model, field) 400s we
# stop sending it rather than burning a retry on every future call.
_UNSUPPORTED_FIELDS = set()

# providers tried in order if the primary provider's whole chain fails outright.
FALLBACK_PROVIDERS = ["groq"]

# auto-test loop: after the model writes code, Frida silently checks it and
# feeds failures back to the model up to this many times before showing you.
# Each round that fires is another full model round-trip, so this is also a speed
# lever: export FRIDA_AUTOTEST_ROUNDS=1 to cap the worst case at two calls.
try:
    AUTOTEST_MAX_ROUNDS = max(0, min(5, int(os.environ.get("FRIDA_AUTOTEST_ROUNDS", "3"))))
except ValueError:
    AUTOTEST_MAX_ROUNDS = 3

# temperature used ONLY for code generation / auto-fix. Lower than the 0.3 default
# used elsewhere: code wants determinism, not creativity — fewer invented APIs and
# careless mistakes, more reproducible output.
BUILD_TEMPERATURE = 0.15

DANGER = [
    # POSIX
    r"rm\s+-rf\s+/", r"rm\s+-rf\s+~", r"rm\s+-rf\s+\$HOME", r"rm\s+-rf\s+\*",
    r":\(\)\s*\{", r"shutil\.rmtree\(\s*['\"]/", r"\bmkfs\b",
    # `dd` is only destructive when it WRITES to a raw device. `dd if=/dev/sda
    # of=backup.img` is a read — a perfectly ordinary thing for a disk-imaging
    # tool to do — and flagging it stopped that whole category of tool from
    # being self-tested at all.
    r"\bdd\b[^\n]*\bof=/dev/", r"\bof=/dev/sd", r"os\.system\(\s*['\"]\s*rm\b", r">\s*/dev/sd",
    # os.fork() was in this list for fork bombs, but the bomb pattern above
    # already catches those, and forking is how any tool daemonises itself.
    r"shutil\.rmtree\(\s*os\.path\.expanduser",
    # Windows
    r"format\s+[a-zA-Z]:\s*/[a-zA-Z]",                  # format c: /q
    r"del\s+/[sSqQfF]\s+/[sSqQfF]",                     # del /s /q /f ...
    r"rd\s+/[sSqQ]\s+/[sSqQ]\s+[a-zA-Z]:\\\\",          # rd /s /q C:\
    r"rmdir\s+/[sSqQ]\s+/[sSqQ]\s+[a-zA-Z]:\\\\",       # rmdir /s /q C:\
    r"cipher\s+/w:[a-zA-Z]:",                           # cipher /w:C:  (overwrite free space)
    r"diskpart",                                        # diskpart (interactive disk wiper)
    r"Remove-Item\s+.*-Recurse\s+.*-Force.*[Cc]:\\\\",  # PowerShell mass delete on C:\
    r"Format-Volume",                                    # PowerShell format

    # --- the list form of a shell call ------------------------------------
    # Every pattern above matches shell text. `subprocess.run(["rm", "-rf",
    # os.path.expanduser("~")])` is the same command with the same effect and
    # matched none of them, because there is no string "rm -rf" anywhere in it.
    r"['\"]rm['\"]\s*,\s*['\"]-[rRfF]{1,2}",
    r"['\"]-[rRfF]{1,2}['\"]\s*,\s*['\"]rm['\"]",
    r"['\"]rmdir['\"]\s*,\s*['\"]/[sS]['\"]",

    # --- wiping the user's home by any of its several spellings -----------
    r"rmtree\(\s*Path\.home\(\)",
    r"rmtree\(\s*(?:str\()?\s*os\.environ\[\s*['\"]HOME",
    r"rmtree\(\s*(?:str\()?\s*Path\(\s*['\"]~",
    r"rmtree\(\s*['\"]~",
    r"rmtree\(\s*os\.path\.expandvars",
    # deleting everything a recursive glob of home returns
    r"(?:os\.remove|os\.unlink|Path\([^)]*\)\.unlink)[^\n]*\bglob\b[^\n]*(?:expanduser|Path\.home)",
    r"\bglob\b[^\n]*(?:expanduser\(\s*['\"]~|Path\.home\(\))[^\n]*\*\*",

    # --- fetching a script and running it ---------------------------------
    # A generated tool that pipes a download into a shell is executing code
    # nobody in this conversation has read, on the user's machine, as them.
    r"(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b",
    r"(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:zsh|python|perl)\b",

    # --- permission and ownership catastrophes ----------------------------
    # `/` here is the end of the argument, so it can be followed by whitespace,
    # the end of the line, or the quote that closes the enclosing string.
    r"chmod\s+(?:-[a-zA-Z]+\s+)*777\s+/(?:[\s'\"`)]|$)",
    r"chown\s+-[rR][a-zA-Z]*\s+[^\n]*\s/(?:[\s'\"`)]|$)",
]

# key persistence: per-provider keys in an owner-only config file
CONFIG_PATH = str(config_dir() / "config.json")

def load_config():
    c = read_json(CONFIG_PATH, {})
    return c if isinstance(c, dict) else {}

def write_json_atomic(path, obj, mode=None):
    """Write JSON so a crash, a full disk or a killed process can never leave a
    half-written file behind.

    The old code wrote straight over the target with the platform's default text
    encoding. Two ways that bit: an interrupted write truncated a saved tool to
    nothing (the whole conversation gone), and a non-UTF-8 locale raised on any
    tool whose code or chat contained a non-ASCII character. Write to a sibling
    temp file, fsync it, then rename — rename is atomic on POSIX, so the target
    is either the old file or the new one, never a stump.
    """
    path = str(path)
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False)
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
        if mode is not None and not IS_WIN:
            try:
                os.chmod(tmp, mode)
            except Exception:
                pass
        os.replace(tmp, path)
        return True
    except Exception:
        try:
            os.unlink(tmp)
        except Exception:
            pass
        return False

def read_json(path, default=None):
    """Read a JSON file as UTF-8. Never raises."""
    try:
        with open(str(path), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def save_config(cfg):
    """Write config (keys + chosen provider) with owner-only perms on POSIX.
    Windows ACLs work differently — the file lives under %APPDATA% which is already
    per-user, so we just write it normally there."""
    return write_json_atomic(CONFIG_PATH, cfg, mode=None if IS_WIN else 0o600)

def _initial_keys():
    """env var wins per provider, else the saved config."""
    saved = load_config().get("keys", {})
    keys = {}
    for pid, p in PROVIDERS.items():
        keys[pid] = os.environ.get(p["env"], "").strip() or (saved.get(pid) or "").strip()
    return keys

# session state: per-provider keys + the currently selected provider + chosen model per provider
STATE = {
    "keys": _initial_keys(),
    "provider": load_config().get("provider") or DEFAULT_PROVIDER,
    "models": load_config().get("models", {}),   # {provider_id: chosen_model}
    "theme": load_config().get("theme", "ember"),
    "big": load_config().get("big", False),
    # None = don't send the field at all (the model's own default).
    # 0 = ask for no thinking. A number = cap the thinking tokens.
    "thinking": load_config().get("thinking", None),
}

# Set from --theme / --model, which apply to one run and must never be written
# to config.json by an unrelated save later in the session.
RUN_OVERRIDES = {"theme": "", "model": None}

# The model that actually answered most recently. STATE["models"] only holds a
# model you PINNED, so on a default setup the HUD had nothing to show.
LAST_MODEL = [""]


def persist_state():
    models = dict(STATE["models"])
    override = RUN_OVERRIDES.get("model")
    if override:
        pid, pinned = override
        if models.get(pid) == pinned:
            was = load_config().get("models", {}).get(pid)
            if was:
                models[pid] = was          # put back what is really on disk
            else:
                models.pop(pid, None)
    theme = STATE.get("theme", "ember")
    if RUN_OVERRIDES.get("theme") and theme == RUN_OVERRIDES["theme"]:
        theme = load_config().get("theme", "ember")
    return save_config({"keys": STATE["keys"], "provider": STATE["provider"],
                        "models": models, "theme": theme,
                        "big": bool(STATE.get("big")),
                        "thinking": STATE.get("thinking")})

# --------------------------------------------------------------------------
# LIVE MODEL CATALOG  -- ask each provider what YOUR key can actually call
# --------------------------------------------------------------------------
# Cache of {provider_id: [model_id, ...]} fetched from each provider's /models
# endpoint. Avoids the whole class of "model unavailable on your plan" errors that
# come from hardcoded names drifting out of date.
_MODEL_CACHE = {}

# Some providers run multiple regional API hosts whose keys are NOT interchangeable
# (a key from one returns 401 on the other). SiliconFlow is the prime example:
# .com (international) vs .cn (China). We try the configured host first, then the
# alternates, and REMEMBER whichever host accepted the key so every later call uses
# it. This makes "which site was my key from?" a non-issue for the user.
HOST_ALIASES = {
    "siliconflow": ["api.siliconflow.com", "api.siliconflow.cn"],
}

# {provider_id: working_host} once discovered for the current key
_HOST_OK = {}

def _provider_urls(provider_id):
    """Yield (chat_url, models_url) candidates for a provider, best-known host first."""
    prov = PROVIDERS[provider_id]
    base_chat = prov["url"]
    base_models = prov.get("models_url", "")
    aliases = HOST_ALIASES.get(provider_id)
    if not aliases:
        yield base_chat, base_models
        return
    # if we already know which host works for this key, use only that
    known = _HOST_OK.get(provider_id)
    hosts = [known] + [h for h in aliases if h != known] if known else list(aliases)
    # derive the host currently in base_chat so we can swap it
    cur_host = re.sub(r"^https?://([^/]+)/.*$", r"\1", base_chat)
    for h in hosts:
        yield (base_chat.replace(cur_host, h, 1),
               base_models.replace(cur_host, h, 1) if base_models else "")

# crude size ranking so "biggest first" still roughly holds for an unknown catalog
def _model_rank(mid):
    s = mid.lower()
    score = 0
    # explicit param-count hints
    m = re.search(r"(\d+)\s*b\b", s) or re.search(r"-(\d+)b", s)
    if m:
        try: score += int(m.group(1))
        except Exception: pass
    # qualitative hints when there's no number
    for kw, pts in (("pro", 300), ("max", 320), ("ultra", 340), ("405", 405), ("671", 671),
                    ("flagship", 350), ("large", 200), ("70", 70), ("32", 32),
                    ("coder", 40), ("instruct", 10),
                    ("flash", -20), ("mini", -40), ("lite", -45), ("small", -50),
                    ("8b", 8), ("7b", 7), ("3b", 3), ("1.5", -10)):
        if kw in s: score += pts
    # generation/version bonus: a newer major version of the same family should sort
    # first (e.g. deepseek-v4-* above deepseek-v3, gemini-2.5 above gemini-1.5). Weighted
    # heavily enough that a newer generation beats an older one even when the newer is a
    # "flash"/"mini" variant (which otherwise carries a size penalty above).
    vm = re.search(r"v(\d+)\b", s) or re.search(r"-(\d+)\.(\d+)", s)
    if vm:
        try: score += int(vm.group(1)) * 25
        except Exception: pass
    return score

def fetch_models(provider_id, force=False):
    """Fetch the live list of chat models a provider exposes to this key.
    Returns {"models": [...], "source": "live"|"fallback"|"error", "error": ...}."""
    prov = PROVIDERS.get(provider_id)
    if not prov:
        return {"models": [], "source": "error", "error": "unknown provider"}
    if not force and _MODEL_CACHE.get(provider_id):
        return {"models": _MODEL_CACHE[provider_id], "source": "live"}
    key = STATE.get("keys", {}).get(provider_id, "")
    if not key:
        return {"models": list(prov["models"]), "source": "fallback", "error": "no key yet"}

    last_err = None
    # try each candidate host (e.g. SiliconFlow .com then .cn) until one accepts the key
    for _chat_url, models_url in _provider_urls(provider_id):
        if not models_url:
            continue
        host = re.sub(r"^https?://([^/]+)/.*$", r"\1", models_url)
        try:
            req = urllib.request.Request(models_url, headers={
                "Authorization": "Bearer " + key,
                "User-Agent": f"frida/{__version__}",
                "Accept": "application/json",
            })
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode())
            items = data.get("data", data if isinstance(data, list) else [])
            ids = []
            for it in items:
                mid = it.get("id") if isinstance(it, dict) else str(it)
                if not mid:
                    continue
                low = mid.lower()
                # keep chat/text LLMs only; drop embeddings/rerank/image/audio/video/tts/etc.
                if any(b in low for b in ("embed", "rerank", "bge-", "whisper", "tts", "stt",
                                          "stable-diffusion", "flux", "sdxl", "kolors", "cogvideo",
                                          "wan-", "speech", "audio", "image", "video", "vl-",
                                          "-vl", "vision", "ocr")):
                    continue
                ids.append(mid)
            if not ids:
                last_err = "no chat models returned"
                continue
            ids = sorted(set(ids), key=_model_rank, reverse=True)
            _MODEL_CACHE[provider_id] = ids
            if provider_id in HOST_ALIASES:
                _HOST_OK[provider_id] = host   # remember the host that worked for this key
            return {"models": ids, "source": "live", "host": host}
        except urllib.error.HTTPError as e:
            detail = ""
            try: detail = e.read().decode(errors="replace")[:150]
            except Exception: pass
            if e.code == 401:
                last_err = "key rejected (401)"
                continue   # try the next host — a .cn key 401s on .com and vice versa
            if e.code == 403:
                last_err = "forbidden (403): " + detail
                continue
            last_err = f"HTTP {e.code}" + (": "+detail if detail else "")
        except Exception as e:
            last_err = str(e)

    # nothing worked → fall back to the static list, with a clear reason
    hint = ""
    if provider_id in HOST_ALIASES and last_err and "401" in last_err:
        hint = (" — the key was rejected on every SiliconFlow host (.com and .cn). "
                "Re-copy the key (watch for spaces), or check the account needs verification.")
    return {"models": list(prov["models"]), "source": "fallback",
            "error": (last_err or "could not reach provider") + hint}

def provider_model_chain(provider_id):
    """The model order to try: live catalog if we have it, else the static fallback.

    Whatever the order, the model Frida actually wants goes first when the
    provider offers it. A live /models listing comes back in the provider's own
    order — often alphabetical, or newest-API-first — so without this the first
    call of every session went to whatever happened to be at the top.
    """
    chain = _MODEL_CACHE.get(provider_id) or list(PROVIDERS[provider_id]["models"])
    want = preferred_model(provider_id, chain)
    if want and want in chain:
        chain = [want] + [m for m in chain if m != want]
    return chain

# --------------------------------------------------------------------------
# TOOL LIBRARY  -- persistent, reloadable tools (code + conversation)
# --------------------------------------------------------------------------
LIBRARY_DIR = str(app_data_dir() / "library")

def _safe_id(name):
    return re.sub(r"[^A-Za-z0-9_\-]", "_", (name or "tool")).strip("_") or "tool"

def library_save(name, code, messages, version="testing", args="", sid=None,
                 ver="1.0.0", named=False, title=""):
    """Snapshot a tool to the library at its CURRENT state: its code, the full build
    conversation, the version badge, and the test args. Reopening it restores all of
    that so you continue exactly where you left off — like saving a chat."""
    os.makedirs(LIBRARY_DIR, exist_ok=True)
    # The record id was just _safe_id(name), and the name is auto-derived from the
    # tool's own window title. Two DIFFERENT tools that happen to title themselves
    # the same thing — or "my tool" and "my_tool" — landed on one filename, and the
    # second ★ library silently destroyed the first. No warning, no undo, and the
    # library list showed one entry where the user had saved two. Re-saving the
    # SAME tool must still overwrite (that's the point), so match on the session it
    # came from and only then reuse the slot; otherwise take the next free suffix.
    tid = _safe_id(name)
    existing = read_json(os.path.join(LIBRARY_DIR, tid + ".json"))
    if isinstance(existing, dict) and existing.get("from_session") and sid \
            and existing.get("from_session") != sid:
        n = 2
        while os.path.exists(os.path.join(LIBRARY_DIR, f"{tid}-{n}.json")) and n < 200:
            prior = read_json(os.path.join(LIBRARY_DIR, f"{tid}-{n}.json")) or {}
            if prior.get("from_session") == sid:
                break
            n += 1
        tid = f"{tid}-{n}"
    rec = {"id": tid, "name": name or tid, "code": code,
           "messages": messages or [], "version": version or "testing",
           "args": args or "", "deps": detect_deps(code or "")["pip"],
           "ver": ver or "1.0.0", "named": bool(named), "title": title or (name or tid),
           "from_session": sid, "saved": time.strftime("%Y-%m-%d %H:%M")}
    if not write_json_atomic(os.path.join(LIBRARY_DIR, tid + ".json"), rec):
        return {"error": "could not write to the library directory"}
    return {"id": tid, "saved": rec["saved"]}

# Opening the library or the in-progress panel used to parse EVERY saved record
# in full — the whole script plus the entire build conversation — just to render a
# one-line summary of each. With a couple of dozen saved tools that is tens of
# megabytes of json parsed on every panel open, and the panel visibly stalled.
# The summary is now cached per file and only recomputed when that file's mtime or
# size changes, so a repeat open costs a stat() per record.
_SUMMARY_CACHE = {}

_SUMMARY_LOCK = threading.Lock()

def _summarise_dir(dirpath, build):
    """Map each *.json in a directory to a small summary dict, cached on (mtime, size)."""
    if not os.path.isdir(dirpath):
        return []
    out = []
    live = set()
    for fn in os.listdir(dirpath):
        if not fn.endswith(".json"):
            continue
        full = os.path.join(dirpath, fn)
        try:
            st = os.stat(full)
        except OSError:
            continue
        key = (st.st_mtime_ns, st.st_size)
        live.add(full)
        with _SUMMARY_LOCK:
            hit = _SUMMARY_CACHE.get(full)
        if hit and hit[0] == key:
            out.append(hit[1])
            continue
        rec = read_json(full)
        if not isinstance(rec, dict):
            continue
        try:
            summary = build(rec)
        except Exception:
            continue
        with _SUMMARY_LOCK:
            _SUMMARY_CACHE[full] = (key, summary)
        out.append(summary)
    # drop cache entries for records that have since been deleted
    with _SUMMARY_LOCK:
        for stale in [k for k in _SUMMARY_CACHE
                      if k.startswith(dirpath + os.sep) and k not in live]:
            _SUMMARY_CACHE.pop(stale, None)
    return out

def library_list():
    def _build(r):
        return {"id": r.get("id"), "name": r.get("name"),
                "saved": r.get("saved"), "deps": r.get("deps") or [],
                "version": r.get("version", "testing"),
                "ver": r.get("ver", "1.0.0"), "title": r.get("title", r.get("name")),
                "lines": len((r.get("code") or "").splitlines())}
    tools = _summarise_dir(LIBRARY_DIR, _build)
    tools.sort(key=lambda t: t.get("saved", ""), reverse=True)
    return tools

def library_load(tid):
    """The saved library record, or None."""
    return read_json(os.path.join(LIBRARY_DIR, _safe_id(tid) + ".json"))

def library_delete(tid):
    path = os.path.join(LIBRARY_DIR, _safe_id(tid) + ".json")
    # Deleting is idempotent: if it's already gone the caller got what they
    # wanted. Leaking a raw "[Errno 2] No such file..." string into the UI on a
    # double-click or a stale list was noise, not an error.
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except Exception as e:
        return {"error": str(e)}
    return {"ok": True}

# --------------------------------------------------------------------------
# SESSIONS  -- live works-in-progress (auto-saved as you build), like chats
# --------------------------------------------------------------------------
SESSION_DIR = str(app_data_dir() / "sessions")

_SID_LOCK = threading.Lock()

_SID_SEQ = [0]

def _new_session_id():
    with _SID_LOCK:
        _SID_SEQ[0] += 1
        seq = _SID_SEQ[0]
    return time.strftime("s%Y%m%d-%H%M%S") + f"-{seq:03d}"

def session_save(sid, name, code, messages, version="testing", args="",
                 ver="1.0.0", named=False, title="", history=None, kind="cli"):
    """Auto-save the live conversation+code for a tool in progress (its full state)."""
    os.makedirs(SESSION_DIR, exist_ok=True)
    # A second-resolution id meant two tools started inside the same second got the
    # same filename, and the second silently overwrote the first. Suffix a counter.
    sid = sid or _new_session_id()
    rec = {"id": sid, "name": name or "untitled", "code": code or "",
           "messages": messages or [], "version": version or "testing", "args": args or "",
           "deps": detect_deps(code or "")["pip"],
           "history": history or [], "lines": len((code or "").splitlines()),
           "kind": kind or "cli",
           "ver": ver or "1.0.0", "named": bool(named), "title": title or (name or "untitled"),
           "updated": time.strftime("%Y-%m-%d %H:%M")}
    if not write_json_atomic(os.path.join(SESSION_DIR, _safe_id(sid) + ".json"), rec):
        return {"error": "could not write the session"}
    return {"id": sid, "updated": rec["updated"]}

def session_list():
    def _build(r):
        msgs = r.get("messages", [])
        return {"id": r.get("id"), "name": r.get("name"),
                "updated": r.get("updated"), "deps": r.get("deps") or [],
                "lines": r.get("lines") or len((r.get("code") or "").splitlines()),
                "ver": r.get("ver") or "1.0.0",
                "turns": sum(1 for m in msgs if m.get("role") == "user"),
                "hasCode": bool(r.get("code"))}
    out = _summarise_dir(SESSION_DIR, _build)
    out.sort(key=lambda s: s.get("updated", ""), reverse=True)
    return out

def session_load(sid):
    """The saved session record, or None. (This used to be wrapped in a
    {"session": ...} envelope for an HTTP response. There is no HTTP any more.)"""
    return read_json(os.path.join(SESSION_DIR, _safe_id(sid) + ".json"))

def session_delete(sid):
    try:
        os.remove(os.path.join(SESSION_DIR, _safe_id(sid) + ".json"))
    except FileNotFoundError:
        pass
    except Exception as e:
        return {"error": str(e)}
    return {"ok": True}

# Top-level module names in an import statement.
#
# One regex is not enough. `^\s*(?:import|from)\s+([a-zA-Z0-9_.]+)` captures ONE
# name, so on
#     import requests, bs4
# it sees `requests` and nothing else — and the second package silently drops out
# of dependency detection and out of the frozen build. Inherited from the engine
# this grew out of, where the same miss made a working tool look broken.
_IMPORT_RE = re.compile(r"^[ \t]*(?:import|from)[ \t]+([a-zA-Z0-9_.]+)", re.M)

_IMPORT_LINE_RE = re.compile(r"^[ \t]*import[ \t]+([^\n#;]+)", re.M)

def _imported_tops(code):
    """Every top-level module name imported anywhere in the source."""
    tops = set()
    for m in _IMPORT_RE.finditer(code or ""):
        t = m.group(1).split(".")[0]
        if t:
            tops.add(t)
    # `import a, b as c, d.e` — the regex above only ever sees `a`
    for m in _IMPORT_LINE_RE.finditer(code or ""):
        for part in m.group(1).split(","):
            nm = part.strip().split(" as ")[0].strip().split(".")[0].strip()
            if nm and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", nm):
                tops.add(nm)
    return tops

def _code_key(code):
    import hashlib
    return hashlib.sha1((code or "").encode("utf-8", "replace")).hexdigest()

VENV_DIR = str(app_data_dir() / "venv")

def _venv_python():
    """Return the python interpreter inside our managed venv, or None if not built yet.
    Windows lives in Scripts/python.exe; POSIX in bin/python."""
    cands = [Path(VENV_DIR) / "Scripts" / "python.exe",
             Path(VENV_DIR) / "bin" / "python",
             Path(VENV_DIR) / "bin" / "python3"]
    for c in cands:
        if c.exists():
            return str(c)
    return None

def install_deps(pkgs):
    """Install pip packages into Frida's managed venv. Returns log + python path.

    The venv is created WITH access to system site-packages so a tool can use BOTH
    pip packages installed here AND anything Python already has on this machine —
    which matters on Arch/CachyOS, where Pillow, requests and friends are usually
    already present as native packages and re-downloading them is pure waste.

    Two speedups over the old behaviour:
      * `uv` is used when it's on PATH. It resolves and installs an order of
        magnitude faster than pip, and it's a single static binary a lot of Arch
        users already have.
      * `--upgrade` is gone. It forced a PyPI round-trip for every package on
        every click, even when the package was already installed and fine.
    """
    if not pkgs:
        return {"ok": True, "log": "no pip packages to install — already covered", "python": sys.executable}
    try:
        if not os.path.isdir(VENV_DIR):
            import venv
            venv.EnvBuilder(with_pip=True, system_site_packages=True).create(VENV_DIR)
        vpy = _venv_python() or sys.executable
        uv = shutil.which("uv")
        if uv:
            cmd = [uv, "pip", "install", "--python", vpy, *pkgs]
        else:
            cmd = [vpy, "-m", "pip", "install", "--disable-pip-version-check",
                   "--no-input", *pkgs]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                              encoding="utf-8", errors="replace")
        out = (proc.stdout or "") + (proc.stderr or "")
        if uv:
            out = f"[using uv — {uv}]\n" + out
        return {"ok": proc.returncode == 0, "log": out[-1800:], "python": vpy}
    except Exception as e:
        return {"ok": False, "log": f"venv/install failed: {e}", "python": sys.executable}

# the interpreter used to run a generated tool. We prefer the managed venv (which sees
# the system site-packages too, so it has everything available). If the venv hasn't
# been built yet, we fall back to the interpreter Frida itself is running on.
def run_python(code=None):
    return _venv_python() or sys.executable

# ==========================================================================
# helpers
# ==========================================================================
def _code_without_prose(code):
    """The source with COMMENTS and DOCSTRINGS blanked out. Line numbers preserved.

    looks_dangerous() matched the raw file, so prose tripped it: a tool whose
    module docstring documents a `dd` example, a comment reading "never run
    rm -rf /". The tool did nothing dangerous — it TALKED about something
    dangerous — and Frida then refused to self-test it.

    Comments and docstrings only. NOT every string literal: a destructive command
    almost always lives inside one — os.system("rm -rf /") — so blanking strings
    wholesale would switch the entire check off. A help string that isn't a
    docstring can therefore still trip it, and that is the right way round to be
    wrong: a false positive now costs one click, a false negative costs the
    machine. Falls back to the raw source if the file doesn't parse.
    """
    try:
        import ast as _ast
        import io as _io
        import tokenize as _tok
        src = code or ""
        out = list(src)
        starts, pos = [], 0
        for ln in src.splitlines(keepends=True):
            starts.append(pos)
            pos += len(ln)

        def _blank(a, b):
            if a is None or b is None:
                return
            for i in range(max(0, a), min(b, len(out))):
                if out[i] != "\n":
                    out[i] = " "

        def _off(row, col):
            return starts[row - 1] + col if 0 < row <= len(starts) else None

        for t in _tok.generate_tokens(_io.StringIO(src).readline):
            if t.type == _tok.COMMENT:
                _blank(_off(*t.start), _off(*t.end))

        tree = _ast.parse(src)
        for node in _ast.walk(tree):
            if not isinstance(node, (_ast.Module, _ast.ClassDef,
                                     _ast.FunctionDef, _ast.AsyncFunctionDef)):
                continue
            body = getattr(node, "body", None) or []
            if not body:
                continue
            first = body[0]
            if (isinstance(first, _ast.Expr) and isinstance(first.value, _ast.Constant)
                    and isinstance(first.value.value, str)):
                _blank(_off(first.lineno, first.col_offset),
                       _off(first.end_lineno, first.end_col_offset))
        return "".join(out)
    except Exception:
        return code or ""

def looks_dangerous(code):
    """Destructive patterns found in the EXECUTABLE code, as the text that matched.

    This used to hand back the regex sources, which is what the confirm dialog
    then showed the user — the pattern instead of the line actually in their tool.
    Nobody can make an informed decision about a regex.
    """
    scan = _code_without_prose(code)
    out = []
    for pat in DANGER:
        m = re.search(pat, scan)
        if m:
            line = scan[:m.start()].count("\n") + 1
            # report the REAL line from the original source, not the blanked copy
            src = (code or "").splitlines()
            text = src[line - 1].strip() if 0 < line <= len(src) else m.group(0)
            out.append("line %d: %s" % (line, " ".join(text.split())[:100]))
    return out

# ==========================================================================
# MODEL TRANSPORT
#
# THE BUG THIS SECTION EXISTS TO FIX (the "it errors out after a few minutes"
# one): every model call went through a single blocking POST with a 45-second
# ceiling. Forty-five seconds is a fine bound for a chat reply. It is nowhere
# near enough for the build path, which asks a REASONING model, at
# reasoning_effort=high, with max_tokens=32000, to write a complete GUI tool.
# That call routinely runs 1-4 minutes, and nothing comes back until the last
# token — so the read timed out EVERY time, on a request the provider was
# happily still working on.
#
# What the user saw: "Calling SiliconFlow model ..." for 45s, then "unreachable
# — retrying...", twice more (137s on a pinned model), then the same again for
# the full-rewrite attempt after the patch round — 4.6 minutes to a "chain
# failed" error, no code, every time, while being billed for three completed
# generations nobody ever read.
#
# Two changes fix it properly:
#   1. The response is STREAMED. Tokens arrive as they're produced, so the
#      timeout that matters is "how long since the last byte", not "how long in
#      total" — a slow model is no longer indistinguishable from a dead one.
#   2. The budget is per-tier and generous, with an idle guard that still fails
#      fast on a genuinely dead endpoint.
# Streaming also feeds the activity channel, so the UI shows a live character
# count instead of a spinner that looks hung.
# ==========================================================================
def _env_int(name, default, lo, hi):
    try:
        return max(lo, min(hi, int(os.environ.get(name, "") or default)))
    except ValueError:
        return default

# seconds of TOTAL SILENCE (not a single byte from the provider) before we call
# a call dead. Streaming makes this the meaningful bound.
MODEL_IDLE_TIMEOUT = _env_int("FRIDA_IDLE_TIMEOUT", 90, 15, 600)

# absolute ceiling per call, per tier. Build work gets real room; clerical calls
# stay short so a wedged helper can't hold a build up.
MODEL_TIMEOUT = {"build": _env_int("FRIDA_TIMEOUT", 900, 60, 3600),
                 "cheap": _env_int("FRIDA_TIMEOUT_CHEAP", 120, 20, 900)}

# ==========================================================================
# RETRY POLICY
#
# THE BUG THIS EXISTS TO FIX: "most of the time it works perfectly and
# sometimes it tells me to refresh model."
#
# A 502/503 from a busy gateway is a routine, self-healing event. Frida had NO
# retry for it. And because a model pinned in Settings makes the chain exactly
# one model long, that single hiccup exhausted the chain instantly — 0.0
# seconds — and, with no fallback provider key configured, dead-ended on
# "chain failed. Try Settings -> refresh models", which is advice for a
# completely different problem. Same for an empty reply, an empty choices list,
# and a connection the provider dropped mid-request.
#
# So: classify the failure, and retry the ones that are worth retrying.
_RETRY_STATUS = {408, 409, 425, 429, 500, 502, 503, 504, 507, 520, 521, 522, 523, 524, 529}

MODEL_RETRIES = _env_int("FRIDA_RETRIES", 4, 0, 10)

_RETRY_CAP = 20.0          # never sit on a backoff longer than this

class _UnusableReply(Exception):
    """HTTP said 200, but there is nothing in the response to use.

    An empty `content`, an empty `choices` list — both happen on real gateways
    under load, and both used to burn the whole model chain on the first
    occurrence instead of simply asking again.
    """

def _retry_wait(attempt, exc=None):
    """Backoff for attempt N, honouring Retry-After when the server sent one."""
    if exc is not None:
        try:
            ra = (exc.headers or {}).get("Retry-After")
        except Exception:
            ra = None
        if ra:
            try:
                want = float(str(ra).strip())
                # A server asking for longer than the cap is telling us to go
                # away; let the caller fall through to another model/provider
                # rather than freezing the UI on a long sleep.
                if 0 < want <= _RETRY_CAP:
                    return want
            except ValueError:
                pass
    base = min(_RETRY_CAP, 0.8 * (2.2 ** attempt))
    # jitter so two concurrent calls (a polish round beside a build) don't
    # synchronise and hammer the same second
    return base * (0.75 + 0.5 * _rand())

def _rand():
    import random
    return random.random()

def _is_idle_timeout(exc):
    """A read that ran out of patience — as opposed to a connection that died.

    The distinction decides whether re-sending is smart or wasteful. A timeout
    means the provider may STILL be generating our answer, and a re-send buys a
    second full generation on the bill. A reset/refused/incomplete-read means
    this request is definitively gone, and asking again is exactly right.
    """
    return isinstance(exc, TimeoutError) or isinstance(
        getattr(exc, "reason", None), (TimeoutError, socket.timeout))

def _http_post(url, headers, body, timeout=None):
    """Non-streaming POST. Kept for gateways that reject `stream`."""
    # urlopen's own timeout bounds BOTH connect and read for this socket, so a dead
    # endpoint fails in seconds instead of freezing the "forging" spinner. We do NOT
    # touch socket.setdefaulttimeout(): that's process-global, and _http_post runs on
    # concurrent worker threads (a polish round while a build is in flight, the
    # parallel model-fetch threads at startup). Racing threads restoring that global
    # could leave EVERY other socket in the process — every other model call
    # waits — stuck on this timeout.
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
    with urllib.request.urlopen(req, timeout=timeout or MODEL_TIMEOUT["build"]) as resp:
        return json.loads(resp.read().decode())

def _http_post_stream(url, headers, body, idle_timeout=None, total_timeout=None,
                      on_progress=None, want_usage=True):
    """Streaming POST against an OpenAI-compatible /chat/completions endpoint.

    Returns the SAME shape a non-streaming call returns — {"choices": [...],
    "usage": {...}} — so every caller downstream is unchanged. The socket
    timeout applies per read, which is exactly the semantics we want: a model
    that is slowly writing keeps the connection alive, a hung one doesn't.
    """
    idle_timeout = idle_timeout or MODEL_IDLE_TIMEOUT
    total_timeout = total_timeout or MODEL_TIMEOUT["build"]
    body = dict(body)
    headers = dict(headers)
    # a couple of stricter gateways refuse to stream unless you ask for it here too
    headers["Accept"] = "text/event-stream, application/json"
    body["stream"] = True
    if want_usage:
        # ask for the usage block on the final frame; without it a streamed call
        # would fall back to the character estimate and the cost chip would drift.
        body["stream_options"] = {"include_usage": True}
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)

    content, reasoning = [], []
    usage, finish = {}, None
    saw_event = False
    saw_content = [False]
    raw_body = []
    started = time.time()
    last_tick = 0.0

    with urllib.request.urlopen(req, timeout=idle_timeout) as resp:
        for raw in resp:                       # one SSE line at a time
            if time.time() - started > total_timeout:
                raise TimeoutError(f"model call exceeded {int(total_timeout)}s")
            try:
                line = raw.decode("utf-8", "replace")
            except Exception:
                continue
            if len(raw_body) < 64:
                raw_body.append(line)          # in case this isn't SSE at all
            line = line.strip()
            if not line or line.startswith(":"):
                continue                       # keep-alive comment
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if payload == "[DONE]":
                break
            try:
                ev = json.loads(payload)
            except Exception:
                continue
            saw_event = True
            if ev.get("usage"):
                usage = ev["usage"]
            for ch in ev.get("choices") or []:
                # `delta` on a stream; a few gateways echo `message` instead
                d = ch.get("delta") or ch.get("message") or {}
                c = d.get("content")
                if c:
                    content.append(c)
                r = d.get("reasoning_content") or d.get("reasoning")
                if isinstance(r, str) and r:
                    reasoning.append(r)
                if ch.get("finish_reason"):
                    finish = ch["finish_reason"]
            if on_progress:
                now = time.time()
                # The moment the first real character arrives after a long
                # think is the moment worth showing promptly — waiting up to a
                # quarter second more to draw the handover wastes the only
                # interesting transition in the whole generation.
                first_content = bool(content) and not saw_content[0]
                if first_content:
                    saw_content[0] = True
                    last_tick = 0.0
                # Four ticks a second when something is actually drawing the text
                # (the live code preview), one a second when it's only a counter.
                # A reasoning model can emit tens of thousands of thinking
                # tokens before one character of content. If the tick only ran
                # for content the screen sat frozen the whole time.
                every = 0.25 if GEN_WATCHER[0] else 1.0
                if now - last_tick >= every:
                    last_tick = now
                    try:
                        on_progress(sum(len(x) for x in content),
                                    sum(len(x) for x in reasoning),
                                    now - started, "".join(content),
                                    "".join(reasoning))
                    except Exception:
                        pass

    if not saw_event:
        # The gateway ignored `stream` and answered with an ordinary JSON body.
        # Parse it rather than reporting an empty reply.
        try:
            return json.loads("".join(raw_body))
        except Exception:
            pass
    msg = {"content": "".join(content)}
    if reasoning:
        msg["reasoning_content"] = "".join(reasoning)
    return {"choices": [{"message": msg, "finish_reason": finish}], "usage": usage}

# --------------------------------------------------------------------------
# CONTEXT BUDGET  -- keep requests under the ACTIVE model's real window
# --------------------------------------------------------------------------
# The previous version used one fixed budget (120k chars). That was the bug behind
# "works on a fresh tool, dies after long use": a long session would fall through
# the model chain to a SMALL-context model (e.g. an 8k-token model) for which 120k
# chars is wildly over the limit — so the request 400'd even though trimming "ran".
# Now we budget against the specific model being called.
#
# Context windows in TOKENS (input side). ~3.5 chars/token for code-heavy text, and
# we reserve room for the reply, so usable input chars ≈ tokens * 3. Unknown models
# get a conservative default so we never overshoot a small one.
MODEL_CONTEXT_TOKENS = {
    # Groq
    "llama-3.3-70b-versatile": 128000, "openai/gpt-oss-120b": 128000,
    "openai/gpt-oss-20b": 128000, "gemma2-9b-it": 8192, "llama-3.1-8b-instant": 128000,
    # SiliconFlow
    "deepseek-ai/deepseek-v3": 64000, "qwen/qwen2.5-72b-instruct": 32000,
    "qwen/qwen2.5-coder-32b-instruct": 32000, "deepseek-ai/deepseek-v2.5": 32000,
    "qwen/qwen2.5-7b-instruct": 32000,
    # Google
    "gemini-2.5-pro": 1000000, "gemini-2.5-flash": 1000000, "gemini-2.0-flash": 1000000,
    "gemini-1.5-pro": 2000000, "gemini-1.5-flash": 1000000,
    # Novita
    "deepseek/deepseek-v3": 64000, "qwen/qwen-2.5-72b-instruct": 32000,
    "meta-llama/llama-3.1-70b-instruct": 128000, "meta-llama/llama-3.1-8b-instruct": 128000,
    # DeepSeek (first-party) — V4 Pro and Flash both carry a 1M-token window
    # DeepSeek V4 context windows (1M-token), as exposed via SiliconFlow / Novita
    "deepseek-ai/deepseek-v4-flash": 1000000, "deepseek-ai/deepseek-v4-pro": 1000000,
    "deepseek/deepseek-v4-flash": 1000000, "deepseek/deepseek-v4-pro": 1000000,
}

DEFAULT_CONTEXT_TOKENS = 16000      # safe assumption for an unknown model

REPLY_RESERVE_TOKENS   = 4000       # leave room for the model's answer

# ==========================================================================
# TOKEN ACCOUNTING  --  you can't shrink a bill you can't see.
# Every response carries a usage block; we keep a running total for the session
# and a per-model breakdown, and surface it in the UI and in `clidawg /cost`.
# ==========================================================================
USAGE = {"session": {"in": 0, "out": 0, "calls": 0}, "by_model": {}}

_USAGE_LOCK = threading.Lock()

# USD per 1M tokens. Published list prices, used only to show a rough running
# figure — treat it as an indicator, not an invoice.
PRICE_PER_MTOK = {
    "deepseek-ai/deepseek-v4-pro":   (0.28, 0.42),
    "deepseek-ai/deepseek-v4-flash": (0.05, 0.10),
    "deepseek/deepseek-v4-pro":      (0.28, 0.42),
    "deepseek/deepseek-v4-flash":    (0.05, 0.10),
}

def record_usage(pid, model, usage, est_in_chars=0, est_out_chars=0):
    """Fold one response's usage into the running totals.

    Not every gateway returns a `usage` block. When one didn't, this returned
    early and the call was not counted AT ALL — not even in `calls`. The cost chip
    then read zero while real tokens were being spent, which is the one way a
    spend display can be worse than having none. Fall back to a character estimate
    and mark the totals as estimated so the UI can say so.
    """
    try:
        pin = int((usage or {}).get("prompt_tokens") or 0)
        pout = int((usage or {}).get("completion_tokens") or 0)
    except Exception:
        pin = pout = 0
    estimated = False
    if not (pin or pout):
        if not (est_in_chars or est_out_chars):
            return
        pin = int(est_in_chars / 3.6)
        pout = int(est_out_chars / 3.6)
        estimated = True
    with _USAGE_LOCK:
        if estimated:
            USAGE["session"]["estimated"] = USAGE["session"].get("estimated", 0) + 1
        USAGE["session"]["in"] += pin
        USAGE["session"]["out"] += pout
        USAGE["session"]["calls"] += 1
        m = USAGE["by_model"].setdefault(model, {"in": 0, "out": 0, "calls": 0})
        m["in"] += pin; m["out"] += pout; m["calls"] += 1

def edit_summary():
    """How much the targeted-edit path is actually saving, for /api/status."""
    a, f, s = EDIT_STATS["applied"], EDIT_STATS["fallbacks"], EDIT_STATS["salvaged"]
    return {"applied": a, "fallbacks": f, "salvaged": s, "retries": EDIT_STATS["retries"],
            "off": EDIT_STATS["off"],
            "hit_rate": round(a / max(1, a + f + s), 2),
            "output_tokens_saved": int(EDIT_STATS["saved_chars"] / 3.6)}

def _with_code(res):
    """Attach the authoritative extracted code to a chat/polish result."""
    try:
        if isinstance(res, dict) and res.get("reply") and not res.get("error"):
            res["code"] = extract_code(res["reply"])
    except Exception:
        pass
    return res

def usage_summary():
    """Totals plus an estimated cost, for the UI and the CLI."""
    with _USAGE_LOCK:
        sess = dict(USAGE["session"])
        by = {k: dict(v) for k, v in USAGE["by_model"].items()}
    cost = 0.0
    priced = True
    for model, m in by.items():
        rate = PRICE_PER_MTOK.get(model.lower())
        if not rate:
            priced = False
            continue
        cost += (m["in"] / 1e6) * rate[0] + (m["out"] / 1e6) * rate[1]
    return {"session": sess, "by_model": by,
            "cost_usd": round(cost, 4), "cost_complete": priced,
            "estimated_calls": sess.get("estimated", 0)}

def _guess_context_tokens(mid):
    """Best guess at an unlisted model's context window.

    Anything not in the table used to be treated as an 8k-class model, so picking a
    brand-new large-context model from the live catalog silently crippled the build:
    the conversation got trimmed to 48k chars and long sessions started failing for
    no visible reason. Recognise the obvious families by name instead, and only fall
    back to the conservative default when the name says nothing.
    """
    s = (mid or "").lower()
    for frag, toks in (("gemini-1.5-pro", 2000000), ("gemini", 1000000),
                       ("v4-pro", 1000000), ("v4-flash", 1000000), ("v4", 1000000),
                       ("gpt-oss", 128000), ("llama-3.1", 128000), ("llama-3.3", 128000),
                       ("qwen3", 128000), ("deepseek-v3", 64000), ("deepseek-r1", 64000),
                       ("qwen2.5", 32000), ("mixtral", 32000)):
        if frag in s:
            return toks
    return DEFAULT_CONTEXT_TOKENS

def context_budget_chars(model):
    """Usable input-char budget for a specific model, conservatively converted from
    its token window with headroom reserved for the reply."""
    mid = (model or "").lower()
    toks = MODEL_CONTEXT_TOKENS.get(mid) or _guess_context_tokens(mid)
    usable = max(2000, toks - REPLY_RESERVE_TOKENS)
    # ~3 input chars per token (conservative for code), capped so we never send an
    # absurdly huge request even to a million-token model (keeps latency/cost sane).
    # The cap is generous enough that a large tool plus a long build conversation
    # survives on a big-window model (e.g. DeepSeek V4 Flash / Gemini) instead of
    # being trimmed prematurely, but still bounds latency and token spend.
    return min(usable * 3, 600_000)

def _msg_len(m):
    return len(m.get("content", "") or "")


def trim_history(messages, model=None):
    """Keep a long build conversation under the ACTIVE model's window without losing
    what matters. Two-stage:
      1. COLLAPSE every OLD assistant code block into a one-line placeholder — only the
         most recent full script is kept verbatim. (This is the real fix: long sessions
         accumulate many full copies of the same growing program, and that redundancy,
         not the chat, is what blows the context window.)
      2. If still over budget, drop the stale middle of the conversation, keeping the
         system prompt, the current code, and the most recent turns; leave a marker.
    """
    if not messages:
        return messages
    budget_total = context_budget_chars(model)

    system = [m for m in messages if m.get("role") == "system"]
    body   = [m for m in messages if m.get("role") != "system"]

    # ---- stage 1: collapse superseded code blocks ----
    last_code_idx = None
    for i in range(len(body) - 1, -1, -1):
        if body[i].get("role") == "assistant" and "```" in (body[i].get("content") or ""):
            last_code_idx = i
            break
    if last_code_idx is not None:
        for i in range(len(body)):
            if i == last_code_idx:
                continue
            m = body[i]
            if m.get("role") == "assistant" and "```" in (m.get("content") or ""):
                # fence-aware: the old regex closed on a ``` inside the code
                collapsed = strip_code_blocks(
                    m["content"],
                    "`[earlier version of the code \u2014 superseded by the latest below]`")
                body[i] = {"role": m["role"], "content": collapsed}

    # ---- stage 1b: collapse OLD attached files -------------------------------
    # A reference file the user dropped in — a sample CSV, a log, an existing
    # script — is embedded in that user message and was then resent verbatim on
    # every single turn for the rest of the session. A 60k-token sample file
    # dwarfed everything else in the payload and never stopped costing.
    #
    # Only ever collapsed once the tool actually exists in the conversation (so a
    # file loaded to work ON is never taken away before the model has read it),
    # and never the most recent user turn, which may be an attachment sent just now.
    if last_code_idx is not None:
        last_user_idx = max((i for i, m in enumerate(body) if m.get("role") == "user"),
                            default=-1)
        for i in range(len(body)):
            if i == last_user_idx or body[i].get("role") != "user":
                continue
            c = body[i].get("content") or ""
            if "```" in c and len(c) > 4000:
                body[i] = {"role": "user", "content": strip_code_blocks(
                    c,
                    "`[an attached file the user shared earlier \u2014 omitted here to save "
                    "context; ask for it again if you need it]`")}

    sys_len = sum(_msg_len(m) for m in system)
    budget  = budget_total - sys_len
    total   = sum(_msg_len(m) for m in body)
    if total <= budget:
        return system + body   # stage-1 collapse alone got us under the limit

    # ---- stage 2: drop the stale middle, force-keeping the current code ----
    # recompute the code index after collapse (it didn't move)
    kept_tail, used = [], 0
    for i in range(len(body) - 1, -1, -1):
        m = body[i]
        L = _msg_len(m)
        if used + L <= budget or not kept_tail:
            kept_tail.append(m); used += L
        elif i == last_code_idx:
            content = m.get("content") or ""
            if L > budget:
                content = content[: max(2000, budget - 200)] + "\n# …(truncated by Frida to fit this model)…"
            kept_tail.append({"role": m["role"], "content": content}); used += min(L, budget)
        else:
            continue
    kept_tail.reverse()

    dropped = len(body) - len(kept_tail)
    marker = []
    if dropped > 0:
        marker = [{"role": "user", "content":
                   f"(Frida note: {dropped} earlier message(s) were trimmed to fit this model's "
                   f"context window. The current code and recent discussion are below; treat the "
                   f"latest code block as the source of truth.)"}]
    result = system + marker + kept_tail

    # ---- stage 3: HARD GUARANTEE — never exceed budget, even by one char ----
    # Stages 1-2 can land slightly over (the newest message is kept whole, the system
    # prompt is large, etc.). That residual overflow was the real cause of the 400 that
    # struck only after long use. Here we make overflow impossible: while the payload is
    # over the model's total budget, truncate the single largest NON-system message (the
    # current code, almost always) until everything fits with headroom.
    # (running total rather than re-summing the whole payload on every pass — with a
    # long conversation the old loop was quadratic in the number of messages)
    running = sum(_msg_len(m) for m in result)
    guard = 0
    while running > budget_total and guard < 200:
        guard += 1
        # find the largest message that isn't a system message
        idx, biggest = -1, -1
        for i, m in enumerate(result):
            if m.get("role") == "system":
                continue
            L = _msg_len(m)
            if L > biggest:
                biggest, idx = L, i
        if idx < 0 or biggest <= 0:
            break
        over = running - budget_total
        # cut the overflow plus a small margin, but keep at least a stub
        keep_len = max(500, _msg_len(result[idx]) - over - 400)
        c = result[idx]["content"]
        if keep_len >= len(c):
            break
        result[idx] = {"role": result[idx]["role"],
                       "content": c[:keep_len] + "\n…(truncated by Frida to fit this model's context)…"}
        running += _msg_len(result[idx]) - biggest
    return result

_REFUSAL_RE = re.compile(
    r"^\W{0,3}(?:i(?:'m| am)? (?:sorry|afraid)\b|i (?:can(?:'|no)?t|won'?t|am unable to|"
    r"cannot) (?:help|assist|provide|create|write|build|do that)|"
    r"unfortunately,? i (?:can'?t|cannot)|i must decline|as an ai\b)",
    re.I)

def _looks_like_refusal(reply):
    """True when a reply is the model declining rather than building.

    Deliberately narrow: it only fires on a decline in the OPENING of the reply,
    and never when the reply carries code. A tool that happens to print "Sorry,
    that file doesn't exist" must not read as a refusal, and neither must a build
    that merely mentions a limitation in passing.
    """
    text = (reply or "").strip()
    if not text or "```" in text:
        return False                      # it produced code; that's a build
    if len(text) > 1500:
        return False                      # a decline is short; an explanation isn't
    head = text[:240]
    return bool(_REFUSAL_RE.search(head))

def redact(text):
    """Blank out anything that looks like one of our own keys.

    Provider error bodies are echoed to the user and into the model's next
    prompt. Most gateways don't repeat your key back at you — but "most" is not
    a property worth relying on when the cost of being wrong is a live
    credential in a screenshot or a log.
    """
    out = str(text or "")
    for key in (STATE.get("keys") or {}).values():
        key = (key or "").strip()
        if len(key) >= 8 and key in out:
            out = out.replace(key, key[:4] + "…" + key[-2:] + " [redacted]")
    return out


def _err_detail(exc):
    """Read an HTTPError's body at most once and cache it on the exception.

    urllib gives you a file-like body that is consumed on first read. When the
    retry path read it and then re-raised, the outer handler saw an empty string
    and every check that greps the message — context-overflow, rate limits, bad
    key — quietly stopped matching. Caching it makes the body safe to read from
    as many places as need it.
    """
    cached = getattr(exc, "_frida_detail", None)
    if cached is not None:
        return cached
    detail = ""
    try:
        detail = exc.read().decode(errors="replace")[:400]
    except Exception:
        detail = ""
    detail = redact(detail)
    try:
        exc._frida_detail = detail
    except Exception:
        pass
    return detail

def _unpack_reply(data):
    """(reply, finish_reason) from a completion, defensively.

    Shared so the 401 host-retry and the transient-retry paths behave exactly
    like the main one. They each had their own `content or reasoning_content`
    line, which meant a truncated or reasoning-only response coming back through
    a RETRY still surfaced as a raw monologue with no `truncated` flag — the very
    thing the main path stopped doing.
    """
    choices = (data or {}).get("choices") or []
    if not choices:
        return "", ""
    msg = choices[0].get("message") or {}
    finish = (choices[0].get("finish_reason") or "").lower()
    reply = msg.get("content") or ""
    if not reply.strip() and finish != "length":
        reply = msg.get("reasoning_content") or ""
    return reply, finish

def call_model(messages, provider_id=None, temperature=0.3, _fallback_chain=None,
               tier="cheap", max_tokens=None):
    """Call the selected provider, falling through its model chain on error.
    Returns {"reply", "model", "provider"} or {"error"}.
    `temperature` defaults to 0.3; the code-build path lowers it for determinism.
    If the whole provider chain fails AND a key exists for a configured fallback
    provider (e.g. Groq behind SiliconFlow), the call is retried there once so a
    SiliconFlow outage or quota stop doesn't dead-end the build."""
    pid = provider_id or STATE.get("provider") or DEFAULT_PROVIDER
    prov = PROVIDERS.get(pid)
    if not prov:
        return {"error": f"Unknown provider '{pid}'."}
    key = STATE.get("keys", {}).get(pid, "")
    # compute fallback providers up front so even a missing key can fall through.
    if _fallback_chain is None:
        _fallback_chain = [p for p in FALLBACK_PROVIDERS
                           if p != pid and STATE.get("keys", {}).get(p)]
    if not key:
        if _fallback_chain:
            nxt_pid, rest = _fallback_chain[0], _fallback_chain[1:]
            alt = call_model(messages, nxt_pid, temperature, _fallback_chain=rest,
                             tier=tier, max_tokens=max_tokens)
            if not alt.get("error"):
                alt["fellback_from"] = pid
                return alt
        return {"error": f"No API key for {prov['label']}. Add it in Settings, "
                         f"or set {prov['env']} and restart."}

    # raw history; trimmed PER MODEL inside the loop (each model has its own window)
    raw_messages = messages

    # model order: a user-chosen model wins; otherwise fall back to this provider's
    # configured default (e.g. DeepSeek V4 Flash on SiliconFlow) so the primary model
    # is honoured even though the live catalog is rank-sorted (which would otherwise
    # float the pricier V4 Pro to the top). Whatever we pick is pinned to the front.
    # Model selection, in priority order:
    #   1. the model the user picked in Settings — this wins for EVERY tier.
    #      Previously the pick only led the chain and the entire Pro/V3/Qwen list
    #      still trailed it, so one transient error on the chosen model dropped
    #      silently to the next sibling — which is exactly how a box set to V4
    #      Flash "kept going to Qwen". A deliberate choice is now honoured, not
    #      treated as merely the first thing to try.
    #   2. no pick → the tier's model (build=strong, cheap=clerical).
    #   3. neither → the provider default.
    user_pick = STATE.get("models", {}).get(pid)
    pinned = None                     # the model the user chose, if they chose one
    chain = provider_model_chain(pid)
    # The tier's model is a NAME, and the provider may not offer that exact name
    # (0731 not rolled out yet, a different namespace, a retired id). Resolve it
    # against what is really on offer instead of sending an id that 404s.
    tier_pick = (MODEL_TIERS.get(pid) or {}).get(tier)
    if tier_pick and chain and tier_pick not in chain:
        tier_pick = preferred_model(pid, chain) or None
    chosen = user_pick or tier_pick or DEFAULT_MODEL_BY_PROVIDER.get(pid)
    if user_pick:
        # The user named a model. Don't second-guess it by queueing a pile of
        # other models behind it: try that model (repeated briefly to ride out a
        # blip), then fall through to OTHER PROVIDERS, not to sibling models the
        # user didn't choose. This is what makes the setting actually stick.
        pl = user_pick.lower()
        live = provider_model_chain(pid)
        canon = next((m for m in live if m.lower() == pl), user_pick)
        # The pick LEADS the chain; the siblings sit behind it as a last resort.
        #
        # This used to be `chain = [canon]` — your model or nothing. The intent was
        # right (a deliberate choice shouldn't be abandoned on one blip) but with a
        # one-model chain, one blip WAS the whole chain: a single 502 dead-ended
        # the request. Now that _post() retries transient failures properly, the
        # only way we reach a sibling is after every retry on your model has been
        # spent — that isn't "silently dropping to Qwen", it's the difference
        # between a working build and an error message. It says so when it happens.
        chain = [canon] + [m for m in live if m.lower() != pl]
        pinned = canon
    elif chosen:
        # No explicit pick: lead with the tier model but keep the sibling chain as
        # a real fallback, matched case-insensitively so a capitalisation
        # difference from the catalog doesn't duplicate the entry.
        cl = chosen.lower()
        chain = [chosen] + [m for m in chain if m.lower() != cl]

    # which host to call: the one fetch_models proved works for this key, else the
    # configured one. (Handles SiliconFlow .com vs .cn automatically.)
    chat_url = prov["url"]
    for cu, _mu in _provider_urls(pid):
        chat_url = cu
        break

    last = None
    context_hit = False
    refusals = []                 # (model, text) for models that declined outright
    _retried_host = [False]   # one-shot host re-discovery guard (mutable for closure-free use)
    # If the user pinned one model, ride out a transient hiccup on it rather than
    # abandoning their choice — but only for errors that are actually transient
    # (timeouts, 5xx, connection resets), never a 400/401/quota which won't fix
    # itself on a retry.
    single_pick = len(chain) == 1
    total_timeout = MODEL_TIMEOUT.get(tier, MODEL_TIMEOUT["cheap"])
    model = None                     # bound by the loop; referenced by _post below

    def _progress(nchars, nreason, elapsed, text="", reasoning=""):
        # Live feedback while the model writes. This is what turns "the spinner
        # has been going for two minutes, is it dead?" into a visible word count,
        # and it keeps the SSE relay's idle watchdog fed for the whole generation.
        _emit("gen", chars=nchars, reasoning=nreason,
              secs=int(elapsed), model=model)
        watcher = GEN_WATCHER[0]
        if watcher:
            try:
                watcher(text, nchars, elapsed, reasoning, nreason)
            except Exception:
                pass

    provider_degraded = [False]     # set once a 5xx exhausts a model's retry budget

    def _post_once(b):
        """One request. Streams unless this (provider, model) proved it can't."""
        if (pid, model, "stream") in _UNSUPPORTED_FIELDS:
            return _http_post(chat_url, headers, b, timeout=total_timeout)
        try:
            return _http_post_stream(
                chat_url, headers, b,
                idle_timeout=MODEL_IDLE_TIMEOUT, total_timeout=total_timeout,
                on_progress=_progress if tier == "build" else None,
                want_usage=(pid, model, "stream_options") not in _UNSUPPORTED_FIELDS)
        except urllib.error.HTTPError as he:
            det = _err_detail(he).lower()
            if he.code in (400, 404, 422, 501) and "thinking_budget" in det:
                # This gateway or model doesn't take the field. Remember it and
                # retry without, rather than failing the build over a setting.
                _UNSUPPORTED_FIELDS.add((pid, model, "thinking_budget"))
                b.pop("thinking_budget", None)
                return _post_once(b)
            if he.code == 400 and "reasoning_content" in det:
                # Some V4 deployments in thinking mode demand the previous
                # turn's reasoning_content back. Frida doesn't keep it (it is
                # not part of the file, and storing it would bloat every
                # session), so ask for no thinking instead of dying.
                _UNSUPPORTED_FIELDS.add((pid, model, "thinking_budget"))
                b["thinking_budget"] = 0
                return _post_once(b)
            if he.code in (400, 404, 422, 501) and "stream_options" in det:
                _UNSUPPORTED_FIELDS.add((pid, model, "stream_options"))
                return _post_once(b)
            if he.code in (400, 404, 422, 501) and "stream" in det:
                # this gateway won't stream — remember it and take the plain path
                _UNSUPPORTED_FIELDS.add((pid, model, "stream"))
                return _http_post(chat_url, headers, b, timeout=total_timeout)
            raise

    def _post(b):
        """_post_once, with the retry policy wrapped around it.

        This is the whole answer to "sometimes it tells me to refresh model".
        A 502, a 503, a dropped connection, an empty reply — all of them used to
        end the request on the first occurrence. Now each one is simply asked
        again, backed off, up to MODEL_RETRIES times, before anything is
        allowed to fail.
        """
        # Once one model has spent its whole retry budget on 5xx, the PROVIDER is
        # having the problem, not the model. Paying the full budget again on each
        # sibling just makes the user wait four times as long for the same answer,
        # so the rest of the chain gets one attempt each and we move on to the
        # fallback provider quickly.
        budget = 1 if provider_degraded[0] else MODEL_RETRIES
        attempt = 0
        while True:
            try:
                data = _post_once(b)
            except urllib.error.HTTPError as he:
                if he.code in _RETRY_STATUS and attempt >= budget and he.code >= 500:
                    provider_degraded[0] = True
                if he.code in _RETRY_STATUS and attempt < budget:
                    wait = _retry_wait(attempt, he)
                    attempt += 1
                    _emit("stage", text=f"{prov['label']} returned {he.code} — "
                                        f"retrying in {wait:.0f}s "
                                        f"(attempt {attempt} of {budget})")
                    time.sleep(wait)
                    continue
                raise
            except (urllib.error.URLError, ConnectionError, TimeoutError,
                    http.client.HTTPException) as e:
                # A read timeout is NOT retried here: the provider may still be
                # generating, and re-sending buys a second full generation. Every
                # other transport failure means this request is definitively
                # gone, so asking again is the right move.
                if _is_idle_timeout(e) or attempt >= budget:
                    raise
                wait = _retry_wait(attempt)
                attempt += 1
                _emit("stage", text=f"connection to {prov['label']} dropped ({e}) — "
                                    f"retrying in {wait:.0f}s "
                                    f"(attempt {attempt} of {budget})")
                time.sleep(wait)
                continue
            # HTTP was fine; is there anything in it?
            _reply, _finish = _unpack_reply(data)
            if not _reply.strip() and _finish != "length":
                if attempt < budget:
                    wait = _retry_wait(attempt)
                    attempt += 1
                    _emit("stage", text=f"{model} returned an empty reply — "
                                        f"retrying in {wait:.0f}s "
                                        f"(attempt {attempt} of {budget})")
                    time.sleep(wait)
                    continue
                raise _UnusableReply("the provider kept returning an empty reply")
            return data

    for model in chain:
        if pinned and model != pinned:
            _emit("stage", text=f"{pinned} isn't answering after {MODEL_RETRIES} tries — "
                                f"falling back to {model} so the build still happens")
        _emit("stage", text=f"Calling {prov['label']} model {model}...")
        # trim to THIS model's context window — the fix for "dies after long use":
        # a small-context model deeper in the chain now gets a request sized for it.
        messages = trim_history(raw_messages, model)
        # pre-flight: if even the trimmed payload won't fit this model (e.g. system
        # prompt + current code alone exceeds a tiny 8k window), skip it instead of
        # sending a request we know will 400. A bigger model later in the chain may fit.
        if sum(_msg_len(m) for m in messages) > context_budget_chars(model):
            last = f"{model}: skipped (payload exceeds its context window)"
            context_hit = True
            continue
        t_call = time.time()
        try:
            headers = {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + key,
                "User-Agent": f"frida/{__version__}",
                "Accept": "application/json",
            }
            body = {"model": model, "temperature": temperature, "messages": messages}
            budget = STATE.get("thinking")
            if budget is not None and (pid, model, "thinking_budget") not in _UNSUPPORTED_FIELDS:
                # SiliconFlow's control for hybrid reasoning models. If a
                # gateway rejects it, the 400 handler below remembers that and
                # the next attempt goes without it.
                body["thinking_budget"] = int(budget)
            cap = max_tokens or MAX_TOKENS.get(tier)
            if cap and (pid, model, "max_tokens") not in _UNSUPPORTED_FIELDS:
                body["max_tokens"] = cap
            effort = REASONING_EFFORT.get(tier)
            if effort and (pid, model, "reasoning_effort") not in _UNSUPPORTED_FIELDS:
                body["reasoning_effort"] = effort
            try:
                data = _post(body)
            except urllib.error.HTTPError as he:
                # A gateway that doesn't know these fields answers 400. Remember
                # that and retry clean, rather than failing the whole request over
                # an optional parameter.
                det = _err_detail(he)
                dl = det.lower()
                dropped = False
                for field in ("reasoning_effort", "max_tokens"):
                    if field in body and (field in dl or "unsupported" in dl
                                          or "unknown" in dl or "unrecognized" in dl):
                        _UNSUPPORTED_FIELDS.add((pid, model, field))
                        body.pop(field, None)
                        dropped = True
                if not dropped:
                    raise
                data = _post(body)
            # Defensive unpacking. `data["choices"][0]["message"]["content"]` has
            # three ways to blow up or come back empty against a real gateway:
            # an empty choices list on a soft error, a null content, and reasoning
            # models that put everything in reasoning_content. All three used to
            # surface as a blank assistant turn or a cryptic KeyError.
            choices = data.get("choices") or []
            if not choices:
                last = f"{model}: the provider returned no choices"
                continue
            msg = choices[0].get("message") or {}
            finish = (choices[0].get("finish_reason") or "").lower()
            # `content` empty with a reasoning trace present means one of two very
            # different things, and treating them the same is how a build ends with
            # no code and no explanation:
            #   finish_reason=stop   -> this gateway simply files the answer under
            #                           reasoning_content. Use it.
            #   finish_reason=length -> the reasoning budget ate max_tokens before a
            #                           single line of code was written. That is a
            #                           FAILURE, not an answer. Say so; handing the
            #                           raw monologue back as the reply is what made
            #                           Frida respond with a wall of thinking and
            #                           no tool.
            reply = msg.get("content") or ""
            if not reply.strip() and finish != "length":
                reply = msg.get("reasoning_content") or ""
            if not reply.strip():
                if finish == "length":
                    last = (f"{model}: hit the {body.get('max_tokens') or 'output'}-token "
                            f"ceiling while reasoning and never wrote an answer")
                else:
                    last = f"{model}: the provider returned an empty reply"
                continue
            record_usage(pid, model, data.get("usage") or {},
                         est_in_chars=sum(len(m.get("content") or "") for m in messages),
                         est_out_chars=len(reply))
            # A model that declines the job is not a finished build. It used to be
            # treated as one: no code in the reply, so the follow-up helper spent
            # another call turning "I can't help with that" into tappable
            # "questions", and the user got a fake intake instead of a tool.
            # Models differ a lot on this — the next one in the chain will often
            # just build it — so move on rather than presenting a decline as work.
            if tier == "build" and _looks_like_refusal(reply):
                last = f"{model}: declined the request"
                _emit("stage", text=f"{model} declined this one — trying the next model")
                refusals.append((model, reply.strip()[:400]))
                continue
            LAST_MODEL[0] = model
            out = {"reply": reply, "model": model, "provider": pid,
                   "usage": data.get("usage") or {}}
            if finish == "length":
                # Cut off mid-answer. Downstream must not quietly treat half a
                # file as a finished build.
                out["truncated"] = True
            # a distinct reasoning trace (present on reasoning models when content
            # is also set) is worth showing the user — it's the "how it thinks"
            rc = msg.get("reasoning_content")
            if rc and rc.strip() and rc.strip() != reply.strip():
                out["reasoning"] = rc.strip()
            return out
        except urllib.error.HTTPError as e:
            detail = _err_detail(e)
            low = detail.lower()
            # --- the conversation got too big for this model's context window ---
            if (e.code in (400, 413) and any(s in low for s in (
                    "context", "token", "maximum context", "too long", "context_length",
                    "context length", "max_tokens", "reduce the length", "input is too long"))):
                context_hit = True
                last = f"{model}: context-window limit"
                continue   # a smaller-context sibling won't help, but try in case limits differ
            if e.code == 403 and "1010" in detail:
                return {"error": f"Blocked by Cloudflare (403/1010) before reaching "
                                 f"{prov['label']}. Usually a VPN/proxy or outdated client, not your key."}
            if e.code == 401:
                # For a multi-host provider (SiliconFlow .com/.cn), a 401 may just mean
                # we're hitting the wrong regional host for this key. Discover the right
                # one and retry this same request once.
                if pid in HOST_ALIASES and not _retried_host[0]:
                    _retried_host[0] = True
                    probe = fetch_models(pid, force=True)
                    if probe.get("source") == "live" and _HOST_OK.get(pid):
                        new_url = None
                        for cu, _mu in _provider_urls(pid):
                            new_url = cu; break
                        if new_url and new_url != chat_url:
                            chat_url = new_url
                            # retry the very same model against the correct host.
                            # Reuse the SAME body — rebuilding it from scratch dropped
                            # max_tokens and reasoning_effort, so the one request that
                            # went through on the fallback host was uncapped and its
                            # spend never reached the usage counter.
                            try:
                                data = _post(body)
                                reply, finish = _unpack_reply(data)
                                if not reply.strip():
                                    last = f"{model}: empty reply from {_HOST_OK[pid]}"
                                    continue
                                record_usage(pid, model, data.get("usage") or {})
                                LAST_MODEL[0] = model
                                out = {"reply": reply, "model": model, "provider": pid,
                                       "usage": data.get("usage") or {}}
                                if finish == "length":
                                    out["truncated"] = True
                                return out
                            except Exception as e2:
                                last = f"{model}: retry on {_HOST_OK[pid]} failed: {e2}"
                                continue
                return {"error": f"{prov['label']} rejected the key (401). Check it in Settings — "
                                 f"and confirm you're using a {prov['label']} key, not another provider's."
                                 + (" For SiliconFlow, the key must be from the same site as the "
                                    "endpoint (cloud.siliconflow.com \u2194 api.siliconflow.com)."
                                    if pid == "siliconflow" else "")}
            if e.code == 429:
                # Rate-limited. Trying another MODEL on the same provider won't help
                # (shared quota), but the whole point of FALLBACK_PROVIDERS is that a
                # quota stop shouldn't dead-end the build — so break out of this
                # provider's chain and let _try_fallback() reach Groq below. Returning
                # here (as it used to) skipped the fallback entirely, which is why a
                # 429 hard-failed despite the "trying next..." message above.
                _emit("stage", text=f"{prov['label']} rate-limited this request (429) — trying next...")
                last = (f"{prov['label']} rate-limited this request (429): "
                        f"{detail or 'slow down or check your quota'}.")
                break
            if e.code in (404, 400):
                # this specific model name isn't callable with your key — try the next
                last = f"{model}: HTTP {e.code} (this model isn't available to your {prov['label']} key)"
                continue
            last = f"{model}: HTTP {e.code} {detail}"
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            # Transient transport error — worth another go on the SAME model, but
            # only when it failed FAST. Blindly retrying used to be free-ish against
            # a 45s cap; now that a build call may legitimately run for minutes, an
            # automatic re-send of a request the provider was still working on costs
            # the user another full generation in both time and money. So: retry a
            # connection that died quickly (dead host, reset, DNS), never one that
            # burned its whole idle/total budget.
            spent = time.time() - t_call
            timed_out = isinstance(e, TimeoutError) or isinstance(
                getattr(e, "reason", None), (TimeoutError, socket.timeout))
            last = f"{model}: {e}" + (f" after {int(spent)}s" if timed_out else "")
            if timed_out:
                _emit("stage", text=f"{model} stopped responding after {int(spent)}s "
                                    f"(no data for {MODEL_IDLE_TIMEOUT}s) — moving on")
            else:
                _emit("stage", text=f"{model} unreachable ({e}) — retrying...")
            # No ad-hoc retry loop here any more: _post() already backed this
            # request off and re-sent it up to MODEL_RETRIES times before the
            # exception reached us. Retrying again on top of that just doubled
            # the spend on a provider that is genuinely down.
        except Exception as e:
            last = f"{model}: {e}"

    def _try_fallback(reason):
        # raw_messages, NOT `messages`: the loop above rebinds `messages` to the
        # payload trimmed for whichever model failed last, so handing that to another
        # provider silently sent it a conversation cut down for someone else's context
        # window. The fallback re-trims for its own models.
        if _fallback_chain:
            nxt_pid, rest = _fallback_chain[0], _fallback_chain[1:]
            alt = call_model(raw_messages, nxt_pid, temperature, _fallback_chain=rest,
                             tier=tier, max_tokens=max_tokens)
            if not alt.get("error"):
                alt["fellback_from"] = pid
                return alt
        return None

    if context_hit:
        return {"error": "context_overflow",
                "detail": "Your current tool plus the build conversation is too large for the "
                          "available model(s). Frida already collapses old code revisions and "
                          "trims old turns automatically, so this means the tool itself is now very "
                          "big. Two fixes: pick a larger-context model in Settings (Gemini and the "
                          "70B/120B models have huge windows), or hit ＋ new tool to start fresh — "
                          "your saved work in the library is untouched. You can also save the current "
                          "tool to the library first, then reopen it in a clean session to keep going."}
    alt = _try_fallback(last)
    if alt:
        return alt
    if refusals:
        # Don't dress a decline up as a technical fault, and don't dress it up as
        # the model asking a question either (which is what happened before —
        # a no-code reply went to the follow-up helper and came back as fake
        # tappable options). Show what it said and let the user judge.
        who = ", ".join(m for m, _ in refusals)
        return {"error": "declined",
                "detail": (f"The model declined this one ({who}). That's the provider's "
                           f"model making its own call — Frida passed the request "
                           f"straight through and has no setting that overrides it. "
                           f"Different providers answer differently, so switching "
                           f"provider in Settings is worth a try.\n\nWhat it said:\n\n"
                           + refusals[0][1])}
    return {"error": _chain_error(prov["label"], last)}

def _chain_error(label, last):
    """Say what actually went wrong, and give advice that matches it.

    Every failure used to end with the same sentence: "Try Settings → refresh
    models, or pick a different model/provider." For a 502 that is simply the
    wrong advice — nothing about the model list is broken, the gateway had a bad
    second — and it sent people into Settings to fiddle with a configuration that
    was working fine. Refreshing the catalog is now suggested only when the
    failure really is about the catalog.
    """
    low = (last or "").lower()
    if "401" in low or "rejected the key" in low:
        fix = f"Check the {label} key in Settings."
    elif "429" in low or "rate-limit" in low or "quota" in low:
        fix = (f"{label} is rate-limiting this key. Give it a moment and send again, or "
               f"add a second provider key in Settings — builds fall through to it "
               f"automatically when the first one is throttled.")
    elif any(c in low for c in ("500", "502", "503", "504", "520", "522", "524", "529")):
        fix = (f"{label} is having a bad moment — that's their end, not your setup. "
               f"Frida already retried {MODEL_RETRIES} times with backoff and tried "
               f"every other model on the account. Send it again shortly, or add a "
               f"second provider key so it can route around an outage by itself.")
    elif "timed out" in low or "stopped responding" in low:
        fix = (f"The model went quiet for {MODEL_IDLE_TIMEOUT}s mid-answer. If it's slow "
               f"rather than stuck, give it more room: FRIDA_IDLE_TIMEOUT=180. "
               f"FRIDA_REASONING=medium also makes build calls answer a lot faster.")
    elif any(c in low for c in ("unreachable", "connection", "dropped", "resolve", "network")):
        fix = "Nothing reached the provider — check the network."
    elif "not available" in low or "404" in low or "no such model" in low:
        fix = ("That model isn't callable with this key. Settings → ↻ refresh models "
               "pulls the list your key can actually use.")
    elif "empty reply" in low:
        fix = (f"{label} kept returning an empty response — usually transient on their "
               f"side. Try again, or pick a different model in Settings.")
    elif "context" in low or "too large" in low:
        fix = ("The conversation outgrew the model's window. Hit ＋ new tool, or pick a "
               "larger-context model in Settings.")
    else:
        fix = ("Try again. If it keeps happening, pick a different model or provider in "
               "Settings.")
    return f"{label} couldn't finish this build.\n\nLast error: {last}\n\n{fix}"

_FENCE = re.compile(r"^([ \t]*)(`{3,})[ \t]*([A-Za-z0-9_+.-]*)[ \t]*$", re.M)

def _code_spans(reply):
    """Every fenced block in a reply, as (lang, body_start, body_end, ticks).

    Fence length is respected: a ```` fence is NOT closed by a ``` line. That is
    what lets Frida emit code containing markdown fences safely.
    """
    marks = [(m.start(), m.end(), len(m.group(2)), (m.group(3) or "").lower())
             for m in _FENCE.finditer(reply or "")]
    spans, i = [], 0
    while i < len(marks):
        start, end, ticks, lang = marks[i]
        closers = [j for j in range(i + 1, len(marks))
                   if marks[j][2] >= ticks and not marks[j][3]]
        if closers:
            spans.append((lang, end + 1, marks[closers[0]][0], ticks, closers))
            i = closers[0] + 1
        else:
            spans.append((lang, end + 1, len(reply), ticks, []))
            break
    return spans

def split_fences(reply):
    """Split a reply into [("prose", text) | ("code", lang, body)] segments.

    Uses the same fence-length-aware scan as extract_code, so a tool whose own
    source contains a markdown fence — `line.startswith("```")`, a --help string
    with a fenced example — no longer ends the block early. The naive
    ```...``` regex closed on that INNER fence and handed everything after it
    back as prose, which is how a whole 200-line tool ended up wrapped and
    un-indented in the chat.
    """
    reply = reply or ""
    marks = list(_FENCE.finditer(reply))
    segs, i, cursor = [], 0, 0
    while i < len(marks):
        opener = marks[i]
        ticks, lang = len(opener.group(2)), (opener.group(3) or "").lower()
        closer = None
        for j in range(i + 1, len(marks)):
            if len(marks[j].group(2)) >= ticks and not marks[j].group(3):
                closer = marks[j]
                i = j + 1
                break
        if closer is None:
            body_end, next_cursor, i = len(reply), len(reply), len(marks)
        else:
            body_end, next_cursor = closer.start(), closer.end()
        before = reply[cursor:opener.start()]
        if before.strip():
            segs.append(("prose", before))
        segs.append(("code", lang, reply[opener.end() + 1:body_end]))
        cursor = next_cursor
    tail = reply[cursor:]
    if tail.strip():
        segs.append(("prose", tail))
    return segs


def strip_code_blocks(reply, placeholder=""):
    """The reply with every fenced block removed or replaced."""
    parts = []
    for seg in split_fences(reply):
        parts.append(seg[1] if seg[0] == "prose" else placeholder)
    text = "".join(parts)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def _parses(text):
    import ast
    try:
        ast.parse(text)
        return True
    except Exception:
        return False

def extract_code(reply):
    """Pull the python code block out of a model reply (tagged, else any fence).

    The hard case, and one that used to silently wreck real tools: the code
    itself contains a markdown fence — a --help string with a fenced usage
    example, a tool that prints markdown. A non-greedy `.*?` stopped at that
    INNER fence and handed back a truncated file, which then failed the smoke
    test with a syntax error the model never made and burned every autotest fix
    round trying to repair code that was fine when it left the model.

    So when a block doesn't parse as Python, try the later closing fences too and
    take the widest span that does. Falls back to the old behaviour if nothing
    parses, so a genuinely broken reply still reaches the analyzer as before.
    """
    reply = reply or ""
    marks = [(m.start(), m.end(), len(m.group(2)), (m.group(3) or "").lower())
             for m in _FENCE.finditer(reply)]
    spans = _code_spans(reply)
    if not spans:
        return None
    chosen = None
    for sp in spans:
        if sp[0] in ("python", "py"):
            chosen = sp
            break
    chosen = chosen or spans[0]
    lang, bstart, bend, ticks, closers = chosen
    body = reply[bstart:bend]
    if _parses(body) or not closers:
        return body.rstrip() or None
    # the first closer truncated it — widen to the furthest fence that parses
    for j in reversed(closers):
        wider = reply[bstart:marks[j][0]]
        if _parses(wider):
            return wider.rstrip() or None
    return body.rstrip() or None

def fenced(code, lang="python"):
    """Wrap code in a fence long enough that the code can't close it early.

    Six prompts hardcoded ```python around the tool. A tool whose source contains
    a markdown fence — a --help string with a usage example — closed the fence
    mid-file, so the MODEL received a truncated program and 'fixed' problems that
    were really just the cut. Same root cause as the extraction bug, on the way in
    instead of the way out.
    """
    f = fence_for(code)
    return f"{f}{lang}\n{code}\n{f}"

def fence_for(code):
    """A fence long enough that `code` cannot close it from the inside."""
    longest = max((len(r) for r in re.findall(r"`+", code or "")), default=0)
    return "`" * max(3, longest + 1)

def replace_first_code_block(reply, new_code):
    """Swap the body of the code block extract_code would read, preserving the
    surrounding prose. Returns the rewritten reply, or the original if there is
    no fenced block."""
    old = extract_code(reply)
    if old is None:
        return reply
    idx = reply.find(old)
    if idx < 0:
        return reply
    return reply[:idx] + new_code.rstrip() + reply[idx + len(old):]

# --------------------------------------------------------------------------
# WHOLE-CODE ANALYSIS  -- catch clashes the model can't see in its own output
# --------------------------------------------------------------------------
# A model checking its OWN code shares its own blind spots ("correlated error
# modes"), so it can convince itself broken code is fine. An INDEPENDENT analyzer
# breaks that: it reads the file as a whole and flags real problems — undefined
# names, calls with the wrong number of arguments, unused variables, redefinitions,
# unreachable code — BEFORE the tool is ever run. Uses Ruff if it's installed
# (faster, deeper); otherwise falls back to a built-in ast pass so Frida stays
# zero-dependency and "just works".

_RUFF_PATH = []

_ANALYSIS_CACHE = {}

_ANALYSIS_LOCK = threading.Lock()

def _ruff_path():
    """Resolve ruff once. This is called on every analysis and every autofix, and
    shutil.which() walks the whole PATH each time."""
    if not _RUFF_PATH:
        _RUFF_PATH.append(shutil.which("ruff") or "")
    return _RUFF_PATH[0] or None

def _cached(kind, code, produce):
    """Memoise an expensive whole-file pass on (kind, source hash).

    One build turn runs ruff over identical bytes three times — autofix checks,
    autofix applies, then the smoke test analyses. Each is a process spawn.
    """
    key = (kind, _code_key(code))
    with _ANALYSIS_LOCK:
        if key in _ANALYSIS_CACHE:
            return _ANALYSIS_CACHE[key]
    val = produce()
    with _ANALYSIS_LOCK:
        if len(_ANALYSIS_CACHE) > 64:
            _ANALYSIS_CACHE.clear()
        _ANALYSIS_CACHE[key] = val
    return val

def analyze_with_ruff(code):
    """Run Ruff's correctness lints (the F/E9 families: undefined names, bad calls,
    unused vars, syntax) and return a list of issue strings. None if Ruff absent."""
    return _cached("ruff", code, lambda: _analyze_with_ruff_uncached(code))

def _analyze_with_ruff_uncached(code):
    ruff = _ruff_path()
    if not ruff:
        return None
    fd, path = tempfile.mkstemp(prefix="frida_ruff_", suffix=".py")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(code)
        # F = pyflakes (undefined names, unused imports/vars, redefinitions, f-string bugs)
        # E9 = syntax/runtime-ish errors. We deliberately skip pure-style rules.
        proc = subprocess.run(
            [ruff, "check", "--select", "F,E9", "--output-format", "json", "--no-cache", path],
            capture_output=True, text=True, timeout=20)
        try:
            items = json.loads(proc.stdout or "[]")
        except Exception:
            return None
        out = []
        for it in items:
            loc = it.get("location") or {}
            ln = loc.get("row")
            code_id = it.get("code") or ""
            msg = it.get("message") or ""
            out.append(f"L{ln} {code_id}: {msg}" if ln else f"{code_id}: {msg}")
        return out
    except Exception:
        return None
    finally:
        try: os.unlink(path)
        except Exception: pass

def autofix_with_ruff(code):
    return _cached("autofix", code, lambda: _autofix_with_ruff_uncached(code))

def _autofix_with_ruff_uncached(code):
    """The 'lint-and-fix' loop every serious AI coding tool runs (aider, etc.):
    if Ruff is present, silently apply its SAFE auto-fixes to generated code before
    the user ever sees it. Only fixes that cannot change behaviour are applied —
    things like a stray unused variable or a redundant f-string prefix — so the
    model never burns a whole fix-round on trivial mechanical cleanup. Import
    removal (F401) and redefinition rewrites (F811) are deliberately EXCLUDED, as
    those can touch import side-effects or intent. Returns (code, [rule_ids fixed]);
    a no-op returning the code unchanged when Ruff is absent or nothing is fixable."""
    ruff = _ruff_path()
    if not ruff:
        return code, []
    fd, path = tempfile.mkstemp(prefix="frida_fix_", suffix=".py")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(code)
        sel = ["--select", "F,E9", "--ignore", "F401,F811", "--no-cache"]
        before = subprocess.run([ruff, "check", *sel, "--output-format", "json", path],
                                capture_output=True, text=True, timeout=20)
        try:
            items = json.loads(before.stdout or "[]")
        except Exception:
            items = []
        fixable = sorted({it.get("code") for it in items
                          if (it.get("fix") or {}).get("applicability") == "safe" and it.get("code")})
        if not fixable:
            return code, []
        subprocess.run([ruff, "check", *sel, "--fix", path], capture_output=True, text=True, timeout=20)
        with open(path, encoding="utf-8", errors="replace") as f:
            fixed = f.read().rstrip()
        # only accept the fix if it still parses (paranoia — ruff safe fixes always do)
        try:
            import ast as _ast; _ast.parse(fixed)
        except SyntaxError:
            return code, []
        return (fixed or code), fixable
    except Exception:
        return code, []
    finally:
        try: os.unlink(path)
        except Exception: pass

def analyze_with_ast(code):
    """Built-in, zero-dependency fallback analyzer. Walks the AST to catch the
    highest-value clashes a model can't see in its own output:
      - use of a name that is bound NOWHERE in the file (typo / hallucinated name)
      - calls to a top-level function with the wrong number of positional args
      - calls to a class's OWN method (self.method(...)) with the wrong arity
      - local variables assigned a side-effect-free value but never used
    Precision over recall: it deliberately over-collects 'bound names' (scope-
    insensitively) so it will essentially never flag a name that is legitimately
    defined somewhere — at the cost of missing a few real bugs. Staying silent on
    correct code matters more here than catching everything, because a false alarm
    makes the model 'fix' code that was already right."""
    import ast, builtins
    issues = []
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return [f"L{e.lineno} syntax: {e.msg}"]

    # ---- collect EVERY name bound anywhere in the module (scope-insensitive) ----
    # If the file does `from x import *` we can't know what it pulls in, so the
    # undefined-name check is skipped entirely rather than risk false positives.
    star_import = False
    bound = set()       # every name assigned / defined / imported / used as a param

    def _bind_target(t):
        # record names bound by an assignment/loop/with target (incl. tuple unpacking)
        if isinstance(t, ast.Name):
            bound.add(t.id)
        elif isinstance(t, (ast.Tuple, ast.List)):
            for e in t.elts:
                _bind_target(e)
        elif isinstance(t, ast.Starred):
            _bind_target(t.value)
        # attribute/subscript targets (self.x = …, d[k] = …) bind no bare name

    def _bind_args(a):
        for grp in (getattr(a, "posonlyargs", []), a.args, a.kwonlyargs):
            for arg in grp:
                bound.add(arg.arg)
        if a.vararg: bound.add(a.vararg.arg)
        if a.kwarg:  bound.add(a.kwarg.arg)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                bound.add((a.asname or a.name).split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                if a.name == "*":
                    star_import = True
                else:
                    bound.add(a.asname or a.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            bound.add(node.name); _bind_args(node.args)
        elif isinstance(node, ast.Lambda):
            _bind_args(node.args)
        elif isinstance(node, ast.ClassDef):
            bound.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                _bind_target(t)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            _bind_target(node.target)
        elif isinstance(node, ast.NamedExpr):                 # walrus  (x := …)
            _bind_target(node.target)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            _bind_target(node.target)
        elif isinstance(node, ast.comprehension):
            _bind_target(node.target)
        elif isinstance(node, ast.withitem):
            if node.optional_vars is not None:
                _bind_target(node.optional_vars)
        elif isinstance(node, ast.ExceptHandler):
            if node.name:
                bound.add(node.name)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for n in node.names:
                bound.add(n)
        elif node.__class__.__name__ in ("MatchAs", "MatchStar") and getattr(node, "name", None):
            bound.add(node.name)                              # match … as name (3.10+)

    builtin_names = set(dir(builtins)) | {
        "__name__", "__file__", "__doc__", "__builtins__", "__spec__", "__class__",
        "__loader__", "__package__", "__path__", "self", "cls",
    }
    allowed = bound | builtin_names

    # ---- undefined names: a Load-context bare name bound NOWHERE and not built-in ----
    if not star_import:
        seen_undef = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                nm = node.id
                if nm not in allowed and nm not in seen_undef:
                    seen_undef.add(nm)
                    issues.append(f"L{node.lineno} undefined: name '{nm}' is used but never "
                                  f"defined, imported, or built-in (typo or missing definition?)")

    # ---- arity helpers ----
    def _sig(fnnode, drop_first=False):
        a = fnnode.args
        posonly = getattr(a, "posonlyargs", [])
        pos = len(posonly) + len(a.args) - (1 if drop_first else 0)
        ndef = len(a.defaults)
        has_var = a.vararg is not None or a.kwarg is not None or bool(a.kwonlyargs)
        return (max(0, pos - ndef), None if has_var else max(0, pos))

    def _check_call(label, mn, mx, callnode):
        # skip calls using *args/**kwargs — too dynamic to judge
        if any(isinstance(a, ast.Starred) for a in callnode.args) or \
           any(k.arg is None for k in callnode.keywords):
            return
        nargs = len(callnode.args) + len(callnode.keywords)
        ln = getattr(callnode, "lineno", "?")
        if mx is not None and nargs > mx:
            issues.append(f"L{ln} call: {label}() called with {nargs} args but takes at most {mx}")
        elif nargs < mn:
            issues.append(f"L{ln} call: {label}() called with {nargs} args but needs at least {mn}")

    # --- arity: direct calls to an UNDECORATED top-level function by bare name ---
    # (a decorator can change a function's effective signature, so we skip those.)
    func_sigs = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.decorator_list:
            func_sigs[node.name] = _sig(node)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in func_sigs:
            mn, mx = func_sigs[node.func.id]
            _check_call(node.func.id, mn, mx, node)

    # --- arity: self.method(...) calls vs methods defined in the SAME class ---
    # We know the real signature regardless of base classes, so this is safe even
    # for a tool that subclasses argparse.Action or threading.Thread. Decorated
    # methods (static/class/property/custom) are skipped — their call shape differs.
    for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
        methods = {}
        for b in cls.body:
            if isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef)) and not b.decorator_list:
                methods[b.name] = _sig(b, drop_first=True)
        for node in ast.walk(cls):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "self"
                    and node.func.attr in methods):
                mn, mx = methods[node.func.attr]
                _check_call("self." + node.func.attr, mn, mx, node)

    # --- unused local variables (per-function, conservative) ---
    # GUI code constantly assigns the result of a call for its side effects
    # (building a widget, wiring a signal), so flagging those produces noise. We
    # ONLY flag a variable that is unused AND was assigned a plain literal/name
    # (a value with no side effect) — that's far more likely to be a real mistake.
    # SCOPING MATTERS HERE. A plain ast.walk() descends into nested class and
    # function bodies, which made `class App(QWidget): CSS = ...` look like an
    # unused local of the enclosing function. Class attributes are API, not dead
    # locals — and since almost every generated GUI tool declares them, that false
    # positive would have burned a fix round on nearly every build.
    #
    # So: collect ASSIGNMENTS from this function's own scope only, but collect
    # USES from everywhere inside it, because a nested function may close over an
    # outer local and that absolutely counts as using it.
    def _own_scope(node):
        """Nodes belonging to this function's scope, not to a nested one."""
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef,
                                  ast.ClassDef, ast.Lambda)):
                continue                     # a scope of its own — skip its body
            yield child
            yield from _own_scope(child)

    class UnusedVisitor(ast.NodeVisitor):
        def visit_FunctionDef(self, fn):
            assigned, used, simple = {}, set(), set()
            for n in _own_scope(fn):
                if isinstance(n, ast.Assign):
                    # is the RHS side-effect-free? (literal, name, tuple/list of those)
                    rhs = n.value
                    is_simple = isinstance(rhs, (ast.Constant, ast.Name, ast.Tuple,
                                                 ast.List, ast.Dict, ast.Set))
                    for t in n.targets:
                        if isinstance(t, ast.Name):
                            assigned.setdefault(t.id, t.lineno)
                            if is_simple:
                                simple.add(t.id)
            # uses come from the WHOLE subtree, closures included
            for n in ast.walk(fn):
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                    used.add(n.id)
                elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name):
                    used.add(n.target.id)
                elif isinstance(n, ast.Nonlocal):
                    used.update(n.names)
                elif isinstance(n, ast.Global):
                    used.update(n.names)
            for name, ln in assigned.items():
                if name == "_" or name.startswith("_"):
                    continue
                if name not in used and name in simple:
                    issues.append(f"L{ln} unused: local variable '{name}' assigned but never used")
            self.generic_visit(fn)

        visit_AsyncFunctionDef = visit_FunctionDef

    UnusedVisitor().visit(tree)

    # --- self.<attr> read but never assigned anywhere in the SAME class ---
    # Runs as a shared helper so it also supplements Ruff (which doesn't catch this).
    if not star_import:
        issues.extend(_unassigned_self_attrs(tree))
    # --- high-confidence quality findings (silent except: pass, shell injection) ---
    issues.extend(_extra_safety_findings(tree) + _signature_findings(tree))
    issues = _dedupe_issues(issues)

    # de-dup and cap so we never flood the model
    seen, uniq = set(), []
    for i in issues:
        if i not in seen:
            seen.add(i); uniq.append(i)
    return uniq[:25]

def _unassigned_self_attrs(tree):
    """The #1 runtime crash the import-safe smoke test can NEVER catch: a callback or
    thread reads self.something that no method ever set, so the window opens fine and
    then throws AttributeError the moment the user clicks. Flag only the high-confidence
    case; bail out of a class entirely if it does anything dynamic (setattr/getattr,
    __getattr__/__setattr__) that could create attributes we can't see statically.
    Returns a list of issue strings (possibly empty). Caller handles de-dup."""
    import ast
    out = []
    for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
        # CRITICAL false-positive guard: a class that subclasses anything (QMainWindow,
        # tk.Frame, QWidget, a project base class, etc.) inherits attributes and methods
        # we cannot see — self.setWindowTitle, self.pack, self.master are all legitimate
        # there. Flagging them would make the model "fix" correct code, the worst outcome.
        # So we ONLY analyze classes with no bases, or whose only base is `object`. That
        # covers plain controller/state classes while staying silent on every widget
        # subclass. (Decorators or keyword bases like metaclass= also mean: skip.)
        bases_ok = all(isinstance(b, ast.Name) and b.id == "object" for b in cls.bases)
        if cls.bases and not bases_ok:
            continue
        if getattr(cls, "keywords", None) or cls.decorator_list:
            continue
        assigned_attrs, read_attrs = set(), {}
        dynamic = False
        # an augmented assignment (self.x += 1) READS self.x before writing it, so a
        # name that ONLY ever appears as an augassign target was never truly initialized.
        # Collect those targets so a typo'd `self.valeu += 1` is caught.
        augained = {}
        for n in ast.walk(cls):
            if (isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Attribute)
                    and isinstance(n.target.value, ast.Name) and n.target.value.id == "self"):
                augained.setdefault(n.target.attr, n.target.lineno)
        for n in ast.walk(cls):
            if (isinstance(n, ast.Attribute)
                    and isinstance(n.value, ast.Name) and n.value.id == "self"):
                if isinstance(n.ctx, (ast.Store, ast.Del)):
                    assigned_attrs.add(n.attr)
                elif isinstance(n.ctx, ast.Load):
                    read_attrs.setdefault(n.attr, n.lineno)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) \
                    and n.func.id in ("setattr", "getattr", "vars"):
                dynamic = True
        # an attr whose ONLY assignment is an augmented one (self.x += …) was never
        # initialized: treat it as a read of an unassigned attr, not an assignment.
        for attr, ln in augained.items():
            assigned_attrs.discard(attr)
            read_attrs.setdefault(attr, ln)
        if any(m for m in cls.body
               if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
               and m.name in ("__getattr__", "__setattr__", "__getattribute__")):
            dynamic = True
        if dynamic:
            continue
        for m in cls.body:
            if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                assigned_attrs.add(m.name)
            # Class-level attributes are real attributes reachable through self:
            #   class C:
            #       count = 0            # -> self.count is defined
            #       label: str = "x"     # annotated with a value, likewise
            # Missing these produced a false "self.count read but never assigned",
            # which made the model rewrite correct code. Count a bare annotation
            # (label: str) too — it's a declared slot the class intends to carry.
            elif isinstance(m, ast.Assign):
                for t in m.targets:
                    if isinstance(t, ast.Name):
                        assigned_attrs.add(t.id)
                    elif isinstance(t, (ast.Tuple, ast.List)):
                        for e in t.elts:
                            if isinstance(e, ast.Name):
                                assigned_attrs.add(e.id)
            elif isinstance(m, ast.AnnAssign) and isinstance(m.target, ast.Name):
                assigned_attrs.add(m.target.id)
        assigned_attrs |= {"__class__", "__dict__", "__doc__", "__module__"}
        for attr, ln in read_attrs.items():
            if attr not in assigned_attrs:
                out.append(f"L{ln} attribute: self.{attr} is read but never assigned in "
                           f"class '{cls.name}' (AttributeError at runtime — set it in "
                           f"__init__, or fix the name)")
    return out

def _dedupe_issues(issues):
    """Collapse findings that describe the same defect twice.

    The ast clash pass and the signature pass both catch wrong-arity calls, from
    different angles, and both are worth keeping in general — but reporting one bug
    twice wastes tokens on every fix round and reads as noise. Two findings about
    the same function on the same line are the same finding.
    """
    import re
    seen, out = set(), []
    for msg in issues:
        m = re.match(r"L(\d+)\s+([a-z-]+):", msg or "")
        if not m:
            key = ("raw", (msg or "").strip())
        else:
            line, kind = m.group(1), m.group(2)
            fn = re.search(r"((?:self\.)?[A-Za-z_][\w.]*)\(\)", msg)
            # arity complaints share one bucket regardless of which pass found them
            family = "arity" if kind in ("call", "bad-call") else kind
            key = (line, family, fn.group(1) if fn else "")
        if key in seen:
            continue
        seen.add(key)
        out.append(msg)
    return out

def _signature_findings(tree):
    """Catch the mistakes language models actually make, locally and for free.

    Calling a function with the wrong number of arguments is the single most common
    way generated code dies at runtime — it parses, it imports, and it blows up the
    moment that line executes. Every one of these caught here is a paid round-trip
    to the model that never has to happen, which is why this pass is worth its
    strictness budget.

    Deliberately conservative. We skip anything whose signature we can't pin down
    exactly — decorated functions, *args/**kwargs, names that get reassigned — so a
    finding here is a real bug, not a guess. A false positive costs a wasted fix
    round, which is exactly what this is meant to prevent.
    """
    import ast
    out = []

    def sig_of(fn, drop_self=False):
        a = fn.args
        if a.vararg or a.kwarg or getattr(a, "posonlyargs", None):
            return None                       # variadic: any arity is legal
        if fn.decorator_list:
            return None                       # a decorator may rewrite the signature
        pos = list(a.args)
        if drop_self and pos:
            pos = pos[1:]
        names = [p.arg for p in pos]
        ndef = len(a.defaults)
        required = len(names) - ndef
        kwonly = [k.arg for k in a.kwonlyargs]
        kwdefaults = sum(1 for d in a.kw_defaults if d is not None)
        kwrequired = len(kwonly) - kwdefaults
        return {"names": names, "required": required, "max": len(names),
                "kwonly": kwonly, "kwrequired": kwrequired}

    # ---- collect definitions -------------------------------------------------
    module_fns, methods, classes = {}, {}, {}
    reassigned = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            for t in ([n.targets] if isinstance(n, ast.Assign) else [[n.target]]):
                for tt in t:
                    if isinstance(tt, ast.Name):
                        reassigned.add(tt.id)
    for n in tree.body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            sg = sig_of(n)
            if sg:
                module_fns[n.name] = sg
        elif isinstance(n, ast.ClassDef):
            classes[n.name] = n
            for b in n.body:
                if isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    sg = sig_of(b, drop_self=True)
                    if sg:
                        methods.setdefault(n.name, {})[b.name] = sg

    def check(callnode, sg, label):
        npos = sum(1 for x in callnode.args if not isinstance(x, ast.Starred))
        if any(isinstance(x, ast.Starred) for x in callnode.args):
            return
        if any(k.arg is None for k in callnode.keywords):        # **kwargs at call site
            return
        kwnames = [k.arg for k in callnode.keywords]
        ln = getattr(callnode, "lineno", "?")
        if npos > sg["max"] and not sg["kwonly"]:
            out.append(f"L{ln} bad-call: {label} takes at most {sg['max']} positional "
                       f"argument(s) but is called with {npos}")
            return
        supplied = set(sg["names"][:npos]) | set(kwnames)
        missing = [nm for nm in sg["names"][:sg["required"]] if nm not in supplied]
        if missing:
            out.append(f"L{ln} bad-call: {label} is missing required argument(s): "
                       f"{', '.join(missing)}")
            return
        unknown = [k for k in kwnames if k not in sg["names"] and k not in sg["kwonly"]]
        if unknown:
            out.append(f"L{ln} bad-call: {label} has no parameter(s) named "
                       f"{', '.join(unknown)}")
            return
        missing_kw = [k for k in sg["kwonly"][:sg["kwrequired"]] if k not in kwnames]
        if missing_kw:
            out.append(f"L{ln} bad-call: {label} is missing required keyword argument(s): "
                       f"{', '.join(missing_kw)}")

    # ---- check call sites ----------------------------------------------------
    # map each method body back to its class so `self.x()` resolves correctly
    owner = {}
    for cname, cnode in classes.items():
        for b in ast.walk(cnode):
            owner[id(b)] = cname

    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        if isinstance(f, ast.Name) and f.id in module_fns and f.id not in reassigned:
            check(n, module_fns[f.id], f"{f.id}()")
        elif (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name)
              and f.value.id == "self"):
            cname = owner.get(id(n))
            sg = (methods.get(cname) or {}).get(f.attr) if cname else None
            if sg:
                check(n, sg, f"self.{f.attr}()")

    # ---- mutable default arguments ------------------------------------------
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for d in list(n.args.defaults) + [x for x in n.args.kw_defaults if x]:
                if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                    ln = getattr(d, "lineno", "?")
                    out.append(f"L{ln} mutable-default: {n.name}() has a mutable default "
                               f"argument — it is created once and shared between calls "
                               f"(use None and build it inside the function)")
                    break
    return out

def _extra_safety_findings(tree):
    """A small set of HIGH-CONFIDENCE quality findings the system prompt explicitly
    forbids, so the model can clean them up. Engine-independent (used by both the Ruff
    and the ast paths). Kept deliberately narrow to avoid flagging correct code:

      1. SILENT FAILURE: a bare `except:` or a broad `except Exception/BaseException:`
         whose body does nothing but `pass` (or `...`). That swallows every error with
         no message — exactly the "it silently did nothing" bug the standards prohibit.
      2. SHELL INJECTION: `subprocess.run/Popen/call/check_output/check_call(..., shell=True)`
         where the command is NOT a constant string (a variable/f-string/concatenation),
         or any `os.system(...)` / `os.popen(...)` with a non-constant argument. Both run
         a string through the shell, so a built-from-input command is an injection risk —
         the standards require a list argv instead.
    Returns a list of issue strings (possibly empty). Caller de-dups."""
    import ast
    out = []
    SHELL_FUNCS = {"run", "Popen", "call", "check_output", "check_call"}
    for n in ast.walk(tree):
        # --- 1. silent except: pass ---
        if isinstance(n, ast.ExceptHandler):
            # drop a docstring-only line, and treat a bare `...` exactly like `pass`
            # (the docstring always claimed it did; it didn't)
            body = [s for s in n.body if not (isinstance(s, ast.Expr)
                    and isinstance(getattr(s, "value", None), ast.Constant)
                    and isinstance(s.value.value, (str, type(Ellipsis))))]
            only_pass = all(isinstance(s, ast.Pass) for s in body) and len(body) > 0
            if not body:  # body was just a string/ellipsis expression
                only_pass = True
            etype = n.type
            broad = (etype is None
                     or (isinstance(etype, ast.Name) and etype.id in ("Exception", "BaseException")))
            if only_pass and broad:
                ln = getattr(n, "lineno", "?")
                out.append(f"L{ln} silent-failure: a broad 'except: pass' swallows every error "
                           f"with no message (forbidden — surface the failure in the window, or "
                           f"narrow the except and handle it)")
        # --- 2. shell injection ---
        if isinstance(n, ast.Call):
            f = n.func
            # subprocess.<func>(..., shell=True, ...) with non-constant command
            is_subprocess = (isinstance(f, ast.Attribute) and f.attr in SHELL_FUNCS
                             and isinstance(f.value, ast.Name) and f.value.id == "subprocess")
            if is_subprocess:
                shell_true = any(k.arg == "shell" and isinstance(k.value, ast.Constant)
                                 and k.value.value is True for k in n.keywords)
                cmd = n.args[0] if n.args else None
                cmd_const = isinstance(cmd, ast.Constant)
                if shell_true and cmd is not None and not cmd_const:
                    ln = getattr(n, "lineno", "?")
                    out.append(f"L{ln} shell-injection: subprocess.{f.attr}(..., shell=True) with a "
                               f"built command runs it through the shell (injection risk — pass a "
                               f"list argv and drop shell=True)")
            # os.system(x) / os.popen(x) with a non-constant arg
            is_ossys = (isinstance(f, ast.Attribute) and f.attr in ("system", "popen")
                        and isinstance(f.value, ast.Name) and f.value.id == "os")
            if is_ossys:
                cmd = n.args[0] if n.args else None
                if cmd is not None and not isinstance(cmd, ast.Constant):
                    ln = getattr(n, "lineno", "?")
                    out.append(f"L{ln} shell-injection: os.{f.attr}() runs a built string through "
                               f"the shell (injection risk — use subprocess with a list argv)")
    return out

def code_map(code):
    """Build a compact structural map of the current tool: imports, top-level
    functions (with signatures), and classes (with their methods). Given to the
    model before it edits, so it sees the file's shape at a glance and stops
    re-introducing bugs it already fixed or calling things that don't exist.
    Returns a short string, or '' if the code doesn't parse."""
    import ast
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return ""

    def sig(fn):
        a = fn.args
        parts = []
        posonly = getattr(a, "posonlyargs", [])
        allpos = posonly + a.args
        ndef = len(a.defaults)
        first_def = len(allpos) - ndef
        for i, arg in enumerate(allpos):
            parts.append(arg.arg + ("=…" if i >= first_def else ""))
        if a.vararg: parts.append("*" + a.vararg.arg)
        for kw in a.kwonlyargs: parts.append(kw.arg + "=…")
        if a.kwarg: parts.append("**" + a.kwarg.arg)
        return f"{fn.name}({', '.join(parts)})"

    imports, funcs, classes = [], [], []
    for node in tree.body:
        if isinstance(node, ast.Import):
            imports += [a.asname or a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            imports += [f"{mod}.{a.name}" for a in node.names]
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs.append(sig(node))
        elif isinstance(node, ast.ClassDef):
            methods = [sig(b) for b in node.body
                       if isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef))]
            bases = [b.id for b in node.bases if isinstance(b, ast.Name)]
            head = node.name + (f"({', '.join(bases)})" if bases else "")
            classes.append((head, methods))

    lines = ["STRUCTURE OF THE CURRENT TOOL (for your reference — keep calls consistent with this):"]
    if imports:
        lines.append("imports: " + ", ".join(imports[:30]))
    for head, methods in classes:
        lines.append(f"class {head}:")
        for m in methods:
            lines.append(f"    {m}")
    if funcs:
        lines.append("functions: " + "; ".join(funcs))
    return "\n".join(lines)

def analyze_code(code):
    """Whole-code clash analysis. Prefers Ruff, falls back to the ast pass.
    Returns {"issues": [...], "engine": "ruff"|"ast", "clean": bool}.

    Cached on the source hash: a single polish round asks for this from the smoke
    test, from its own deep-read pass and again from the review path, and it is a
    full AST walk plus a ruff subprocess each time.
    """
    return _cached("analyze", code, lambda: _analyze_code_uncached(code))

def _analyze_code_uncached(code):
    ruff_issues = analyze_with_ruff(code)
    if ruff_issues is not None:
        # Ruff is fast and deep on style/logic but does NOT track instance attributes.
        # Supplement it with our high-confidence self.<attr>-never-assigned pass plus the
        # extra safety findings (silent except: pass, shell injection) so those are caught
        # regardless of which engine runs.
        supplemental = []
        try:
            import ast as _ast
            tree = _ast.parse(code)
            if not any(isinstance(n, _ast.ImportFrom) and any(a.name == "*" for a in n.names)
                       for n in _ast.walk(tree)):
                supplemental = _unassigned_self_attrs(tree)
            supplemental = _dedupe_issues(
                supplemental + _extra_safety_findings(tree) + _signature_findings(tree))
        except SyntaxError:
            pass
        merged = ruff_issues + [s for s in supplemental if s not in ruff_issues]
        return {"issues": merged, "engine": "ruff", "clean": not merged}
    ast_issues = analyze_with_ast(code)
    return {"issues": ast_issues, "engine": "ast", "clean": not ast_issues}

# The same script gets smoke-tested by several callers in one turn — the build
# loop, then the polish round, then a review. Each run spawned an interpreter and
# re-ran Ruff over identical bytes. Keyed on a hash of the source, so a changed
# script is never served a stale verdict.
_SMOKE_CACHE = {}

_SMOKE_LOCK = threading.Lock()

_SMOKE_CACHE_MAX = 24

def _smoke_key(code):
    import hashlib
    return hashlib.sha1(code.encode("utf-8", "replace")).hexdigest()

def _which(*names):
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None

def _latest_code_in(convo):
    """Find the most recent code block in a conversation (the current tool)."""
    for m in reversed(convo):
        if m.get("role") == "assistant":
            c = extract_code(m.get("content", ""))
            if c:
                return c
    return None

# ==========================================================================
# TARGETED EDITS
#
# The single biggest cost in a long build is that every change — "make the
# button blue", "fix the off-by-one" — made the model retype the ENTIRE file.
# On a 380-line tool that is ~7,700 output tokens to alter one line, and output
# is billed several times the rate of input.
#
# So for a change to code that already exists, ask for search/replace blocks
# instead and apply them here. A one-line change becomes ~150 output tokens.
# The reply handed back upstream still carries the complete new script in a
# ```python block, so the autotest loop, the UI and the session format never
# learn this happened.
#
# The safety property that makes this usable: an edit is applied ONLY if its
# SEARCH text occurs EXACTLY once. Zero matches or several and the whole round
# is abandoned and retried as an ordinary full rewrite. A patch that doesn't
# fit is never guessed at.
# ==========================================================================
EDIT_PROMPT = """You are modifying an existing single-file Python tool.

Return your changes as SEARCH/REPLACE blocks — never the whole file.

<<<<<<< SEARCH
(lines copied EXACTLY from the current file, including indentation)
=======
(what they become)
>>>>>>> REPLACE

Rules:
- SEARCH must be copied character for character from the file you were shown,
  and must appear EXACTLY ONCE in it. If a line isn't unique, include the lines
  above and below it until the block is.
- To insert: SEARCH a nearby anchor line, REPLACE with that line plus the new ones.
- To delete: leave the REPLACE side empty.
- Change only what the request needs. Do not reformat untouched code.
- Use as many blocks as you need, but keep each one tight.
- Put ONE short sentence about what you changed before the first block.
- If the request genuinely requires rewriting most of the file, reply with the
  single word FULL_REWRITE and nothing else.

The rules the file was built under still apply to every line you touch:
- ONE self-contained script. No new files, no imports of things that aren't
  installed, no placeholder comments and no TODOs — finished code only.
- Never swallow an error. No bare `except: pass`. If something can fail, the
  user must be able to SEE that it failed, in the window, in plain language.
- Every name you reference must already exist in the file or be defined by your
  own edit, and every call must match the signature it's calling.
- Don't leave the program in a state it can't get out of, and don't do slow work
  on the UI thread."""

_EDIT_BLOCK = re.compile(
    r"<{5,}\s*SEARCH\s*\n(.*?)\n?={5,}\s*\n(.*?)\n?>{5,}\s*REPLACE",
    re.S)

def parse_edit_blocks(reply):
    """Pull (search, replace) pairs out of a model reply."""
    return [(m.group(1), m.group(2)) for m in _EDIT_BLOCK.finditer(reply or "")]

def _find_line_span(hay_lines, needle_lines, loose=False):
    """Every index where needle_lines occurs as a run of WHOLE lines in hay_lines.

    Line-anchored, not substring. Substring matching looked reasonable and was
    quietly terrible: a SEARCH of `    return a + b + 3` also matches inside
    `    return a + b + 30`, so a perfectly good single-line patch gets rejected
    as ambiguous — or worse, a shorter needle silently matches a prefix of a
    longer line. Whole-line comparison is what the model thinks it is writing.
    """
    if not needle_lines:
        return []
    norm = (lambda s: s.strip()) if loose else (lambda s: s.rstrip())
    hay = [norm(x) for x in hay_lines]
    ned = [norm(x) for x in needle_lines]
    n = len(ned)
    return [i for i in range(len(hay) - n + 1) if hay[i:i + n] == ned]

def apply_edit_blocks(code, blocks):
    """Apply every block or none. Returns (new_code, error_or_None).

    Matching a block EXACTLY ONCE is the whole safety story here — a fuzzy match
    would let a plausible-looking patch land in the wrong place, which is far
    worse than spending the tokens on a rewrite. Two passes: exact lines
    (trailing whitespace ignored), then indentation-insensitive as a last resort,
    and only ever when that pass finds precisely one home for the block.
    """
    if not blocks:
        return None, "no edit blocks in the reply"
    lines = (code or "").split("\n")
    for i, (search, replace) in enumerate(blocks, 1):
        if not search.strip():
            return None, f"block {i}: empty SEARCH"
        s_lines = search.split("\n")
        r_lines = replace.split("\n") if replace else []
        if r_lines == [""]:
            r_lines = []
        hits = _find_line_span(lines, s_lines)
        if not hits:
            hits = _find_line_span(lines, s_lines, loose=True)
            if len(hits) == 1:
                # keep the file's own indentation for the replaced region
                pad = lines[hits[0]][:len(lines[hits[0]]) - len(lines[hits[0]].lstrip())]
                base = min((len(x) - len(x.lstrip()) for x in r_lines if x.strip()), default=0)
                r_lines = [(pad + x[base:]) if x.strip() else x for x in r_lines]
        if not hits:
            return None, f"block {i}: SEARCH text not found in the file"
        if len(hits) > 1:
            return None, (f"block {i}: SEARCH text appears {len(hits)} times — "
                          f"not unique, needs more surrounding context")
        at = hits[0]
        lines = lines[:at] + r_lines + lines[at + len(s_lines):]
    out = "\n".join(lines)
    if out.strip() == (code or "").strip():
        return None, "the edits changed nothing"
    return out, None

def _edit_request(code, instruction, prior_user=""):
    """The compact payload for an edit round: no build doctrine, no history."""
    ctx = f"The user's request:\n{prior_user.strip()[:1500]}\n\n" if prior_user else ""
    return [
        {"role": "system", "content": EDIT_PROMPT},
        {"role": "user", "content":
            f"{ctx}=== CURRENT FILE ===\n" + fenced(code) + f"\n\n{instruction}"},
    ]

def try_edit_round(code, instruction, prior_user="", provider_id=None, retries=1):
    """One targeted-edit attempt. Returns a normal result dict with the FULL new
    script in its reply, or None to mean 'fall back to a full rewrite'.

    A block that doesn't match gets ONE cheap correction round before we give up.
    This matters more than it looks: the usual failure is a SEARCH copied slightly
    wrong, and telling the model exactly which block missed costs ~300 tokens,
    where falling straight through to a full rewrite costs thousands. Without the
    retry the whole scheme is only worth having when the model is already good at
    the format; with it, a mediocre run still comes out ahead.
    """
    if not code or not code.strip() or not edit_mode_on():
        return None
    convo = _edit_request(code, instruction, prior_user)
    res = None
    applied_code = None
    for attempt in range(retries + 1):
        # Capped below the build ceiling but high enough to hold a full file, so a
        # model that ignores the format and rewrites anyway isn't truncated.
        res = call_model(convo, provider_id, temperature=BUILD_TEMPERATURE,
                         tier="build", max_tokens=16000)
        if res.get("error"):
            # The CALL failed — timeout, rate limit, dead provider. That has
            # nothing to do with the patch format, so returning None here (which
            # means "fall through to a full rewrite") sent the SAME failing
            # request again with a bigger payload. On a provider that is down,
            # that is what turned a 2-minute failure into a 5-minute one. Hand
            # the error up; every caller already checks .get("error").
            return {**res, "edit_call_failed": True}
        reply = res.get("reply", "")
        # EDIT_PROMPT tells the model: "if the request genuinely requires
        # rewriting most of the file, reply with the single word FULL_REWRITE".
        # Nothing anywhere ever checked for it. A model that COMPLIED was scored
        # as a failed patch — and three of those in a row made _edit_lost() switch
        # targeted editing off for the rest of the process, quietly putting every
        # later change back on the expensive full-rewrite path. Take the model at
        # its word, and don't count doing as it was told against it.
        if reply.strip().upper().startswith("FULL_REWRITE"):
            EDIT_STATS["last_error"] = "model asked for a full rewrite"
            return None
        blocks = parse_edit_blocks(reply)
        if not blocks:
            break
        _new, _err = apply_edit_blocks(code, blocks)
        if _err is None:
            applied_code = _new          # keep it; re-deriving it below is free but pointless
            break
        if attempt == retries:
            break
        EDIT_STATS["retries"] += 1
        convo = convo + [
            {"role": "assistant", "content": reply},
            {"role": "user", "content":
                f"That patch did not apply: {_err}.\n\nCopy the SEARCH lines "
                f"character for character from the file above, and include enough "
                f"surrounding lines to make the block unique. Send the corrected "
                f"SEARCH/REPLACE blocks only."},
        ]
    reply = res.get("reply", "")
    blocks = parse_edit_blocks(reply)

    # SALVAGE: some models ignore the format and just hand back the whole script.
    # Throwing that away and paying for a second full call is the worst of both
    # worlds — if what came back is a complete, parseable file, take it.
    if not blocks:
        whole = extract_code(reply)
        if whole and whole.strip() != (code or "").strip():
            ok, _report, _checks = smoke_test(whole)
            if ok:
                EDIT_STATS["salvaged"] += 1
                _edit_won()          # we still got a usable answer for one call
                res["edit_mode"] = False
                return res
        EDIT_STATS["fallbacks"] += 1
        EDIT_STATS["last_error"] = "no edit blocks and no usable full script"
        _edit_lost()
        return None

    new_code, err = (applied_code, None) if applied_code else apply_edit_blocks(code, blocks)
    if err:
        EDIT_STATS["fallbacks"] += 1
        EDIT_STATS["last_error"] = err
        _edit_lost()
        return None
    # Models very often wrap their SEARCH/REPLACE blocks in a ```python fence.
    # Removing the blocks then leaves an EMPTY fence behind in the prose, and the
    # first thing downstream that looks for a code block finds that instead of the
    # real script — which is exactly how the new file ended up printed into the
    # chat while the code pane kept the old version.
    prose = _EDIT_BLOCK.sub("", reply)
    prose = re.sub(r"^[ \t]*`{3,}[A-Za-z0-9_+.-]*[ \t]*\n\s*`{3,}[ \t]*$", "",
                   prose, flags=re.M)                    # empty fence pairs
    prose = re.sub(r"^[ \t]*`{3,}[A-Za-z0-9_+.-]*[ \t]*$", "", prose, flags=re.M)  # orphans
    prose = re.sub(r"\n{3,}", "\n\n", prose).strip() or "Applied the change."
    EDIT_STATS["applied"] += 1
    _edit_won()
    EDIT_STATS["saved_chars"] += max(0, len(code) - len(reply))
    # Pick a fence longer than any backtick run in the code. Without this, a tool
    # whose help text contains a markdown example closed our own fence early and
    # everything downstream read a truncated file.
    f = fence_for(new_code)
    res["reply"] = f"{prose}\n\n{f}python\n{new_code}\n{f}"
    res["edit_mode"] = True
    return res

def _edit_stats_reset():
    EDIT_STATS.update(applied=0, fallbacks=0, salvaged=0, retries=0,
                      saved_chars=0, last_error="", streak=0, off=False)

EDIT_STATS = {"applied": 0, "fallbacks": 0, "salvaged": 0, "retries": 0,
              "saved_chars": 0, "last_error": "", "streak": 0, "off": False}

# How many patch attempts in a row may fail before we stop trying.
EDIT_GIVE_UP_AFTER = 3

def edit_mode_on():
    """Targeted edits are a bet: they save 4-8x when they land, and cost one wasted
    call when they don't. Against a model that simply can't produce the format the
    bet loses every time and the feature would be worse than not having it — so
    after EDIT_GIVE_UP_AFTER consecutive misses it switches itself off for the rest
    of the process, and the build goes back to plain full rewrites."""
    return not EDIT_STATS["off"]

def _edit_won():
    EDIT_STATS["streak"] = 0
    EDIT_STATS["off"] = False

def edit_mode_rearm():
    """A new tool is a new model, a new file and a new chance. The breaker exists
    to stop throwing money at a model that can't patch THIS file — not to punish
    the rest of the process for one bad session."""
    EDIT_STATS["streak"] = 0
    EDIT_STATS["off"] = False

def _edit_lost():
    EDIT_STATS["streak"] += 1
    if EDIT_STATS["streak"] >= EDIT_GIVE_UP_AFTER:
        EDIT_STATS["off"] = True

def _drop_code_block(text, code):
    """Remove a fenced block from `text` when it holds exactly `code`."""
    if not text or not code:
        return text
    target = code.strip()
    for _lang, bstart, bend, _ticks, _cl in _code_spans(text):
        if text[bstart:bend].strip() == target:
            head = text.rfind("\n", 0, bstart)
            head = text.rfind("\n", 0, head) if head > 0 else 0
            tail = text.find("\n", bend)
            tail = text.find("\n", tail + 1) if tail != -1 else len(text)
            return (text[:max(0, head)] +
                    "\n(the current file is shown above, in the CURRENT FILE section)\n" +
                    text[tail if tail != -1 else len(text):])
    return text

def _wants_fresh_build(text):
    """Requests that are asking for a NEW program, not a change to this one."""
    t = (text or "").lower()
    return any(k in t for k in ("start over", "from scratch", "rewrite it", "rewrite the",
                                "new tool", "completely different", "throw it away"))

# ==========================================================================
# ACTIVITY CHANNEL
#
# The build is a sequence of real stages — the model thinks, writes, then
# Frida lint-fixes, smoke-tests, and (if needed) feeds specific failures back
# for another round. The user used to see none of that: a spinner, then an
# answer. This channel lets each stage announce itself, and the /api/chat/stream
# endpoint relays those announcements to the UI live. It's the actual pipeline
# narrating itself, not a decorative animation.
# ==========================================================================
_ACTIVITY = threading.local()

# Set while something is drawing the model's output as it streams in. A single
# slot rather than a list: there is one terminal, and exactly one thing may own
# the live region at a time.
GEN_WATCHER = [None]


class watching_generation:
    """`with engine.watching_generation(fn):` — fn(text, chars, secs) as it streams."""

    def __init__(self, fn):
        self.fn = fn
        self.prev = None

    def __enter__(self):
        self.prev = GEN_WATCHER[0]
        GEN_WATCHER[0] = self.fn
        return self

    def __exit__(self, *exc):
        GEN_WATCHER[0] = self.prev
        return False

def _emit(kind, **data):
    """Push one activity event to the channel bound to THIS build thread, if any.
    A no-op when nothing is listening, so every code path works with or without a
    stream attached."""
    ch = getattr(_ACTIVITY, "chan", None)
    if ch is not None:
        try:
            ch.put({"kind": kind, **data})
        except Exception:
            pass

class ActivityChannel:
    """A bounded queue of build events with a sentinel to mark completion."""
    def __init__(self):
        import queue
        self.q = queue.Queue(maxsize=256)
        self.done = object()

    def put(self, ev):
        try:
            self.q.put_nowait(ev)
        except Exception:
            pass  # a slow reader must never stall the build

    def finish(self, result):
        """Deliver the final result — without ever blocking the build thread.

        These were plain blocking puts on a maxsize=256 queue. If the client
        disconnected mid-build the relay stops draining, and a chatty build then
        wedged its worker thread here FOREVER holding the finished result. Drop
        the backlog instead: nobody is reading the progress events at that point
        anyway, and the result is the only frame that matters.
        """
        for ev in ({"kind": "result", "result": result}, self.done):
            try:
                self.q.put_nowait(ev)
            except Exception:
                try:
                    while True:
                        self.q.get_nowait()      # make room, oldest first
                except Exception:
                    pass
                try:
                    self.q.put_nowait(ev)
                except Exception:
                    pass

    def drain(self, timeout=0.5):
        import queue
        try:
            ev = self.q.get(timeout=timeout)
        except queue.Empty:
            return None
        return ev

def run_with_activity(fn):
    """Run build fn in a worker thread with an activity channel bound to it, and
    return (channel, thread). The caller relays events until the sentinel."""
    chan = ActivityChannel()

    def _worker():
        _ACTIVITY.chan = chan
        try:
            result = fn()
        except Exception as e:
            result = {"error": f"{type(e).__name__}: {e}"}
        finally:
            _ACTIVITY.chan = None
        chan.finish(result)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    return chan, t

def _parse_json_reply(reply):
    """Extract a JSON object from a model reply, tolerating fences/prose."""
    reply = re.sub(r"```(?:json)?", "", reply).strip()
    m = re.search(r"\{.*\}", reply, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None

# Live GUI processes launched by Run, so we can report status and stop them.
# {pid: {"proc": Popen, "name": str, "path": tmpfile, "started": ts}}
RUNNING = {}

_RUNNING_LOCK = threading.Lock()

def _reap():
    """Drop finished processes and clean up their temp files."""
    with _RUNNING_LOCK:
        for pid in list(RUNNING):
            info = RUNNING[pid]
            if info["proc"].poll() is not None:
                try: os.unlink(info["path"])
                except Exception: pass
                RUNNING.pop(pid, None)

def list_running():
    _reap()
    with _RUNNING_LOCK:
        return {"running": [{"pid": pid, "name": i["name"],
                             "seconds": round(time.time() - i["started"], 1)}
                            for pid, i in RUNNING.items()]}

def stop_running(pid):
    """Terminate a launched GUI (and its children) — cross-platform.
    POSIX: signal the whole process group (we made one with start_new_session=True).
    Windows: taskkill /F /T does the equivalent — terminate the tree."""
    _reap()
    with _RUNNING_LOCK:
        info = RUNNING.get(pid)
    if not info:
        return {"ok": False, "error": "not running (already closed?)"}
    proc = info["proc"]
    try:
        if IS_WIN:
            # taskkill /T = terminate the entire tree, /F = forceful
            try:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                               capture_output=True, timeout=10)
            except Exception:
                try: proc.terminate()
                except Exception: pass
                try: proc.kill()
                except Exception: pass
        else:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except Exception:
                proc.terminate()
            try: proc.wait(timeout=3)
            except Exception:
                try: os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception: proc.kill()
        return {"ok": True, "pid": pid}
    finally:
        _reap()

LICENSES = {
    "MIT": ("MIT License\n\nCopyright (c) {year} {holder}\n\nPermission is hereby granted, "
            "free of charge, to any person obtaining a copy of this software and associated "
            "documentation files (the \"Software\"), to deal in the Software without restriction, "
            "including without limitation the rights to use, copy, modify, merge, publish, "
            "distribute, sublicense, and/or sell copies of the Software, and to permit persons "
            "to whom the Software is furnished to do so, subject to the following conditions:\n\n"
            "The above copyright notice and this permission notice shall be included in all "
            "copies or substantial portions of the Software.\n\nTHE SOFTWARE IS PROVIDED \"AS IS\", "
            "WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE "
            "WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. "
            "IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES "
            "OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING "
            "FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE "
            "SOFTWARE.\n"),
}

_SH_SAFE = re.compile(r"[^A-Za-z0-9_./+@\-]")

def shell_safe(value, default="", maxlen=120):
    """Strip anything that could break out of a double-quoted shell string.

    `install.sh` is assembled by string interpolation and then PUBLISHED — other
    people curl|bash it. Three of the values going into it were never checked:
    the GitHub username and branch come straight from a text field, and the pip
    dependency list is whatever the MODEL put in requirements.txt. A quote, a
    backtick or a `$(...)` in any of them lands as live shell in someone else's
    installer. Nothing legitimate here needs a character outside this set.
    """
    cleaned = _SH_SAFE.sub("", str(value or ""))[:maxlen].strip("-")
    return cleaned or default

# A pip requirement legitimately contains characters the identifier filter above
# strips — `requests>=2.31`, `uvicorn[standard]`, `numpy!=1.24.0`. Those are only
# dangerous UNQUOTED, so the generated installer puts them in a bash array with
# every element quoted (see _install_sh) and this filter just keeps out the
# characters that would end a double-quoted string or start a substitution.
_PIP_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+\-]*(?:\[[A-Za-z0-9,._\-]+\])?"
                       r"(?:\s*[=!~<>]=?\s*[0-9A-Za-z.\-*+]+)?$")

def pip_safe(tokens):
    """Keep only tokens that look like a real pip requirement. Anything else —
    a shell fragment the model slipped into requirements.txt, a stray quote — is
    dropped rather than escaped, because a mangled package name is a confusing
    install error and a dropped one is simply absent."""
    out = []
    for tok in (tokens or "").split():
        tok = tok.strip()
        if tok and len(tok) <= 100 and _PIP_SAFE.match(tok) and tok not in out:
            out.append(tok)
    return out

# --------------------------------------------------------------------------
# PYINSTALLER  -- pack a tool into a standalone Linux binary
# --------------------------------------------------------------------------
# Frida builds a single-file binary for Linux via PyInstaller in its managed
# venv. (No cross-compilation: PyInstaller bakes the host Python + libs into the
# output, so a binary built here runs on Linux only — which is the target.)
def _missing_in_venv(venv_py, pkgs):
    """Which of `pkgs` the venv can't already import. One interpreter start, not one
    per package, and no network at all."""
    if not pkgs:
        return []
    probe = (
        "import importlib.util,sys\n"
        "names={'pyinstaller':'PyInstaller','pillow':'PIL','pyyaml':'yaml',"
        "'beautifulsoup4':'bs4','python-dateutil':'dateutil'}\n"
        "out=[]\n"
        "for p in sys.argv[1:]:\n"
        "    m=names.get(p.lower(), p.replace('-','_'))\n"
        "    try:\n"
        "        if importlib.util.find_spec(m) is None: out.append(p)\n"
        "    except Exception: out.append(p)\n"
        "print('\\n'.join(out))\n"
    )
    try:
        r = subprocess.run([venv_py, "-c", probe, *pkgs], capture_output=True,
                           text=True, timeout=60, encoding="utf-8", errors="replace")
        if r.returncode != 0:
            return list(pkgs)
        return [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()]
    except Exception:
        return list(pkgs)

def build_executable(code, name, console=False):
    """Run PyInstaller in Frida's managed venv to produce a single-file Linux
    binary. Returns the path to the artefact + a tail of the build log."""
    name = re.sub(r"[^A-Za-z0-9_\-]", "_", (name or "tool")).strip("_") or "tool"
    if not code or not code.strip():
        return {"ok": False, "log": "no code to build"}

    # 1) ensure the venv exists and PyInstaller is installed in it
    venv_py = _venv_python()
    if not venv_py:
        # build the venv lazily so the user doesn't pay the cost until they actually build
        try:
            import venv
            venv.EnvBuilder(with_pip=True, system_site_packages=True).create(VENV_DIR)
            venv_py = _venv_python() or sys.executable
        except Exception as e:
            return {"ok": False, "log": f"venv creation failed: {e}"}

    # also install whatever the TOOL imports (toolkit + pip deps) so PyInstaller can
    # actually find them when it sniffs the script
    deps = detect_deps(code)
    pip_to_install = ["pyinstaller"] + [p for p in deps["pip"] if p]
    # `--upgrade` forced a full PyPI resolve of PyInstaller and every dependency on
    # EVERY build, which is minutes of network on a repeat build that needed none of
    # it. Install only what's missing, and let uv do it when it's on PATH — the same
    # policy install_deps() already uses.
    try:
        missing = _missing_in_venv(venv_py, pip_to_install)
        if missing:
            uv = shutil.which("uv")
            cmd = ([uv, "pip", "install", "--python", venv_py, *missing] if uv else
                   [venv_py, "-m", "pip", "install", "--disable-pip-version-check",
                    "--no-input", *missing])
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900,
                                  encoding="utf-8", errors="replace")
            if proc.returncode != 0:
                return {"ok": False, "log": "pip install failed:\n" + (proc.stderr or proc.stdout)[-2000:]}
    except Exception as e:
        return {"ok": False, "log": f"pip install error: {e}"}

    # 2) lay out a work dir under frida-tools/dist/<name>/
    workdir = tools_dir() / "dist" / name
    workdir.mkdir(parents=True, exist_ok=True)
    py_file = workdir / (name + ".py")
    py_file.write_text(code, encoding="utf-8")

    dist_dir  = workdir / "out"
    build_dir = workdir / "build"
    spec_dir  = workdir / "spec"
    for p in (dist_dir, build_dir, spec_dir):
        p.mkdir(exist_ok=True)

    # 3) build args: --onefile bakes everything into one binary, --windowed drops the
    #    controlling console for GUI tools, --clean wipes PyInstaller's cache so
    #    re-builds always reflect the latest code
    # `--clean` wiped PyInstaller's analysis cache before every build, so each
    # rebuild of the same tool paid the full cold-build cost. The work dir is
    # per-tool and PyInstaller re-analyses changed sources anyway.
    args = [venv_py, "-m", "PyInstaller", "--onefile", "--noconfirm",
            "--name", name,
            "--distpath", str(dist_dir),
            "--workpath", str(build_dir),
            "--specpath", str(spec_dir)]
    if not console:
        args.append("--windowed")
    # bundle the Dawg icon if present (PyInstaller takes a PNG on Linux)
    icon_png = Path(HERE) / "assets" / "icon.png"
    if icon_png.exists():
        args += ["--icon", str(icon_png)]
    args.append(str(py_file))

    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=1200,
                              encoding="utf-8", errors="replace")
        log = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    except subprocess.TimeoutExpired:
        return {"ok": False, "log": "PyInstaller timed out after 20 minutes."}
    except Exception as e:
        return {"ok": False, "log": f"PyInstaller crashed: {e}"}

    # 4) find the artefact
    out_name, target = name, "Linux binary"
    out_path = dist_dir / out_name
    if proc.returncode == 0 and out_path.exists():
        size_mb = round(out_path.stat().st_size / (1024 * 1024), 1)
        return {"ok": True, "path": str(out_path), "target": target,
                "size_mb": size_mb, "log": log[-2000:]}
    return {"ok": False, "log": "PyInstaller didn't produce a binary.\n\n" + log[-2500:]}

# --------------------------------------------------------------------------
# SESSION LOG  -- every run is appended; one button hands it all to the model
# --------------------------------------------------------------------------
SESSION_LOG = []   # list of dicts: {ts, kind, name, args, exit, seconds, stdout, stderr}

_LOG_ENTRY_MAX = 20000     # per stream, per run

def log_run(name, args, result):
    # Cap each stream. The list was bounded at 40 entries but a single chatty tool
    # could put megabytes into one of them, which then rode along in every fix
    # round's prompt and in memory for the rest of the session.
    def _clip(s):
        s = s or ""
        if len(s) <= _LOG_ENTRY_MAX:
            return s
        head = _LOG_ENTRY_MAX // 4
        return (s[:head] + f"\n…[{len(s) - _LOG_ENTRY_MAX} chars trimmed by Frida]…\n"
                + s[-(_LOG_ENTRY_MAX - head):])
    SESSION_LOG.append({
        "ts": time.strftime("%H:%M:%S"),
        "name": name, "args": args,
        "exit": result.get("exit"), "seconds": result.get("seconds"),
        "stdout": _clip(result.get("stdout")), "stderr": _clip(result.get("stderr")),
    })
    # keep it bounded so we never blow the context window
    if len(SESSION_LOG) > 40:
        del SESSION_LOG[0:len(SESSION_LOG) - 40]

def render_log(full=True):
    """Render the session log as a single text blob (also what gets saved to file)."""
    lines = [f"Frida session log — {len(SESSION_LOG)} run(s)", "=" * 50]
    for i, e in enumerate(SESSION_LOG, 1):
        lines.append(f"\n[run {i}] {e['ts']}  {e['name']}.py {e['args']}".rstrip())
        lines.append(f"exit {e['exit']} · {e['seconds']}s")
        if e["stdout"]:
            out = e["stdout"] if full else e["stdout"][-1500:]
            lines.append("--- stdout ---\n" + out.rstrip())
        if e["stderr"]:
            lines.append("--- stderr ---\n" + e["stderr"].rstrip())
    return "\n".join(lines)


# ==========================================================================
# WHAT A TOOL NEEDS  --  dependency detection, no toolkits involved
# ==========================================================================
_STDLIB = set(getattr(sys, "stdlib_module_names", ())) | {
    "os", "sys", "re", "json", "time", "math", "csv", "argparse", "pathlib",
    "subprocess", "shutil", "typing", "datetime", "random", "itertools",
    "functools", "collections", "hashlib", "base64", "socket", "threading",
    "urllib", "textwrap", "tempfile", "sqlite3", "logging", "glob", "signal",
    "platform", "string", "struct", "zipfile", "tarfile", "gzip", "shlex",
    "traceback", "unicodedata", "statistics", "difflib", "ipaddress", "uuid",
    "concurrent", "contextlib", "dataclasses", "enum", "io", "select", "stat",
    "termios", "tty", "getpass", "configparser", "http", "ssl", "email", "ast",
}

# import name -> pip name, where they differ. A generated tool that writes
# `import yaml` needs `pip install PyYAML`; getting this wrong means the deps
# step installs a package that doesn't exist and the tool still won't run.
PIP_ALIASES = {
    "yaml": "PyYAML", "PIL": "Pillow", "cv2": "opencv-python", "bs4": "beautifulsoup4",
    "dateutil": "python-dateutil", "serial": "pyserial", "usb": "pyusb",
    "OpenSSL": "pyOpenSSL", "Crypto": "pycryptodome", "magic": "python-magic",
    "docx": "python-docx", "fitz": "PyMuPDF", "sklearn": "scikit-learn",
    "git": "GitPython", "jwt": "PyJWT", "nmap": "python-nmap", "dns": "dnspython",
    "win32api": "pywin32", "zoneinfo": "", "toml": "tomli",
    # Media and audio — a music player is one of the first things anyone asks
    # for, and `pip install vlc` fetches a completely unrelated project.
    "vlc": "python-vlc", "pygame": "pygame", "sounddevice": "sounddevice",
    "soundfile": "soundfile", "pyaudio": "PyAudio", "simpleaudio": "simpleaudio",
    "just_playback": "just_playback", "miniaudio": "miniaudio",
    "audioread": "audioread", "eyed3": "eyeD3", "tinytag": "tinytag",
    "PIL": "Pillow", "gi": "PyGObject", "cairo": "pycairo",
    # Terminal and TUI
    "blessed": "blessed", "readchar": "readchar", "getch": "py-getch",
    "curses": "", "_curses": "",          # stdlib on POSIX, not a pip package
    # Frequently mis-named elsewhere
    "attr": "attrs", "pkg_resources": "setuptools", "google": "protobuf",
    "lxml": "lxml", "Xlib": "python-xlib", "psycopg2": "psycopg2-binary",
    "MySQLdb": "mysqlclient", "redis": "redis", "OpenGL": "PyOpenGL",
    "speech_recognition": "SpeechRecognition", "telebot": "pyTelegramBotAPI",
    "discord": "discord.py", "dotenv": "python-dotenv", "slugify": "python-slugify",
    "ruamel": "ruamel.yaml", "pytz": "pytz", "tqdm": "tqdm",
}


def tk_available(python=None):
    """Is tkinter importable by the interpreter that will run generated tools?"""
    try:
        out = subprocess.run([python or run_python(), "-c",
                              "import importlib.util,sys;"
                              "sys.exit(0 if importlib.util.find_spec('tkinter') else 1)"],
                             capture_output=True, timeout=20)
        return out.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def tk_install_hint():
    """How to get tkinter on this machine. It is never a pip package.

    Tkinter ships with CPython but most distributions split it into a separate
    system package, so `pip install tkinter` — which is what everyone tries —
    fails with a confusing error about a package that has never existed.
    """
    fam = (DISTRO or {}).get("family", "")
    if fam == "arch":
        return "sudo pacman -S --needed tk"
    if fam == "debian":
        return "sudo apt install -y python3-tk"
    if fam == "fedora":
        return "sudo dnf install -y python3-tkinter"
    if fam == "suse":
        return "sudo zypper install -y python3-tk"
    if IS_MAC:
        return "brew install python-tk"
    if IS_WIN:
        return "re-run the Python installer and tick 'tcl/tk and IDLE'"
    return "install your distribution's python3-tk package"


def missing_deps(code):
    """The declared pip packages that the tool's interpreter cannot import.

    detect_deps says what the file imports; this says what is actually absent,
    so a build doesn't reinstall half of Arch's python packages on every run.
    """
    wanted = detect_deps(code or "")["pip"]
    if not wanted:
        return []
    tops = [t for t in _imported_tops(code or "")
            if t and not t.startswith("_") and t not in _STDLIB]
    by_pkg = {}
    for top in tops:
        pkg = PIP_ALIASES.get(top, top)
        if pkg:
            by_pkg.setdefault(pkg, top)
    if not by_pkg:
        return []
    probe = ("import importlib.util,sys,json\n"
             "print(json.dumps([m for m in sys.argv[1:] "
             "if importlib.util.find_spec(m) is None]))")
    try:
        out = subprocess.run([run_python(), "-c", probe] + list(by_pkg.values()),
                             capture_output=True, text=True, timeout=30)
        absent = set(json.loads(out.stdout.strip() or "[]"))
    except (OSError, ValueError, subprocess.SubprocessError):
        return sorted(wanted)          # can't tell — assume they're needed
    return sorted(pkg for pkg, top in by_pkg.items() if top in absent)

def detect_deps(code):
    """Third-party pip packages a generated tool imports.

    Only pip. Frida builds terminal tools, so there is no toolkit branch here and
    no system-package guessing: anything not in the standard library and not a
    local module is a pip name, mapped through PIP_ALIASES where the import name
    and the package name disagree.
    """
    pip = set()
    for top in _imported_tops(code or ""):
        if not top or top.startswith("_") or top in _STDLIB:
            continue
        name = PIP_ALIASES.get(top, top)
        if name:
            pip.add(name)
    return {"pip": sorted(pip)}


# ==========================================================================
# SMOKE TEST  --  the free checks, before anything is run for real
# ==========================================================================
# This is the cheap pass: does the file parse, is it complete, does importing it
# do nothing surprising, and does static analysis find a defect. It never runs
# the tool's own main() - that is behaviour, and behaviour is harness.py's job.
#
# It matters most for the thing a model does when it runs short on room: hand
# back a script with "# ... rest unchanged ..." in the middle. That parses, it
# imports, every later check passes, and you get a broken tool. Caught first.

TRUNCATION_MARKERS = [
    r"#\s*\.\.\.\s*(?:rest|remaining|the rest|previous|existing|unchanged|same)",
    r"#\s*(?:rest|remainder) of (?:the )?(?:code|file|script|class|method|implementation)",
    r"#\s*\(?(?:previous|existing|original|earlier) (?:code|implementation|methods?)",
    r"#\s*(?:code )?unchanged\b",
    r"#\s*same as (?:before|above|previous)",
    r"#\s*(?:implementation|logic) (?:goes )?here\b",
    r"#\s*\.\.\.\s*$",
    r"<\s*(?:rest of|remaining)[^>]*>",
]

# Running something at import time is a bug in a CLI tool specifically: Frida
# imports the module to check it, `python -c "import tool"` does too, and so does
# every test runner. Work belongs under main().
_TOPLEVEL_RUN = re.compile(
    r"^(?!\s)(?!if\s+__name__)(?:[A-Za-z_][A-Za-z0-9_.]*\s*\(|await\s)", re.M)


def _smoke_test_uncached(code):
    """(passed, report, checks) — the free pass over generated code."""
    checks = []

    # 0. completeness
    for pat in TRUNCATION_MARKERS:
        m = re.search(pat, code, re.M | re.I)
        if m:
            line = code[:m.start()].count("\n") + 1
            msg = ("The script is incomplete: line %d is a placeholder (%r) instead of real "
                   "code. Return the ENTIRE file with every function written out in full — "
                   "no \"rest unchanged\" markers, no elisions." % (line, m.group(0).strip()[:60]))
            return False, msg, [("complete", False, msg)]
    checks.append(("complete", True, ""))

    # 1. it has to parse
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        msg = f"SyntaxError line {e.lineno}: {e.msg}"
        return False, msg, [("parses", False, msg)]
    checks.append(("parses", True, ""))

    # 2. shape checks — cheap, local, and they catch the two ways a generated CLI
    #    tool is most often wrong: it does its work at import time, or it has no
    #    entry point at all.
    shape = []
    has_main_guard = bool(re.search(r"^if\s+__name__\s*==\s*[\"']__main__[\"']", code, re.M))
    if not has_main_guard:
        shape.append("no `if __name__ == \"__main__\":` guard — the tool has no entry point "
                     "and importing it does nothing")
    stray = _TOPLEVEL_RUN.search(_code_without_prose(code))
    if stray:
        ln = code[:stray.start()].count("\n") + 1
        head = stray.group(0).strip()
        if not head.startswith(("print(", "sys.exit(")) and "=" not in head:
            shape.append(f"line {ln} calls `{head}` at module top level — that runs on import. "
                         f"Top level holds imports, constants and definitions only")
    if shape:
        msg = "Shape problems:\n  - " + "\n  - ".join(shape)
        checks.append(("shape", False, msg))
        return False, msg, checks
    checks.append(("shape", True, ""))

    # 3. import-ability. exec_module() runs every top-level statement, and this
    #    fires unattended on every build — so a destructive call at module level
    #    would execute before anyone had seen the code. Skip execution entirely in
    #    that case and say so; the build still proceeds, nothing runs unasked.
    danger = looks_dangerous(code)
    if danger:
        checks.append(("imports", True,
                       "NOT RUN — destructive commands present, so the code was not "
                       "executed for this check:\n  - " + "\n  - ".join(danger)))
    else:
        ok, note, fatal = _import_probe(code)
        checks.append(("imports", ok, note))
        if fatal:
            return False, note, checks

    # 4. whole-code analysis — undefined names, wrong arity, mutable defaults.
    #    Free, local, and every defect it catches here is a paid fix round that
    #    never happens.
    analysis = analyze_code(code)
    if analysis["clean"]:
        checks.append(("analysis", True, f"{analysis['engine']}: no issues"))
        return True, "", checks

    serious = [i for i in analysis["issues"]
               if any(k in i for k in ("undefined", "call:", "attribute:", "F821", "F811",
                                       "F706", "F702", "E9", "syntax"))]
    report = (f"Whole-code analysis ({analysis['engine']}) found:\n  - "
              + "\n  - ".join(analysis["issues"]))
    if serious:
        checks.append(("analysis", False, report))
        return False, report, checks
    checks.append(("analysis", True, f"{analysis['engine']}: minor only — "
                   + "; ".join(analysis["issues"][:5])))
    return True, "", checks


def _import_probe(code):
    """Import the candidate in a subprocess. Returns (ok, note, fatal)."""
    fd, path = tempfile.mkstemp(prefix="frida_test_", suffix=".py")
    try:
        # Explicit utf-8: the default is the locale codec, so under LANG=C (a
        # systemd unit, a bare tty, a container) a single ✓ in a help string
        # raised UnicodeEncodeError and killed the check for reasons that had
        # nothing to do with the code being checked.
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(code)
        probe = (
            "import importlib.util, sys\n"
            f"spec = importlib.util.spec_from_file_location('frida_candidate', {path!r})\n"
            "mod = importlib.util.module_from_spec(spec)\n"
            "try:\n"
            "    spec.loader.exec_module(mod)\n"
            "except (ModuleNotFoundError, ImportError) as e:\n"
            "    print('DEP_MISSING:' + str(e)); sys.exit(0)\n"
            "except SystemExit as e:\n"
            "    print('EXIT_AT_IMPORT:' + str(e)); sys.exit(0)\n"
            "except BaseException:\n"
            "    import traceback; sys.stderr.write(traceback.format_exc()); sys.exit(7)\n"
        )
        try:
            proc = subprocess.run([run_python(), "-c", probe], capture_output=True,
                                  stdin=subprocess.DEVNULL, timeout=15,
                                  cwd=tempfile.gettempdir())
        except subprocess.TimeoutExpired:
            return (False, "import timed out — top-level code is blocking. Everything that "
                           "runs, waits or reads input belongs inside main().", True)
        out = proc.stdout.decode("utf-8", errors="replace")
        err = proc.stderr.decode("utf-8", errors="replace")
        if out.startswith("DEP_MISSING:"):
            miss = out.split(":", 1)[1].strip()
            return True, f"needs a package that isn't installed yet ({miss[:120]})", False
        if out.startswith("EXIT_AT_IMPORT:"):
            return (False, "the tool called sys.exit() while being imported — argparse is "
                           "running at module level. Parse arguments inside main().", True)
        if proc.returncode != 0:
            return False, (err.strip()[-600:] or "import failed"), True
        return True, "", False
    finally:
        try:
            os.unlink(path)
        except Exception:
            pass


def smoke_test(code):
    key = _smoke_key(code)
    with _SMOKE_LOCK:
        hit = _SMOKE_CACHE.get(key)
    if hit is not None:
        return hit
    result = _smoke_test_uncached(code)
    with _SMOKE_LOCK:
        if len(_SMOKE_CACHE) >= _SMOKE_CACHE_MAX:
            _SMOKE_CACHE.clear()
        _SMOKE_CACHE[key] = result
    return result
