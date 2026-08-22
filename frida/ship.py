#!/usr/bin/env python3
"""
frida.ship  —  getting the tool out of Frida and into your shell
================================================================
A finished command-line tool is not a file in a chat log. It is a name you can
type. This module is the part that makes that true:

  install()      ~/.local/bin/<name>, executable, on your PATH, no .py extension
  save_copy()    a plain file in ~/frida-tools, for when you just want the source
  write_repo()   a full GitHub-ready repo — README, install.sh, LICENSE, push
                 commands over HTTPS
  freeze()       a single-file binary via PyInstaller, with the console kept

The generated `install.sh` gets the same treatment Frida gives its own: every
value the model chose is passed through a shell-safety filter before it reaches a
script that other people will run. A release artefact with an injection hole in
it is worse than no release at all.

License: MIT
"""

import os
import re
import stat
import time
from pathlib import Path

from . import engine

BIN_DIR = Path.home() / ".local" / "bin"
MARKER = "# installed by frida"


def _clean_name(name):
    name = re.sub(r"[^A-Za-z0-9_\-]", "-", (name or "tool").strip().lower())
    name = re.sub(r"-{2,}", "-", name).strip("-_") or "tool"
    return name[:40]


# ==========================================================================
# INSTALL  --  the whole point
# ==========================================================================
def is_ours(path):
    """Was this file put here by Frida? Decided by the marker line, not the name."""
    try:
        p = Path(path)
        if not p.is_file():
            return False
        return MARKER in p.open("r", encoding="utf-8", errors="replace").read(400)
    except OSError:
        return False


def install(code, name, overwrite=False):
    """Drop the tool on the PATH as an executable command. Returns a dict.

    Refuses to clobber a file it did not write. The tool's name is chosen by a
    model, so `ls`, `grep` or `serve` are entirely possible — and this used to
    overwrite whatever was already there, silently and unrecoverably.
    """
    name = _clean_name(name)
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    target = BIN_DIR / name

    if target.exists() and not overwrite and not is_ours(target):
        return {"ok": False, "occupied": str(target), "name": name,
                "error": "%s already exists in %s and Frida didn't put it there"
                         % (name, BIN_DIR)}

    body = code if code.startswith("#!") else "#!/usr/bin/env python3\n" + code
    # One marker line, right after the shebang. It is what makes `frida tools`
    # honest: without it the listing has to guess from the shebang and claims
    # every python script in ~/.local/bin as its own.
    if MARKER not in body:
        head, _, tail = body.partition("\n")
        body = head + "\n" + MARKER + "\n" + tail
    tmp = target.with_suffix(".frida-tmp")
    try:
        tmp.write_text(body, encoding="utf-8")
        os.chmod(tmp, os.stat(tmp).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        os.replace(tmp, target)
    except OSError as e:
        try:
            tmp.unlink()
        except OSError:
            pass
        return {"ok": False, "error": str(e)}

    return {"ok": True, "path": str(target), "name": name,
            "on_path": _on_path(BIN_DIR), "hint": path_hint()}


def _on_path(directory):
    parts = [Path(p).expanduser() for p in (os.environ.get("PATH") or "").split(os.pathsep) if p]
    return any(p == Path(directory) for p in parts)


def path_hint():
    """The line that puts ~/.local/bin on PATH, in the syntax of the running shell.

    CachyOS ships fish, and `export PATH=...` is a syntax error there. Telling
    someone to paste bash into fish is how a working install looks broken.
    """
    shell = os.path.basename(os.environ.get("SHELL") or "bash")
    if shell == "fish":
        return 'fish_add_path ~/.local/bin'
    if shell in ("zsh",):
        return 'echo \'export PATH="$HOME/.local/bin:$PATH"\' >> ~/.zshrc'
    return 'echo \'export PATH="$HOME/.local/bin:$PATH"\' >> ~/.bashrc'


def uninstall(name):
    target = BIN_DIR / _clean_name(name)
    try:
        target.unlink()
        return {"ok": True, "path": str(target)}
    except FileNotFoundError:
        return {"ok": False, "error": "not installed"}
    except OSError as e:
        return {"ok": False, "error": str(e)}


def installed():
    """Tools Frida installed — matched on its marker line, so this never claims
    something else that happens to live in ~/.local/bin."""
    found = []
    if not BIN_DIR.is_dir():
        return found
    for p in sorted(BIN_DIR.iterdir()):
        try:
            if not p.is_file() or not os.access(p, os.X_OK):
                continue
            head = p.open("r", encoding="utf-8", errors="replace").read(400)
        except (OSError, UnicodeDecodeError):
            continue
        if MARKER in head:
            found.append(str(p))
    return found


# ==========================================================================
# PLAIN COPY
# ==========================================================================
def save_copy(code, name, directory=None):
    d = Path(directory) if directory else engine.tools_dir()
    d.mkdir(parents=True, exist_ok=True)
    path = d / (_clean_name(name) + ".py")
    path.write_text(code, encoding="utf-8")
    return {"ok": True, "path": str(path)}


# ==========================================================================
# REPO
# ==========================================================================
_INSTALL_SH = """#!/usr/bin/env bash
# {name} — installer
# Puts {name} on your PATH as a command. No root needed.
set -euo pipefail

RAW="https://raw.githubusercontent.com/{user}/{repo}/{branch}"
BIN="${{HOME}}/.local/bin"
mkdir -p "$BIN"

need() {{ command -v "$1" >/dev/null 2>&1; }}

if ! need python3; then
  echo "{name}: python3 is required." >&2
  exit 1
fi

PIP_PKGS=({pip_array})
if [ ${{#PIP_PKGS[@]}} -gt 0 ]; then
  echo "installing dependencies: ${{PIP_PKGS[*]}}"
  python3 -m pip install --user --upgrade "${{PIP_PKGS[@]}}" 2>/dev/null \\
    || python3 -m pip install --user --break-system-packages --upgrade "${{PIP_PKGS[@]}}" \\
    || echo "{name}: could not install dependencies automatically — install them yourself: ${{PIP_PKGS[*]}}" >&2
fi

echo "fetching {name}"
curl -fsSL "$RAW/{name}.py" -o "$BIN/{name}"
chmod +x "$BIN/{name}"

case ":$PATH:" in
  *":$BIN:"*) ;;
  *) echo ""
     echo "  $BIN is not on your PATH. Add it:"
     echo "    {path_hint}"
     echo "" ;;
esac

echo "{name} installed — try: {name} --help"
"""

_GITIGNORE = """__pycache__/
*.py[cod]
.venv/
venv/
dist/
build/
*.spec
.env
"""


def write_repo(code, name, meta, user="", repo="", branch="main", holder=""):
    """Assemble a complete, publishable repo directory. Returns {path, files, push}."""
    name = _clean_name(name)
    user = engine.shell_safe(user or "your-username", "your-username", 39)
    repo = engine.shell_safe(repo or name, name, 100)
    branch = engine.shell_safe(branch or "main", "main", 60)
    holder = (holder or user or "the author").strip()[:80]

    d = engine.tools_dir() / "repos" / name
    d.mkdir(parents=True, exist_ok=True)

    tagline = (meta.get("tagline") or f"{name} — a command-line tool").strip()
    description = (meta.get("description") or tagline).strip()
    usage = (meta.get("usage") or f"{name} --help").strip()
    install_notes = (meta.get("install_notes") or "").strip()
    deps = engine.detect_deps(code)["pip"]
    pip_array = " ".join(f'"{p}"' for p in engine.pip_safe(deps))

    (d / f"{name}.py").write_text(
        code if code.startswith("#!") else "#!/usr/bin/env python3\n" + code,
        encoding="utf-8")

    readme = [
        f"# {name}", "", f"**{tagline}**", "", description, "",
        "## Install", "",
        "```bash",
        f"curl -fsSL https://raw.githubusercontent.com/{user}/{repo}/{branch}/install.sh | bash",
        "```", "",
        "Or just take the file — it's one script with no build step:", "",
        "```bash",
        f"curl -fsSL https://raw.githubusercontent.com/{user}/{repo}/{branch}/{name}.py -o {name}",
        f"chmod +x {name}",
        "```", "",
    ]
    if install_notes:
        readme += [install_notes, ""]
    if deps:
        readme += ["Dependencies: " + ", ".join(f"`{p}`" for p in deps), ""]
    readme += ["## Use", "", "```bash"] + usage.split("\n") + ["```", "",
               "## License", "", "MIT", ""]
    (d / "README.md").write_text("\n".join(readme), encoding="utf-8")

    (d / "install.sh").write_text(_INSTALL_SH.format(
        name=name, user=user, repo=repo, branch=branch,
        pip_array=pip_array, path_hint=path_hint()), encoding="utf-8")
    os.chmod(d / "install.sh", 0o755)

    mit = engine.LICENSES["MIT"]
    if isinstance(mit, tuple):
        mit = mit[0]
    (d / "LICENSE").write_text(mit.format(year=time.strftime("%Y"), holder=holder),
                               encoding="utf-8")
    (d / ".gitignore").write_text(_GITIGNORE, encoding="utf-8")

    push = "\n".join([
        f"cd {d}",
        "git init -b " + branch,
        "git add .",
        f'git commit -m "{name}: initial release"',
        f"git remote add origin https://github.com/{user}/{repo}.git",
        f"git push -u origin {branch}",
    ])

    return {"ok": True, "path": str(d),
            "files": sorted(p.name for p in d.iterdir()),
            "push": push, "topics": meta.get("topics") or []}


# ==========================================================================
# BINARY
# ==========================================================================
def freeze(code, name):
    """Single-file binary. console=True — this is a terminal tool and taking its
    console away would be the one packaging choice guaranteed to break it."""
    return engine.build_executable(code, _clean_name(name), console=True)
