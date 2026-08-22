<h1 align="center">Frida</h1>

<p align="center">
  <b>Describe a command-line tool. Get a working one, on your PATH, in a minute.</b>
</p>

<p align="center">
  <img alt="platform" src="https://img.shields.io/badge/Linux-CachyOS%20%C2%B7%20Arch%20%C2%B7%20Debian%20%C2%B7%20Fedora%20%C2%B7%20SUSE-1793d1?style=flat-square&logo=linux&logoColor=white">
  <img alt="python" src="https://img.shields.io/badge/Python-3.10%2B-e8a33d?style=flat-square&logo=python&logoColor=white">
  <img alt="interface" src="https://img.shields.io/badge/interface-terminal%20only-9fe04a?style=flat-square">
  <img alt="deps" src="https://img.shields.io/badge/dependencies-none-46c7d4?style=flat-square">
  <img alt="license" src="https://img.shields.io/badge/License-MIT-c79be0?style=flat-square">
</p>

<p align="center">
  <i>No window. No browser. No toolkit. A terminal program that makes terminal programs.</i>
</p>

---

```
$ frida "hash every file in a directory and show me the duplicates"

  ✔ Agree on the shape        · 2 answered
  ✔ Plan the build            · dupefind
  ✔ Write dupefind            · 186 lines · 41s
  ✔ Read the code             · 5 checks clean
  ✔ Run it for real           · 7/7 cases passed
  — Fix what the run found    · nothing to fix
  ✔ Hand it over              · dupefind on your PATH

  ✔ dupefind is installed                              6.1 KB
    /home/you/.local/bin/dupefind
    run it: dupefind --help
```

That checklist is the whole idea. Every line is a gate, every gate has to actually
pass, and you can see which one you're waiting on.

---

## What makes it different from asking a chatbot for a script

A chatbot hands you code. Frida hands you a tool that has been **run**.

Before anything reaches your PATH, Frida:

| | |
|---|---|
| **reads it** | complete file (no `# ... rest unchanged`), parses, no work at import time, has an entry point |
| **analyses it** | ruff + a purpose-built AST pass — undefined names, wrong-arity calls, unassigned attributes, mutable defaults. Free, local, and every defect caught here is a paid fix round that never happens |
| **runs `--help`** | exits 0, has a real description, has a worked example |
| **runs it with no arguments** | a tool with required arguments must exit **2**, like argparse says |
| **writes its own test cases** | the model produces real invocations — normal run, bad input, empty input — with files staged into a scratch directory |
| **pipes it into `head`** | the `BrokenPipeError` traceback nobody ever tests for |
| **sends it Ctrl-C** | exit 130, quietly, no stack trace |
| **checks the disciplines** | results on stdout, talk on stderr, **no ANSI escape codes in output that isn't a terminal** |

Then it feeds every real failure back — as observed evidence, not as an opinion —
and patches the code until the run is clean.

Everything runs in a scratch directory with a scratch `HOME`. A generated tool
that writes to `~/.config/whatever` writes into the sandbox, not into yours.

---

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/the-priest/frida/main/install.sh | bash
```

Installs into `~/.local/share/frida`, puts `frida` on your PATH, no root needed.
Re-run to update, `install.sh --uninstall` to remove.

The installer writes the PATH line in **your** login shell's syntax — including
fish, which CachyOS ships by default and which does not understand `export`.

Then:

```bash
frida doctor
```

It prints what's present, what's missing, and one copy-pasteable command in your
package manager's names to fix it. On CachyOS that's a `pacman` line, not `apt`.

**Nothing to install beyond Python 3.10+.** No Rich, no Textual, no curses. The
whole interface is ANSI escape codes and a careful eye on what a terminal
actually guarantees — truecolour degrades to 256, to 16, to none; the live
checklist degrades to plain scrolling lines the moment you pipe it somewhere.

---

## Set an API key

Frida asks for one the first time. Or set it yourself:

| Provider | Environment variable | |
|---|---|---|
| **SiliconFlow** | `SILICONFLOW_API_KEY=sk-...` | **default** |
| Groq | `GROQ_API_KEY=gsk_...` | fallback, fast, free tier |
| Google AI Studio | `GOOGLE_API_KEY=AIza...` | |
| Novita AI | `NOVITA_API_KEY=sk_...` | |

Keys live in `~/.config/frida/config.json` and go nowhere else. Everything except
the model call happens on your machine.

---

## Use it

```bash
frida                              # open the workshop
frida "a tool that ..."            # build one now, then stay for changes
frida "a tool that ..." --yes      # no questions, no approval, just build it
frida resume                       # pick up where you left off
frida tools                        # everything you've built
frida code | wc -l                 # the source, on stdout, pipeable
frida doctor --json                # for scripts
```

### Two kinds of input

Anything that isn't a command is an instruction for Frida — *"add `--json`"*,
*"it crashes on an empty file"*, *"make the output a table"*. Everything else
is a command, and commands do exactly one predictable thing:

| | |
|---|---|
| `/run [args]` | run it with arguments |
| `/test` | run it for real again — cases, pipes, exit codes |
| `/fix` | feed the last failing run back and patch it |
| `/review` | a proper read-through: severity, line, and the change to make |
| `/undo` `/redo` `/versions` `/revert <n>` | every version is kept; nothing is lost |
| `/code` `/diff` `/status` | look at it, compare it, see where it stands |
| `/deps` `/install` `/save` | dependencies, PATH, or a copy in `~/frida-tools` |
| `/release` | a GitHub-ready repo — README, install.sh, LICENSE, push commands |
| `/freeze` | a single-file binary via PyInstaller |
| `/resume` `/new` `/tools` `/rename` | sessions and history |
| `/model` `/key` `/cost` `/doctor` | settings, spend, and this machine |

The slash is optional at the main prompt: a bare word that names a command
**is** that command, so `test` runs the tests. A sentence that merely starts
with one is still a sentence, so `test it with an empty file` goes to Frida.
When you want the word taken literally, lead with `>`:

```
test                          → runs the tests
test it with an empty file    → an instruction
> test                        → the word "test", sent to Frida
```

Commands work **everywhere** — at a question, at the plan, mid-flow. A question
is a pause, not a cage: you can `/code` to look at what you have, `/save` it,
and come back to the same question. Tab completes, `↑` recalls across sessions,
`ctrl-c` stops the current step without killing the session.

### Nothing you build is lost

Every accepted change is a version. `/versions` lists them, `/undo` steps back,
`/revert 3` jumps. A bad patch at midnight costs you one keystroke, which is
the only reason it is safe to keep going at midnight.

```
── versions ──────────────────────────────────────────────
   1  v1.0.0     27 ln  first build
   2  v1.0.1     51 ln  add --json
  ✔  v1.0.2     58 ln  current
```

---

## What it builds

One self-contained Python file per tool, and it is opinionated about the shape,
because the shape is what separates a script from a tool:

- **Exit codes are the API.** 0 success, non-zero failure, 2 bad usage, 130 Ctrl-C.
  A tool that prints `error:` and exits 0 lies to `&&`, to `set -e`, and to CI.
- **stdout is data, stderr is talk.** Results pipe. Progress doesn't pollute them.
- **`--help` is the documentation**, with a worked example you can paste, and
  `--version` is always there.
- **`--json` whenever there's structure** — humans get the table, scripts get JSON,
  nobody parses your columns with awk.
- **Colour only when attached to a terminal**, `NO_COLOR` honoured.
- **stdin when the argument is `-`** or absent and stdin isn't a tty.
- **XDG paths**, `pathlib`, `encoding="utf-8"` everywhere, argv lists not `shell=True`.
- **It knows what machine it's for.** The prompt is built at startup from your
  actual distro, so a tool that shells out to `nmap` tells you
  `sudo pacman -S nmap` on CachyOS — not the Debian package name.

---

## Spend

Frida is built to make a token budget last.

- **Targeted edits.** A one-line change asks for a SEARCH/REPLACE patch applied on
  your machine, not a retyped file — 4–8× fewer output tokens on every fix and
  iterate round. A patch that doesn't apply cleanly falls back to a rewrite, and
  the whole scheme switches itself off if a model can't produce the format.
- **Free local analysis first.** ruff and the AST pass catch wrong argument counts,
  undefined names and mutable defaults for nothing. Each one is a fix round
  that never gets billed.
- **Superseded code collapses out of the history**, so a long session doesn't
  resend ten copies of the same growing file.
- **Streamed responses**, so the timeout is idle-time. A reasoning model thinking
  for three minutes is not mistaken for a hang and re-sent.

`frida cost` breaks it down. The figures are list-rate indicators, not an invoice.

---

## Tests

```bash
tests/run_all.sh
```

Runs the whole pipeline against a fake provider — no network, no key, no tokens.
The fake deliberately returns a **broken** first draft: colour written straight to
stdout, no example in `--help`, an uncaught `FileNotFoundError`. The test passes
only if Frida catches all three, fixes them, installs the corrected tool, and the
installed command then behaves from a real shell.

If the harness ever stops catching that tool, the tests go red. That's the point
of them.

---

## It came from somewhere

Frida is the terminal-only descendant of **theDawg**, which built GUI apps and
carried a GTK4 window, a WebKit view and a local HTTP server to do it. All of that
is gone — no server, no browser, no toolkit, no screenshotting a hidden X display
to find out whether a program works.

What survived is the part worth keeping: the provider chain and its retry policy,
streamed responses, per-model context trimming, the AST analyser, targeted edit
blocks, the dependency venv, the packaging. Roughly 1,800 lines of window came
out. What went in was a test harness that runs command-line tools the way a person
does — which a command-line tool, unlike a window, will just tell you about
directly.

---

<p align="center">
  <i>Named after a dog. She was very good, and she is not here for this one.</i><br>
  <sub>She'd have been asleep under the desk the whole time.</sub>
</p>
