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

## Providers and models

Five providers, all OpenAI-compatible:

| | key | default model |
|---|---|---|
| SiliconFlow *(default)* | `SILICONFLOW_API_KEY` | `deepseek-ai/DeepSeek-V4-Flash` |
| Z.ai | `ZAI_API_KEY` | `glm-5.3` |
| Groq | `GROQ_API_KEY` | best available |
| Google AI Studio | `GOOGLE_API_KEY` | `gemini-2.5-pro` |
| Novita | `NOVITA_API_KEY` | `deepseek/deepseek-v4-flash` |

Frida defaults to plain **DeepSeek V4 Flash** on SiliconFlow, and that is a
deliberate choice over the newer `0731` revision. 0731 is re-post-trained for
agentic work and plans better — but it is a *reasoning* model: it spends tens of
thousands of tokens thinking before it emits a character of code. In a workshop
you sit in front of, watching the file get written is most of the feedback, and
a minute of silence beforehand makes a better model into a worse tool.

Both are one `/model` away, and `/think` controls the budget where the provider
honours it:

```
/think off     fastest — code starts arriving immediately
/think 2000    a short think, then write
/think auto    let the model decide
```

When a model does think, you see it think — the reasoning streams into the
checklist with a running token count, and the moment the first real character
of code arrives the view switches to the file.

The preference is a ranked list matched against what the provider actually
offers, not a hardcoded id — so if `0731` isn't on your account yet it falls to
plain Flash rather than 404-ing every call. `/model` shows the list with
Frida's pick marked, and `let Frida choose` hands the decision back.

```bash
export ZAI_API_KEY=...            # or just run /key inside the workshop
frida --provider zai              # this run
frida                             # then /model to pin glm-5.3
```

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
| `/edit` | open the tool in `$EDITOR`; Frida picks the change up |
| `/uninstall` | take the command back off your PATH |
| `/resume` `/new` `/tools` `/rename` | sessions and history |
| `/theme` `/big` | how it looks |
| `/think` | how long the model may think before writing |
| `/model` `/key` `/cost` `/doctor` | settings, spend, and this machine |

The slash is optional at the main prompt: a bare word that names a command
**is** that command, so `test` runs the tests. A sentence that merely starts
with one is still a sentence, so `test it with an empty file` goes to Frida.
When you want the word taken literally, lead with `>`:

```
test                          → runs the tests
test it with an empty file    → an instruction
--help                        → runs your tool with --help
--help should mention foo     → an instruction
> test                        → the word "test", sent to Frida
```

A line that is nothing but flags runs your tool with them, because typing
`--help` at the prompt should show you the tool's help — not spend a minute
and real money asking a model to change it.

Commands work **everywhere** — at a question, at the plan, mid-flow. A question
is a pause, not a cage: you can `/code` to look at what you have, `/save` it,
and come back to the same question. Tab completes, `↑` recalls across sessions,
`ctrl-c` stops the current step without killing the session.

### It should look like something

Five themes. `/theme` on its own shows them all, swatched, and it sticks
between sessions.

```
── themes ──────────────────────────────────────────
  ✔  ember       warm amber · the default       text ✔ ✗ tool
     matrix      green phosphor                 text ✔ ✗ tool
     ice         cold blues · easiest at 3am    text ✔ ✗ tool
     synthwave   loud. gloriously loud          text ✔ ✗ tool
     paper       for light terminals            text ✔ ✗ tool
```

There is animation, and there is a rule about it: **it plays on something that
happens rarely, or it does not play.** The wordmark sweeps in once at startup.
A finished tool gets one pass of light when it lands. The things you do a
hundred times a day stay perfectly still, because a flourish you see once a
session is delight and the same flourish on every keystroke is a tax.

The one piece of theatre that is also load-bearing is the live code view. While
the model writes, the last few lines of your tool appear under the checklist as
they arrive:

```
  ⠦ Write jointcalc
    › thinking  4s
      1,840 chars  ·  575/s
      │ def split(total, ratio):
      │     weed = total * ratio
      │     return weed, total - weed
```

A spinner for ninety seconds tells you nothing. This tells you it understood
the request, and lets you hit `ctrl-c` at second four instead of second ninety.

`--plain` (or `FRIDA_PLAIN=1`) turns all motion off and changes nothing else.
Motion is off automatically whenever output isn't a terminal, so piping and CI
logs stay clean. `FORCE_COLOR=1` keeps the colours when you *do* want to pipe
somewhere that understands them — `frida code | less -R`.

### Frida cannot change your font — but it can draw big

Font size belongs to the terminal, not to the program drawing inside it. Any
CLI claiming to resize your font is lying to you. What Frida does instead:

`frida doctor` names your terminal and tells you where its font setting lives —
kitty, alacritty, foot, wezterm, konsole, gnome-terminal, xterm and VS Code are
all recognised:

```
font too small? that's kitty, not Frida:
  ctrl + shift + =   (ctrl+shift+- smaller, ctrl+shift+0 to reset)
  ~/.config/kitty/kitty.conf: font_size 16
```

And `/big` draws tool names and headings three rows tall, in the same block
idiom as the wordmark:

```
▄▀▄ █▀▄ █ █ █▀▀ █▄ █ ▀█▀ █ █ █▀▄ █▀▀
█▀█ █ █ █ █ █▀▀ █ ▀█  █  █ █ █▀▄ █▀▀
▀ ▀ ▀▀   ▀  ▀▀▀ ▀  ▀  ▀  ▀▀▀ ▀ ▀ ▀▀▀
```

It sticks between sessions, and `/big <anything>` draws one line on demand.

### What Frida does with your key

The key is stored in `~/.config/frida/config.json` at mode `0600`, and that is
the only place it is written.

- **Typing it doesn't echo, and isn't recorded.** `input()` echoes, and because
  the workshop loads readline it also appends to the history buffer — which
  Frida writes to disk. A pasted key was landing in
  `~/.local/share/frida/history` in plain text. Key entry now uses `getpass`,
  which readline never sees, and the history file is filtered for anything
  key-shaped on the way out and written `0600`.
- **Generated tools cannot see it.** Frida runs code a model wrote seconds ago,
  and that code used to inherit the whole environment — your provider keys,
  `GITHUB_TOKEN`, cloud credentials — with working network access. A tool doing
  `os.environ["SILICONFLOW_API_KEY"]` isn't even malicious; it's a plausible
  accident. The sandbox environment is now an allowlist: `PATH`, a locale, a
  temp dir, and a throwaway `HOME`. Nothing else.
- **Errors are redacted.** Provider error bodies get shown to you and fed back
  to the model. If one ever echoes your key, it is masked first.
- **Released repos are clean** — verified by the test suite, not by assertion.

### It sends less

Every assistant turn holds a full copy of your file, and all of them used to go
back to the model on every call: ten changes to a 300-line tool meant ten copies
of mostly-superseded code in each request. Superseded turns now collapse to a
one-line placeholder — **about 90% fewer input tokens by the tenth turn** — while
the current file is still sent in full and every instruction you gave is kept.

The placeholders are fixed, so the prompt prefix stays byte-stable as the
conversation grows and providers that cache prefixes still hit their cache.
That matters: cached input on DeepSeek is roughly a fifth the price of fresh
input, so saving tokens by rewriting history would have been a bad trade.

### It installs what the tool needs

A tool that imports `vlc` or `mutagen` used to fail static analysis, fail the
run, burn every fix round on an error no edit could repair, get installed on
your PATH regardless, and die with `ModuleNotFoundError` the first time you
typed its name. Nothing ever installed the dependencies.

Now the build has a step for it. Only genuinely-absent packages are installed —
on Arch, Pillow and requests are usually already there as native packages, and
reinstalling them is pure waste — and import names are mapped to real package
names, because `pip install vlc` fetches an unrelated project. The right one is
`python-vlc`.

They go into Frida's own venv, created with system site-packages, so nothing is
forced into your system Python.

### It won't call broken code "ready"

If the checks still fail after the fix rounds run out, the tool is **not**
installed. It is saved, the conversation is kept, and Frida says plainly that
it isn't working — rather than putting it on your PATH under the word "ready".
`/install` is then a decision you make.

And `/fix` works from a run you did yourself. `/run` tees stderr — echoing the
traceback live while keeping it — so the crash you just watched is the thing
`/fix` acts on, instead of "nothing to fix from, run /test first".

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
