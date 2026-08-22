#!/usr/bin/env python3
"""
frida.agent  —  the loop
========================
The part that decides what happens next.

Frida works the way a careful person works, and shows you the same checklist they
would keep:

    ✔ Agree on the shape          two questions, tapped not typed
    ✔ Plan the build              a name, a summary, the steps
    ◐ Write portscan              live, while the model writes it
    ○ Read the code               complete? parses? import-safe? analysed?
    ○ Run it for real             --help, exit codes, pipes, Ctrl-C, real cases
    ○ Fix what the run found      targeted patches, not whole rewrites
    ○ Hand it over                on your PATH, as a command

Nothing on that list is decoration. Every line is a gate that has failed for real
at some point, and the last four are the difference between a script that looks
right and a tool that works.

Two rules the loop keeps:

  Never claim a step passed that didn't run. A skipped verification is reported
  as skipped, in the checklist, where you can see it.

  Never run anything without consent. Destructive code stops the harness and
  asks. It doesn't refuse — refusing outright is how the previous generation of
  this program made itself useless to anyone building a disk wiper — but it does
  ask, and it tells you exactly what it found.

License: MIT
"""

import re
import time

from . import engine, harness, prompts, ship, ui

P = prompts.build(engine.DISTRO)

STEP_AGREE = "Agree on the shape"
STEP_PLAN = "Plan the build"
STEP_READ = "Read the code"
STEP_RUN = "Run it for real"
STEP_FIX = "Fix what the run found"
STEP_SHIP = "Hand it over"


# ==========================================================================
# THE TOOL UNDER CONSTRUCTION
# ==========================================================================
class Tool:
    """Everything Frida knows about the tool it is currently building."""

    def __init__(self, provider=None):
        self.sid = None
        self.name = "tool"
        self.title = ""
        self.named = False
        self.code = ""
        self.messages = []
        self.version = "testing"
        self.ver = "1.0.0"
        self.args = ""
        self.cases = []
        self.last_run = None
        self.provider = provider
        self.summary = ""
        # Every accepted version of the code, oldest first, each with the note
        # that produced the NEXT one. You cannot spend a week perfecting a tool
        # if a bad patch is unrecoverable, so nothing here is ever overwritten
        # in place — changes push, /undo pops, /revert jumps.
        self.history = []
        self.future = []
        # Bumping the version before the write meant the snapshot banked the NEW
        # number against the OLD code, so /versions showed two v1.0.0 entries and
        # told you nothing. The bump is now applied after the snapshot, by write().
        self.pending_bump = None

    # ---- history --------------------------------------------------------
    def snapshot(self, note=""):
        """Bank the current code before replacing it."""
        if not self.code:
            return
        self.history.append({"ver": self.ver, "code": self.code,
                             "note": (note or "").strip()[:400]})
        del self.history[:-60]      # keep the last 60; a tool is not a git repo
        self.future.clear()

    def previous_code(self):
        return self.history[-1]["code"] if self.history else None

    def undo(self):
        if not self.history:
            return None
        self.future.append({"ver": self.ver, "code": self.code, "note": "undone"})
        snap = self.history.pop()
        self.code, self.ver = snap["code"], snap["ver"]
        self.last_run = None
        return snap

    def redo(self):
        if not self.future:
            return None
        self.history.append({"ver": self.ver, "code": self.code, "note": "redone"})
        snap = self.future.pop()
        self.code, self.ver = snap["code"], snap["ver"]
        self.last_run = None
        return snap

    def revert(self, n):
        """Jump to version n as /versions numbers them (1-based, oldest first)."""
        if not (1 <= n <= len(self.history)):
            return None
        target = self.history[n - 1]
        self.snapshot("reverted to v" + target["ver"])
        self.code, self.ver = target["code"], target["ver"]
        self.last_run = None
        return target

    # ---- versioning -----------------------------------------------------
    def bump(self, kind="patch"):
        try:
            major, minor, patch = (int(x) for x in self.ver.split("."))
        except Exception:
            major, minor, patch = 1, 0, 0
        if kind == "minor":
            minor, patch = minor + 1, 0
        elif kind == "major":
            major, minor, patch = major + 1, 0, 0
        else:
            patch += 1
        self.ver = f"{major}.{minor}.{patch}"
        return self.ver

    def save(self):
        self.sid = engine.session_save(self.sid, self.name, self.code, self.messages,
                                       self.version, self.args, self.ver, self.named,
                                       self.title, self.history).get("id", self.sid)
        return self.sid

    @classmethod
    def restore(cls, record, provider=None):
        t = cls(provider)
        t.sid = record.get("id")
        t.name = record.get("name") or "tool"
        t.title = record.get("title") or t.name
        t.named = bool(record.get("named"))
        t.code = record.get("code") or ""
        t.messages = record.get("messages") or []
        t.version = record.get("version") or "testing"
        t.ver = record.get("ver") or "1.0.0"
        t.args = record.get("args") or ""
        t.history = record.get("history") or []
        return t


# ==========================================================================
# THE AGENT
# ==========================================================================
class Frida:
    def __init__(self, provider=None, auto=False, quiet=False, rounds=None):
        self.tool = Tool(provider)
        self.provider = provider
        self.auto = auto            # answer questions myself, approve my own plan
        self.quiet = quiet
        self.rounds = engine.AUTOTEST_MAX_ROUNDS if rounds is None else rounds
        self._attempt = 0        # how many times the tool has been run for real

    # ----------------------------------------------------------------------
    # model plumbing
    # ----------------------------------------------------------------------
    def _call(self, messages, board=None, tier="cheap", temperature=0.2,
              max_tokens=None, stage=""):
        """One model call, with its progress relayed into the task board."""
        def work():
            return engine.call_model(messages, provider_id=self.provider,
                                     temperature=temperature, tier=tier,
                                     max_tokens=max_tokens)

        if board is None:
            return work()

        if stage:
            board.set_stage(stage)
        chan, thread = engine.run_with_activity(work)
        result = {"error": "the model call ended without a result"}
        while True:
            ev = chan.drain(timeout=0.25)
            if ev is None:
                continue
            if ev is chan.done:
                break
            kind = ev.get("kind")
            if kind == "result":
                result = ev.get("result") or result
            elif kind == "gen":
                chars = ev.get("chars") or 0
                reasoning = ev.get("reasoning") or 0
                bits = [f"{chars // 5} words written"]
                if reasoning:
                    bits.append(f"{reasoning // 5} thinking")
                board.set_detail("  ·  ".join(bits))
            elif kind == "stage":
                board.set_detail(str(ev.get("text") or "")[:160])
        thread.join(timeout=1.0)
        return result

    # ----------------------------------------------------------------------
    # 1 · agree on the shape
    # ----------------------------------------------------------------------
    def clarify(self, request, board):
        """Ask the two or three questions that change what gets built."""
        board.start(STEP_AGREE, "working out what to ask")
        if self.auto:
            board.skip(STEP_AGREE, "not asking — auto mode")
            return request

        res = self._call(
            [{"role": "system", "content": P["intake"]},
             {"role": "user", "content": request}],
            board=board, tier="cheap", stage="working out what to ask")
        if res.get("error"):
            board.skip(STEP_AGREE, "asked nothing — " + _short(res["error"]))
            return request

        data = engine._parse_json_reply(res.get("reply", "")) or {}
        questions = data.get("questions") or []
        if data.get("ready") or not questions:
            board.finish(STEP_AGREE, "clear enough already")
            return request

        board.close()
        answers = []
        for q in questions[:3]:
            options = q.get("options") or []
            if not options:
                continue
            choice = ui.ask(q.get("q") or "", options, why=q.get("why") or "")
            answers.append(f"{q.get('q')} → {choice}")
        board.show()
        board.finish(STEP_AGREE, f"{len(answers)} answered" if answers else "asked nothing")
        if not answers:
            return request
        return request + "\n\nDecisions already made:\n  - " + "\n  - ".join(answers)

    # ----------------------------------------------------------------------
    # 2 · plan
    # ----------------------------------------------------------------------
    def plan(self, request, board):
        board.start(STEP_PLAN, "sketching the build")
        res = self._call(
            [{"role": "system", "content": P["plan"]},
             {"role": "user", "content": request}],
            board=board, tier="cheap", stage="sketching the build")
        data = engine._parse_json_reply(res.get("reply", "")) if not res.get("error") else None
        if not data:
            board.skip(STEP_PLAN, "building without a plan")
            return {"name": _name_from_request(request), "summary": "", "tasks": [], "risks": []}
        name = ship._clean_name(data.get("name") or _name_from_request(request))
        self.tool.name = name
        self.tool.title = data.get("name") or name
        self.tool.summary = (data.get("summary") or "").strip()
        board.finish(STEP_PLAN, name)
        return {"name": name, "summary": self.tool.summary,
                "tasks": [str(t) for t in (data.get("tasks") or [])][:6],
                "risks": [str(r) for r in (data.get("risks") or [])][:2]}

    def show_plan(self, plan, board):
        """Show it and, unless auto, let the user redirect before anything is built."""
        board.close()
        ui.rule("the plan")
        ui.blank()
        ui.out("  " + ui.c("amber", plan["name"], bold=True) +
               (("  " + ui.c("grey", plan["summary"])) if plan["summary"] else ""))
        ui.blank()
        for t in plan["tasks"]:
            ui.out("    " + ui.c("faint", ui.G.bullet) + " " + ui.c("cream", t))
        for r in plan["risks"]:
            ui.out("    " + ui.c("amber", "! ") + ui.c("grey", r))
        ui.blank()
        if self.auto:
            board.show()
            return True
        answer = ui.prompt(ui.G.arrow, "enter to build it · or say what to change",
                           commands=True)
        if answer.strip():
            board.show()
            return answer.strip()
        board.show()
        return True

    # ----------------------------------------------------------------------
    # 3 · write
    # ----------------------------------------------------------------------
    def write(self, instruction, board, step_label):
        """One build turn. Uses targeted edits when there is already code."""
        board.start(step_label, "thinking")
        t0 = time.time()
        prior = _last_user(self.tool.messages)

        if self.tool.code and not engine._wants_fresh_build(instruction):
            res = self._call_edit(instruction, prior, board)
            if res is None:
                # A missed patch format is cheap to recover from: rewrite in full.
                # A failed CALL is not — that path returns the error as-is below,
                # rather than re-sending the same request with more in it.
                board.set_stage("writing it out in full")
                res = self._full_write(instruction, board)
        else:
            res = self._full_write(instruction, board)

        if res.get("error"):
            board.fail(step_label, _short(res["error"]))
            return None, res["error"]

        reply = res.get("reply", "")
        code = engine.extract_code(reply)
        if not code:
            board.finish(step_label, "no code this turn")
            self.tool.messages.append({"role": "user", "content": instruction})
            self.tool.messages.append({"role": "assistant", "content": reply})
            return {"reply": reply, "code": "", "res": res}, None

        self.tool.messages.append({"role": "user", "content": instruction})
        self.tool.messages.append({"role": "assistant", "content": reply})
        had_code = bool(self.tool.code)
        self.tool.snapshot(instruction)
        self.tool.code = code
        if had_code:
            self.tool.bump(self.tool.pending_bump or "patch")
        self.tool.pending_bump = None
        secs = time.time() - t0
        board.finish(step_label, f"{len(code.splitlines())} lines  ·  {secs:.0f}s"
                     + ("  ·  patched" if res.get("edit_mode") else ""))
        return {"reply": reply, "code": code, "res": res}, None

    def _full_write(self, instruction, board):
        convo = ([{"role": "system", "content": P["system"]}]
                 + self.tool.messages
                 + [{"role": "user", "content": instruction}])
        return self._call(convo, board=board, tier="build",
                          temperature=engine.BUILD_TEMPERATURE,
                          max_tokens=engine.MAX_TOKENS["build"], stage="writing")

    def _call_edit(self, instruction, prior, board):
        board.set_stage("patching")
        res = engine.try_edit_round(self.tool.code, instruction, prior,
                                    provider_id=self.provider, retries=1)
        if res is None:
            return None
        if res.get("edit_call_failed"):
            return res
        return res

    # ----------------------------------------------------------------------
    # 4 · read the code (free, local)
    # ----------------------------------------------------------------------
    def read_code(self, board):
        board.start(STEP_READ, "checking it over")
        ok, report, checks = engine.smoke_test(self.tool.code)
        passed = [k for k, good, _ in checks if good]
        board.set_detail("  ".join(f"{ui.G.done} {k}" for k in passed))
        time.sleep(0.25)
        if ok:
            board.finish(STEP_READ, f"{len(passed)} checks clean")
            return True, ""
        failed = next((k for k, good, _ in checks if not good), "checks")
        board.fail(STEP_READ, failed)
        return False, report

    # ----------------------------------------------------------------------
    # 5 · run it for real
    # ----------------------------------------------------------------------
    def run_for_real(self, board, allow_danger=False):
        board.start(STEP_RUN, "writing the test cases")
        cases, error = harness.make_cases(self.tool.code, P, provider_id=self.provider)
        if error:
            board.set_detail("no model cases — running the standard checks only")
            cases = []
        self.tool.cases = cases

        done = {"n": 0}
        total = len(cases) + 3

        def on_case(case):
            done["n"] += 1
            mark = ui.G.done if case["ok"] else ui.G.fail
            board.set_detail(f"[{done['n']}/{total}] {mark} {case['name']}")

        board.set_stage("running it", f"0/{total}")
        result = harness.verify(self.tool.code, name=self.tool.name, cases=cases,
                                allow_danger=allow_danger, on_case=on_case)
        self.tool.last_run = result

        if result.get("blocked"):
            board.skip(STEP_RUN, "not run — destructive code")
            return result

        self._attempt += 1
        # Later runs overwrite this row, so say which attempt it was — otherwise a
        # tool that failed twice and passed on the third looks like it passed first
        # time, which is exactly the kind of quiet lie this program exists to catch.
        suffix = "" if self._attempt == 1 else f"  (attempt {self._attempt})"
        ran = len(result["cases"])
        if result["ok"]:
            board.finish(STEP_RUN, f"{ran}/{ran} cases passed" + suffix)
        else:
            bad = sum(1 for c in result["cases"] if not c["ok"])
            board.fail(STEP_RUN, f"{bad} of {ran} cases failed" + suffix)
        return result

    # ----------------------------------------------------------------------
    # 6 · fix
    # ----------------------------------------------------------------------
    def fix_loop(self, board, static_report="", run_result=None):
        """Feed real failures back until it is clean or the rounds run out."""
        rounds = 0
        report = static_report
        result = run_result

        while rounds < self.rounds:
            problems = report or (harness.problems_for_model(result) if result else "")
            if not problems:
                return True

            rounds += 1
            board.start(STEP_FIX, f"round {rounds} of {self.rounds}")
            instruction = (
                "The tool you just wrote does not pass. Fix it.\n\n" + problems +
                "\n\nReturn the complete corrected file. Change only what is needed to fix "
                "these problems — do not rewrite working parts, do not rename things, and do "
                "not remove features to make a failure go away.")
            res = self._call_edit(instruction, _last_user(self.tool.messages), board)
            if res is None:
                # The patch format missed. That says nothing about the provider, so
                # a full rewrite is worth the call.
                board.set_stage("rewriting it in full")
                res = self._full_write(instruction, board)
            elif res.get("edit_call_failed"):
                # The CALL failed — timeout, rate limit, a provider that is down.
                # Re-sending the same request with a BIGGER payload is how a two
                # minute failure became a five minute one in this engine's past.
                # Stop and say so instead.
                board.fail(STEP_FIX, _short(res.get("error", "the model call failed")))
                return False
            if res.get("error"):
                board.fail(STEP_FIX, _short(res["error"]))
                return False

            code = engine.extract_code(res.get("reply", ""))
            if not code:
                board.fail(STEP_FIX, "the model returned no code")
                return False
            self.tool.snapshot("fix round %d" % rounds)
            self.tool.code = code
            self.tool.bump("patch")
            self.tool.messages.append({"role": "user", "content": instruction})
            self.tool.messages.append({"role": "assistant", "content": res["reply"]})
            board.finish(STEP_FIX, f"round {rounds} applied")

            # re-verify: free checks first, then the real run
            passed, report = self.read_code(board)
            if not passed:
                continue
            report = ""
            result = self.run_for_real(board)
            if result.get("blocked"):
                return True
            if result["ok"]:
                return True

        board.fail(STEP_FIX, f"still failing after {self.rounds} rounds")
        return False

    # ----------------------------------------------------------------------
    # 7 · hand it over
    # ----------------------------------------------------------------------
    def hand_over(self, board, do_install=True):
        board.start(STEP_SHIP, "naming and installing")
        if not self.tool.named:
            self._name_it(board)
        self.tool.save()
        engine.library_save(self.tool.name, self.tool.code, self.tool.messages,
                            self.tool.version, self.tool.args, self.tool.sid,
                            self.tool.ver, self.tool.named, self.tool.title)
        result = {"installed": None, "copy": None}
        copy = ship.save_copy(self.tool.code, self.tool.name)
        result["copy"] = copy.get("path")
        if do_install:
            res = ship.install(self.tool.code, self.tool.name)
            if res.get("ok"):
                result["installed"] = res
                board.finish(STEP_SHIP, self.tool.name + " on your PATH"
                             if res.get("on_path") else self.tool.name + " installed")
            else:
                board.fail(STEP_SHIP, _short(res.get("error", "install failed")))
        else:
            board.finish(STEP_SHIP, "saved")
        return result

    def _name_it(self, board):
        res = self._call(
            [{"role": "system", "content": P["name"]},
             {"role": "user", "content": engine.fenced(self.tool.code)}],
            board=board, tier="cheap", stage="naming it")
        data = engine._parse_json_reply(res.get("reply", "")) if not res.get("error") else None
        if data and data.get("name"):
            self.tool.name = ship._clean_name(data["name"])
            self.tool.title = data.get("title") or self.tool.name
        self.tool.named = True

    # ----------------------------------------------------------------------
    # THE WHOLE THING
    # ----------------------------------------------------------------------
    def build(self, request, install=True, ask=True):
        """Take a sentence, hand back a working command. Returns the Tool."""
        self._attempt = 0
        write_step = "Write it"
        board = ui.TaskBoard("", [STEP_AGREE, STEP_PLAN, write_step, STEP_READ,
                                  STEP_RUN, STEP_FIX, STEP_SHIP])
        board.show()
        try:
            if ask:
                request = self.clarify(request, board)
            else:
                board.skip(STEP_AGREE, "not asking")

            plan = self.plan(request, board)
            board.tasks[2]["text"] = f"Write {plan['name']}"
            write_step = board.tasks[2]["text"]

            verdict = self.show_plan(plan, board)
            if isinstance(verdict, str):
                request = request + "\n\nAlso: " + verdict

            built, error = self.write(_build_instruction(request, plan), board, write_step)
            if error or not built or not built["code"]:
                board.close()
                if error:
                    ui.err(error)
                elif built:
                    ui.say(_prose(built["reply"]))
                return self.tool

            passed, report = self.read_code(board)
            result = None
            if passed:
                result = self.run_for_real(board)
                if result.get("blocked"):
                    board.close()
                    ui.warn("Frida did not run this tool:")
                    ui.note(result["blocked"])
                    if ui.confirm("run it anyway, in a scratch directory?", default=False):
                        board.show()
                        result = self.run_for_real(board, allow_danger=True)
                    else:
                        board.show()
                        board.skip(STEP_FIX, "nothing to fix from")
                        self.hand_over(board, do_install=install)
                        board.close()
                        self._closing(built)
                        return self.tool

            if (not passed) or (result and not result["ok"]):
                self.fix_loop(board, static_report=report, run_result=result)
            else:
                board.skip(STEP_FIX, "nothing to fix")

            delivered = self.hand_over(board, do_install=install)
            board.close()
            self._closing(built, delivered)
            return self.tool
        finally:
            board.close()

    def _closing(self, built, delivered=None):
        reply = _prose(built["reply"]) if built else ""
        if reply:
            ui.say(reply)
        if delivered and delivered.get("installed"):
            inst = delivered["installed"]
            ui.file_card(inst["path"], f"{self.tool.name} is installed",
                         run_hint=f"{self.tool.name} --help")
            if not inst.get("on_path"):
                ui.warn("~/.local/bin isn't on your PATH yet:")
                ui.note(inst["hint"])
        elif delivered and delivered.get("copy"):
            ui.file_card(delivered["copy"], "saved",
                         run_hint=f"python3 {delivered['copy']} --help")
        self.cost_line()

    def cost_line(self):
        u = engine.usage_summary()
        s = u["session"]
        if not s.get("calls"):
            return
        tilde = "" if u.get("cost_complete") else "~"
        edits = engine.edit_summary() if hasattr(engine, "edit_summary") else {}
        bits = [f"{s['in'] + s['out']:,} tokens", f"{s['calls']} calls",
                f"{tilde}${u['cost_usd']:.4f}"]
        if edits.get("applied"):
            bits.append(f"{edits['applied']} patched")
        ui.out("  " + ui.c("faint", "  ·  ".join(bits)))

    # ----------------------------------------------------------------------
    # FOLLOW-UPS
    # ----------------------------------------------------------------------
    def iterate(self, instruction, verify=True, install=True):
        """A change to the tool that already exists."""
        step = "Change it"
        board = ui.TaskBoard("", [step, STEP_READ, STEP_RUN, STEP_FIX, STEP_SHIP])
        board.show()
        try:
            self.tool.pending_bump = "patch"
            built, error = self.write(instruction, board, step)
            if error or not built:
                board.close()
                ui.err(error or "nothing came back")
                return
            if not built["code"]:
                board.close()
                ui.say(_prose(built["reply"]))
                return
            if not verify:
                board.skip(STEP_READ)
                board.skip(STEP_RUN)
                board.skip(STEP_FIX)
                self.hand_over(board, do_install=install)
                board.close()
                self._closing(built)
                return
            passed, report = self.read_code(board)
            result = self.run_for_real(board) if passed else None
            if (not passed) or (result and not result.get("ok") and not result.get("blocked")):
                self.fix_loop(board, static_report=report, run_result=result)
            else:
                board.skip(STEP_FIX, "nothing to fix")
            delivered = self.hand_over(board, do_install=install)
            board.close()
            self._closing(built, delivered)
        finally:
            board.close()

    def review(self):
        board = ui.TaskBoard("", ["Read it properly"])
        board.show()
        res = self._call(
            [{"role": "system", "content": P["review"]},
             {"role": "user", "content": engine.fenced(self.tool.code)}],
            board=board, tier="build", stage="reviewing")
        board.finish(0)
        board.close()
        if res.get("error"):
            ui.err(res["error"])
            return
        data = engine._parse_json_reply(res.get("reply", "")) or {}
        verdict = data.get("verdict") or ""
        issues = data.get("issues") or []
        if verdict:
            ui.say(verdict)
        if not issues:
            ui.ok("nothing worth changing")
            return
        colour = {"high": "red", "medium": "amber", "low": "grey"}
        for i in issues[:8]:
            sev = str(i.get("severity") or "low").lower()
            line = f"line {i['line']}" if i.get("line") else ""
            ui.out("  " + ui.c(colour.get(sev, "grey"), sev.upper().ljust(6)) +
                   ui.c("cream", str(i.get("what") or "")) +
                   (ui.c("faint", "  " + line) if line else ""))
            if i.get("fix"):
                ui.out("         " + ui.c("faint", str(i["fix"])))
        ui.blank()
        return issues

    def release(self, user="", repo="", branch="main"):
        board = ui.TaskBoard("", ["Write the release version", "Assemble the repo"])
        board.show()
        try:
            self.tool.version = "release"
            self.tool.pending_bump = "minor"
            built, error = self.write(
                "Produce the RELEASE version of this tool: a proper module docstring, clean "
                "structure, comments where the code isn't obvious, no dead code, no debug "
                "output. Same behaviour, same interface. Return the complete file.",
                board, "Write the release version")
            if error:
                board.close()
                ui.err(error)
                return None
            board.start("Assemble the repo", "writing the README")
            res = self._call(
                [{"role": "system", "content": P["release"]},
                 {"role": "user", "content": engine.fenced(self.tool.code)}],
                board=board, tier="cheap", stage="writing the README")
            meta = engine._parse_json_reply(res.get("reply", "")) or {}
            out = ship.write_repo(self.tool.code, meta.get("name") or self.tool.name,
                                  meta, user=user, repo=repo, branch=branch)
            board.finish("Assemble the repo", str(len(out["files"])) + " files")
            board.close()
            ui.file_card(out["path"] + "/README.md", "repo ready", extra=out["files"])
            ui.rule("push it")
            ui.code(out["push"], numbers=False)
            ui.blank()
            return out
        finally:
            board.close()


# ==========================================================================
# HELPERS
# ==========================================================================
def _build_instruction(request, plan):
    steps = "\n".join(f"  {i}. {t}" for i, t in enumerate(plan.get("tasks") or [], 1))
    text = request
    if plan.get("name"):
        text += f"\n\nName the command `{plan['name']}` and set prog= to that."
    if steps:
        text += "\n\nThe plan you agreed:\n" + steps
    text += ("\n\nWrite it now: one complete single-file script, and a couple of sentences "
             "before it saying what you built.")
    return text


def _last_user(messages):
    for m in reversed(messages or []):
        if m.get("role") == "user":
            return m.get("content", "")[:2000]
    return ""


def _name_from_request(request):
    words = re.findall(r"[a-z]{3,}", (request or "").lower())
    skip = {"the", "and", "that", "with", "for", "make", "build", "tool", "cli",
            "command", "line", "script", "python", "program", "write", "create"}
    for w in words:
        if w not in skip:
            return w[:14]
    return "tool"


def _prose(reply):
    """The model's message with its code block taken out."""
    text = re.sub(r"```[a-zA-Z0-9_+-]*\n.*?```", "", reply or "", flags=re.S)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text


def _short(text, limit=60):
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[:limit - 1] + "…"
