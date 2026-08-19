#!/usr/bin/env python3
"""Fixture tests for the two Bash hooks. The corpus is empirical: every EATEN entry is a
command the Claude Code harness mangled when run through the Bash tool (verified byte-exact
against a file-run control), every OK entry is a shape that came through byte-exact and
must stay allowed, MANGLED_OUTPUT / CLEAN_OUTPUT are verbatim outputs (flagged / quiet).
Add to the corpus before touching a rule; a rule change that flips a corpus entry is a
finding, not a fix.

Run: python tests/test_bash_mangling.py
"""
import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
HOOKS = os.path.join(os.path.dirname(HERE), "hooks")
sys.path.insert(0, HOOKS)
import bash_mangling_rules as rules  # noqa: E402
import bash_pre  # noqa: E402
import bash_post  # noqa: E402

# --- corpus: commands the harness ate (axis 1: backslash runs; axis 2: non-ASCII) --------

EATEN = {
    "axis1: python heredoc, \\\\n and \\\" in the body -> real newline, stripped quote":
        "python - <<'EOF'\nprint(\"a\\\\nb and \\\"q\\\"\")\nEOF\n",
    "axis1: python heredoc rewriting a literal with \\\\n (the replace became a no-op)":
        "python - <<'EOF'\np='main.das'; s=open(p).read()\nold='for the network rows\\n\")'\nnew='for the network rows\\\\n\")'\ns=s.replace(old,new)\nEOF\n",
    "axis1: cat heredoc with backslash pairs":
        "cat > \"$D/f.txt\" <<'EOF'\na\\\\nb and s|a\\\\|b|\nEOF\n",
    "axis1: backslash ladder in a quoted heredoc":
        "cat > \"$D/l.txt\" <<'EOF'\n1:\\ 2:\\\\ 3:\\\\\\ 4:\\\\\\\\\nEOF\n",
    "axis1: backslash ladder in a single-quoted argument":
        r"printf '%s' '1:\ 2:\\ 3:\\\ 4:\\\\' > \"$D/l2.txt\"",
    "axis1: backslash pair in single quotes (a Windows path)":
        r"printf '%s' 'lit:D:\\MCP\\x' > \"$D/p.txt\"",
    "axis1: sed with a doubled backslash in its expression":
        'sed -i "s|a\\\\\\\\|b|" "$D/s.txt"',
    "axis1: python -c with a quadruple backslash":
        'python -c "print(\'P31-OK \\\\\\\\ two\')"',
    "axis1: three backslashes in double quotes":
        'printf "%s" "x\\\\\\"y" > "$D/t.txt"',
    "axis2: em dash in a single-quoted printf":
        "printf '%s' 'Verified rather than assumed \u2014 the whole smoke' > \"$D/r1.md\"",
    "axis2: em dash alone":
        "printf '%s' '\u2014' > \"$D/d.txt\"",
    "axis2: non-ASCII inside a quoted heredoc":
        "cat > \"$D/q.txt\" <<'EOF'\n\u201cquoted\u201d text\nEOF\n",
    "axis2: non-ASCII in a python heredoc string (PR body edit)":
        "python - \"$S\" <<'EOF'\ns = s.replace(\"Two changes\", \"Three changes \u2014 see above\")\nEOF\n",
    "unquoted heredoc with $ in the body (bash semantics, never meant)":
        "git commit -F - <<EOF\nrpath: $ORIGIN and $ORIGIN/../lib\nEOF\n",
}

# --- corpus: shapes that came through byte-exact and must stay allowed -------------------

OK = {
    "backtick inside single quotes":
        "printf '%s' 'a `word` b' > \"$D/a.txt\"",
    "backtick inside a quoted heredoc body":
        "cat > \"$D/b.txt\" <<'EOF'\na `word` b\nEOF\n",
    "backticks inside a python heredoc (PR body edit without non-ASCII)":
        'python - "$S" <<\'EOF\'\nimport sys\ns = open(p).read()\ns = s.replace("- Fixture tests `python -W error ci/test_wheel_build.py`: 9/9", "x")\nEOF\n',
    "python heredoc, plain code":
        "python - <<'EOF'\nprint('P07-OK')\nEOF\n",
    "python heredoc with single quotes in the body":
        "python - <<'EOF'\nold = '''    if system == \"Windows\":\n        return table[machine]\n'''\nprint(old)\nEOF\n",
    "python heredoc with f-string braces":
        "python - <<'EOF'\ny = 7\nprint(f\"val={y} braces {{lit}} and x{y}\")\nEOF\n",
    "$( ) and $HOME inside single quotes stay literal":
        "printf '%s' 'lit $(echo x) $HOME end' > \"$D/s.txt\"",
    "$( ) and ${ } in double quotes (normal bash)":
        'jid=$(gh run view 1 --json jobs --jq ".jobs[0].databaseId"); for pair in a:b c:d; do id=${pair%%:*}; f=${pair#*:}; echo "$id $f"; done',
    "quoted heredoc commit message with $ORIGIN, #3779 and apostrophes":
        "git add -A && git commit -q -F - <<'EOF'\nrelease bundle: -exe tools find the runtime lib\n\ndaslang -exe stamped its output with rpath $ORIGIN + the build-tree lib/ (#3779); it's Boris's call.\n\nCo-Authored-By: Claude Fable 5 <noreply@anthropic.com>\nEOF\ngit log --oneline -1",
    "gh with a body file":
        'gh pr create -R GaijinEntertainment/daScript --base master --head x --title "t" --body-file "$S/pr.md"',
    "gh api reply from a file":
        'gh api -X POST repos/o/r/pulls/1/comments/2/replies -F body=@"$S/r1.md" --jq .id',
    "python script by path":
        'python "C:/Users/Boris/AppData/Local/Temp/claude/scratchpad/patch_copilot.py" && python -W error ci/test_wheel_build.py',
    "cat heredoc writing a file, quoted delimiter, $ inside":
        "cat > \"$S/route.sh\" <<'EOF'\nif [[ \"$TAG\" =~ ^v?[0-9]+$ ]]; then echo pypi; fi\nEOF\nbash \"$S/route.sh\"",
    "unquoted heredoc with no expansions":
        "cat <<EOF\nhello world\nEOF\n",
    "python heredoc with unquoted delimiter, expansions intended":
        "python - <<EOF\nprint('home=$HOME sub=`echo s`')\nEOF\n",
    "ASCII printf with ( # ! inside single quotes":
        "printf '%s' 'paren ( hash # bang ! done' > \"$D/c.txt\"",
    "long single-quoted string with the '\"'\"' dance":
        "printf '%s' 'it'\"'\"'s fine and '\"'\"'quoted'\"'\"' too' > \"$D/e.txt\"",
    "backslash pair in double quotes before an ordinary char (bash collapses it too)":
        "echo '{\"jsonrpc\":\"2.0\",\"id\":1}' | timeout 20 cmd //c \"D:\\\\MCP\\\\x.cmd\" | head -c 300",
    "lone backslashes before special characters":
        "printf '%s' 'q:\\\" d:\\$ b:\\` t:\\t' > \"$D/lone.txt\"",
    "line continuation":
        "echo continued-ok \\\n  > \"$D/cont.txt\"",
    "pipes, redirects, grep -E with braces":
        "bash ci/smoke_test_bundle.sh \"$S/lb\" 2>&1 | grep -E \"dastest.exe runs|lint.exe lints|ALL OK|FAILED:\"",
    "for loop":
        "for x in a b; do printf '%s' \"$x\"; done > \"$D/for.txt\"",
    "bash heredoc script (no backslash pairs)":
        "bash <<'EOF'\nset -e\necho hi > \"$D/bash.txt\"\nEOF\n",
    "python -c with a single escaped quote and no backslash pairs":
        "python -c \"import json; d=json.load(open('x.json')); print(list(d))\"",
    "awk with an escaped tab in single quotes (lone backslash)":
        "gh pr checks 3781 -R o/r | awk -F'\\t' '{print $2}' | sort | uniq -c",
}

# --- corpus: outputs of mangled runs (verbatim fragments) ---------------------------------

MANGLED_OUTPUT = {
    "wrapper tail only (the non-ASCII class leaves just this)":
        "/usr/bin/bash: line 34: export TEMP='C:\\Users\\Boris\\AppData\\Local\\Temp' && eval 'printf' && pwd -P >| /c/Users/Boris/AppData/Local/Temp/claude-2dca-cwd: No such file or directory",
    "eval syntax error":
        "/usr/bin/bash: eval: line 0: syntax error near unexpected token `done'\n/usr/bin/bash: eval: line 0: `gh run view 1; until for r in 1 2; do echo; done | grep -qv completed; done'",
    "command substitution syntax error":
        "/usr/bin/bash: command substitution: line 1: syntax error: unexpected end of file\n/usr/bin/bash: line 0: wheel_build:: command not found",
    "unterminated quote":
        "/usr/bin/bash: -c: line 3: unexpected EOF while looking for matching `''\n/usr/bin/bash: -c: line 4: syntax error: unexpected end of file",
    "backslash sequence split":
        "/usr/bin/bash: line 32: \\ \\: No such file or directory\n/usr/bin/bash: line 32: export TEMP='C:\\Users\\Boris\\AppData\\Local\\Temp' ...",
    "words ran as commands then the wrapper dump":
        "/usr/bin/bash: line 0: pypi_route: command not found\n/usr/bin/bash: line 0: v?X.Y.Z: command not found\nERROR: You must give at least one requirement to install\n/usr/bin/bash: line 0: export TEMP='C:\\Users\\Boris\\AppData\\Local\\Temp' TMP='...' && shopt -u extglob 2>/dev/null || true && eval 'S=\"...\"; printf' ...",
    "python saw a collapsed escape":
        "<stdin>:3: SyntaxWarning: invalid escape sequence '\\z'\nP10 a\nb",
    "sed saw a collapsed escape":
        "sed: -e expression #1, char 7: unterminated `s' command",
}

CLEAN_OUTPUT = {
    "ordinary failure: program's own error":
        "error[30151]: syntax error, unexpected name, expecting ']'\nutils/internal/test-release/utils_phase.das:32:26\nrc=1",
    "a real command-not-found (typo), no wrapper dump":
        "/usr/bin/bash: line 1: dastset: command not found",
    "clean success":
        "17 tests, 17 passed, 0 failed, 0 errors, 0 skipped\nSUCCESS! (0.757411s)",
    "python traceback":
        "Traceback (most recent call last):\n  File \"<stdin>\", line 19, in <module>\nAssertionError: block",
    "export TEMP mentioned in ordinary output without a cascade":
        "PowerShell: $env:TEMP set; run export TEMP=... yourself\nok",
}


class PreRules(unittest.TestCase):
    def test_every_eaten_command_is_denied(self):
        for name, cmd in EATEN.items():
            with self.subTest(name):
                self.assertIsNotNone(rules.pre_check(cmd), f"should deny: {name}")

    def test_every_ok_command_is_allowed(self):
        for name, cmd in OK.items():
            with self.subTest(name):
                self.assertIsNone(rules.pre_check(cmd), f"should allow: {name} -> {rules.pre_check(cmd)}")

    def test_messages_name_the_fix(self):
        for name, cmd in EATEN.items():
            with self.subTest(name):
                self.assertIn("Write tool", rules.pre_check(cmd))

    def test_non_ascii_rule_names_the_codepoint(self):
        msg = rules.rule_non_ascii("echo '\u2014'")
        self.assertIn("U+2014", msg)
        self.assertIsNone(rules.rule_non_ascii("echo plain ascii ~ {} [] | & ;"))

    def test_backslash_runs_scanner_tracks_context(self):
        runs = list(rules.backslash_runs("echo 'a\\\\b' \"c\\\\\\\\d\" e\\\\\\f"))
        self.assertEqual([(2, "literal", "b"), (4, "processed", "d"), (3, "processed", "f")], runs)
        heredoc = list(rules.backslash_runs("cat <<'EOF'\nx\\\\y\nEOF\ncat <<EOF\nx\\\\y\nEOF\n"))
        self.assertEqual([(2, "literal", "y"), (2, "processed", "y")], heredoc)

    def test_backslash_pair_rule_boundaries(self):
        self.assertIsNone(rules.rule_backslash_pair('printf "%s" "D:\\\\MCP\\\\x"'), "processed pair before an ordinary char cancels out")
        self.assertIsNotNone(rules.rule_backslash_pair('printf "%s" "x\\\\\\"y"'), "three in double quotes always change")
        self.assertIsNotNone(rules.rule_backslash_pair('printf "%s" "x\\\\$y"'), "pair before a double-quote-special char")
        self.assertIsNotNone(rules.rule_backslash_pair("printf '%s' 'x\\\\y'"), "any pair in single quotes is a byte change")
        self.assertIsNone(rules.rule_backslash_pair("printf '%s' 'x\\y'"), "lone backslashes survive")

    def test_heredoc_parser_sees_quoting(self):
        cmd = "cat <<'EOF'\na $b\nEOF\ncat <<X\nc\nX\n"
        docs = [(q, cmd[a:b]) for q, a, b in rules.heredocs(cmd)]
        self.assertEqual([(True, "a $b"), (False, "c")], docs)

    def test_unquoted_heredoc_rule_is_for_prose_sinks_only(self):
        self.assertIsNone(rules.rule_unquoted_heredoc_expansion("git commit -F - <<EOF\nplain\nEOF\n"))
        self.assertIsNotNone(rules.rule_unquoted_heredoc_expansion("git commit -F - <<EOF\na `b`\nEOF\n"))
        self.assertIsNotNone(rules.rule_unquoted_heredoc_expansion("gh pr create --body-file - <<EOF\ncost $5\nEOF\n"))
        self.assertIsNone(rules.rule_unquoted_heredoc_expansion("cat <<EOF\na `b` $c\nEOF\n"), "expansion into cat/python may be intended")


class PostSignatures(unittest.TestCase):
    def test_every_mangled_output_is_flagged(self):
        for name, out in MANGLED_OUTPUT.items():
            with self.subTest(name):
                self.assertIsNotNone(rules.post_check("x", out), f"should flag: {name}")

    def test_clean_outputs_stay_quiet(self):
        for name, out in CLEAN_OUTPUT.items():
            with self.subTest(name):
                self.assertIsNone(rules.post_check("x", out), f"should be quiet: {name}")

    def test_each_signature_is_reachable_alone(self):
        # one corpus fragment per signature, so deleting any single signature reds a test
        for rx, _why in rules.POST_SIGNATURES:
            hits = [n for n, out in MANGLED_OUTPUT.items() if rx.search(out)]
            with self.subTest(rx.pattern):
                self.assertTrue(hits, f"no corpus entry exercises {rx.pattern}")
        for name, out in MANGLED_OUTPUT.items():
            if name == "words ran as commands then the wrapper dump":
                continue
            with self.subTest(name):
                self.assertEqual(1, sum(1 for rx, _ in rules.POST_SIGNATURES if rx.search(out)),
                                 f"{name} should isolate exactly one signature")

    def test_cascade_needs_both_halves(self):
        self.assertTrue(rules._command_not_found_cascade("x: command not found\nblah eval 'y'"))
        self.assertFalse(rules._command_not_found_cascade("x: command not found\nno anchor"))
        self.assertFalse(rules._command_not_found_cascade("eval 'y' but nothing missing"))

    def test_cascade_is_bounded_not_quadratic(self):
        import time
        text = ("x: command not found\n" * 20000) + "tail with no anchor at all"
        t0 = time.perf_counter()
        self.assertIsNone(rules.post_check("x", text))
        self.assertLess(time.perf_counter() - t0, 0.5, "a 400 KB non-matching cascade must stay cheap")

    def test_backslash_command_flags_even_with_quiet_output(self):
        msg = rules.post_check("printf '%s' 'lit:D:\\\\MCP\\\\x'", "")
        self.assertIn("backslash run", msg)
        self.assertIsNone(rules.post_check("printf '%s' 'plain'", ""))

    def test_message_says_not_to_trust_side_effects(self):
        msg = rules.post_check("x", MANGLED_OUTPUT["eval syntax error"])
        self.assertIn("do not trust", msg)
        self.assertIn("Write tool", msg)


class PreHook(unittest.TestCase):
    def test_decide_denies_with_the_documented_shape(self):
        out = bash_pre.decide({"tool_name": "Bash", "tool_input": {"command": "echo '\u2014'"}})
        self.assertEqual("deny", out["hookSpecificOutput"]["permissionDecision"])
        self.assertEqual("PreToolUse", out["hookSpecificOutput"]["hookEventName"])
        self.assertTrue(out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_decide_allows_clean_and_ignores_other_tools(self):
        self.assertIsNone(bash_pre.decide({"tool_name": "Bash", "tool_input": {"command": "git status"}}))
        self.assertIsNone(bash_pre.decide({"tool_name": "Read", "tool_input": {"command": "echo '\u2014'"}}),
                          "a non-Bash tool is ignored even when its input would be denied as a command")
        self.assertIsNone(bash_pre.decide({"tool_name": "Bash", "tool_input": {}}))
        self.assertIsNone(bash_pre.decide({}))

    def test_process_contract(self):
        deny = run_hook("bash_pre.py", {"tool_name": "Bash", "tool_input": {"command": "echo '\u2014'"}})
        self.assertEqual(0, deny.returncode)
        self.assertEqual("deny", json.loads(deny.stdout)["hookSpecificOutput"]["permissionDecision"])
        allow = run_hook("bash_pre.py", {"tool_name": "Bash", "tool_input": {"command": "git status"}})
        self.assertEqual(0, allow.returncode)
        self.assertEqual("", allow.stdout.strip())

    def test_fails_open_on_garbage_stdin(self):
        r = subprocess.run([sys.executable, os.path.join(HOOKS, "bash_pre.py")], input="not json",
                           capture_output=True, text=True)
        self.assertEqual(0, r.returncode)
        self.assertEqual("", r.stdout.strip())
        self.assertIn("hook error", r.stderr)

    def test_fails_open_when_the_rules_module_is_missing(self):
        env = dict(os.environ, PYTHONPATH="")
        r = subprocess.run([sys.executable, "-c",
                            "import sys, json, io; sys.argv=['x']; sys.path[:]=[p for p in sys.path if 'hooks' not in p];"
                            "import importlib.util; spec=importlib.util.spec_from_file_location('bp', %r);"
                            "m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m);"
                            "sys.stdin=io.StringIO(json.dumps({'tool_name':'Bash','tool_input':{'command':'x'}}));"
                            "m.os.path.dirname=lambda p: 'nope'; sys.exit(m.main())" % os.path.join(HOOKS, "bash_pre.py")],
                           capture_output=True, text=True, env=env)
        self.assertEqual(0, r.returncode, r.stderr)
        self.assertIn("hook error", r.stderr)


class PostHook(unittest.TestCase):
    def test_response_text_reads_dict_string_and_other(self):
        self.assertIn("boom", bash_post.response_text({"stdout": "ok", "stderr": "boom"}))
        self.assertEqual("raw", bash_post.response_text("raw"))
        self.assertEqual("", bash_post.response_text(None))
        for key in ("output", "result", "content", "error", "message"):
            with self.subTest(key):
                self.assertEqual("v", bash_post.response_text({key: "v"}))
        self.assertIn("eval: line 0: syntax error", bash_post.response_text({"weird": {"nested": "eval: line 0: syntax error"}}))

    def test_decide_flags_only_mangled(self):
        ev = {"tool_name": "Bash", "tool_input": {"command": "x"}, "tool_response": {"stdout": MANGLED_OUTPUT["eval syntax error"]}}
        out = bash_post.decide(ev)
        self.assertIn("shell-ate-it", out["additionalContext"])
        self.assertEqual("PostToolUse", out["hookSpecificOutput"]["hookEventName"])
        quiet = {"tool_name": "Bash", "tool_input": {"command": "x"}, "tool_response": {"stdout": CLEAN_OUTPUT["clean success"]}}
        self.assertIsNone(bash_post.decide(quiet))
        self.assertIsNone(bash_post.decide({"tool_name": "Edit", "tool_input": {"command": "x"}, "tool_response": {"stdout": MANGLED_OUTPUT["eval syntax error"]}}))

    def test_process_contract(self):
        ev = {"tool_name": "Bash", "tool_input": {"command": "x"}, "tool_response": {"stdout": MANGLED_OUTPUT["wrapper tail only (the non-ASCII class leaves just this)"]}}
        r = run_hook("bash_post.py", ev)
        self.assertEqual(0, r.returncode)
        self.assertIn("shell-ate-it", json.loads(r.stdout)["additionalContext"])
        r2 = run_hook("bash_post.py", {"tool_name": "Bash", "tool_input": {"command": "x"}, "tool_response": "fine"})
        self.assertEqual(0, r2.returncode)
        self.assertEqual("", r2.stdout.strip())

    def test_fails_open_on_garbage_stdin(self):
        r = subprocess.run([sys.executable, os.path.join(HOOKS, "bash_post.py")], input="{not json",
                           capture_output=True, text=True)
        self.assertEqual(0, r.returncode)
        self.assertEqual("", r.stdout.strip())
        self.assertIn("hook error", r.stderr)


def run_hook(name, event):
    return subprocess.run([sys.executable, os.path.join(HOOKS, name)], input=json.dumps(event),
                          capture_output=True, text=True, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
