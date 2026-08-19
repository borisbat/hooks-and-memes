#!/usr/bin/env python3
"""Fixture tests for the two Bash hooks. The corpus is real: every EATEN entry is a command
the Claude Code harness mangled in practice (backticks expanded inside single quotes,
heredoc bodies rewritten); every OK entry is a shape that ran fine and must stay allowed.
The post-hook corpus is the literal output those mangled runs produced.

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

# --- corpus: commands the harness ate ----------------------------------------------------

EATEN = {
    "backticks inside single quotes (gh reply text)":
        "printf '%s' 'Verified rather than assumed: MSYS resolves `\"$VB/python\"` / `\"$VB/daslang\"` to the `.exe` on exec' > r1.md",
    "backticks inside a python heredoc (PR body edit)":
        'python - "$S" <<\'EOF\'\nimport sys\ns = open(p).read()\ns = s.replace("- Fixture tests `python -W error ci/test_wheel_build.py`: 9/9", "x")\nEOF\n',
    "python heredoc with quotes + backslashes (patch script)":
        "python - <<'EOF'\np=\"ci/packaging/wheel_build.py\"; s=open(p).read()\nold='''    if system == \"Windows\":\n        return {\"amd64\": \"win_amd64\"}[machine]\n'''\ns=s.replace(old, new)\nEOF\n",
    "python heredoc rewriting a literal with \\n":
        "cd /d/Work/daScript-testrel && python - <<'EOF'\np=\"main.das\"; s=open(p).read()\nold='for the network rows\\n\")'\nnew='for the network rows\\\\n\")'\ns=s.replace(old,new)\nEOF\n",
    "python3 heredoc":
        "python3 - <<'PYEOF'\nprint('x')\nPYEOF\n",
    "backtick in a gh --body argument":
        'gh pr comment 12 --body "use `daslang` here"',
    "unquoted heredoc with $ in the body":
        "git commit -F - <<EOF\nrpath: $ORIGIN and $ORIGIN/../lib\nEOF\n",
}

# --- corpus: shapes that ran fine and must stay allowed ---------------------------------

OK = {
    "quoted heredoc commit message with $ and # inside":
        "git add -A && git commit -q -F - <<'EOF'\nrelease bundle: -exe tools find the runtime lib\n\ndaslang -exe stamped its output with rpath $ORIGIN + the build-tree lib/ (#3779).\n\nCo-Authored-By: Claude Fable 5 <noreply@anthropic.com>\nEOF\ngit log --oneline -1",
    "gh with a body file":
        'gh pr create -R GaijinEntertainment/daScript --base master --head x --title "t" --body-file "$S/pr.md"',
    "gh api reply from a file":
        'gh api -X POST repos/o/r/pulls/1/comments/2/replies -F body=@"$S/r1.md" --jq .id',
    "command substitution with $( ) and ${ }":
        'jid=$(gh run view 1 --json jobs --jq ".jobs[0].databaseId"); for pair in a:b c:d; do id=${pair%%:*}; f=${pair#*:}; echo $id $f; done',
    "python script by path":
        'python "C:/Users/Boris/AppData/Local/Temp/claude/scratchpad/patch_copilot.py" && python -W error ci/test_wheel_build.py',
    "cat heredoc writing a file, quoted delimiter, $ inside":
        "cat > \"$S/route.sh\" <<'EOF'\nif [[ \"$TAG\" =~ ^v?[0-9]+$ ]]; then echo pypi; fi\nEOF\nbash \"$S/route.sh\"",
    "unquoted heredoc with no expansions":
        "cat <<EOF\nhello world\nEOF\n",
    "pipes, redirects, grep -E with braces":
        "bash ci/smoke_test_bundle.sh \"$S/lb\" 2>&1 | grep -E \"dastest.exe runs|lint.exe lints|ALL OK|FAILED:\"",
    "plain git/gh status":
        "git status --short; gh pr checks 3781 -R GaijinEntertainment/daScript | awk -F'\\t' '{print $2}' | sort | uniq -c",
    "echo json into a process":
        "echo '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}' | timeout 20 cmd //c \"D:\\\\MCP\\\\x.cmd\" | head -c 300",
    "powershell-ish quoting in bash":
        "python -c \"import json; d=json.load(open('x.json')); print(list(d))\"",
}

# --- corpus: outputs of mangled runs (verbatim fragments) ---------------------------------

MANGLED_OUTPUT = {
    "wrapper tail: pwd -P >| cwd file":
        "/usr/bin/bash: line 34: daslang: command not found\n/usr/bin/bash: line 34: export TEMP='C:\\Users\\Boris\\AppData\\Local\\Temp' TMP='C:\\Users\\Boris\\AppData\\Local\\Temp' && shopt -u extglob 2>/dev/null || true && eval 'python - <<'\"'\"'EOF'\"'\"'\n...' && pwd -P >| /c/Users/Boris/AppData/Local/Temp/claude-653d-cwd: No such file or directory",
    "eval syntax error":
        "/usr/bin/bash: eval: line 0: syntax error near unexpected token `done'\n/usr/bin/bash: eval: line 0: `gh run view 1; until for r in 1 2; do echo; done | grep -qv completed; done'",
    "command substitution syntax error":
        "/usr/bin/bash: command substitution: line 1: syntax error: unexpected end of file\n/usr/bin/bash: line 0: wheel_build:: command not found",
    "backslash sequence split":
        "/usr/bin/bash: line 32: \\ \\: No such file or directory\n/usr/bin/bash: line 32: export TEMP='C:\\Users\\Boris\\AppData\\Local\\Temp' ...",
    "words ran as commands then the wrapper dump":
        "/usr/bin/bash: line 0: pypi_route: command not found\n/usr/bin/bash: line 0: v?X.Y.Z: command not found\nERROR: You must give at least one requirement to install\n/usr/bin/bash: line 0: export TEMP='C:\\Users\\Boris\\AppData\\Local\\Temp' TMP='...' && shopt -u extglob 2>/dev/null || true && eval 'S=\"...\"; printf' ...",
}

CLEAN_OUTPUT = {
    "ordinary failure: program's own error":
        "error[30151]: syntax error, unexpected name, expecting ']'\nutils/internal/test-release/utils_phase.das:32:26\nrc=1",
    "sed misuse is not the harness":
        "sed: -e expression #1, char 358: unterminated `s' command",
    "a real command-not-found (typo), no wrapper dump":
        "/usr/bin/bash: line 1: dastset: command not found",
    "clean success":
        "17 tests, 17 passed, 0 failed, 0 errors, 0 skipped\nSUCCESS! (0.757411s)",
    "python traceback":
        "Traceback (most recent call last):\n  File \"<stdin>\", line 19, in <module>\nAssertionError: block",
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

    def test_heredoc_parser_sees_quoting(self):
        docs = list(rules.heredocs("cat <<'EOF'\na $b\nEOF\ncat <<X\nc\nX\n"))
        self.assertEqual([(True, "a $b"), (False, "c")], docs)

    def test_unquoted_heredoc_without_expansion_is_fine(self):
        self.assertIsNone(rules.rule_unquoted_heredoc_expansion("cat <<EOF\nplain\nEOF\n"))

    def test_interpreter_rule_is_specific_to_stdin_scripts(self):
        self.assertIsNotNone(rules.rule_interpreter_heredoc("python - <<'EOF'\nx\nEOF\n"))
        self.assertIsNotNone(rules.rule_interpreter_heredoc("python3 - <<EOF\nx\nEOF\n"))
        self.assertIsNone(rules.rule_interpreter_heredoc("python script.py <<'EOF'\ninput\nEOF\n"))
        self.assertIsNone(rules.rule_interpreter_heredoc("git commit -F - <<'EOF'\nmsg\nEOF\n"))


class PostSignatures(unittest.TestCase):
    def test_every_mangled_output_is_flagged(self):
        for name, out in MANGLED_OUTPUT.items():
            with self.subTest(name):
                self.assertIsNotNone(rules.post_check("x", out), f"should flag: {name}")

    def test_clean_outputs_stay_quiet(self):
        for name, out in CLEAN_OUTPUT.items():
            with self.subTest(name):
                self.assertIsNone(rules.post_check("x", out), f"should be quiet: {name}")

    def test_message_says_not_to_trust_side_effects(self):
        msg = rules.post_check("x", MANGLED_OUTPUT["eval syntax error"])
        self.assertIn("do not trust", msg)
        self.assertIn("Write tool", msg)


class PreHook(unittest.TestCase):
    def test_decide_denies_with_the_documented_shape(self):
        out = bash_pre.decide({"tool_name": "Bash", "tool_input": {"command": "echo `x`"}})
        self.assertEqual("deny", out["hookSpecificOutput"]["permissionDecision"])
        self.assertEqual("PreToolUse", out["hookSpecificOutput"]["hookEventName"])
        self.assertTrue(out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_decide_allows_clean_and_non_bash(self):
        self.assertIsNone(bash_pre.decide({"tool_name": "Bash", "tool_input": {"command": "git status"}}))
        self.assertIsNone(bash_pre.decide({"tool_name": "Read", "tool_input": {"file_path": "`x`"}}))
        self.assertIsNone(bash_pre.decide({"tool_name": "Bash", "tool_input": {}}))
        self.assertIsNone(bash_pre.decide({}))

    def test_process_contract(self):
        deny = run_hook("bash_pre.py", {"tool_name": "Bash", "tool_input": {"command": "echo `x`"}})
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


class PostHook(unittest.TestCase):
    def test_response_text_reads_dict_string_and_other(self):
        self.assertIn("boom", bash_post.response_text({"stdout": "ok", "stderr": "boom"}))
        self.assertEqual("raw", bash_post.response_text("raw"))
        self.assertEqual("", bash_post.response_text(None))
        self.assertIn("eval: line 0: syntax error", bash_post.response_text({"weird": {"nested": "eval: line 0: syntax error"}}))

    def test_decide_flags_only_mangled(self):
        ev = {"tool_name": "Bash", "tool_input": {"command": "x"}, "tool_response": {"stdout": MANGLED_OUTPUT["eval syntax error"]}}
        out = bash_post.decide(ev)
        self.assertIn("shell-ate-it", out["additionalContext"])
        self.assertEqual("PostToolUse", out["hookSpecificOutput"]["hookEventName"])
        quiet = {"tool_name": "Bash", "tool_input": {"command": "x"}, "tool_response": {"stdout": CLEAN_OUTPUT["clean success"]}}
        self.assertIsNone(bash_post.decide(quiet))
        self.assertIsNone(bash_post.decide({"tool_name": "Edit", "tool_response": {"stdout": MANGLED_OUTPUT["eval syntax error"]}}))

    def test_process_contract(self):
        ev = {"tool_name": "Bash", "tool_input": {"command": "x"}, "tool_response": {"stdout": MANGLED_OUTPUT["wrapper tail: pwd -P >| cwd file"]}}
        r = run_hook("bash_post.py", ev)
        self.assertEqual(0, r.returncode)
        self.assertIn("shell-ate-it", json.loads(r.stdout)["additionalContext"])
        r2 = run_hook("bash_post.py", {"tool_name": "Bash", "tool_input": {"command": "x"}, "tool_response": "fine"})
        self.assertEqual(0, r2.returncode)
        self.assertEqual("", r2.stdout.strip())


def run_hook(name, event):
    return subprocess.run([sys.executable, os.path.join(HOOKS, name)], input=json.dumps(event),
                          capture_output=True, text=True)


if __name__ == "__main__":
    unittest.main()
