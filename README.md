# hooks-and-memes

Claude Code hooks that eliminate whole classes of tool-use failure, one script per class,
with the corpus of real failures that motivated each as its test suite.

## bash: the "shell ate it" class (Windows)

**Scope: Claude Code on Windows.** Both mangling axes live in the Windows spawn path
(Git-Bash/MSYS launched via a command-line string that gets re-parsed); on Linux/macOS the
command reaches bash as untouched argv bytes and neither axis is expected to exist - though
that is presumed, not probed. The hooks are harmless on a clean harness (the rules just
never fire truthfully; the backslash denial stays as deliberate conservatism), but the
corpus and fingerprints are Windows-harness measurements.

The Bash tool's command text passes through a harness wrapper before bash runs it. Two
shapes do not survive that trip — both established by running probes *through the Bash
tool itself* and comparing bytes against a file-run control:

1. **Backslash runs collapse**: N consecutive backslashes (N ≥ 2) arrive as ⌈N/2⌉ — inside
   single quotes, inside `<<'EOF'` heredoc bodies, in `-c` strings, everywhere. Lone
   backslashes survive. The program then runs with the *wrong bytes and no error*: a
   `sed` expression that no longer parses, a Python `\\n` that became a newline, a
   `replace()` that silently no-ops.
2. **Non-ASCII kills the command**: any codepoint above U+007F (an em dash in a PR reply,
   smart quotes in a commit message) makes the wrapper's re-quoting fail — exit 127, a
   cascade of `command not found`, and the `pwd -P >| …-cwd: No such file or directory`
   tail — before bash runs anything.

Backticks, `$(…)`, `${…}` and quoted heredocs behave exactly as bash defines them.

Two hooks, one per phase:

- `hooks/bash_pre.py` — **PreToolUse**: denies commands with a collapsing backslash run
  (context-aware: a `\\` pair in double quotes before an ordinary character is fine, bash
  collapses it too) or any non-ASCII character, and — the one bash-semantics guard —
  an unquoted heredoc with `$`/backticks feeding a prose sink (`git commit`, `gh …`). The
  deny message names the fix: write the text or script to a file with the Write tool and
  pass the path (`--body-file`, `-F body=@file`, `python script.py`, `git commit -F file`).
- `hooks/bash_post.py` — **PostToolUse + PostToolUseFailure**: when the output carries a mangling fingerprint
  (the wrapper tail, `eval: … syntax error`, command-substitution syntax errors, a
  `command not found` cascade ending in the wrapper dump, Python's `SyntaxWarning: invalid
  escape sequence`, sed's `unterminated`), or when the command itself carried a collapsing
  backslash run and the output is quiet, it tells the model in context that the run was
  mangled and its side effects are not to be trusted. Register it for BOTH events: on this
  harness a nonzero Bash exit routes through `PostToolUseFailure` (with a top-level `error`
  instead of `tool_response`), and only exit-0 runs through `PostToolUse`. The context is
  emitted in both documented placements (top-level `additionalContext` per the reference,
  `hookSpecificOutput.additionalContext` which is what the harness actually reads).

Rules and fingerprints live in `hooks/bash_mangling_rules.py` (pure functions); the hooks are
thin I/O wrappers that fail open — a crashing hook (even a broken rules import) never
blocks a command.

### Install (user scope, all projects)

`~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash", "hooks": [
        { "type": "command", "command": "python", "args": ["D:/Work/hooks-and-memes/hooks/bash_pre.py"], "timeout": 10 } ] }
    ],
    "PostToolUse": [
      { "matcher": "Bash", "hooks": [
        { "type": "command", "command": "python", "args": ["D:/Work/hooks-and-memes/hooks/bash_post.py"], "timeout": 10 } ] }
    ],
    "PostToolUseFailure": [
      { "matcher": "Bash", "hooks": [
        { "type": "command", "command": "python", "args": ["D:/Work/hooks-and-memes/hooks/bash_post.py"], "timeout": 10 } ] }
    ]
  }
}
```

Exec form (`args` present) needs a real executable — `python` resolves to `python.exe`
on Windows; use `python3` where that is the real binary. Restart the session after editing.

### Tests

```
python tests/test_bash_mangling.py
```

The corpus is the contract: `EATEN` are commands the harness mangled (every one must be
denied), `OK` are shapes that came through byte-exact (every one must stay allowed),
`MANGLED_OUTPUT` / `CLEAN_OUTPUT` are verbatim outputs (flagged / quiet). Add to the corpus
before touching a rule; a rule change that flips a corpus entry is a finding, not a fix.

Provenance: the first cut of this hook blamed backticks, from a day of failures that all
turned out to contain an em dash. The probe pass replaced belief with bytes; if the harness
changes (or you are not on Windows), re-run the probes before trusting either list.
Review credit: colleague code-review rounds surfaced the heredoc delimiter gaps, the
quote-state desyncs (comments, command substitution, escaped quotes), the quadratic
heredoc scan (a flood past the hook timeout = fail-open bypass), and the harness's actual
event routing and context placement - all reproduced red-first in the corpus before fixing.
