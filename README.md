# hooks-and-memes

Claude Code hooks that eliminate whole classes of tool-use failure, one script per class,
with the corpus of real failures that motivated each as its test suite.

## bash: the "shell ate it" class

The Bash tool's command text passes through a harness wrapper (`eval '...'`) before bash
runs it. Some shapes do not survive that trip: backticks expand even inside single quotes
or heredocs, and scripts fed to an interpreter through a heredoc come out with quotes and
backslashes rewritten. The command then runs *something else* — often partially, often
exit 127 with a page of `command not found` — and the model, having seen it "succeed" or
fail confusingly, moves on.

Two hooks, one per phase:

- `hooks/bash_pre.py` — **PreToolUse**: denies the shapes that get mangled (backtick anywhere,
  `python - <<EOF` style interpreter heredocs, unquoted heredocs with `$` in the body). The
  deny message names the fix: write the text or script to a file with the Write tool and
  pass the path (`--body-file`, `-F body=@file`, `python script.py`, `git commit -F file`).
- `hooks/bash_post.py` — **PostToolUse**: when the output carries a mangling fingerprint
  (the wrapper's `pwd -P >| ...-cwd` tail, `eval: line 0: syntax error`, command-substitution
  syntax errors, a `command not found` cascade followed by the wrapper dump), it tells the
  model in context that the run was mangled and its side effects are not to be trusted.

Rules and fingerprints live in `hooks/bash_mangling_rules.py` (pure functions); the hooks are
thin I/O wrappers that fail open — a crashing hook never blocks a command.

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

The corpus is the contract: `EATEN` are commands the harness actually mangled (every one
must be denied), `OK` are shapes that ran fine (every one must stay allowed),
`MANGLED_OUTPUT` / `CLEAN_OUTPUT` are verbatim outputs (flagged / quiet). Add to the corpus
before touching a rule; a rule change that flips a corpus entry is a finding, not a fix.
