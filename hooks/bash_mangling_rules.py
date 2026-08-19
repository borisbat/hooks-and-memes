"""Detection rules for the "shell ate it" class: Bash tool commands the Claude Code harness
mangles before they run (backtick expansion, heredoc bodies rewritten) and the fingerprints
such a mangled run leaves in its output. Pure functions - the hooks are thin wrappers.

Every rule's message has to stand on its own: it is what the model reads instead of the
tool running, so it names the fix, not the theory.
"""
import re

FIX_FILE = ("write the text/script to a file with the Write tool and pass the PATH "
            "(python script.py, --body-file FILE, -F body=@FILE, git commit -F FILE)")

# --- PreToolUse: command shapes that get mangled ---------------------------------------

_HEREDOC = re.compile(r"<<-?\s*(?P<q>['\"]?)(?P<tag>\w+)(?P=q)[^\n]*\n(?P<body>.*?)\n\s*(?P=tag)\s*$",
                      re.S | re.M)
_INTERPRETER_STDIN = re.compile(r"\b(python3?|py|node|perl|ruby|bash|sh|pwsh|powershell)(\.exe)?\s+(-\s|-c\s*<<|-s\b|- <<)")


def heredocs(command):
    """Yield (quoted_delimiter: bool, body: str) for every heredoc in the command."""
    for m in _HEREDOC.finditer(command):
        yield bool(m.group("q")), m.group("body")


def rule_backtick(command):
    if "`" in command:
        return ("the harness expands backticks in the command text (even inside single quotes "
                "and heredocs) - `word` becomes a command substitution and the rest of the line "
                "is lost; " + FIX_FILE)
    return None


def rule_interpreter_heredoc(command):
    """python - <<EOF ... : the heredoc body is re-parsed by the harness's eval; quotes and
    backslashes inside it do not survive reliably."""
    if _INTERPRETER_STDIN.search(command) and "<<" in command:
        return ("a script fed to an interpreter through a heredoc is re-parsed by the harness - "
                "backslashes and quotes inside it do not survive; " + FIX_FILE)
    return None


def rule_unquoted_heredoc_expansion(command):
    """<<EOF (no quotes) expands $ and backticks inside the body - almost never intended
    for prose/commit messages."""
    for quoted, body in heredocs(command):
        if not quoted and ("$" in body or "`" in body):
            return ("heredoc delimiter is unquoted, so $... inside the body expands before the "
                    "program sees it; quote it (<<'EOF') or " + FIX_FILE)
    return None


PRE_RULES = [rule_backtick, rule_interpreter_heredoc, rule_unquoted_heredoc_expansion]


def pre_check(command):
    """First matching rule's message, or None when the command looks safe."""
    for rule in PRE_RULES:
        msg = rule(command)
        if msg:
            return msg
    return None


# --- PostToolUse: fingerprints a mangled run leaves behind ------------------------------

POST_SIGNATURES = [
    (re.compile(r"pwd -P >\|.*-cwd: No such file or directory"),
     "the harness wrapper tail errored - the command text failed to parse as a whole"),
    (re.compile(r"/usr/bin/bash: eval: line \d+: syntax error"),
     "the harness eval could not parse the command"),
    (re.compile(r"command substitution: line \d+: syntax error"),
     "a backtick/$( in the text was executed as a command substitution"),
    (re.compile(r"unexpected EOF while looking for matching"),
     "a quote in the text was consumed by the harness, leaving an unterminated string"),
    (re.compile(r"/usr/bin/bash: line \d+: [^\n]*: command not found[\s\S]*(export TEMP=|eval ')"),
     "words from the command text ran as commands - backtick or quote expansion"),
    (re.compile(r"line \d+: \\ \\: No such file or directory"),
     "a backslash sequence in the text was split into commands"),
]


def post_check(command, response_text):
    """Message when the output carries a mangling fingerprint, else None."""
    for rx, why in POST_SIGNATURES:
        if rx.search(response_text):
            return ("shell-ate-it: the harness mangled this command before it ran (" + why + "). "
                    "Whatever side effects happened are partial at best - do not trust them; "
                    "redo via a file: " + FIX_FILE)
    return None
