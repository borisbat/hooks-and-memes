"""Detection rules for the "shell ate it" class: Bash tool commands the Claude Code harness
mangles before bash runs them, and the fingerprints a mangled run leaves in its output.
Pure functions - the hooks are thin wrappers.

Two mangling axes, each byte-proven against a file-run control (see tests/ corpus):
  1. a run of N>=2 backslashes arrives as ceil(N/2) - in single quotes, in <<'EOF' bodies,
     in -c strings, everywhere; lone backslashes survive
  2. any codepoint above U+007F makes the wrapper's re-quoting fail: exit 127 and the
     `pwd -P >|...-cwd` dump, before bash runs anything
Backticks, $(...), ${...} and quoted heredocs behave exactly as bash defines them.

Every rule's message has to stand on its own: it is what the model reads instead of the
tool running, so it names the fix, not the theory.
"""
import functools
import re

FIX_FILE = ("write the text/script to a file with the Write tool and pass the PATH "
            "(python script.py, --body-file FILE, -F body=@FILE, git commit -F FILE)")

# --- PreToolUse: command shapes that get mangled ---------------------------------------

_DQ_SPECIAL = set('"$`\\\n')

# one heredoc opener token: <<[-] then a delimiter that is quoted ('tag' / "tag"),
# backslash-escaped (\tag - quoted semantics too), or bare. <<< herestrings excluded.
_OPENER = re.compile(
    r"(?<!<)<<(?!<)(?P<dash>-?)\s*"
    r"(?:'(?P<sq>[^'\n]+)'|\"(?P<dq>[^\"\n]+)\"|\\(?P<esc>[^\s;&|<>()]+)|(?P<bare>[^\s'\"\\;&|<>()]+))")


def _strip_line_comment(line):
    """The code part of one line: an unquoted # at a word start begins a comment."""
    in_s = in_d = False
    prev = " "
    for k, ch in enumerate(line):
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif ch == "#" and not in_s and not in_d and prev in " \t;&|(":
            return line[:k]
        prev = ch
    return line


def _is_terminator(line, tag, dash):
    return (line.lstrip("\t") if dash else line).strip() == tag


@functools.lru_cache(maxsize=64)
def heredocs(command):
    """(quoted_delimiter: bool, body_start, body_end) for every heredoc, in order.

    A single line-walk, linear in the command size: openers are collected per code line
    (comments stripped - `# <<EOF` opens nothing), bodies are assigned in bash's order
    (all openers of a line get their bodies sequentially after it), and an opener whose
    terminator never comes is not a heredoc at all (an inline `<<` in ordinary text).
    """
    lines = command.split("\n")
    offsets = []
    pos = 0
    for ln in lines:
        offsets.append(pos)
        pos += len(ln) + 1
    res = []
    i = 0
    while i < len(lines):
        openers = list(_OPENER.finditer(_strip_line_comment(lines[i])))
        if not openers:
            i += 1
            continue
        j = i + 1
        assigned = False
        for m in openers:
            tag = m.group("sq") or m.group("dq") or m.group("esc") or m.group("bare")
            dash = m.group("dash") == "-"
            body_first = j
            while j < len(lines) and not _is_terminator(lines[j], tag, dash):
                j += 1
            if j >= len(lines):
                j = body_first
                break
            a = offsets[body_first]
            res.append((m.group("bare") is None, a, max(a, offsets[j] - 1)))
            j += 1
            assigned = True
        i = j if assigned else i + 1
    return tuple(res)


def backslash_runs(command):
    """Yield (run_length, context, next_char) for every maximal run of backslashes.

    context is "literal" where bash does no backslash processing (single quotes, a quoted
    heredoc body) and "processed" elsewhere (double quotes, bare words, unquoted heredocs).
    Quote characters inside ANY heredoc body are ordinary text, and a quote escaped by an
    odd run of backslashes outside single quotes never toggles the state - both would
    otherwise desync the scanner and misclassify everything after.
    """
    literal_spans = sorted((a, b) for quoted, a, b in heredocs(command) if quoted)
    body_spans = sorted((a, b) for _quoted, a, b in heredocs(command))
    lit_idx = body_idx = 0
    n = len(command)
    i = 0
    in_single = in_double = in_comment = False
    saved_quotes = []  # (in_single, in_double) at each $( entry - substitutions restart quoting
    while i < n:
        c = command[i]
        while body_idx < len(body_spans) and body_spans[body_idx][1] <= i:
            body_idx += 1
        if body_idx < len(body_spans) and body_spans[body_idx][0] <= i:
            # inside a heredoc body: quotes, comments and parens are ordinary text
            if c == "\\":
                j = i
                while j < n and command[j] == "\\":
                    j += 1
                while lit_idx < len(literal_spans) and literal_spans[lit_idx][1] <= i:
                    lit_idx += 1
                in_literal = lit_idx < len(literal_spans) and literal_spans[lit_idx][0] <= i
                yield j - i, ("literal" if in_literal else "processed"), (command[j] if j < n else "")
                i = j
                continue
            i += 1
            continue
        if in_comment:
            if c == "\n":
                in_comment = False
            i += 1  # a comment is inert text - its backslashes are not runs, its quotes not quotes
            continue
        if c == "\\":
            j = i
            while j < n and command[j] == "\\":
                j += 1
            ctx = "literal" if in_single else "processed"
            yield j - i, ctx, (command[j] if j < n else "")
            if ctx == "processed" and (j - i) % 2 == 1 and j < n and command[j] in "\"'":
                j += 1  # the quote is escaped - consume it without toggling
            i = j
            continue
        if c == "'" and not in_double:
            in_single = not in_single
        elif c == '"' and not in_single:
            in_double = not in_double
        elif c == "#" and not in_single and not in_double and (i == 0 or command[i - 1] in " \t\n;&|("):
            in_comment = True
        elif c == "$" and not in_single and i + 1 < n and command[i + 1] == "(":
            saved_quotes.append((in_single, in_double))
            in_single = in_double = False
            i += 2
            continue
        elif c == ")" and saved_quotes and not in_single and not in_double:
            in_single, in_double = saved_quotes.pop()
        i += 1


def rule_non_ascii(command):
    bad = sorted({c for c in command if ord(c) > 127})
    if bad:
        shown = " ".join("U+%04X %s" % (ord(c), c) for c in bad[:4])
        return ("the command text contains non-ASCII characters (%s) - the harness wrapper fails "
                "to re-quote them and the whole command dies with exit 127 before bash runs it; "
                "use ASCII in the command, or %s" % (shown, FIX_FILE))
    return None


def rule_backslash_pair(command):
    """In a literal context any pair is a visible byte change; in a processed context bash
    itself collapses pairs, so exactly 2 cancels out unless the next char is
    double-quote-special - and 3+ always changes."""
    for run, ctx, nxt in backslash_runs(command):
        if run < 2:
            continue
        if ctx == "literal" or run > 2 or nxt in _DQ_SPECIAL:
            return ("the harness collapses backslash runs in the command text (N backslashes "
                    "arrive as ceil(N/2)), so this \\\\ sequence reaches the program with one "
                    "backslash too few - silently wrong bytes, no error; " + FIX_FILE)
    return None


_PROSE_SINK = re.compile(r"\b(git\s+commit|git\s+tag|gh\s+\w+)\b")
_LIST_SEP = re.compile(r"&&|\|\||;")


def sink_segment(command, body_start):
    """The piece of the heredoc's opener line that owns the `<<`: split on && || ; but not
    on |, so `cat <<EOF | git commit -F -` keeps its sink while an earlier, unrelated
    `git commit && cat <<EOF` does not leak into this heredoc."""
    head = command[:body_start].rstrip("\n")
    line = head[head.rfind("\n") + 1:]
    op = line.rfind("<<")
    if op < 0:
        return line
    lo = 0
    for m in _LIST_SEP.finditer(line):
        if m.end() <= op:
            lo = m.end()
        else:
            return line[lo:m.start()]
    return line[lo:]


def rule_unquoted_heredoc_expansion(command):
    """<<EOF (no quotes) expands $ and backticks inside the body - bash semantics, not the
    harness, and fine when meant; but a commit message or PR body fed that way never means
    it, so only prose sinks (git commit/tag, gh) are denied."""
    for quoted, a, b in heredocs(command):
        body = command[a:b]
        if not quoted and ("$" in body or "`" in body) and _PROSE_SINK.search(sink_segment(command, a)):
            return ("heredoc delimiter is unquoted, so $... and `...` inside the message expand "
                    "before the program sees it; quote it (<<'EOF') or " + FIX_FILE)
    return None


PRE_RULES = [rule_non_ascii, rule_backslash_pair, rule_unquoted_heredoc_expansion]


def pre_check(command):
    """First matching rule's message, or None when the command looks safe."""
    for rule in PRE_RULES:
        msg = rule(command)
        if msg:
            return msg
    return None


# --- PostToolUse: fingerprints a mangled run leaves behind ------------------------------

_WRAPPER_ANCHOR = re.compile(r"export TEMP=|eval '")

POST_SIGNATURES = [
    (re.compile(r"pwd -P >\|[^\n]*-cwd: No such file or directory"),
     "the harness wrapper tail errored - the command text failed to parse as a whole (non-ASCII in the command is the usual cause)"),
    (re.compile(r"/usr/bin/bash: eval: line \d+: syntax error"),
     "the harness eval could not parse the command"),
    (re.compile(r"command substitution: line \d+: syntax error"),
     "a backtick/$( in the text was executed as a command substitution"),
    (re.compile(r"unexpected EOF while looking for matching"),
     "a quote in the text was consumed by the harness, leaving an unterminated string"),
    (re.compile(r"line \d+: \\ \\: No such file or directory"),
     "a backslash sequence in the text was split into commands"),
    (re.compile(r"SyntaxWarning: invalid escape sequence"),
     "python received a backslash run one shorter than written - the harness collapsed it"),
    (re.compile(r"sed: -e expression #\d+, char \d+: unterminated"),
     "sed received a backslash run one shorter than written - the harness collapsed it (or the expression is wrong; check the command's backslashes)"),
]


def _command_not_found_cascade(text):
    """`command not found` lines followed, within a bounded window, by the wrapper dump."""
    anchor = _WRAPPER_ANCHOR.search(text)
    if not anchor:
        return False
    return "command not found" in text[max(0, anchor.start() - 4000):anchor.start()]


def post_check(command, response_text):
    """Message when the output carries a mangling fingerprint - or, with no fingerprint at
    all, when the command itself had a backslash run the harness collapses (that axis
    usually fails silently, so the command is the only evidence). None otherwise."""
    for rx, why in POST_SIGNATURES:
        if rx.search(response_text):
            return _mangled(why)
    if _command_not_found_cascade(response_text):
        return _mangled("words from the command text ran as commands - the wrapper re-quoting broke")
    if rule_backslash_pair(command):
        return _mangled("no error fingerprint, but the command carried a backslash run the harness "
                        "collapses - the bytes it wrote or matched may be silently wrong")
    return None


def _mangled(why):
    return ("shell-ate-it: the harness mangled this command before it ran (" + why + "). "
            "Whatever side effects happened are partial at best - do not trust them; "
            "redo via a file: " + FIX_FILE)
