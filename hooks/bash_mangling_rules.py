"""Detection rules for the "shell ate it" class: Bash tool commands the Claude Code harness
mangles before bash runs them, and the fingerprints a mangled run leaves in its output.
Pure functions - the hooks are thin wrappers. Scope: Claude Code on WINDOWS (the Git-Bash
spawn path); see README.

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

# --- heredoc parsing ---------------------------------------------------------------------

_DQ_SPECIAL = set('"$`\\\n')

# a heredoc delimiter WORD: any mix of quoted segments, escaped chars and bare chars -
# bash applies quote removal to get the tag, and ANY quoting anywhere makes it literal
_DELIM_WORD = re.compile(r"(?:'[^'\n]*'|\"[^\"\n]*\"|\\[^\s]|[^\s'\"\\;&|<>()])+")


def _parse_delim(word):
    """(tag, quoted) after bash quote removal on the delimiter word."""
    tag = []
    quoted = False
    k = 0
    while k < len(word):
        ch = word[k]
        if ch == "'" or ch == '"':
            end = word.index(ch, k + 1)
            tag.append(word[k + 1:end])
            quoted = True
            k = end + 1
        elif ch == "\\":
            tag.append(word[k + 1:k + 2])
            quoted = True
            k += 2
        else:
            tag.append(ch)
            k += 1
    return "".join(tag), quoted


def _scan_openers(line):
    """(pos_in_line, dash, tag, quoted) for each heredoc opener on one code line.

    A single quote-aware walk: `<<` inside a quoted region or after an unquoted `#`
    (a comment) opens nothing; the delimiter word is consumed wholesale so its own
    quotes never leak into the line's quote state.
    """
    out = []
    in_s = in_d = False
    k = 0
    n = len(line)
    while k < n:
        ch = line[k]
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif ch == "#" and not in_s and not in_d and (k == 0 or line[k - 1] in " \t;&|("):
            break
        elif (ch == "<" and not in_s and not in_d and line[k:k + 2] == "<<"
              and line[k + 2:k + 3] != "<" and line[k - 1:k] != "<"):
            m = re.match(r"<<(-?)\s*", line[k:])
            word = _DELIM_WORD.match(line, k + m.end())
            if word:
                tag, quoted = _parse_delim(word.group())
                out.append((k, m.group(1) == "-", tag, quoted))
                k = word.end()
                continue
        k += 1
    return out


def _is_terminator(line, tag, dash):
    """Bash requires the delimiter line to match exactly; <<- strips leading tabs only."""
    line = line.rstrip("\r")
    if dash:
        line = line.lstrip("\t")
    return line == tag


@functools.lru_cache(maxsize=64)
def heredoc_records(command):
    """(quoted, body_start, body_end, opener_pos) per heredoc, in order - one linear walk.

    Openers are collected per code line (quote-aware, comments open nothing), bodies are
    assigned in bash's order (all openers of a line get their bodies sequentially after
    it), and an opener whose terminator never comes is not a heredoc at all (an inline
    `<<` in ordinary text).
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
        openers = _scan_openers(lines[i])
        if not openers:
            i += 1
            continue
        j = i + 1
        assigned = False
        for col, dash, tag, quoted in openers:
            body_first = j
            while j < len(lines) and not _is_terminator(lines[j], tag, dash):
                j += 1
            if j >= len(lines):
                j = body_first
                break
            a = offsets[body_first]
            res.append((quoted, a, max(a, offsets[j] - 1), offsets[i] + col))
            j += 1
            assigned = True
        i = j if assigned else i + 1
    return tuple(res)


def heredocs(command):
    """(quoted_delimiter: bool, body_start, body_end) - the classic view of heredoc_records."""
    return tuple((q, a, b) for q, a, b, _pos in heredoc_records(command))


# --- the quote/context scanner -----------------------------------------------------------

def backslash_runs(command):
    """Yield (run_length, context, next_char) for every maximal run of backslashes.

    context is "literal" where bash does no backslash processing (single quotes, a quoted
    heredoc body) and "processed" elsewhere (double quotes, bare words, unquoted heredocs).
    The scanner tracks what bash tracks: comments are inert to the end of line, $( opens a
    fresh quoting context (with bare subshell parens counted, so an inner `)` does not pop
    it), quotes inside heredoc bodies are ordinary text - except that an UNQUOTED body
    runs command substitutions for real, so a `$(` there re-enters full scanning.
    """
    records = heredoc_records(command)
    body_spans = sorted((a, b, quoted) for quoted, a, b, _p in records)
    span_idx = 0
    n = len(command)
    i = 0
    in_single = in_double = in_comment = False
    frames = []  # [saved_single, saved_double, paren_depth] per open $(
    while i < n:
        c = command[i]
        while span_idx < len(body_spans) and body_spans[span_idx][1] <= i:
            span_idx += 1
        in_body = span_idx < len(body_spans) and body_spans[span_idx][0] <= i
        body_quoted = in_body and body_spans[span_idx][2]
        if in_body and not frames:
            # a heredoc body outside any substitution: quotes/comments/parens are text
            if c == "\\":
                j = i
                while j < n and command[j] == "\\":
                    j += 1
                yield j - i, ("literal" if body_quoted else "processed"), (command[j] if j < n else "")
                i = j
                continue
            if not body_quoted and c == "$" and command[i + 1:i + 2] == "(":
                frames.append([in_single, in_double, 0])
                in_single = in_double = False
                i += 2
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
        elif c == "$" and not in_single and command[i + 1:i + 2] == "(":
            frames.append([in_single, in_double, 0])
            in_single = in_double = False
            i += 2
            continue
        elif c == "(" and not in_single and not in_double and frames:
            frames[-1][2] += 1
        elif c == ")" and not in_single and not in_double and frames:
            if frames[-1][2] > 0:
                frames[-1][2] -= 1
            else:
                in_single, in_double, _depth = frames.pop()
        i += 1


# --- PreToolUse rules --------------------------------------------------------------------

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


def sink_segment(command, opener_pos):
    """The piece of the opener's line that owns THIS heredoc's `<<`: split on && || ; but
    not on |, so `cat <<EOF | git commit -F -` keeps its sink while an earlier, unrelated
    `git commit && cat <<EOF` - or a sibling heredoc's command - does not leak in."""
    start = command.rfind("\n", 0, opener_pos) + 1
    end = command.find("\n", opener_pos)
    line = command[start:] if end < 0 else command[start:end]
    op = opener_pos - start
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
    for quoted, a, b, pos in heredoc_records(command):
        body = command[a:b]
        if not quoted and ("$" in body or "`" in body) and _PROSE_SINK.search(sink_segment(command, pos)):
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
