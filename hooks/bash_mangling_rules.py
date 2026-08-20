"""Detection rules for the "shell ate it" class: Bash tool commands the Claude Code harness
mangles before bash runs them, and the fingerprints a mangled run leaves in its output.
Pure functions - the hooks are thin wrappers. Scope: Claude Code on WINDOWS (the Git-Bash
spawn path); see README.

One live mangling axis, byte-proven against a file-run control (see tests/ corpus):
a run of N>=2 backslashes arrives as ceil(N/2) - in single quotes, in <<'EOF' bodies,
in -c strings, everywhere; lone backslashes survive. Re-proven unchanged on Git for
Windows 2.55.0.4 (bash 5.3.15, msys 3.6.9) - the defect is the harness spawn encoding,
not Git's.

A second axis existed on old Git for Windows runtimes only: any codepoint above U+007F
made the wrapper's re-quoting fail (exit 127, `pwd -P >|...-cwd` dump, before bash ran
anything). Measured broken on Git 2.17.1 (msys 2.10.0), byte-exact on 2.55.0.4 - the fix
is upgrading Git, so there is no pre rule for it; the post fingerprints below still name
it for boxes that have not upgraded.
Backticks, $(...), ${...} and quoted heredocs behave exactly as bash defines them.

The heart is one forward lexer (_lex) that carries what bash carries - quote state,
comments, $( ) frames (with subshell parens and case patterns), and the heredoc queue -
because every split-scanner design leaked: line-local opener scans missed heredocs inside
substitutions and invented them inside multiline strings.

Every rule's message has to stand on its own: it is what the model reads instead of the
tool running, so it names the fix, not the theory.
"""
import functools
import re

FIX_FILE = ("write the text/script to a file with the Write tool and pass the PATH "
            "(python script.py, --body-file FILE, -F body=@FILE, git commit -F FILE)")

# --- the lexer ---------------------------------------------------------------------------

_DQ_SPECIAL = set('"$`\\\n')

# a heredoc delimiter WORD: quoted segments, escaped chars (escaped space included) and
# bare chars - bash applies quote removal, and ANY quoting anywhere makes the body literal
_DELIM_WORD = re.compile(r"(?:'[^'\n]*'|\"[^\"\n]*\"|\\.|[^\s'\"\\;&|<>()])+")


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


def _ends_with_odd_backslash(text):
    k = len(text)
    while k > 0 and text[k - 1] == "\\":
        k -= 1
    return (len(text) - k) % 2 == 1


def _match_word(command, i, word):
    """True when `word` sits at i as a whole bare word."""
    if command[i:i + len(word)] != word:
        return False
    before = command[i - 1] if i else "\n"
    after = command[i + len(word):i + len(word) + 1] or "\n"
    return before in " \t\n;&|(" and after in " \t\n;&|)"


@functools.lru_cache(maxsize=32)
def _lex(command):
    """One pass; returns (runs, heredoc_records).

    runs = ((run_length, context, next_char), ...) for every maximal backslash run -
    context "literal" where bash does no backslash processing (single quotes, quoted
    heredoc bodies), "processed" elsewhere. Comment text and delimiter/terminator lines
    yield nothing. heredoc_records = ((quoted, body_start, body_end, opener_pos), ...).
    """
    n = len(command)
    runs = []
    records = []
    i = 0
    in_single = in_double = in_comment = False
    cmd_pos = True   # at a command position (start / after ; & | ( && || newline)
    arith = 0        # unmatched parens inside a $(( )) / (( )) region - no heredocs there
    frames = []      # [saved_s, saved_d, paren_depth, case_depth, awaiting_in, pattern_wait]
    pending = []  # opener queue: [tag, dash, quoted, opener_pos]
    body = None   # active heredoc: [tag, dash, quoted, opener_pos, body_start, base_frames]
    # base_frames = frame depth when the body began: an ENCLOSING $( (the heredoc lives
    # inside a substitution) keeps the body running, while a $( opened FROM the body
    # suspends it until that frame pops back to base

    def start_next_body(pos):
        return [*pending.pop(0), pos, len(frames)] if pending else None

    def emit_word_runs(word_text, tail):
        k = 0
        while k < len(word_text):
            if word_text[k] == "\\":
                j = k
                while j < len(word_text) and word_text[j] == "\\":
                    j += 1
                nxt = word_text[j] if j < len(word_text) else (tail or "")
                runs.append((j - k, "processed", nxt))
                k = j
            else:
                k += 1

    while i < n:
        # ---- heredoc body mode (suspended while a substitution frame is open) ----------
        if body is not None and len(frames) == body[5]:
            tag, dash, quoted, opener_pos, body_start, _base = body
            at_line_start = i == 0 or command[i - 1] == "\n"
            eol = command.find("\n", i)
            if eol < 0:
                eol = n
            if at_line_start:
                term_line = command[i:eol]
                term_end = eol
                if not quoted:  # bash joins backslash-newline before the terminator check
                    while _ends_with_odd_backslash(term_line) and term_end < n:
                        nxt = command.find("\n", term_end + 1)
                        if nxt < 0:
                            nxt = n
                        term_line = term_line[:-1] + command[term_end + 1:nxt]
                        term_end = nxt
                t = term_line.rstrip("\r")
                if dash:
                    t = t.lstrip("\t")
                if t == tag:
                    records.append((quoted, body_start, max(body_start, i - 1), opener_pos))
                    i = term_end + 1  # the terminator line is inert - never scanned
                    body = start_next_body(i)
                    continue
                eol = term_end  # a joined line that is NOT the terminator is body wholesale
            k = i
            while k < eol:
                ch = command[k]
                if ch == "\\":
                    j = k
                    while j < n and command[j] == "\\":
                        j += 1
                    runs.append((j - k, "literal" if quoted else "processed",
                                 command[j] if j < n else ""))
                    k = j
                elif not quoted and ch == "$" and command[k + 1:k + 2] == "(":
                    break  # an unquoted body runs substitutions for real
                else:
                    k += 1
            if k < eol:  # broke on $(
                frames.append([in_single, in_double, 0, 0, False, False])
                in_single = in_double = False
                i = k + 2
                continue
            i = eol + 1
            continue

        # ---- normal shell scanning ------------------------------------------------------
        c = command[i]
        if arith:
            if c == "(":
                arith += 1
            elif c == ")":
                arith -= 1
            i += 1
            continue
        if in_comment:
            if c == "\n":
                in_comment = False
                if body is None and pending:
                    body = start_next_body(i + 1)
            i += 1
            continue
        if c == "\\":
            j = i
            while j < n and command[j] == "\\":
                j += 1
            ctx = "literal" if in_single else "processed"
            runs.append((j - i, ctx, command[j] if j < n else ""))
            if ctx == "processed" and (j - i) % 2 == 1 and j < n:
                if not in_double:
                    j += 1  # bare context: the backslash escapes the next char outright
                elif command[j] == '"':
                    j += 1  # in double quotes an escaped quote must not toggle
            i = j
            continue
        if c == "'" and not in_double:
            in_single = not in_single
        elif c == '"' and not in_single:
            in_double = not in_double
        elif c == "#" and not in_single and not in_double and (i == 0 or command[i - 1] in " \t\n;&|("):
            in_comment = True
        elif c == "$" and not in_single and command[i + 1:i + 3] == "((":
            arith = 2  # $(( )) is arithmetic: << is a shift, quotes and heredocs do not apply
            i += 3
            continue
        elif c == "$" and not in_single and command[i + 1:i + 2] == "(":
            frames.append([in_single, in_double, 0, 0, False, False])
            in_single = in_double = False
            cmd_pos = True
            i += 2
            continue
        elif c == "(" and not in_single and not in_double and cmd_pos and command[i + 1:i + 2] == "(":
            arith = 2  # (( )) arithmetic command
            i += 2
            continue
        elif c == "(" and not in_single and not in_double and frames:
            if frames[-1][5]:
                pass  # the optional open paren of a case pattern
            else:
                frames[-1][2] += 1
                cmd_pos = True
        elif c == ")" and not in_single and not in_double and frames:
            f = frames[-1]
            if f[5]:
                f[5] = False  # a pattern closer: `x)` starts the action
                cmd_pos = True
            elif f[2] > 0:
                f[2] -= 1
            else:
                in_single, in_double, _d, _c, _a, _p = frames.pop()
        elif (c == ";" and command[i + 1:i + 2] == ";" and frames and frames[-1][3] > 0
              and not in_single and not in_double):
            frames[-1][5] = True  # `;;` - the next pattern follows
            cmd_pos = True
            i += 2
            continue
        elif (c == "c" and frames and not in_single and not in_double and cmd_pos
              and _match_word(command, i, "case")):
            frames[-1][3] += 1
            frames[-1][4] = True   # awaiting the `in` that opens the pattern list
        elif (c == "i" and frames and frames[-1][4] and not in_single and not in_double
              and _match_word(command, i, "in")):
            frames[-1][4] = False
            frames[-1][5] = True   # the first pattern follows
        elif (c == "e" and frames and not in_single and not in_double and cmd_pos
              and _match_word(command, i, "esac")):
            frames[-1][3] = max(0, frames[-1][3] - 1)
            frames[-1][4] = frames[-1][5] = False
        elif (c == "<" and not in_single and not in_double and command[i:i + 2] == "<<"
              and command[i + 2:i + 3] != "<" and command[i - 1:i] != "<"):
            m = re.compile(r"<<(-?)[ \t]*").match(command, i)
            word = _DELIM_WORD.match(command, m.end())
            if word:
                raw = word.group()
                end = word.end()
                while command[end:end + 2] == "\\\n":  # bash removes backslash-newline before tokenizing
                    more = _DELIM_WORD.match(command, end + 2)
                    if not more:
                        break
                    raw += more.group()
                    end = more.end()
                tag, quoted = _parse_delim(raw)
                emit_word_runs(raw, command[end:end + 1])
                pending.append([tag, m.group(1) == "-", quoted, i])
                cmd_pos = False
                i = end
                continue
        elif c == "\n":
            if body is None and pending:
                body = start_next_body(i + 1)
        if c in ";&|\n":
            cmd_pos = True
        elif c not in " \t":
            cmd_pos = False
        i += 1
    # an opener whose terminator never comes is not a heredoc (its runs already stand)
    return tuple(runs), tuple(records)


def backslash_runs(command):
    """(run_length, context, next_char) per maximal backslash run - see _lex."""
    return _lex(command)[0]


def heredoc_records(command):
    """(quoted, body_start, body_end, opener_pos) per terminated heredoc, in order."""
    return _lex(command)[1]


def heredocs(command):
    """(quoted_delimiter: bool, body_start, body_end) - the classic view of heredoc_records."""
    return tuple((q, a, b) for q, a, b, _pos in heredoc_records(command))


# --- PreToolUse rules --------------------------------------------------------------------

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


def sink_segment(command, opener_pos):
    """The piece of the opener's line that owns THIS heredoc's `<<`: split on unquoted
    && || ; but not on |, so `cat <<EOF | git commit -F -` keeps its sink while an
    earlier, unrelated command - or a `;` inside a quoted argument - does not leak in."""
    start = command.rfind("\n", 0, opener_pos) + 1
    end = command.find("\n", opener_pos)
    line = command[start:] if end < 0 else command[start:end]
    op = opener_pos - start
    seps = []
    in_s = in_d = False
    k = 0
    while k < len(line):
        ch = line[k]
        if ch == "\\" and not in_s:
            k += 2
            continue
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif not in_s and not in_d:
            if line[k:k + 2] in ("&&", "||"):
                seps.append((k, k + 2))
                k += 2
                continue
            if ch == ";":
                seps.append((k, k + 1))
        k += 1
    lo = 0
    for a, b in seps:
        if b <= op:
            lo = b
        else:
            return line[lo:a]
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


PRE_RULES = [rule_backslash_pair, rule_unquoted_heredoc_expansion]


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
     "the harness wrapper tail errored - the command text failed to parse as a whole (non-ASCII in the command on an old Git for Windows runtime is the usual cause; upgrading Git for Windows fixes that class)"),
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
