#!/usr/bin/env python3
"""Claude Code PostToolUse hook for the Bash tool: when the output carries the fingerprint
of a harness-mangled command, tell the model so in context (it cannot un-run the command,
but it can stop trusting the result).

The tool_response shape is read defensively - dict fields, a plain string, or anything
json-serializable - so a schema drift degrades to "no signal", never to a crash.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bash_mangling_rules import post_check  # noqa: E402


def response_text(tool_response):
    if tool_response is None:
        return ""
    if isinstance(tool_response, str):
        return tool_response
    if isinstance(tool_response, dict):
        parts = []
        for key in ("stdout", "stderr", "output", "result", "content", "error", "message"):
            v = tool_response.get(key)
            if isinstance(v, str):
                parts.append(v)
        if parts:
            return "\n".join(parts)
    try:
        return json.dumps(tool_response)
    except Exception:
        return str(tool_response)


def decide(event):
    """The hook's pure half: event dict -> output dict or None (quiet)."""
    if event.get("tool_name") != "Bash":
        return None
    command = (event.get("tool_input") or {}).get("command") or ""
    text = response_text(event.get("tool_response"))
    msg = post_check(command, text)
    if not msg:
        return None
    return {
        "hookSpecificOutput": {"hookEventName": "PostToolUse"},
        "additionalContext": msg,
        "systemMessage": "shell-ate-it: the last Bash command was mangled by the harness",
    }


def main():
    try:
        event = json.load(sys.stdin)
        out = decide(event)
    except Exception as e:
        sys.stderr.write(f"bash_post hook error (ignored): {e}\n")
        return 0
    if out:
        sys.stdout.write(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
