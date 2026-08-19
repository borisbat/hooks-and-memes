#!/usr/bin/env python3
"""Claude Code PreToolUse hook for the Bash tool: deny commands the harness would mangle.

stdin: the hook event JSON; stdout: a deny decision when a rule matches, nothing otherwise.
Fail-open by design - a hook that crashes must not block every command, so any error in
this script (including importing its own rules) is reported on stderr and the call proceeds.
"""
import json
import os
import sys


def decide(event):
    """The hook's pure half: event dict -> output dict or None (allow)."""
    if event.get("tool_name") != "Bash":
        return None
    from bash_mangling_rules import pre_check
    command = (event.get("tool_input") or {}).get("command") or ""
    reason = pre_check(command)
    if not reason:
        return None
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def main():
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        event = json.load(sys.stdin)
        out = decide(event)
    except Exception as e:  # fail open
        sys.stderr.write(f"bash_pre hook error (command allowed): {e}\n")
        return 0
    if out:
        sys.stdout.write(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
