#!/usr/bin/env python3
"""agent-plan-guard: pre-flight safety gate + audit trail for autonomous agents.

Pattern (original code, inspired by the "every action decided in advance and
recorded" idea popularized by open-source AI-coworker platforms): an agent may
only run the exact plan it declared up front. The guard checks every step
against a policy *before* anything runs, refuses the whole plan on any
violation (nothing is half-executed), and appends an audit record for every
action it takes.

Stdlib only. No network. No shell — commands are argv lists.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

EXIT_OK = 0
EXIT_STEP_FAILED = 1
EXIT_BAD_INPUT = 2
EXIT_POLICY_VIOLATION = 3

DEFAULT_DENIED_BINARIES = [
    "sudo", "su", "doas", "runas",
    "sh", "bash", "zsh", "fish", "dash", "ksh", "powershell", "pwsh", "cmd",
    "curl", "wget", "aria2c",
    "ssh", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "telnet", "ftp",
    "mkfs", "dd", "fdisk", "parted",
]

DEFAULT_DENIED_ARGV_PATTERNS = [
    r"(?:^|\s)rm\s+(?:-[a-zA-Z]*r[a-zA-Z]*\s+)+(?:/|\*|~)(?:\s|$)",  # rm -rf / * ~
    r":\(\)\{\s*:\|\:&\s*\};:",                                     # fork bomb
    r">\s*/dev/(sd|hd|nvme|vd|xvd)",                               # raw disk write redirect
    r"\bdd\b\s+if=\S+\s+of=/dev/",                                 # dd onto a device
    r"mkfs\.",                                                     # format a filesystem
    r"--(token|password|api[-_]?key|secret)\s+\S+",                # secret baked into argv
]

TAIL_CHARS = 2000


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def load_json(path: str):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh), None
    except FileNotFoundError:
        return None, f"file not found: {path}"
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON in {path}: {exc}"
    except OSError as exc:
        return None, f"cannot read {path}: {exc}"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_plan(plan) -> list[str]:
    """Return a list of schema errors (empty = structurally valid)."""
    errors = []
    if not isinstance(plan, dict):
        return ["plan must be a JSON object"]
    steps = plan.get("steps")
    if not isinstance(steps, list) or not steps:
        return ["plan.steps must be a non-empty list"]
    seen_ids = set()
    for i, step in enumerate(steps):
        where = f"steps[{i}]"
        if not isinstance(step, dict):
            errors.append(f"{where}: must be an object")
            continue
        sid = step.get("id")
        if not isinstance(sid, str) or not sid:
            errors.append(f"{where}: id must be a non-empty string")
        elif sid in seen_ids:
            errors.append(f"{where}: duplicate id {sid!r}")
        else:
            seen_ids.add(sid)
        argv = step.get("argv")
        if not isinstance(argv, list) or not argv or not all(
                isinstance(a, str) and a for a in argv):
            errors.append(f"{where}: argv must be a non-empty list of strings")
        timeout = step.get("timeout", 60)
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            errors.append(f"{where}: timeout must be a positive number")
        cwd = step.get("cwd", ".")
        if not isinstance(cwd, str) or not cwd:
            errors.append(f"{where}: cwd must be a non-empty string")
    return errors


# ---------------------------------------------------------------------------
# Policy checking
# ---------------------------------------------------------------------------

def _binary_of(argv: list[str]) -> str:
    return os.path.basename(argv[0])


def check_step(step: dict, policy: dict, plan_dir: str) -> list[str]:
    """Return a list of policy violations for one step (empty = allowed)."""
    problems = []
    argv = step["argv"]
    joined = " ".join(argv)
    binary = _binary_of(argv)

    denied_binaries = policy.get(
        "denied_binaries", DEFAULT_DENIED_BINARIES)
    if binary in denied_binaries:
        problems.append(f"denied binary: {binary!r}")

    allowed_binaries = policy.get("allowed_binaries")
    if allowed_binaries is not None and binary not in allowed_binaries:
        problems.append(
            f"binary {binary!r} not in policy.allowed_binaries")

    for pattern in policy.get("denied_argv_patterns",
                              DEFAULT_DENIED_ARGV_PATTERNS):
        try:
            if re.search(pattern, joined):
                problems.append(
                    f"argv matches denied pattern: {pattern}")
                break
        except re.error:
            problems.append(f"invalid denied_argv_pattern: {pattern}")
            break

    max_timeout = policy.get("max_timeout_seconds", 600)
    if step.get("timeout", 60) > max_timeout:
        problems.append(
            f"timeout {step['timeout']}s exceeds policy max "
            f"{max_timeout}s")

    if policy.get("require_note", True) and not step.get("note"):
        problems.append(
            "step has no note — every action must be explained in advance")

    allowed_roots = policy.get("allowed_roots", ["."])
    if allowed_roots:
        cwd = os.path.realpath(os.path.join(plan_dir, step.get("cwd", ".")))
        inside = any(
            cwd == os.path.realpath(os.path.join(plan_dir, root))
            or cwd.startswith(
                os.path.realpath(os.path.join(plan_dir, root)) + os.sep)
            for root in allowed_roots
        )
        if not inside:
            problems.append(
                f"cwd {step.get('cwd', '.')!r} escapes policy.allowed_roots")

    return problems


def review_plan(plan: dict, policy: dict, plan_dir: str):
    """Return [(step, problems)] — problems empty means the step is allowed."""
    return [(step, check_step(step, policy, plan_dir))
            for step in plan["steps"]]


def plan_hash(plan: dict) -> str:
    canonical = json.dumps(plan, sort_keys=True, ensure_ascii=True,
                           separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run_step(step: dict, plan_dir: str) -> dict:
    cwd = os.path.realpath(os.path.join(plan_dir, step.get("cwd", ".")))
    started = time.monotonic()
    try:
        proc = subprocess.run(
            step["argv"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=step.get("timeout", 60),
            # argv lists only — never passed through a shell
        )
        timed_out = False
        code = proc.returncode
        out, err = proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        code = -1
        out = (exc.stdout or b"").decode("utf-8", "replace") \
            if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = (exc.stderr or b"").decode("utf-8", "replace") \
            if isinstance(exc.stderr, bytes) else (exc.stderr or "")
    except FileNotFoundError:
        timed_out = False
        code = -1
        out, err = "", f"binary not found: {step['argv'][0]!r}"
    except OSError as exc:
        timed_out = False
        code = -1
        out, err = "", f"cannot start: {exc}"
    duration = time.monotonic() - started
    return {
        "ts": utcnow(),
        "step_id": step["id"],
        "binary": _binary_of(step["argv"]),
        "argv": step["argv"],
        "cwd": os.path.relpath(cwd, plan_dir),
        "timeout_s": step.get("timeout", 60),
        "timed_out": timed_out,
        "exit_code": code,
        "duration_s": round(duration, 3),
        "note": step.get("note", ""),
        "stdout_tail": (out or "")[-TAIL_CHARS:],
        "stderr_tail": (err or "")[-TAIL_CHARS:],
    }


def execute(plan: dict, review, audit_path: str, plan_dir: str) -> int:
    """Run an already-approved plan; every action is appended to the audit log."""
    phash = plan_hash(plan)
    record = {
        "ts": utcnow(),
        "event": "plan_started",
        "plan_name": plan.get("plan_name", ""),
        "plan_hash": phash,
        "step_count": len(plan["steps"]),
    }
    lines = [json.dumps(record, ensure_ascii=False)]
    failed = []
    for step, _problems in review:
        rec = run_step(step, plan_dir)
        rec["plan_hash"] = phash
        rec["event"] = "step_completed"
        lines.append(json.dumps(rec, ensure_ascii=False))
        if rec["exit_code"] != 0:
            failed.append(step["id"])
    summary = {
        "ts": utcnow(),
        "event": "plan_finished",
        "plan_hash": phash,
        "status": "ok" if not failed else "failed",
        "failed_steps": failed,
    }
    lines.append(json.dumps(summary, ensure_ascii=False))
    with open(audit_path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return EXIT_OK if not failed else EXIT_STEP_FAILED


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_review(args) -> int:
    plan, err = load_json(args.plan)
    if err:
        print(f"error: {err}", file=sys.stderr)
        return EXIT_BAD_INPUT
    errors = validate_plan(plan)
    if errors:
        print("plan schema errors:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return EXIT_BAD_INPUT
    policy = {}
    if args.policy:
        policy, perr = load_json(args.policy)
        if perr:
            print(f"error: {perr}", file=sys.stderr)
            return EXIT_BAD_INPUT
    plan_dir = os.path.dirname(os.path.abspath(args.plan)) or "."
    review = review_plan(plan, policy, plan_dir)
    denied = 0
    print(f"plan: {plan.get('plan_name', '(unnamed)')} "
          f"[{len(review)} steps] hash={plan_hash(plan)}")
    for step, problems in review:
        verdict = "ALLOW" if not problems else "DENY"
        if problems:
            denied += 1
        print(f"  [{verdict}] {step['id']}: {' '.join(step['argv'])}")
        for p in problems:
            print(f"           - {p}")
        if step.get("note"):
            print(f"           note: {step['note']}")
    if denied:
        print(f"\n{denied} step(s) DENIED — nothing will run.",
              file=sys.stderr)
        return EXIT_POLICY_VIOLATION
    print("\nall steps allowed — nothing ran (review only).")
    return EXIT_OK


def cmd_run(args) -> int:
    plan, err = load_json(args.plan)
    if err:
        print(f"error: {err}", file=sys.stderr)
        return EXIT_BAD_INPUT
    errors = validate_plan(plan)
    if errors:
        print("plan schema errors:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return EXIT_BAD_INPUT
    policy = {}
    if args.policy:
        policy, perr = load_json(args.policy)
        if perr:
            print(f"error: {perr}", file=sys.stderr)
            return EXIT_BAD_INPUT
    plan_dir = os.path.dirname(os.path.abspath(args.plan)) or "."
    review = review_plan(plan, policy, plan_dir)
    denied = [(s["id"], p) for s, p in review if p]
    if denied:
        print("policy violations — plan refused, nothing executed:",
              file=sys.stderr)
        for sid, problems in denied:
            for p in problems:
                print(f"  - {sid}: {p}", file=sys.stderr)
        return EXIT_POLICY_VIOLATION
    return execute(plan, review, args.audit, plan_dir)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Pre-flight safety gate + audit trail for agent plans.")
    sub = ap.add_subparsers(dest="command", required=True)

    r = sub.add_parser("review",
                       help="check a plan against the policy (runs nothing)")
    r.add_argument("--plan", required=True)
    r.add_argument("--policy", default=None)
    r.set_defaults(func=cmd_review)

    x = sub.add_parser("run",
                       help="run a plan only if every step is policy-allowed")
    x.add_argument("--plan", required=True)
    x.add_argument("--policy", default=None)
    x.add_argument("--audit", default="audit.log.jsonl")
    x.set_defaults(func=cmd_run)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
