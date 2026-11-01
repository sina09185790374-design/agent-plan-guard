"""Tests for agent_plan_guard — all run locally, stdlib only."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import agent_plan_guard as g  # noqa: E402

GOOD_STEP = {
    "id": "s1",
    "argv": ["python3", "-c", "print('ok')"],
    "cwd": ".",
    "timeout": 30,
    "note": "harmless smoke test",
}
GOOD_PLAN = {"plan_name": "t", "steps": [dict(GOOD_STEP)]}


def write_tmp(tmpdir, name, obj):
    path = os.path.join(tmpdir, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)
    return path


class SchemaTest(unittest.TestCase):
    def test_valid_plan(self):
        self.assertEqual(g.validate_plan(GOOD_PLAN), [])

    def test_missing_argv(self):
        bad = {"plan_name": "t",
               "steps": [{"id": "s1", "note": "x"}]}
        self.assertTrue(g.validate_plan(bad))

    def test_duplicate_ids(self):
        bad = {"plan_name": "t", "steps": [dict(GOOD_STEP),
                                          dict(GOOD_STEP)]}
        errors = g.validate_plan(bad)
        self.assertTrue(any("duplicate" in e for e in errors))

    def test_bad_timeout(self):
        bad = {"plan_name": "t",
               "steps": [dict(GOOD_STEP, timeout=-5)]}
        self.assertTrue(g.validate_plan(bad))

    def test_empty_steps(self):
        self.assertTrue(g.validate_plan({"plan_name": "t", "steps": []}))


class PolicyTest(unittest.TestCase):
    def test_denied_binary_sudo(self):
        step = dict(GOOD_STEP, argv=["sudo", "ls"])
        self.assertTrue(g.check_step(step, {}, "/tmp"))

    def test_denied_rm_rf_root(self):
        step = dict(GOOD_STEP, argv=["rm", "-rf", "/"])
        self.assertTrue(g.check_step(step, {}, "/tmp"))

    def test_denied_curl(self):
        step = dict(GOOD_STEP, argv=["curl", "https://example.com"])
        self.assertTrue(g.check_step(step, {}, "/tmp"))

    def test_denied_secret_in_argv(self):
        step = dict(GOOD_STEP, argv=["tool", "--api-key", "sk-live-123"])
        self.assertTrue(g.check_step(step, {}, "/tmp"))

    def test_strict_allowlist(self):
        policy = {"allowed_binaries": ["ls"]}
        step = dict(GOOD_STEP, argv=["python3", "-c", "pass"])
        self.assertTrue(g.check_step(step, policy, "/tmp"))
        ok_step = dict(GOOD_STEP, argv=["ls", "-la"])
        self.assertEqual(g.check_step(ok_step, policy, "/tmp"), [])

    def test_cwd_escape_blocked(self):
        policy = {"allowed_roots": ["sub"]}
        step = dict(GOOD_STEP, cwd="../..")
        self.assertTrue(g.check_step(step, policy, "/tmp"))

    def test_require_note(self):
        step = dict(GOOD_STEP)
        del step["note"]
        self.assertTrue(g.check_step(step, {"require_note": True}, "/tmp"))
        self.assertEqual(
            g.check_step(step, {"require_note": False}, "/tmp"), [])

    def test_timeout_cap(self):
        policy = {"max_timeout_seconds": 10}
        step = dict(GOOD_STEP, timeout=999)
        self.assertTrue(g.check_step(step, policy, "/tmp"))

    def test_no_shell_anywhere(self):
        import re
        src = os.path.join(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))),
            "agent_plan_guard.py")
        with open(src, encoding="utf-8") as fh:
            code = fh.read()
        self.assertIsNone(re.search(r"shell\s*=\s*True", code))


class CliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def run_cli(self, *args):
        script = os.path.join(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))),
            "agent_plan_guard.py")
        return subprocess.run(
            [sys.executable, script, *args],
            capture_output=True, text=True, cwd=self.tmp)

    def test_review_ok(self):
        plan = write_tmp(self.tmp, "plan.json", GOOD_PLAN)
        r = self.run_cli("review", "--plan", plan)
        self.assertEqual(r.returncode, g.EXIT_OK)
        self.assertIn("ALLOW", r.stdout)

    def test_review_denies_sudo(self):
        bad = {"plan_name": "t", "steps": [
            dict(GOOD_STEP, argv=["sudo", "ls"])]}
        plan = write_tmp(self.tmp, "plan.json", bad)
        r = self.run_cli("review", "--plan", plan)
        self.assertEqual(r.returncode, g.EXIT_POLICY_VIOLATION)
        self.assertIn("DENY", r.stdout)

    def test_run_writes_audit_log(self):
        plan = write_tmp(self.tmp, "plan.json", GOOD_PLAN)
        audit = os.path.join(self.tmp, "audit.log.jsonl")
        r = self.run_cli("run", "--plan", plan, "--audit", audit)
        self.assertEqual(r.returncode, g.EXIT_OK)
        with open(audit, encoding="utf-8") as fh:
            lines = [json.loads(x) for x in fh if x.strip()]
        events = [l["event"] for l in lines]
        self.assertEqual(events,
                         ["plan_started", "step_completed", "plan_finished"])
        step = lines[1]
        self.assertEqual(step["step_id"], "s1")
        self.assertEqual(step["exit_code"], 0)
        self.assertIn("ok", step["stdout_tail"])
        self.assertEqual(lines[-1]["status"], "ok")

    def test_run_refuses_before_anything_executes(self):
        bad = {"plan_name": "t", "steps": [
            dict(GOOD_STEP),
            dict(GOOD_STEP, id="s2", argv=["sudo", "ls"])]}
        plan = write_tmp(self.tmp, "plan.json", bad)
        audit = os.path.join(self.tmp, "audit.log.jsonl")
        r = self.run_cli("run", "--plan", plan, "--audit", audit)
        self.assertEqual(r.returncode, g.EXIT_POLICY_VIOLATION)
        # refused BEFORE execution: no audit file, s1 never ran
        self.assertFalse(os.path.exists(audit))

    def test_run_records_step_failure(self):
        fail = {"plan_name": "t", "steps": [
            dict(GOOD_STEP, argv=["python3", "-c", "import sys; sys.exit(3)"])]}
        plan = write_tmp(self.tmp, "plan.json", fail)
        audit = os.path.join(self.tmp, "audit.log.jsonl")
        r = self.run_cli("run", "--plan", plan, "--audit", audit)
        self.assertEqual(r.returncode, g.EXIT_STEP_FAILED)
        with open(audit, encoding="utf-8") as fh:
            lines = [json.loads(x) for x in fh if x.strip()]
        self.assertEqual(lines[-1]["status"], "failed")
        self.assertEqual(lines[-1]["failed_steps"], ["s1"])

    def test_run_timeout(self):
        slow = {"plan_name": "t", "steps": [
            dict(GOOD_STEP,
                 argv=["python3", "-c", "import time; time.sleep(10)"],
                 timeout=1)]}
        plan = write_tmp(self.tmp, "plan.json", slow)
        audit = os.path.join(self.tmp, "audit.log.jsonl")
        r = self.run_cli("run", "--plan", plan, "--audit", audit)
        self.assertEqual(r.returncode, g.EXIT_STEP_FAILED)
        with open(audit, encoding="utf-8") as fh:
            lines = [json.loads(x) for x in fh if x.strip()]
        self.assertTrue(lines[1]["timed_out"])

    def test_bad_input_exit_code(self):
        r = self.run_cli("review", "--plan", "/nonexistent/plan.json")
        self.assertEqual(r.returncode, g.EXIT_BAD_INPUT)


if __name__ == "__main__":
    unittest.main()
