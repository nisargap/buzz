"""Offline end-to-end proof against disposable Python and JavaScript Git repos."""

import contextlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts.refactor.cli import main
from scripts.refactor.policy import RefactorError, load_policy
from scripts.refactor.proposal import generate_proposal, validate_proposal
from scripts.refactor.repository import collect_context, digest, git, inspect_repository
from scripts.refactor.runner import create_run, recheck_run, review_run

PYTHON_BEFORE = """def normalize(value):
    if value is None:
        return ''
    cleaned = value.strip()
    return cleaned
"""
PYTHON_AFTER = """def normalize(value):
    if value is None:
        return ''
    return value.strip()
"""
JS_BEFORE = """function normalize(value) {
  if (value === null) return '';
  const cleaned = value.trim();
  return cleaned;
}
module.exports = { normalize };
"""
JS_AFTER = """function normalize(value) {
  if (value === null) return '';
  return value.trim();
}
module.exports = { normalize };
"""


class RefactorIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "customer"
        self.repo.mkdir()
        self.command("init", "-b", "main")
        self.command("config", "user.name", "Refactor Test")
        self.command("config", "user.email", "refactor-test@example.invalid")
        self.put(".gitignore", "__pycache__/\n.refactor/runs/\n")
        self.put("src/normalize.py", PYTHON_BEFORE)
        self.put("tests/check.py", "import sys\nsys.path.insert(0, 'src')\nfrom normalize import normalize\nassert normalize(None) == ''\nassert normalize('  hello  ') == 'hello'\nassert normalize('') == ''\n")
        self.put("pyproject.toml", "[project]\nname = 'fixture'\nversion = '0.0.0'\n")
        self.command("add", ".")
        self.command("commit", "-m", "Fixture baseline")
        self.rules_path = self.repo / ".refactor/RULES.md"
        self.set_policy()

    def command(self, *args):
        result = subprocess.run(["git", *args], cwd=self.repo, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def put(self, path, content):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def set_policy(self, checks=None, **overrides):
        config = {"include": ["src/"], "exclude": [], "max_files": 3, "max_changed_lines": 100,
                  "checks": checks if checks is not None else [{"name": "tests", "argv": [sys.executable, "tests/check.py"]}]}
        config.update(overrides)
        self.put(".refactor/RULES.md", "# Customer rules\n\n```json\n" + json.dumps(config) + "\n```\n\nRemove redundant local variables, but keep explicit null handling.\n")
        return load_policy(self.rules_path)

    def inputs(self, path="src/normalize.py"):
        policy = load_policy(self.rules_path)
        revision = self.command("rev-parse", "HEAD")
        sources, context = collect_context(self.repo, revision, policy, [path], ["tests/check.py"] if path.endswith(".py") else [])
        return policy, revision, sources, context

    def proposal(self, sources, content):
        return {"summary": "Remove a redundant local variable", "rule": "Keep simple code straightforward",
                "tradeoffs": "No new abstraction; null handling is unchanged", "edits": [
                    {"path": sources[0]["path"], "before_sha256": sources[0]["sha256"], "content": content}]}

    def run_candidate(self, content=PYTHON_AFTER, path="src/normalize.py", feedback=""):
        policy, revision, sources, _ = self.inputs(path)
        proposal = self.proposal(sources, content)
        validate_proposal(proposal, sources, policy)
        return create_run(self.repo, self.rules_path, policy, sources, proposal, revision, feedback)

    def test_python_full_review_and_recheck_leaves_original_untouched(self):
        # Dirty work is intentionally not sent to the model or copied to its branch.
        self.put("src/normalize.py", PYTHON_BEFORE + "# customer's uncommitted work\n")
        original_status = self.command("status", "--porcelain")
        run_dir, report = self.run_candidate()
        self.assertEqual(report["status"], "ready_for_review", report)
        self.assertEqual(report["review"], "pending")
        self.assertEqual(self.command("status", "--porcelain"), original_status)
        self.assertTrue((run_dir / "candidate.patch").is_file())
        approved, _ = review_run(self.repo, report["id"], "approve")
        self.assertEqual(approved["review"], "approved")
        worktree = Path(report["worktree"])
        self.assertEqual(worktree.parent, self.repo.parent)
        self.assertEqual(git(worktree, "rev-parse", "HEAD").decode().strip(), report["revision"])
        (worktree / "src/normalize.py").write_text(PYTHON_AFTER + "\n", encoding="utf-8")
        with self.assertRaisesRegex(RefactorError, "exact checked patch"):
            review_run(self.repo, report["id"], "approve")
        shown, _ = review_run(self.repo, report["id"], None)
        self.assertEqual(shown["status"], "needs_recheck")
        _, checked = recheck_run(self.repo, report["id"], True)
        self.assertEqual(checked["status"], "ready_for_review")
        self.assertEqual(checked["review"], "pending")
        self.assertEqual(review_run(self.repo, report["id"], "approve")[0]["review"], "approved")
        self.assertIn("customer's uncommitted work", (self.repo / "src/normalize.py").read_text())

    @unittest.skipUnless(shutil.which("node"), "Node required for the second-language fixture")
    def test_same_runner_on_javascript(self):
        self.command("rm", "src/normalize.py", "tests/check.py", "pyproject.toml")
        self.put("src/normalize.js", JS_BEFORE)
        self.put("tests/check.js", "const assert = require('node:assert/strict');\nconst { normalize } = require('../src/normalize');\nassert.equal(normalize(null), '');\nassert.equal(normalize('  hello  '), 'hello');\nassert.equal(normalize(''), '');\n")
        self.put("package.json", '{"name":"fixture","private":true}\n')
        self.command("add", "src/normalize.js", "tests/check.js", "package.json")
        self.command("commit", "-m", "JavaScript fixture")
        self.set_policy(checks=[{"name": "tests", "argv": [shutil.which("node"), "tests/check.js"]}])
        _, report = self.run_candidate(JS_AFTER, "src/normalize.js")
        self.assertEqual(report["status"], "ready_for_review", report)
        discovery = inspect_repository(self.repo, load_policy(self.rules_path))
        self.assertIn("JavaScript", discovery["languages"])
        self.assertIn("package.json", discovery["manifests"])
        self.assertEqual((self.repo / "src/normalize.js").read_text(), JS_BEFORE)

    def test_failed_candidate_cannot_be_approved(self):
        _, report = self.run_candidate("def normalize(value):\n    return 'wrong'\n")
        self.assertEqual(report["status"], "verification_failed", report)
        with self.assertRaises(RefactorError):
            review_run(self.repo, report["id"], "approve")
        self.assertEqual((self.repo / "src/normalize.py").read_text(), PYTHON_BEFORE)

    def test_missing_checks_stays_unverified(self):
        self.set_policy(checks=[])
        _, report = self.run_candidate()
        self.assertEqual(report["status"], "unverified")
        with self.assertRaises(RefactorError):
            review_run(self.repo, report["id"], "approve")
        rejected, _ = review_run(self.repo, report["id"], "reject")
        self.assertEqual(rejected["review"], "rejected")

    def test_baseline_failure_is_not_a_success(self):
        self.set_policy(checks=[{"name": "broken baseline", "argv": [sys.executable, "-c", "raise SystemExit(1)"]}])
        _, report = self.run_candidate()
        self.assertEqual(report["status"], "baseline_failed")

    def test_scope_budget_enforced_outside_model(self):
        self.set_policy(max_changed_lines=1)
        _, report = self.run_candidate()
        self.assertEqual(report["status"], "blocked")
        self.assertIn("exceeds policy", report["error"])
        self.assertEqual((self.repo / "src/normalize.py").read_text(), PYTHON_BEFORE)

    def test_proposal_cannot_change_tests_or_expand_scope(self):
        policy, _, sources, _ = self.inputs()
        proposal = self.proposal(sources, PYTHON_AFTER)
        for path in ("tests/check.py", "../outside.py", ".refactor/RULES.md", "src/other.py"):
            with self.subTest(path=path):
                proposal["edits"][0]["path"] = path
                with self.assertRaises(RefactorError):
                    validate_proposal(proposal, sources, policy)
        proposal["edits"][0]["path"] = "src/normalize.py"
        proposal["edits"][0]["before_sha256"] = "stale"
        with self.assertRaisesRegex(RefactorError, "stale"):
            validate_proposal(proposal, sources, policy)

    def test_manual_test_edits_block_recheck(self):
        _, report = self.run_candidate()
        (Path(report["worktree"]) / "tests/check.py").write_text("pass\n", encoding="utf-8")
        _, checked = recheck_run(self.repo, report["id"], True)
        self.assertEqual(checked["status"], "blocked")
        self.assertIn("protected or unselected", checked["error"])

    def test_policy_change_requires_a_new_attempt(self):
        _, report = self.run_candidate()
        self.set_policy(max_changed_lines=20)
        with self.assertRaisesRegex(RefactorError, "rules changed"):
            recheck_run(self.repo, report["id"], True)

    def test_check_that_edits_source_is_blocked(self):
        self.set_policy(checks=[{"name": "mutator", "argv": [sys.executable, "-c", "from pathlib import Path; Path('src/normalize.py').write_text('changed')"]}])
        _, report = self.run_candidate()
        self.assertEqual(report["status"], "blocked")
        self.assertIn("modified tracked source", report["error"])

    def test_untracked_or_symlink_manual_edits_blocked(self):
        _, report = self.run_candidate()
        worktree = Path(report["worktree"])
        (worktree / "surprise.txt").write_text("unexpected", encoding="utf-8")
        _, checked = recheck_run(self.repo, report["id"], True)
        self.assertEqual(checked["status"], "blocked")
        (worktree / "surprise.txt").unlink()
        (worktree / "src/normalize.py").unlink()
        (worktree / "src/normalize.py").symlink_to(self.repo / "src/normalize.py")
        _, checked = recheck_run(self.repo, report["id"], True)
        self.assertEqual(checked["status"], "blocked")

    def test_context_is_committed_and_secret_files_are_excluded(self):
        self.put(".env", "SECRET=not-for-model\n")
        self.command("add", ".env")
        self.command("commit", "-m", "Accidentally tracked environment file")
        policy, revision, _, _ = self.inputs()
        with self.assertRaises(RefactorError):
            collect_context(self.repo, revision, policy, ["src/normalize.py"], [".env"])

    def test_check_timeout_is_reported(self):
        self.set_policy(checks=[{"name": "timeout", "argv": [sys.executable, "-c", "import time; time.sleep(20)"], "timeout_seconds": 1}])
        _, report = self.run_candidate()
        self.assertEqual(report["status"], "baseline_failed")
        self.assertTrue(report["baseline"][0]["timed_out"])
        self.assertTrue(report["candidate"][0]["timed_out"])

    def test_rule_edits_during_generation_do_not_change_run_policy(self):
        policy, revision, sources, _ = self.inputs()
        proposal = self.proposal(sources, PYTHON_AFTER)
        self.set_policy(max_changed_lines=5)
        with self.assertRaisesRegex(RefactorError, "Rules changed"):
            create_run(self.repo, self.rules_path, policy, sources, proposal, revision, "")

    def test_manual_binary_replacement_is_blocked(self):
        _, report = self.run_candidate()
        target = Path(report["worktree"]) / "src/normalize.py"
        target.write_bytes(b"\xff\xfe")
        _, checked = recheck_run(self.repo, report["id"], True)
        self.assertEqual(checked["status"], "blocked")
        self.assertIn("UTF-8", checked["error"])

    def test_feedback_is_per_attempt_and_no_change_is_valid(self):
        policy, revision, sources, _ = self.inputs()
        rules_before = self.rules_path.read_bytes()
        proposal = self.proposal(sources, PYTHON_AFTER)
        proposal["edits"] = []
        validate_proposal(proposal, sources, policy)
        _, report = create_run(self.repo, self.rules_path, policy, sources, proposal, revision, "Keep explicit guards")
        self.assertEqual(report["status"], "no_change")
        self.assertEqual(report["feedback"], "Keep explicit guards")
        self.assertIsNone(report["worktree"])
        self.assertEqual(self.rules_path.read_bytes(), rules_before)

    def test_cli_requires_execution_and_upload_consent(self):
        with contextlib.redirect_stderr(io.StringIO()) as output:
            result = main(["run", "--repo", str(self.repo), "--file", "src/normalize.py"])
        self.assertEqual(result, 1)
        self.assertIn("approve-checks", output.getvalue())
        self.set_policy(checks=[])
        with contextlib.redirect_stderr(io.StringIO()) as output:
            result = main(["run", "--repo", str(self.repo), "--file", "src/normalize.py"])
        self.assertEqual(result, 1)
        self.assertIn("allow-source-upload", output.getvalue())

    def test_offline_cli_reports_run_and_checks(self):
        _, _, sources, _ = self.inputs()
        proposal_path = Path(self.temp.name) / "proposal.json"
        proposal_path.write_text(json.dumps(self.proposal(sources, PYTHON_AFTER)), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = main(["run", "--repo", str(self.repo), "--file", "src/normalize.py", "--proposal", str(proposal_path), "--approve-checks"])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "ready_for_review")

    def test_model_uses_feedback_without_saving_rules(self):
        policy, _, sources, context = self.inputs()
        proposal = self.proposal(sources, PYTHON_AFTER)
        response = {"candidates": [{"finishReason": "STOP", "content": {"parts": [{"text": json.dumps(proposal)}]}}]}
        fake_response = io.BytesIO(json.dumps(response).encode())
        with patch.dict("os.environ", {"GEMINI_API_KEY": "test-only-key"}), patch("urllib.request.urlopen", return_value=fake_response) as request:
            value = generate_proposal(policy, sources, context, "Keep explicit guards", "example-model")
        self.assertEqual(value, proposal)
        payload = json.loads(request.call_args.args[0].data)
        sent = json.loads(payload["contents"][0]["parts"][0]["text"])
        self.assertEqual(sent["feedback"], "Keep explicit guards")
        self.assertEqual(sent["editable_files"][0]["sha256"], digest(PYTHON_BEFORE))
        self.assertNotIn("Keep explicit guards", self.rules_path.read_text())


if __name__ == "__main__":
    unittest.main()
