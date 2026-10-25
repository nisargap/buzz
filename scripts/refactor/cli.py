"""Command-line interface for the Markdown-driven refactoring prototype."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from .policy import RefactorError, default_rules, load_policy, safe_relative
from .proposal import generate_proposal, validate_proposal
from .repository import collect_context, git, inspect_repository, repository_root
from .runner import create_run, local_path, recheck_run, review_run


def parser():
    root = argparse.ArgumentParser(description="Small, review-required refactors guided by Markdown; no auto-commit or merge.")
    commands = root.add_subparsers(dest="command", required=True)
    for name in ("init", "inspect", "run", "check", "review"):
        child = commands.add_parser(name)
        child.add_argument("--repo", default=".", help="Local Git repository (committed HEAD is the source)")
        if name in ("init", "inspect", "run"):
            child.add_argument("--rules", default=".refactor/RULES.md", help="Repository-relative Markdown policy")
        if name == "init":
            child.add_argument("--include", action="append", default=[], help="Allowed exact file or directory ending in /; repeatable")
        elif name == "run":
            child.add_argument("--file", action="append", required=True, help="Tracked file to refactor; repeatable")
            child.add_argument("--context", action="append", default=[], help="Additional read-only tracked caller/type/test file")
            child.add_argument("--feedback", default="", help="Customer guidance for this attempt; not saved as a rule")
            child.add_argument("--proposal", type=Path, help="Offline JSON proposal instead of calling Gemini")
            child.add_argument("--model", default=os.environ.get("GEMINI_MODEL", "gemini-4-argon"))
            child.add_argument("--allow-source-upload", action="store_true", help="Consent to send selected source/context/rules to Gemini")
            child.add_argument("--approve-checks", action="store_true", help="Approve configured commands (trusted code only; not an OS sandbox)")
        elif name == "check":
            child.add_argument("run_id")
            child.add_argument("--approve-checks", action="store_true")
        elif name == "review":
            child.add_argument("run_id")
            child.add_argument("--decision", choices=("approve", "reject"), help="Records a decision; never commits or merges")
    return root


def print_json(value):
    print(json.dumps(value, indent=2))


def report_result(run_dir, report):
    print_json({"run_id": report["id"], "status": report["status"], "review": report["review"],
                "summary": report["summary"], "report": str(run_dir / "report.json"),
                "worktree": report["worktree"], "branch": report["branch"],
                "error": report.get("error"),
                "note": "Original source untouched. Review required. No commits, pushes, or merges performed."})
    return 0 if report["status"] in ("ready_for_review", "no_change") else 2


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        repo = repository_root(args.repo)
        if args.command == "review":
            report, diff = review_run(repo, args.run_id, args.decision)
            print_json(report)
            if diff:
                # Escape terminal controls without changing the patch file on disk.
                print("\n" + "".join(char if char in "\n\t" or char.isprintable() else "?" for char in diff.decode("utf-8", errors="replace")))
            return 0
        if args.command == "check":
            return report_result(*recheck_run(repo, args.run_id, args.approve_checks))
        rules_path = local_path(repo, args.rules)
        if args.command == "init":
            for include in args.include:
                safe_relative(include.rstrip("/"))
            rules_path.parent.mkdir(parents=True, exist_ok=True)
            with rules_path.open("x", encoding="utf-8") as handle:
                handle.write(default_rules(args.include))
            print_json({"rules": str(rules_path), "next": "Edit scope, prose, and check commands, then run inspect. An empty scope must be filled before use."})
            return 0
        policy = load_policy(rules_path)
        if args.command == "inspect":
            print_json(inspect_repository(repo, policy))
            return 0
        if policy.checks and not args.approve_checks:
            raise RefactorError("Inspect the configured commands, then pass --approve-checks. Checks execute trusted project code, not in an OS sandbox.")
        if not args.proposal and not args.allow_source_upload:
            raise RefactorError("Pass --allow-source-upload to send selected code, context, feedback, and rules to Gemini, or use --proposal for offline review.")
        revision = git(repo, "rev-parse", "HEAD").decode().strip()
        sources, context = collect_context(repo, revision, policy, args.file, args.context)
        if args.proposal:
            if args.proposal.stat().st_size > 2_000_000:
                raise RefactorError("Proposal exceeds the 2 MB input limit.")
            proposal = json.loads(args.proposal.read_text(encoding="utf-8"))
        else:
            proposal = generate_proposal(policy, sources, context, args.feedback, args.model)
        validate_proposal(proposal, sources, policy)
        return report_result(*create_run(repo, rules_path, policy, sources, proposal, revision, args.feedback))
    except (RefactorError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 1
