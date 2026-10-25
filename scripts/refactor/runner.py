"""Bounded local execution. Worktrees isolate edits, not arbitrary project code."""

from dataclasses import asdict
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import uuid

from .policy import RefactorError, load_policy, safe_relative
from .repository import MAX_FILE_BYTES, digest, git, tracked_files


def local_path(root, relative):
    """Never follow a repository symlink when reading/writing a candidate."""
    safe_relative(relative)
    if root.is_symlink():
        raise RefactorError("The workspace root must not be a symlink.")
    current = root
    for part in Path(relative).parts:
        current = current / part
        if current.is_symlink():
            raise RefactorError(f"Symlink paths are not permitted: {relative}")
    if not current.resolve().is_relative_to(root.resolve()):
        raise RefactorError(f"Path escapes the repository: {relative}")
    return current


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def patch_state(worktree, revision, selected, policy):
    if git(worktree, "rev-parse", "HEAD").decode().strip() != revision:
        raise RefactorError("Worktree HEAD changed. Start a new run against the new revision.")
    untracked = git(worktree, "ls-files", "--others", "--exclude-standard", "-z")
    if untracked:
        raise RefactorError("Untracked files appeared in the worktree; this MVP only edits selected existing files.")
    names = git(worktree, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--name-only", "-z", "HEAD", "--")
    paths = [name.decode("utf-8") for name in names.split(b"\0") if name]
    originals = tracked_files(worktree, revision)
    for path in paths:
        if path not in selected or not policy.allows(path):
            raise RefactorError(f"Candidate changes a protected or unselected path: {path}")
        target = local_path(worktree, path)
        if not target.is_file():
            raise RefactorError(f"Deleting files is outside the MVP scope: {path}")
        if target.stat().st_size > MAX_FILE_BYTES:
            raise RefactorError(f"Candidate file exceeds {MAX_FILE_BYTES} bytes: {path}")
        data = target.read_bytes()
        try:
            data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise RefactorError(f"Candidate must remain UTF-8: {path}") from error
        if b"\0" in data:
            raise RefactorError(f"Candidate must remain a text file: {path}")
        expected_executable = originals.get(path) == "100755"
        if bool(target.stat().st_mode & 0o111) != expected_executable:
            raise RefactorError(f"File mode changes are outside the MVP scope: {path}")
    numstat = git(worktree, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--numstat", "-z", "HEAD", "--")
    changed_lines = 0
    for entry in numstat.split(b"\0"):
        if entry:
            added, deleted, _ = entry.split(b"\t", 2)
            if added == b"-" or deleted == b"-":
                raise RefactorError("Binary changes are not supported.")
            changed_lines += int(added) + int(deleted)
    if len(paths) > policy.max_files or changed_lines > policy.max_changed_lines:
        raise RefactorError(f"Patch exceeds policy: {len(paths)} files / {changed_lines} changed lines.")
    diff = git(worktree, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--binary", "HEAD", "--")
    return {"files": paths, "changed_lines": changed_lines, "sha256": digest(diff)}, diff


def execute_check(worktree, check):
    cwd = worktree if check.cwd == "." else local_path(worktree, check.cwd)
    if not cwd.is_dir():
        return {"name": check.name, "returncode": None, "output": f"Missing check directory: {check.cwd}"}
    # Do not forward cloud credentials, API keys, or the real home directory.
    # This is not an OS sandbox: only run trusted repositories/commands.
    with tempfile.TemporaryDirectory(prefix="buzz-check-") as home, tempfile.TemporaryFile() as log:
        env = {"PATH": os.environ.get("PATH", os.defpath), "HOME": home, "TMPDIR": home,
               "LANG": "en_US.UTF-8", "CI": "true", "GIT_TERMINAL_PROMPT": "0",
               "GIT_CONFIG_NOSYSTEM": "1", "XDG_CONFIG_HOME": home,
               "PYTHONDONTWRITEBYTECODE": "1"}
        timed_out = False
        try:
            process = subprocess.Popen(
                check.argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
            )
            try:
                returncode = process.wait(timeout=check.timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                returncode = None
        except OSError as error:
            return {"name": check.name, "returncode": None, "output": str(error)}
        log.seek(0)
        output = log.read(32_769)
        truncated = len(output) > 32_768
        return {"name": check.name, "returncode": returncode, "timed_out": timed_out,
                "output": output[:32_768].decode("utf-8", errors="replace"), "output_truncated": truncated}


def verify_checks(worktree, revision, selected, policy):
    before, _ = patch_state(worktree, revision, selected, policy)
    results = []
    for check in policy.checks:
        result = execute_check(worktree, check)
        results.append(result)
        after, _ = patch_state(worktree, revision, selected, policy)
        if before["sha256"] != after["sha256"]:
            raise RefactorError(f"Check '{check.name}' modified tracked source. Validation is invalid.")
    return results


def result_status(baseline, candidate):
    if not baseline or not candidate:
        return "unverified"
    if any(item["returncode"] != 0 for item in baseline):
        return "baseline_failed"
    if any(item["returncode"] != 0 for item in candidate):
        return "verification_failed"
    return "ready_for_review"


def create_run(repo, rules_path, policy, sources, proposal, revision, feedback):
    # A customer edit during the provider request must not silently authorize a
    # different set of commands, or leave a saved policy unlike the one used.
    if load_policy(rules_path) != policy:
        raise RefactorError("Rules changed during proposal generation; start a new run.")
    run_id = uuid.uuid4().hex[:12]
    run_dir = local_path(repo, f".refactor/runs/{run_id}")
    run_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    rules_text = rules_path.read_text(encoding="utf-8")
    (run_dir / "rules.md").write_text(rules_text, encoding="utf-8")
    write_json(run_dir / "proposal.json", proposal)
    worktree = repo.parent / f"{repo.name}-refactor-{run_id}"
    branch = f"refactor/{run_id}"
    report = {
        "id": run_id, "repository": str(repo), "revision": revision,
        "rules_path": str(rules_path), "rules_sha256": digest(rules_text),
        "selected": [source["path"] for source in sources], "feedback": feedback,
        "summary": proposal["summary"], "rule": proposal["rule"], "tradeoffs": proposal["tradeoffs"],
        "commands": [asdict(check) for check in policy.checks],
        "worktree": str(worktree), "branch": branch, "status": "preparing", "review": "pending",
        "baseline": [], "candidate": [], "patch": None,
    }
    try:
        if not proposal["edits"]:
            report.update(status="no_change", worktree=None, branch=None)
        else:
            git(repo, "worktree", "add", "-b", branch, str(worktree), revision)
            report["baseline"] = verify_checks(worktree, revision, report["selected"], policy)
            for edit in proposal["edits"]:
                target = local_path(worktree, edit["path"])
                if digest(target.read_bytes()) != edit["before_sha256"]:
                    raise RefactorError(f"Worktree bytes differ from proposal base: {edit['path']}")
                target.write_bytes(edit["content"].encode("utf-8"))
            report["patch"], diff = patch_state(worktree, revision, report["selected"], policy)
            (run_dir / "candidate.patch").write_bytes(diff)
            report["candidate"] = verify_checks(worktree, revision, report["selected"], policy)
            report["status"] = result_status(report["baseline"], report["candidate"])
    except (RefactorError, OSError, subprocess.SubprocessError) as error:
        report["status"] = "blocked"
        report["error"] = str(error)
    write_json(run_dir / "report.json", report)
    return run_dir, report


def load_run(repo, run_id):
    if not re.fullmatch(r"[a-f0-9]{12}", run_id):
        raise RefactorError("Invalid run ID.")
    run_dir = local_path(repo, f".refactor/runs/{run_id}")
    report = json.loads(local_path(repo, f".refactor/runs/{run_id}/report.json").read_text(encoding="utf-8"))
    expected_worktree = repo.parent / f"{repo.name}-refactor-{run_id}"
    if report["repository"] != str(repo) or report["worktree"] != str(expected_worktree):
        raise RefactorError("This run has no active worktree or belongs to a different repository.")
    saved_rules = local_path(repo, f".refactor/runs/{run_id}/rules.md")
    if digest(saved_rules.read_bytes()) != report["rules_sha256"]:
        raise RefactorError("Saved run policy changed; start a new run.")
    if digest(Path(report["rules_path"]).read_bytes()) != report["rules_sha256"]:
        raise RefactorError("Customer rules changed; start a new run to use them explicitly.")
    return run_dir, report, load_policy(saved_rules), expected_worktree


def recheck_run(repo, run_id, approved):
    run_dir, report, policy, worktree = load_run(repo, run_id)
    if policy.checks and not approved:
        raise RefactorError("Pass --approve-checks to execute the policy's commands on trusted code.")
    report["review"] = "pending"
    try:
        report["patch"], diff = patch_state(worktree, report["revision"], report["selected"], policy)
        (run_dir / "candidate.patch").write_bytes(diff)
        report["candidate"] = verify_checks(worktree, report["revision"], report["selected"], policy)
        report["status"] = result_status(report["baseline"], report["candidate"])
        report.pop("error", None)
    except (RefactorError, OSError, subprocess.SubprocessError) as error:
        report["status"] = "blocked"
        report["error"] = str(error)
    write_json(run_dir / "report.json", report)
    return run_dir, report


def review_run(repo, run_id, decision):
    run_dir, report, policy, worktree = load_run(repo, run_id)
    if decision == "reject":
        report["review"] = "rejected"
        write_json(run_dir / "report.json", report)
        return report, b""
    state, diff = patch_state(worktree, report["revision"], report["selected"], policy)
    if decision == "approve":
        if not state["files"] or report["status"] != "ready_for_review" or state != report["patch"]:
            raise RefactorError("Only the exact checked patch can be approved. Run check after edits; missing/failed checks block approval.")
        report["review"] = "approved"
        write_json(run_dir / "report.json", report)
    elif state != report["patch"]:
        report = {**report, "status": "needs_recheck", "review": "pending"}
        write_json(run_dir / "report.json", report)
    return report, diff
