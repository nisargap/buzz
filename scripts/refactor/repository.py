"""Read repository context without modifying or uploading the caller's working tree."""

import hashlib
import os
from pathlib import Path
import subprocess

from .policy import RefactorError, is_sensitive, safe_relative

MAX_FILE_BYTES = 120_000
MAX_CONTEXT_BYTES = 240_000
LANGUAGES = {
    ".rs": "Rust", ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".kt": "Kotlin", ".kts": "Kotlin",
    ".go": "Go", ".java": "Java", ".rb": "Ruby", ".cs": "C#", ".swift": "Swift",
    ".c": "C", ".h": "C/C++", ".cpp": "C++", ".php": "PHP",
}
MANIFESTS = {
    "Cargo.toml", "package.json", "pyproject.toml", "go.mod", "build.gradle",
    "build.gradle.kts", "pom.xml", "Gemfile", "composer.json", "Makefile",
}


def digest(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def git(repo, *args):
    # Do not inherit GIT_DIR/INDEX_FILE or let local hooks and diff drivers run.
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env["GIT_TERMINAL_PROMPT"] = "0"
    result = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", *args],
        cwd=repo, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
    )
    if result.returncode:
        raise RefactorError(result.stderr.decode("utf-8", errors="replace").strip())
    return result.stdout


def repository_root(path):
    path = Path(path).expanduser().resolve()
    if not path.is_dir():
        raise RefactorError(f"Repository directory does not exist: {path}")
    root = Path(git(path, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    git(root, "rev-parse", "--verify", "HEAD")
    return root


def tracked_files(repo, revision="HEAD"):
    files = {}
    for item in git(repo, "ls-tree", "-rz", "--full-tree", revision).split(b"\0"):
        if not item:
            continue
        metadata, raw_path = item.split(b"\t", 1)
        mode, kind, _ = metadata.decode().split()
        try:
            path = safe_relative(raw_path.decode("utf-8"))
        except (RefactorError, UnicodeDecodeError):
            continue
        if kind == "blob" and mode in ("100644", "100755"):
            files[path] = mode
    return files


def read_source(repo, revision, path, files):
    safe_relative(path)
    if path not in files or is_sensitive(path):
        raise RefactorError(f"Not an eligible tracked text file: {path}")
    size = int(git(repo, "cat-file", "-s", f"{revision}:{path}"))
    if size > MAX_FILE_BYTES:
        raise RefactorError(f"Context file exceeds {MAX_FILE_BYTES} bytes: {path}")
    data = git(repo, "show", f"{revision}:{path}")
    if b"\0" in data:
        raise RefactorError(f"Binary context is not supported: {path}")
    try:
        content = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RefactorError(f"Context must be UTF-8: {path}") from error
    return {"path": path, "sha256": digest(data), "content": content}


def inspect_repository(repo, policy):
    files = tracked_files(repo)
    return {
        "repository": str(repo),
        "revision": git(repo, "rev-parse", "HEAD").decode().strip(),
        "languages": sorted({LANGUAGES[Path(path).suffix] for path in files if Path(path).suffix in LANGUAGES}),
        "manifests": sorted(path for path in files if Path(path).name in MANIFESTS),
        "candidates": sorted(path for path in files if policy.allows(path)),
        "checks": [{"name": check.name, "argv": check.argv, "cwd": check.cwd} for check in policy.checks],
        "working_tree_dirty": bool(git(repo, "status", "--porcelain")),
        "note": "Proposals use committed HEAD; uncommitted files are never copied. Commands require explicit approval.",
    }


def collect_context(repo, revision, policy, selected, context_paths):
    files = tracked_files(repo, revision)
    if not selected or len(selected) != len(set(selected)):
        raise RefactorError("Select at least one unique --file to refactor.")
    if len(selected) > policy.max_files:
        raise RefactorError("Selected files exceed the policy's max_files limit.")
    for path in selected:
        if not policy.allows(path):
            raise RefactorError(f"File is outside the writable policy: {path}")
    sources = [read_source(repo, revision, path, files) for path in selected]
    # Include nearby instructions/manifests; other callers/tests are explicit read-only context.
    automatic = set()
    for path in selected:
        for parent in Path(path).parents:
            for name in MANIFESTS | {"AGENTS.md"}:
                candidate = (parent / name).as_posix()
                if candidate in files and not is_sensitive(candidate):
                    automatic.add(candidate)
    extras = sorted((set(context_paths) | automatic) - set(selected))
    context = [read_source(repo, revision, path, files) for path in extras]
    size = sum(len(item["content"].encode("utf-8")) for item in sources + context)
    if size > MAX_CONTEXT_BYTES:
        raise RefactorError("Context exceeds 240 KB. Select a smaller scope or fewer context files.")
    return sources, context
