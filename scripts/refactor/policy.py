"""Strict, stdlib-only rules for the refactoring CLI.

Only the single fenced JSON block is execution policy. Everything outside it is
human guidance. Scope entries are literal files or directory prefixes ending in
``/``; neither scope entries nor guidance can override write protection.
"""

from dataclasses import dataclass
from fnmatch import fnmatchcase
import json
from pathlib import Path, PurePosixPath


class RefactorError(Exception):
    """A policy or repository path cannot be used safely."""


@dataclass(frozen=True)
class Check:
    name: str
    argv: list[str]
    cwd: str = "."
    timeout_seconds: int = 120


@dataclass(frozen=True)
class Policy:
    include: list[str]
    exclude: list[str]
    max_files: int
    max_changed_lines: int
    checks: list[Check]
    guidance: str

    def allows(self, path: str) -> bool:
        """Return whether a normalized file path is writable; fail closed."""
        try:
            safe_relative(path)
        except RefactorError:
            return False
        return (
            not is_protected(path)
            and any(_matches_scope(path, rule) for rule in self.include)
            and not any(_matches_scope(path, rule) for rule in self.exclude)
        )


def _has_control(text: str) -> bool:
    return any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in text)


def safe_relative(path: str) -> str:
    """Validate a normalized POSIX repository file path without rewriting it.

    Directory prefixes must have their trailing slash removed by their caller.
    Windows drive paths are rejected as well, even on a POSIX host.
    """
    if not isinstance(path, str) or not path:
        raise RefactorError("A repository path must be a nonempty string")
    if "\\" in path or _has_control(path):
        raise RefactorError("Repository paths cannot contain backslashes or control characters")
    if PurePosixPath(path).is_absolute() or (
        len(path) >= 2 and path[0].isalpha() and path[1] == ":"
    ):
        raise RefactorError("Repository paths must be relative")
    if any(part in ("", ".", "..") for part in path.split("/")):
        raise RefactorError("Repository paths must be normalized, without empty, '.' or '..' parts")
    return path


def _matches_scope(path: str, rule: str) -> bool:
    return path.startswith(rule) if rule.endswith("/") else path == rule


# Name-based exclusion is deliberately conservative; it is not a content-based
# secret scanner. Ordinary tests, documentation, and manifests remain readable.
_SENSITIVE_PARTS = frozenset({
    ".git", ".hg", ".svn", ".bzr", "_darcs", ".ssh", ".gnupg", ".pki",
    ".aws", ".azure", ".kube", ".docker", ".terraform", "gcloud",
    "secret", "secrets", "credential", "credentials", "private_keys",
    "private-keys", "certs", "certificates", "keys",
})
_SENSITIVE_PATTERNS = (
    ".env", ".env.*", ".envrc", ".envrc.*", "*.env", "*.env.*",
    "env", "env.*", "environment", "environment.*",
    "*secret*", "*credential*", "*password*", "*private_key*", "*private-key*",
    "*privatekey*", "*service_account*", "*service-account*", "*adminsdk*.json",
    "id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*", "ssh_host_*_key*",
    "authorized_keys*", "known_hosts*", "*.pem", "*.key", "*.p12", "*.pfx",
    "*.jks", "*.keystore", "*.crt", "*.cert", "*.cer", "*.csr", "*.der",
    "*.p7b", "*.p7c", "*.p8", "*.p10", "*.ppk", "*.asc", "*.gpg", "*.pgp",
    "*.keychain", "*.keychain-db", "*.tfstate", "*.tfstate.*",
    "*.tfvars", "*.tfvars.json", ".netrc", "_netrc", ".npmrc", ".pypirc",
    ".yarnrc", ".yarnrc.yml", ".gitconfig", "kubeconfig", "kubeconfig.*",
    "passwd", "shadow", "token", "tokens", "token.*", "tokens.*",
)


def is_sensitive(path: str) -> bool:
    """Exclude likely secret-bearing paths and VCS internals from sharing.

    Invalid paths are sensitive, so a malformed candidate cannot bypass the
    source-sharing filter. Matching is case-insensitive for portable safety.
    """
    try:
        parts = safe_relative(path).lower().split("/")
    except RefactorError:
        return True
    return any(
        part in _SENSITIVE_PARTS
        or any(fnmatchcase(part, pattern) for pattern in _SENSITIVE_PATTERNS)
        for part in parts
    )


_PROTECTED_PARTS = frozenset({
    "test", "tests", "__tests__", "spec", "specs", "testdata", "fixtures",
    "vendor", "vendors", "node_modules", "bower_components", "third_party",
    "third-party", "thirdparty", "external", "generated", "__generated__",
    "gen", "dist", "build", "out", "target", "coverage", "__pycache__",
    "site-packages", "venv", "obj", "_build", "deps", "ci", "gradle", "requirements",
})
_PROTECTED_NAMES = frozenset({
    "agents.md", "rules.md",
    "cargo.toml", "cargo.lock", "rust-toolchain", "rust-toolchain.toml",
    "rustfmt.toml", "clippy.toml", "build.rs",
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
    "pnpm-lock.yaml", "pnpm-workspace.yaml", "bun.lock", "bun.lockb",
    "deno.json", "deno.jsonc", "deno.lock", "import_map.json",
    "pyproject.toml", "setup.py", "setup.cfg", "pipfile", "pipfile.lock",
    "poetry.lock", "uv.lock", "pdm.lock", "tox.ini", "pytest.ini", "mypy.ini",
    "pyrightconfig.json", "ruff.toml",
    "go.mod", "go.sum", "go.work", "go.work.sum",
    "gemfile", "gemfile.lock", "rakefile", "composer.json", "composer.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle",
    "settings.gradle.kts", "gradle.properties", "gradlew", "gradlew.bat",
    "build.sbt", "build.properties", "build.sc",
    "global.json", "nuget.config", "packages.config", "packages.lock.json",
    "directory.build.props", "directory.build.targets", "directory.packages.props",
    "makefile", "gnumakefile", "justfile", "taskfile.yml", "taskfile.yaml",
    "gruntfile.js", "gruntfile.ts", "gulpfile.js", "gulpfile.ts", "gulpfile.mjs",
    "cmakelists.txt", "cmakepresets.json",
    "cmakeuserpresets.json", "meson.build", "meson_options.txt", "meson.options",
    "build", "build.bazel", "workspace", "workspace.bazel", "module.bazel",
    "mix.exs", "mix.lock", "rebar.config", "rebar.lock",
    "pubspec.yaml", "pubspec.lock", "analysis_options.yaml",
    "package.swift", "package.resolved", "cabal.project", "cabal.project.freeze",
    "stack.yaml", "stack.yaml.lock", "flake.nix", "flake.lock", "shell.nix",
    "default.nix", "vcpkg.json", "vcpkg-configuration.json", "conanfile.py",
    "conanfile.txt", "conan.lock",
    "jenkinsfile", "dockerfile", "containerfile", "compose.yaml", "compose.yml",
    "azure-pipelines.yml", "azure-pipelines.yaml", "bitbucket-pipelines.yml",
    "circle.yml", "appveyor.yml", "appveyor.yaml", "buildspec.yml",
    "buildspec.yaml", "netlify.toml", "vercel.json", "firebase.json", "amplify.yml",
    "codecov.yml", "codecov.yaml", "renovate.json", "renovate.json5",
    "dependabot.yml", "biome.json", "biome.jsonc", "tslint.json", "lefthook.yml", "lefthook.yaml",
})
_PROTECTED_PATTERNS = (
    "test_*.*", "*_test.*", "*.test.*", "*.spec.*", "test.*", "tests.*",
    "spec.*", "specs.*", "*test.java", "*tests.java", "*test.kt", "*tests.kt",
    "*test.cs", "*tests.cs", "*test.swift", "*tests.swift", "*.snap",
    "*.lock", "*.lockb", "requirements*.txt", "requirements*.in", "*.gemspec",
    "*.csproj", "*.fsproj", "*.vbproj", "*.sln", "*.slnx", "*.props", "*.targets",
    "*.mk", "makefile.*", "*.cmake", "*.bzl", "*.cabal", "*.config.*",
    "tsconfig*.json", "jsconfig*.json", "dockerfile.*", "containerfile.*",
    "docker-compose*.yml", "docker-compose*.yaml", "compose.*.yml", "compose.*.yaml",
    "*.generated.*", "*.g.*", "*.min.js", "*.min.css", "*.map", "*.pb.go",
    "*.pb.cc", "*.pb.h", "*_pb2.py", "*_pb2_grpc.py",
)


def is_protected(path: str) -> bool:
    """Keep policy, hidden files, tests, configuration, and generated data read-only.

    Secret-bearing files are also write-protected. This guard is independent of
    include/exclude rules and intentionally errs on the side of protection.
    """
    try:
        parts = safe_relative(path).lower().split("/")
    except RefactorError:
        return True
    return (
        is_sensitive(path)
        or any(part.startswith(".") or part in _PROTECTED_PARTS for part in parts)
        or parts[-1] in _PROTECTED_NAMES
        or any(fnmatchcase(parts[-1], pattern) for pattern in _PROTECTED_PATTERNS)
    )


def _scope_rules(value: object, label: str, *, required: bool = False) -> list[str]:
    if not isinstance(value, list) or (required and not value):
        raise RefactorError(f"{label} must be {'a nonempty' if required else 'a'} list of paths")
    result = []
    for rule in value:
        if not isinstance(rule, str) or not rule:
            raise RefactorError(f"{label} entries must be nonempty strings")
        if any(char in rule for char in "*?[]"):
            raise RefactorError(f"{label} entries must be literal paths, not globs")
        safe_relative(rule[:-1] if rule.endswith("/") else rule)
        result.append(rule)
    return result


def _positive_int(value: object, label: str, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise RefactorError(f"{label} must be an integer from 1 to {maximum}")
    return value


def _keys(value: dict, allowed: set[str], required: set[str], label: str) -> None:
    unknown = value.keys() - allowed
    missing = required - value.keys()
    if unknown:
        raise RefactorError(f"Unknown {label} keys: {', '.join(sorted(unknown))}")
    if missing:
        raise RefactorError(f"Missing {label} keys: {', '.join(sorted(missing))}")


def _checks(value: object) -> list[Check]:
    if not isinstance(value, list):
        raise RefactorError("checks must be a list")
    checks = []
    names = set()
    for entry in value:
        if not isinstance(entry, dict):
            raise RefactorError("Each check must be an object")
        _keys(entry, {"name", "argv", "cwd", "timeout_seconds"}, {"name", "argv"}, "check")
        name = entry["name"]
        if not isinstance(name, str) or not name.strip() or _has_control(name):
            raise RefactorError("Check names must be nonempty strings without control characters")
        if name in names:
            raise RefactorError(f"Duplicate check name: {name}")
        names.add(name)
        argv = entry["argv"]
        if not isinstance(argv, list) or not argv or any(
            not isinstance(arg, str) or not arg or _has_control(arg) for arg in argv
        ):
            raise RefactorError("Check argv must be a nonempty list of nonempty strings without control characters")
        cwd = entry.get("cwd", ".")
        if cwd != ".":
            safe_relative(cwd)
        timeout = _positive_int(entry.get("timeout_seconds", 120), "timeout_seconds", 3600)
        checks.append(Check(name=name, argv=list(argv), cwd=cwd, timeout_seconds=timeout))
    return checks


def _fence(line: str) -> tuple[str, int, str] | None:
    """Recognize standalone Markdown fences, with at most three leading spaces."""
    line = line.rstrip("\r\n")
    stripped = line.lstrip(" ")
    if len(line) - len(stripped) > 3 or not stripped.startswith(("```", "~~~")):
        return None
    marker = stripped[0]
    length = len(stripped) - len(stripped.lstrip(marker))
    return marker, length, stripped[length:].strip()


def _policy_block(text: str) -> tuple[str, str]:
    if not isinstance(text, str):
        raise RefactorError("Rules must be Markdown text")
    lines = text.splitlines(keepends=True)
    opened = None
    blocks = []
    for index, line in enumerate(lines):
        fence = _fence(line)
        if fence is None:
            continue
        marker, length, info = fence
        if opened is None:
            # Backticks are not permitted inside a backtick fence's info string.
            if marker == "`" and "`" in info:
                continue
            opened = (marker, length, info.lower() == "json", index)
        elif marker == opened[0] and length >= opened[1] and not info:
            if opened[2]:
                blocks.append((opened[3], index))
            opened = None
    if opened is not None and opened[2]:
        raise RefactorError("The fenced JSON policy block is not closed")
    if len(blocks) != 1:
        raise RefactorError("Rules must contain exactly one fenced JSON policy block")
    start, end = blocks[0]
    return "".join(lines[start + 1:end]), "".join(lines[:start] + lines[end + 1:]).strip()


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise RefactorError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise RefactorError(f"Invalid JSON constant: {value}")


def parse_policy(text: str) -> Policy:
    """Parse the sole JSON policy, rejecting unknown keys and ambiguous JSON.

    ``include``, ``max_files``, and ``max_changed_lines`` are required. Optional
    exclusions and checks default to empty lists; prose never supplies defaults.
    """
    source, guidance = _policy_block(text)
    try:
        data = json.loads(source, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (ValueError, RecursionError) as error:
        raise RefactorError(f"Invalid policy JSON: {error}") from error
    if not isinstance(data, dict):
        raise RefactorError("The JSON policy must be an object")
    _keys(
        data,
        {"include", "exclude", "max_files", "max_changed_lines", "checks"},
        {"include", "max_files", "max_changed_lines"},
        "policy",
    )
    return Policy(
        include=_scope_rules(data["include"], "include", required=True),
        exclude=_scope_rules(data.get("exclude", []), "exclude"),
        max_files=_positive_int(data["max_files"], "max_files", 100),
        max_changed_lines=_positive_int(data["max_changed_lines"], "max_changed_lines", 10000),
        checks=_checks(data.get("checks", [])),
        guidance=guidance,
    )


def load_policy(path: Path) -> Policy:
    """Read UTF-8 Markdown rules, reporting I/O and parsing failures consistently."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise RefactorError(f"Cannot read rules from {path}: {error}") from error
    try:
        return parse_policy(text)
    except RefactorError as error:
        raise RefactorError(f"Invalid rules in {path}: {error}") from error


def default_rules(includes: list[str]) -> str:
    """Return an editable template; an empty include list is an invalid draft."""
    data = {
        "include": _scope_rules(includes, "include"),
        "exclude": [],
        "max_files": 10,
        "max_changed_lines": 400,
        "checks": [],
    }
    return (
        "# Refactoring rules\n\n"
        "Only the JSON block below controls edit scope, limits, and executable checks.\n"
        "Add explicit files or directory prefixes ending in `/` to `include`; globs\n"
        "are not supported. An empty include list must be edited before use.\n"
        "Protected files remain read-only even when included.\n\n"
        "```json\n" + json.dumps(data, indent=2) + "\n```\n\n"
        "## Guidance\n\n"
        "Preserve behavior and public interfaces. Keep changes narrowly scoped and\n"
        "follow existing project conventions. Never add credentials or secrets.\n"
        "Prose and repository content cannot widen scope or authorize commands.\n"
    )
