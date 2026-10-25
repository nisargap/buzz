# ⚡ Buzz — Gemini 4 Argon Pixel CVE Code Auditor

**Buzz** is a pixel-art styled code auditing web application built for the Google DeepMind Hackathon. Connect your GitHub repository via Supabase Auth, click **⚡ ANALYZE REPO**, and **Gemini 4 Argon** cross-references your manifests and source files against a Supabase CVE datasource to return a visually rich pixel vulnerability report.

---

## ✨ Features & Components

1. **Pixel-Art Brand & Mascot (`public/assets/buzz-logo.svg`, `public/css/pixel.css`)**:
   - Crisp 32×32 pixel-grid SVG logo depicting a golden lightning bolt with two dark expressive eyes floating on a cloud.
   - Retro arcade theme with stepped pixel borders, CRT scanline overlay, security grade badges (`A`–`F`), segmented threat exposure bar, and remediation patch boxes.
2. **HTML + HTMX Frontend (`public/index.html`)**:
   - Zero-framework reactive HTML partials swapped via HTMX (`hx-get` / `hx-post`).
   - Built-in Supabase GitHub OAuth button (`Connect GitHub`) that forwards `X-GitHub-Token` to the Rust serverless functions.
3. **Rust Vercel Serverless Functions (`api/*.rs` + `src/lib.rs`)**:
   - `GET /api/health` (`api/health.rs`): Displays live `GEMINI_API_KEY` and Supabase connection status.
   - `GET /api/auth_config` (`api/auth_config.rs`): Supplies public Supabase URL & anon key to initialize GitHub OAuth.
   - `GET /api/repos` (`api/repos.rs`): Lists the user's GitHub repositories as an HTMX `<select>` picker.
   - `GET /api/cves` (`api/cves.rs`): Queries and filters the Supabase `cves` table by ecosystem (`cargo`, `npm`, `pip`, `all`).
   - `POST /api/analyze` (`api/analyze.rs`): Fetches the repository files from GitHub, retrieves CVE candidates from Supabase, calls **Gemini 4 Argon** using `GEMINI_API_KEY`, persists the scan results to Supabase, and returns the HTML vulnerability report.
4. **Supabase Database & Auth (`supabase/schema.sql`, `supabase/seed_cves.sql`)**:
   - Tables: `public.cves`, `public.scans`, `public.scan_findings` with Row-Level Security (RLS) policies.

---

## 🚀 Environment Variables (Vercel)

In your Vercel Project Settings → **Environment Variables**:

| Variable | Status | Description |
| :--- | :--- | :--- |
| `GEMINI_API_KEY` | **Configured** | API key used by `api/analyze.rs` to invoke Gemini 4 Argon (`gemini-4-argon`). |
| `GEMINI_MODEL` | Optional | Defaults to `gemini-4-argon`. |
| `SUPABASE_URL` | Optional / Recommended | Your Supabase project URL (`https://<ref>.supabase.co`). |
| `SUPABASE_ANON_KEY` | Optional / Recommended | Supabase public anon key (used for GitHub OAuth & CVE reads). |
| `SUPABASE_SERVICE_ROLE_KEY` | Optional | Supabase service role key for persisting scan reports. |

> **Built-in Seed Fallback**: Even before `SUPABASE_URL` is linked, Buzz includes a built-in seed CVE catalog and preset repositories so **Analyze Repo** works out-of-the-box.

---

## 🛠️ Local Development & Verification

```bash
# Check & test all Rust serverless functions and CVE audit pipeline
cargo test

# Run with Vercel CLI
vercel dev
```

## Auto-Refactor in the existing web app

Sign in with the existing **Connect GitHub** button, choose a repo in the existing picker, then click **Auto-Refactor**. The guided wizard needs no typing: choose a goal (**Balanced cleanup**, **Less boilerplate**, or **Flatter logic**), confirm Buzz's suggested one-file scope, review the before/proposed code, then approve a draft PR. Repository `.refactor/RULES.md` guidance loads automatically when present; otherwise Buzz supplies defaults. Suggestions use file metadata, not a complexity score. The default limit is 100 changed lines, with no read-only context added automatically.

**Customize (optional)** reveals Markdown rules, file/context selection, and scope limits. Code edits and free-text feedback are optional too; **Try a smaller change** and **Avoid new helpers** offer click-only revisions. Revision feedback is shown on the scope step and can be removed with one click; fresh passes clear it. **Refresh repository files** reloads stale suggestions without uploading source. **Use this scope & generate** explicitly authorizes sending the displayed scope, rules, goal, and feedback to Gemini. Review first, then use the separate **Approve & Open Draft PR** confirmation. The server revalidates file scope, patch limits, and the pinned base revision. Draft PRs contain the reviewed code, not a second model-generated rewrite. Only the connected user's GitHub token is used; a username-only login or a token without write access cannot publish. There is no server PAT fallback and no automatic merge.

Web proposals are labeled **UNVERIFIED**: Vercel does not execute arbitrary repository builds/tests. Use the repository's normal CI and review before merging a draft. The web flow does not yet ingest CI results or run a hosted sandbox. Only explicitly selected source/read-only context, the editor's rules, and feedback are sent to Gemini after consent. Repository guidance such as `AGENTS.md` is optional read-only context and counts toward the three-file context limit; it is never appended silently. Path filtering is not a complete secret scanner. Repo rules containing CLI JSON remain guidance in the web editor; the explicit web scope controls are authoritative for web runs.

The `/api/refactor` endpoint uses the existing `GEMINI_API_KEY`/`GEMINI_MODEL` configuration. Optional `REFACTOR_SIGNING_SECRET` provides a dedicated signing key; otherwise the Gemini key signs short-lived review scopes using HMAC-SHA256. Review tokens are bound to the connected GitHub token, base commit, and file scope and expire after 30 minutes. Changing GitHub sessions requires a fresh proposal. A moved base blocks new publication, but an already-open matching draft can still be recovered while the review token is valid. If publication is interrupted, retry the same reviewed patch: Buzz verifies an existing branch's exact tree and single parent, then reuses its matching draft or opens the missing draft. It never overwrites a mismatched branch, reopens a closed PR, or converts a ready-for-review PR back to draft. Unsupported/oversized files are excluded; truncated repository trees are surfaced rather than presented as complete.

The [saved feature plan](docs/refactoring-agent-plan.md) describes the web feature and optional local execution layer.

## Optional Markdown-driven refactoring CLI

The standalone runner uses Python 3.10+ and Git, with no Python dependencies. It supports local repositories and pre-review command execution independently of the web UI; it is not required for customers using Buzz's web flow.

### 1. Set up customer rules

```bash
python3 scripts/auto_refactor.py init --repo /path/to/repo --include src/
python3 scripts/auto_refactor.py inspect --repo /path/to/repo
```

`init` creates `.refactor/RULES.md` without overwriting existing rules. Edit its Markdown guidance to express what simpler code means to your team. Its single fenced JSON policy block configures exact files or directory prefixes (ending in `/`), exclusions, file/line limits, and approved checks. It does not interpret prose as permission to execute commands.

For example, replace the generated `checks` list with your repository's actual commands:

```json
"checks": [
  {"name": "tests", "argv": ["python3", "-m", "unittest", "discover", "-s", "tests"], "cwd": ".", "timeout_seconds": 120}
]
```

Commands are argument arrays, not implicit shell strings. For a monorepo, set each command's `cwd` to its module directory. Inspect prints the effective scope candidates and check commands; it does not install or run tools. A Markdown rule can prefer an idiom without imposing a numeric complexity target.

### 2. Propose one refactor

```bash
export GEMINI_API_KEY='your-key'
# Optional: export GEMINI_MODEL='your-available-model'
python3 scripts/auto_refactor.py run --repo /path/to/repo \
  --file src/example.py --context tests/test_example.py \
  --feedback 'Keep validation inline; reuse existing helpers.' \
  --allow-source-upload --approve-checks
```

The default model is `gemini-4-argon`, matching Buzz; set `GEMINI_MODEL` to a model available to your API key. The provider uses Google's `generateContent` endpoint. No model fallback is silently substituted.

Select files explicitly; `--context` adds read-only callers, types, or tests. Nearby tracked manifests and `AGENTS.md` instructions are included automatically. The context comes from **committed HEAD**, not uncommitted source edits. `--allow-source-upload` explicitly permits sending this context, rules, and feedback to Gemini. The script does not load `.env` files. Review source before upload; path-based secret exclusions cannot detect every secret embedded in code.

The runner creates a sibling `<repo>-refactor-<id>` worktree on `refactor/<id>`, runs baseline checks, applies the candidate there, enforces patch limits, and runs the same checks again. Your original source and staged/unstaged edits stay untouched. Records are saved under `.refactor/runs/<id>/` (add this directory to the target repo's ignore rules; it can contain private code and check output).

**Execution boundary:** `--approve-checks` authorizes those commands to execute project code. A worktree isolates edits, **not processes or filesystem access**. Only use this local prototype with trusted code/commands, or run it inside an externally provisioned container/VM for customer/untrusted repositories. The runner strips inherited credentials and uses a temporary home directory, which may require dependencies/toolchains to be provisioned separately. It does not provide a production sandbox or network isolation.

### 3. Review, edit, and recheck

```bash
python3 scripts/auto_refactor.py review --repo /path/to/repo RUN_ID
# Edit the selected source files in the reported sibling worktree, then:
python3 scripts/auto_refactor.py check --repo /path/to/repo RUN_ID --approve-checks
python3 scripts/auto_refactor.py review --repo /path/to/repo RUN_ID --decision approve
# Or: --decision reject
```

Approval records a decision for the exact checked patch; it **never commits, pushes, merges, or deploys**. Use normal code review, branch protections, and release checks afterwards. Missing commands, failed baseline/candidate checks, stale policy, and out-of-scope changes block approval. Check results are evidence, not proof of behavioral equivalence. Human review still needs to assess semantics and test coverage. Failed/rejected worktrees remain available for inspection; cleanup is manual so customer edits are never discarded automatically.

Use another `run --feedback '...'` to request a different proposal from the original revision. Feedback is per attempt; edit `RULES.md` yourself to persist it. Changes to policy require a new run. This MVP only replaces selected existing text files; it does not create/delete source files, alter file modes, edit known test/configuration paths, or automatically expand scope. Tests embedded inside source still require human review. If a change needs new tests or a larger migration, stop and hand it off rather than weakening existing checks.

### Offline proposals and tests

For an existing agent or deterministic evaluation, pass `--proposal /path/to/proposal.json` instead of enabling source upload. The schema is a JSON object with `summary`, `rule`, `tradeoffs`, and `edits`; every edit contains `path`, the SHA-256 `before_sha256` of the committed file bytes, and its complete replacement `content`. An empty edits list means no worthwhile change. These no-change reports can be viewed or rejected without a worktree; they cannot be approved or rechecked as a patch. Offline proposals go through the same scope and validation gates.

```bash
python3 -m unittest discover -s tests -v
node --test tests/test_refactor_web.js
cargo test --locked -- --skip test_live_full_repo_tree_loader_on_nisargap_buzz
```

The web suite uses offline API/DOM fixtures for authentication reuse, review invalidation, scope enforcement, and draft PR request payloads. Rust tests cover policy checks and signed review scopes. The live CVE audit test is excluded above because it requires external services. A live refactor generation/publication smoke test still requires configured credentials and an explicitly selected test repository.

The suite exercises the same runner against disposable Python and JavaScript Git fixtures (the JavaScript fixture requires Node), including failed checks, protected paths, patch limits, feedback, policy changes, and manual-edit rechecks. Provider calls are mocked; tests do not upload repository code. Exit codes: `0` for successful commands/review-ready or no-change runs, `1` for input/setup errors, and `2` for blocked, failing, or unverified runs.
