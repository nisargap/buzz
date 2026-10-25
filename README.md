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

Web proposals are labeled **UNVERIFIED**: Vercel does not execute arbitrary repository builds/tests. Use the repository's normal CI and review before merging a draft. The web flow does not yet ingest CI results or run a hosted sandbox. Only explicitly selected source/read-only context, the editor's rules, and feedback are sent to Gemini after consent. Repository guidance such as `AGENTS.md` is optional read-only context and counts toward the three-file context limit; it is never appended silently. Path filtering is not a complete secret scanner.

The `/api/refactor` endpoint uses the existing `GEMINI_API_KEY`/`GEMINI_MODEL` configuration. Optional `REFACTOR_SIGNING_SECRET` provides a dedicated signing key; otherwise the Gemini key signs short-lived review scopes using HMAC-SHA256. Review tokens are bound to the connected GitHub token, base commit, and file scope and expire after 30 minutes. Changing GitHub sessions requires a fresh proposal. A moved base blocks new publication, but an already-open matching draft can still be recovered while the review token is valid. If publication is interrupted, retry the same reviewed patch: Buzz verifies an existing branch's exact tree and single parent, then reuses its matching draft or opens the missing draft. It never overwrites a mismatched branch, reopens a closed PR, or converts a ready-for-review PR back to draft. Unsupported/oversized files are excluded; truncated repository trees are surfaced rather than presented as complete.

The [saved feature plan](docs/refactoring-agent-plan.md) describes the web feature. Refactoring runs through the Rust `/api/refactor` endpoint; optional Markdown instructions stay in the wizard. No Python runner is required.

### Web refactor tests

```bash
node --test tests/test_refactor_web.js
cargo test --locked -- --skip test_live_full_repo_tree_loader_on_nisargap_buzz
```

The web suite uses offline API/DOM fixtures for authentication reuse, review invalidation, scope enforcement, and draft PR request payloads. Rust tests cover policy checks and signed review scopes. The live CVE audit test is excluded above because it requires external services. A live refactor generation/publication smoke test still requires configured credentials and an explicitly selected test repository.
