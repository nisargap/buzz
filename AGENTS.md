# Buzz — Architecture & Implementation Plan (`AGENTS.md`)

> **Buzz** is a visually appealing, pixel-art styled code auditing web app powered by **Gemini 4 Argon**. Users connect their GitHub account via Supabase Auth, select or input a repository, click **Analyze Repo**, and receive an interactive, pixel-styled vulnerability report cross-referenced against a CVE datasource.

---

## 1. Visual Identity & Design Language

- **Mascot / Logo**: A golden-yellow pixel lightning bolt with two dark expressive eyes floating atop a fluffy pixel cloud.
- **Aesthetic**: Crisp 16-bit / arcade pixel-art style (`Press Start 2P` / `VT323` / `Silkscreen` fonts, stepped pixel borders, hard-offset drop shadows, CRT/grid subtle backdrop, severity badges in arcade palette).
- **Interactivity**: Driven by **HTML + HTMX** (`hx-get`, `hx-post`, `hx-target`, `hx-swap`, `hx-indicator`) so every action swaps clean HTML partials directly from Rust Vercel serverless functions without a heavy SPA framework.

---

## 2. Tech Stack & Opinionated Decisions

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Frontend** | Static HTML5 + HTMX + Pixel CSS | Fast, zero-bundle UI; server-rendered HTML fragments for repo list, scan progress, and CVE report cards. |
| **Serverless API** | **Rust** on Vercel (`vercel_runtime`, `tokio`, `reqwest`, `serde`) | Each endpoint lives in `api/*.rs` and returns either HTML fragments (for HTMX) or JSON (when requested). |
| **Auth** | **Supabase Auth (GitHub OAuth)** | Handles "Connect GitHub" login and provides the `provider_token` needed to read the user's repositories and dependency/source files. |
| **Database** | **Supabase Postgres** | Stores the CVE datasource (`cves`), user scan jobs (`scans`), and matched vulnerability findings (`scan_findings`). |
| **AI Engine** | **Gemini 4 Argon** (`gemini-4-argon`) | Analyzes repository manifests (`Cargo.toml`, `package.json`, `requirements.txt`, etc.) and source code snippets against candidate CVEs to confirm applicability, severity, and remediation steps. |

---

## 3. Repository Structure

```text
buzz/
├── AGENTS.md                  # Architecture, component breakdown, and build plan
├── README.md                  # Project overview & setup instructions
├── Cargo.toml                 # Workspace / Rust dependencies for Vercel functions
├── vercel.json                # Vercel routing & Rust runtime configuration
├── supabase/
│   ├── schema.sql             # Tables: cves, scans, scan_findings + RLS policies
│   └── seed_cves.sql          # Initial curated CVE dataset for immediate testing
├── src/
│   └── lib.rs                 # Shared Rust modules (Supabase client, GitHub fetcher, Gemini 4 Argon client, HTML templates)
├── api/
│   ├── health.rs              # GET  /api/health       -> System & Gemini status badge (HTMX partial)
│   ├── auth_config.rs         # GET  /api/auth_config  -> Public Supabase URL/Anon key handshake
│   ├── repos.rs               # GET  /api/repos        -> Fetches user's GitHub repos & renders HTMX selector
│   ├── cves.rs                # GET  /api/cves         -> Browse/search CVE datasource (HTMX partial)
│   └── analyze.rs             # POST /api/analyze      -> Runs Repo -> CVE -> Gemini 4 Argon pipeline & returns HTML report
└── public/
    ├── index.html             # Pixel-art landing page, GitHub auth bar, repo analyzer, report container
    ├── css/
    │   └── pixel.css          # Retro pixel-art theme, stepped borders, animations, report cards
    └── assets/
        └── buzz-logo.svg      # Pixel lightning bolt with two dark eyes floating on a cloud
```

---

## 4. Breakdown into Small Components

### Component 1: Pixel-Art Brand & Landing Page (`public/`)
- **Buzz Logo (`public/assets/buzz-logo.svg`)**: Crisp SVG rendered on a pixel grid (`shape-rendering="crispEdges"`) depicting a floating cloud with a jagged lightning bolt and two dark eyes with subtle idle float/blink animation.
- **Pixel Stylesheet (`public/css/pixel.css`)**:
  - Pixelated borders (`box-shadow` stepped frames), retro status LEDs, arcade buttons with press states, and severity color tokens (`CRITICAL` magenta/red, `HIGH` orange, `MEDIUM` yellow, `LOW` cyan, `CLEAN` emerald).
- **HTMX Shell (`public/index.html`)**:
  - Top bar with Buzz logo, system status indicator, and **Connect GitHub** button.
  - Hero section with repository selector (populated via HTMX after GitHub connect or manual `owner/repo` input for public repos) and the **Analyze Repo** CTA button.
  - Live scan terminal indicator (`hx-indicator`) and `#report-container` target for the vulnerability report.

### Component 2: Supabase Auth & Database Schema (`supabase/`)
- **`cves` table**:
  - `id` (`TEXT PRIMARY KEY`, e.g. `CVE-2024-xxxx`), `ecosystem` (`cargo`, `npm`, `pip`, `go`, `generic`), `package_name`, `affected_versions`, `severity`, `cvss_score`, `summary`, `cwe_id`, `remediation`.
- **`scans` table**:
  - `id` (`UUID`), `user_id` (`UUID nullable`), `repo_full_name` (`TEXT`), `commit_sha` (`TEXT`), `status` (`TEXT`), `summary_markdown` (`TEXT`), `risk_score` (`INT`), `created_at`.
- **`scan_findings` table**:
  - `id` (`UUID`), `scan_id` (`UUID`), `cve_id` (`TEXT`), `file_path` (`TEXT`), `line_hint` (`TEXT`), `confidence` (`TEXT`), `explanation` (`TEXT`), `fix_suggestion` (`TEXT`).
- **GitHub OAuth Flow**:
  - Uses Supabase Auth `signInWithOAuth({ provider: 'github', options: { scopes: 'read:user repo' } })`.
  - Stores/forwards the session & `provider_token` via `HX-Headers` (`X-GitHub-Token`, `Authorization`) to the Rust Vercel endpoints.

### Component 3: Shared Rust Core Library (`src/lib.rs`)
- **`config`**: Reads `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, `GEMINI_API_KEY`, and `GEMINI_MODEL` (defaults to `gemini-4-argon`).
- **`github`**: Fetches repository metadata, file tree, dependency manifests (`Cargo.toml`, `package.json`, `requirements.txt`, `go.mod`), and key source files via the GitHub REST API.
- **`supabase`**: Queries the `cves` datasource by ecosystem/package keywords and persists completed scan reports into `scans` and `scan_findings`.
- **`gemini`**: Calls **Gemini 4 Argon** with structured context (repo files + candidate CVEs from Supabase) and parses structured vulnerability hits, false-positive filtering, severity scoring, and code-level remediation patches.
- **`templates`**: Pure Rust HTML fragment renderers (escaped safely) for HTMX responses: repo dropdown/cards, CVE browser rows, and the visual vulnerability report.

### Component 4: Rust Vercel Serverless Endpoints (`api/*.rs`)
1. **`GET /api/health` (`api/health.rs`)**:
   - Returns an HTMX badge showing Supabase + Gemini 4 Argon readiness.
2. **`GET /api/auth_config` (`api/auth_config.rs`)**:
   - Returns public Supabase configuration so the static HTML page can initialize GitHub OAuth without hardcoding secrets.
3. **`GET /api/repos` (`api/repos.rs`)**:
   - Uses the user's GitHub OAuth `provider_token` to list their repositories and returns an `<optgroup>` / pixel repo picker partial for HTMX.
4. **`GET /api/cves` (`api/cves.rs`)**:
   - Queries the Supabase `cves` datasource (with fallback to built-in seed CVEs if offline) and renders a searchable pixel CVE feed.
5. **`POST /api/analyze` (`api/analyze.rs`)**:
   - Orchestrates the core **Analyze Repo** pipeline:
     1. Validates repo target (`owner/repo`) and fetches manifests + source files from GitHub.
     2. Queries Supabase `cves` table for candidate CVEs matching detected ecosystems/packages/patterns.
     3. Invokes **Gemini 4 Argon** with the repo snapshot and CVE candidates to determine exact vulnerability hits, affected files, exploitability context, and fixes.
     4. Saves the audit record to Supabase (`scans` + `scan_findings`).
     5. Returns a rich, visually appealing pixel-art HTML report fragment swapped directly into `#report-container` via HTMX.

---

## 5. Phased Build Order

- [x] **Phase 0**: Create `AGENTS.md` architecture & component plan.
- [x] **Phase 1**: Scaffold Rust workspace (`Cargo.toml`, `vercel.json`, `.env.example`) and Supabase SQL schema + seed CVE dataset (`supabase/schema.sql`, `supabase/seed_cves.sql`).
- [x] **Phase 2**: Create the pixel-art Buzz logo (`public/assets/buzz-logo.svg`), retro styling (`public/css/pixel.css`), and HTMX landing page (`public/index.html`).
- [x] **Phase 3**: Implement shared Rust library (`src/lib.rs`) covering GitHub repo inspection, Supabase CVE queries, Gemini 4 Argon auditing prompt/parser, and HTMX HTML report rendering.
- [x] **Phase 4**: Implement the Rust Vercel functions (`api/health.rs`, `api/auth_config.rs`, `api/repos.rs`, `api/cves.rs`, `api/analyze.rs`) and verify compilation with `cargo check` and `cargo test`.
