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
