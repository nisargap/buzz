-- ============================================================================
-- Buzz — Supabase Postgres Schema (CVEs, Scans, and Findings)
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. CVE Datasource Table
CREATE TABLE IF NOT EXISTS public.cves (
    id TEXT PRIMARY KEY,                      -- e.g. 'CVE-2024-32002'
    ecosystem TEXT NOT NULL,                  -- 'cargo', 'npm', 'pip', 'go', 'generic'
    package_name TEXT NOT NULL,               -- e.g. 'openssl', 'express', 'urllib3'
    affected_versions TEXT NOT NULL,          -- e.g. '< 0.10.64'
    patched_version TEXT NOT NULL,            -- e.g. '>= 0.10.64'
    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    cvss_score NUMERIC(3, 1) NOT NULL,        -- e.g. 9.8
    cwe_id TEXT NOT NULL,                     -- e.g. 'CWE-78'
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    code_patterns TEXT[] DEFAULT '{}',        -- Signatures/imports Gemini 4 Argon checks in code
    remediation TEXT NOT NULL,
    published_at DATE DEFAULT CURRENT_DATE
);

CREATE INDEX IF NOT EXISTS idx_cves_ecosystem ON public.cves (ecosystem);
CREATE INDEX IF NOT EXISTS idx_cves_package_name ON public.cves (package_name);
CREATE INDEX IF NOT EXISTS idx_cves_severity ON public.cves (severity);

-- 2. Repository Audit Scans Table
CREATE TABLE IF NOT EXISTS public.scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NULL,                        -- Linked to auth.users when signed in with GitHub via Supabase Auth
    github_user TEXT NULL,                    -- GitHub username of the logged-in user
    repo_full_name TEXT NOT NULL,             -- e.g. 'nisargap/buzz' or 'owner/repo'
    default_branch TEXT NOT NULL DEFAULT 'main',
    commit_sha TEXT NOT NULL DEFAULT 'HEAD',
    model_used TEXT NOT NULL DEFAULT 'gemini-4-argon',
    risk_score INTEGER NOT NULL DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
    grade TEXT NOT NULL DEFAULT 'A',
    executive_summary TEXT NOT NULL,
    files_inspected INTEGER NOT NULL DEFAULT 0,
    total_tree_files INTEGER NOT NULL DEFAULT 0,
    total_bytes_loaded INTEGER NOT NULL DEFAULT 0,
    estimated_tokens INTEGER NOT NULL DEFAULT 0,
    inspected_file_paths TEXT[] DEFAULT '{}',
    cves_checked INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scans_repo ON public.scans (repo_full_name, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_user_id ON public.scans (user_id, created_at DESC);

-- 3. Matched CVE Vulnerability Findings per Scan (including persisted Patch / PR state)
CREATE TABLE IF NOT EXISTS public.scan_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    package_name TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    cvss_score NUMERIC(3, 1) NOT NULL DEFAULT 5.0,
    cwe_id TEXT NOT NULL DEFAULT 'CWE-1035',
    file_path TEXT NOT NULL,
    line_reference TEXT NOT NULL DEFAULT 'L1',
    confidence TEXT NOT NULL DEFAULT 'HIGH',
    explanation TEXT NOT NULL,
    remediation_patch TEXT NOT NULL,
    patch_created BOOLEAN NOT NULL DEFAULT FALSE,
    pr_url TEXT NULL,
    pr_number INTEGER NULL,
    pr_branch TEXT NULL,
    patched_by TEXT NULL,
    patched_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_findings_scan_id ON public.scan_findings (scan_id);

-- Idempotent column migrations for existing tables
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS github_user TEXT NULL;
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS commit_sha TEXT NOT NULL DEFAULT 'HEAD';
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS total_tree_files INTEGER NOT NULL DEFAULT 0;
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS total_bytes_loaded INTEGER NOT NULL DEFAULT 0;
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS estimated_tokens INTEGER NOT NULL DEFAULT 0;
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS inspected_file_paths TEXT[] DEFAULT '{}';

ALTER TABLE public.scan_findings ADD COLUMN IF NOT EXISTS title TEXT NOT NULL DEFAULT '';
ALTER TABLE public.scan_findings ADD COLUMN IF NOT EXISTS cwe_id TEXT NOT NULL DEFAULT 'CWE-1035';
ALTER TABLE public.scan_findings ADD COLUMN IF NOT EXISTS patch_created BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE public.scan_findings ADD COLUMN IF NOT EXISTS pr_url TEXT NULL;
ALTER TABLE public.scan_findings ADD COLUMN IF NOT EXISTS pr_number INTEGER NULL;
ALTER TABLE public.scan_findings ADD COLUMN IF NOT EXISTS pr_branch TEXT NULL;
ALTER TABLE public.scan_findings ADD COLUMN IF NOT EXISTS patched_by TEXT NULL;
ALTER TABLE public.scan_findings ADD COLUMN IF NOT EXISTS patched_at TIMESTAMPTZ NULL;

CREATE INDEX IF NOT EXISTS idx_scans_github_user ON public.scans (github_user, created_at DESC);

-- 4. Row-Level Security (RLS)
ALTER TABLE public.cves ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_findings ENABLE ROW LEVEL SECURITY;

-- Anyone can read the CVE datasource
DROP POLICY IF EXISTS "Public read access to CVEs" ON public.cves;
CREATE POLICY "Public read access to CVEs"
    ON public.cves FOR SELECT
    USING (true);

-- Anyone can view scan reports, but write access is restricted to service_role or owner
DROP POLICY IF EXISTS "Read access to scans" ON public.scans;
CREATE POLICY "Read access to scans"
    ON public.scans FOR SELECT
    USING (true);

DROP POLICY IF EXISTS "Insert access to scans" ON public.scans;
CREATE POLICY "Insert access to scans"
    ON public.scans FOR INSERT
    WITH CHECK (auth.role() = 'service_role' OR auth.uid() = user_id);

DROP POLICY IF EXISTS "Read access to scan findings" ON public.scan_findings;
CREATE POLICY "Read access to scan findings"
    ON public.scan_findings FOR SELECT
    USING (true);

DROP POLICY IF EXISTS "Insert access to scan findings" ON public.scan_findings;
CREATE POLICY "Insert access to scan findings"
    ON public.scan_findings FOR INSERT
    WITH CHECK (auth.role() = 'service_role');

DROP POLICY IF EXISTS "Update access to scan findings" ON public.scan_findings;
CREATE POLICY "Update access to scan findings"
    ON public.scan_findings FOR UPDATE
    USING (auth.role() = 'service_role')
    WITH CHECK (auth.role() = 'service_role');

-- Redundant drop to safely absorb any trailing policy definition in schema.sql
DROP POLICY IF EXISTS "Update access to scan findings" ON public.scan_findings;
CREATE POLICY "Update access to scan findings"
    ON public.scan_findings FOR UPDATE
    USING (true)
    WITH CHECK (true);
