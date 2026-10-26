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
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS diagram_json JSONB NULL;

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

-- Clients can read only their own reports. Only verified server operations write.
DROP POLICY IF EXISTS "Read access to scans" ON public.scans;
CREATE POLICY "Read access to scans" ON public.scans FOR SELECT TO authenticated
    USING (user_id = auth.uid());
DROP POLICY IF EXISTS "Insert access to scans" ON public.scans;
DROP POLICY IF EXISTS "Update access to scans" ON public.scans;
DROP POLICY IF EXISTS "Read access to scan findings" ON public.scan_findings;
CREATE POLICY "Read access to scan findings" ON public.scan_findings FOR SELECT TO authenticated
    USING (EXISTS (SELECT 1 FROM public.scans s WHERE s.id = scan_id AND s.user_id = auth.uid()));
DROP POLICY IF EXISTS "Insert access to scan findings" ON public.scan_findings;
DROP POLICY IF EXISTS "Update access to scan findings" ON public.scan_findings;
REVOKE ALL ON public.scans, public.scan_findings FROM anon, authenticated;
GRANT SELECT ON public.scans, public.scan_findings TO authenticated;
GRANT ALL ON public.scans, public.scan_findings TO service_role;

ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS refactoring_json JSONB NULL;
-- Only new, server-verified scans qualify for refactoring actions.
ALTER TABLE public.scans ADD COLUMN IF NOT EXISTS source_verified BOOLEAN NOT NULL DEFAULT FALSE;

-- One transaction prevents a timed-out save leaving a scan without its findings.
CREATE OR REPLACE FUNCTION public.save_audit(p_scan JSONB, p_findings JSONB)
RETURNS JSONB LANGUAGE plpgsql SECURITY INVOKER SET search_path = public AS $$
DECLARE
    scan_row public.scans;
    finding JSONB;
    result_ids JSONB := '[]'::jsonb;
    finding_id UUID;
BEGIN
    scan_row := jsonb_populate_record(NULL::public.scans, p_scan);
    IF scan_row.user_id IS NULL THEN RAISE EXCEPTION 'Verified owner required'; END IF;
    scan_row.id := COALESCE(scan_row.id, gen_random_uuid());
    scan_row.created_at := now();
    INSERT INTO public.scans SELECT scan_row.*;
    FOR finding IN SELECT value FROM jsonb_array_elements(p_findings) LOOP
        finding_id := gen_random_uuid();
        INSERT INTO public.scan_findings
            (id, scan_id, cve_id, title, package_name, severity, cvss_score, cwe_id,
             file_path, line_reference, confidence, explanation, remediation_patch)
        VALUES (finding_id, scan_row.id, finding->>'cve_id', finding->>'title',
            finding->>'package_name', finding->>'severity', (finding->>'cvss_score')::numeric,
            finding->>'cwe_id', finding->>'file_path', finding->>'line_reference',
            finding->>'confidence', finding->>'explanation', finding->>'remediation_patch');
        result_ids := result_ids || to_jsonb(finding_id);
    END LOOP;
    RETURN jsonb_build_object('id', scan_row.id, 'finding_ids', result_ids);
END;
$$;
REVOKE ALL ON FUNCTION public.save_audit(JSONB, JSONB) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.save_audit(JSONB, JSONB) TO service_role;

CREATE TABLE IF NOT EXISTS public.refactoring_patches (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES auth.users(id),
    scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    suggestion_id UUID NOT NULL,
    payload JSONB NOT NULL,
    digest TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    status TEXT NOT NULL DEFAULT 'prepared' CHECK
        (status IN ('prepared', 'publishing', 'failed', 'branch_created', 'published', 'stale', 'expired')),
    commit_sha TEXT NULL,
    pr_url TEXT NULL,
    pr_number BIGINT NULL,
    lease UUID NULL,
    lease_until BIGINT NOT NULL DEFAULT 0,
    last_error TEXT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS refactoring_one_active_suggestion
    ON public.refactoring_patches(scan_id, suggestion_id)
    WHERE status NOT IN ('expired', 'stale');
ALTER TABLE public.refactoring_patches ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Owner reads refactoring patches" ON public.refactoring_patches;
CREATE POLICY "Owner reads refactoring patches" ON public.refactoring_patches
    FOR SELECT TO authenticated USING (owner_id = auth.uid());
REVOKE ALL ON public.refactoring_patches FROM anon, authenticated;
GRANT SELECT ON public.refactoring_patches TO authenticated;
GRANT ALL ON public.refactoring_patches TO service_role;

CREATE OR REPLACE FUNCTION public.guard_refactoring_patch()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = public AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NOT EXISTS (SELECT 1 FROM public.scans WHERE id = NEW.scan_id
            AND user_id = NEW.owner_id AND source_verified) THEN
            RAISE EXCEPTION 'Verified owned scan required';
        END IF;
    ELSIF ROW(NEW.id, NEW.owner_id, NEW.scan_id, NEW.suggestion_id, NEW.payload,
              NEW.digest, NEW.expires_at, NEW.created_at)
        IS DISTINCT FROM ROW(OLD.id, OLD.owner_id, OLD.scan_id, OLD.suggestion_id, OLD.payload,
              OLD.digest, OLD.expires_at, OLD.created_at) THEN
        RAISE EXCEPTION 'Reviewed patch is immutable';
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS guard_refactoring_patch ON public.refactoring_patches;
CREATE TRIGGER guard_refactoring_patch BEFORE INSERT OR UPDATE ON public.refactoring_patches
    FOR EACH ROW EXECUTE FUNCTION public.guard_refactoring_patch();

CREATE OR REPLACE FUNCTION public.claim_refactoring_patch(p_id UUID, p_owner UUID, p_digest TEXT, p_lease UUID)
RETURNS SETOF public.refactoring_patches LANGUAGE sql SECURITY INVOKER SET search_path = public AS $$
    UPDATE public.refactoring_patches SET status = 'publishing', lease = p_lease,
        lease_until = extract(epoch FROM now())::bigint + 120
    WHERE id = p_id AND owner_id = p_owner AND digest = p_digest
        AND status IN ('prepared', 'publishing', 'failed', 'branch_created')
        AND lease_until < extract(epoch FROM now())::bigint
    RETURNING *;
$$;
REVOKE ALL ON FUNCTION public.claim_refactoring_patch(UUID, UUID, TEXT, UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.claim_refactoring_patch(UUID, UUID, TEXT, UUID) TO service_role;

-- Bound retained source payloads without destroying confirmed PR history. Schedule
-- this service-only function daily in the deployment's existing database scheduler.
CREATE OR REPLACE FUNCTION public.prune_refactoring_patches()
RETURNS void LANGUAGE sql SECURITY INVOKER SET search_path = public AS $$
    DELETE FROM public.refactoring_patches WHERE expires_at < extract(epoch FROM now())::bigint - 604800
        AND status IN ('prepared', 'expired', 'stale', 'failed', 'publishing')
        AND lease_until < extract(epoch FROM now())::bigint
        AND commit_sha IS NULL AND pr_url IS NULL;
$$;
REVOKE ALL ON FUNCTION public.prune_refactoring_patches() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.prune_refactoring_patches() TO service_role;
