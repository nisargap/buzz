#!/usr/bin/env python3
"""
Buzz — CVEProject/cvelistV5 Importer for Supabase (`public.cves`)
Source: https://github.com/CVEProject/cvelistV5

Downloads official CVE Record Format v5.x JSON records from CVEProject/cvelistV5
releases and raw tree paths, normalizes package/ecosystem/CVSS/CWE metadata, and
upserts them into the live Supabase `public.cves` table.
"""

import io
import json
import os
import urllib.request
import zipfile
from datetime import date

CVELIST_RELEASES_API = "https://api.github.com/repos/CVEProject/cvelistV5/releases?per_page=5"
CVELIST_RAW_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main"

# Curated high-impact software/library CVE paths in CVEProject/cvelistV5 to guarantee
# rich coverage across Cargo/Rust, NPM/Node, Pip/Python, Go, and Web ecosystems
CURATED_V5_PATHS = [
    "cves/2024/32xxx/CVE-2024-32650.json",
    "cves/2024/24xxx/CVE-2024-24576.json",
    "cves/2024/45xxx/CVE-2024-45296.json",
    "cves/2024/29xxx/CVE-2024-29041.json",
    "cves/2024/39xxx/CVE-2024-39338.json",
    "cves/2024/35xxx/CVE-2024-35195.json",
    "cves/2024/37xxx/CVE-2024-37891.json",
    "cves/2024/24xxx/CVE-2024-24790.json",
    "cves/2024/21xxx/CVE-2024-21538.json",
    "cves/2024/40xxx/CVE-2024-4067.json",
    "cves/2024/43xxx/CVE-2024-43796.json",
    "cves/2024/43xxx/CVE-2024-43799.json",
    "cves/2024/47xxx/CVE-2024-47764.json",
    "cves/2024/48xxx/CVE-2024-48948.json",
    "cves/2024/52xxx/CVE-2024-52798.json",
    "cves/2024/27xxx/CVE-2024-27983.json",
    "cves/2024/28xxx/CVE-2024-28849.json",
    "cves/2024/34xxx/CVE-2024-34064.json",
    "cves/2024/6xxx/CVE-2024-6345.json",
    "cves/2023/4xxx/CVE-2023-4863.json",
]


def load_env_local():
    for fname in (".env.local", ".env"):
        if os.path.exists(fname):
            with open(fname, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    v = v.strip().strip('"').strip("'")
                    os.environ.setdefault(k.strip(), v)


def infer_ecosystem(vendor: str, product: str, pkg_name: str, summary: str, urls: list[str]) -> str:
    joined = f"{vendor} {product} {pkg_name} {summary} {' '.join(urls)}".lower()
    if any(w in joined for w in ("crates.io", "rustsec", "cargo", "rustls", "tokio", "reqwest", "hyper", "serde")):
        return "cargo"
    if any(w in joined for w in ("npmjs.com", "node.js", "nodejs", "express", "axios", "webpack", "next.js", "react", "vite", "cookie", "send", "serve-static", "elliptic", "cross-spawn", "micromatch", "path-to-regexp")):
        return "npm"
    if any(w in joined for w in ("pypi.org", "pip", "python", "django", "flask", "jinja2", "urllib3", "requests", "setuptools", "werkzeug", "fastapi", "pytorch")):
        return "pip"
    if any(w in joined for w in ("pkg.go.dev", "golang", "go.dev", "net/http", "net/netip", "x/net", "x/crypto")):
        return "go"
    return "generic"


def parse_cve_v5_json(doc: dict) -> dict | None:
    meta = doc.get("cveMetadata") or {}
    if meta.get("state") != "PUBLISHED":
        return None

    cve_id = meta.get("cveId")
    if not cve_id:
        return None

    cna = (doc.get("containers") or {}).get("cna") or {}

    # 1. English description
    descriptions = cna.get("descriptions") or []
    summary = ""
    for d in descriptions:
        if d.get("lang", "").startswith("en") and d.get("value"):
            summary = d["value"].strip()
            break
    if not summary and descriptions:
        summary = (descriptions[0].get("value") or "").strip()
    if not summary or "Rejected reason" in summary:
        return None

    title = (cna.get("title") or "").strip()
    if not title:
        first_sentence = summary.split(". ")[0].strip()
        title = first_sentence[:140] if first_sentence else cve_id

    # 2. Affected vendor / product / package & versions
    affected_list = cna.get("affected") or []
    vendor = "unknown"
    product = "unknown"
    package_name = ""
    affected_ver_parts = []
    patched_ver_parts = []

    if affected_list:
        first_aff = affected_list[0]
        vendor = (first_aff.get("vendor") or "unknown").strip()
        product = (first_aff.get("product") or "unknown").strip()
        package_name = (first_aff.get("packageName") or product or vendor).strip()

        for v in (first_aff.get("versions") or [])[:4]:
            status = v.get("status", "")
            ver_val = str(v.get("version") or "").strip()
            less_than = str(v.get("lessThan") or "").strip()
            less_eq = str(v.get("lessThanOrEqual") or "").strip()
            if status == "affected":
                if less_than:
                    affected_ver_parts.append(f"< {less_than}")
                    patched_ver_parts.append(f">= {less_than}")
                elif less_eq:
                    affected_ver_parts.append(f"<= {less_eq}")
                elif ver_val and ver_val != "n/a":
                    affected_ver_parts.append(ver_val)
            elif status == "unaffected" and ver_val and ver_val != "n/a":
                patched_ver_parts.append(f">= {ver_val}")

    if not package_name or package_name.lower() == "n/a":
        package_name = product if product.lower() != "n/a" else vendor

    affected_versions = ", ".join(dict.fromkeys(affected_ver_parts)) or "See advisory"
    patched_version = ", ".join(dict.fromkeys(patched_ver_parts)) or "Upgrade to latest release"

    # 3. CVSS score & severity (check CNA metrics then ADP metrics)
    all_metrics = list(cna.get("metrics") or [])
    for adp in (doc.get("containers") or {}).get("adp") or []:
        all_metrics.extend(adp.get("metrics") or [])

    cvss_score = None
    severity = None
    for m in all_metrics:
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            if key in m and isinstance(m[key], dict):
                cv = m[key]
                if cv.get("baseScore") is not None:
                    cvss_score = float(cv["baseScore"])
                if cv.get("baseSeverity"):
                    severity = str(cv["baseSeverity"]).upper().strip()
                break
        if cvss_score is not None:
            break

    if cvss_score is None:
        cvss_score = 7.2
    if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if cvss_score >= 9.0:
            severity = "CRITICAL"
        elif cvss_score >= 7.0:
            severity = "HIGH"
        elif cvss_score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

    # 4. CWE ID
    cwe_id = "CWE-1035"
    problem_types = list(cna.get("problemTypes") or [])
    for adp in (doc.get("containers") or {}).get("adp") or []:
        problem_types.extend(adp.get("problemTypes") or [])
    for pt in problem_types:
        for desc in pt.get("descriptions") or []:
            cid = desc.get("cweId") or ""
            if cid.startswith("CWE-"):
                cwe_id = cid
                break
        if cwe_id != "CWE-1035":
            break

    # 5. References & ecosystem inference
    refs = [r.get("url", "") for r in (cna.get("references") or []) if r.get("url")]
    ecosystem = infer_ecosystem(vendor, product, package_name, summary, refs)

    # 6. Published date
    date_pub_raw = (meta.get("datePublished") or "")[:10]
    try:
        date.fromisoformat(date_pub_raw)
        published_at = date_pub_raw
    except Exception:
        published_at = date.today().isoformat()

    # 7. Code patterns & remediation
    clean_pkg = package_name.split("/")[-1].strip()
    patterns = [p for p in dict.fromkeys([package_name, clean_pkg]) if p and len(p) >= 3]
    remediation = f"Upgrade `{package_name}` ({ecosystem}) to {patched_version} to remediate {cve_id} ({cwe_id})."

    return {
        "id": cve_id,
        "ecosystem": ecosystem,
        "package_name": package_name[:120],
        "affected_versions": affected_versions[:180],
        "patched_version": patched_version[:120],
        "severity": severity,
        "cvss_score": round(cvss_score, 1),
        "cwe_id": cwe_id[:40],
        "title": title[:220],
        "summary": summary[:900],
        "code_patterns": patterns[:6],
        "remediation": remediation[:300],
        "published_at": published_at,
    }


def fetch_json(url: str):
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Buzz-CVEListV5-Sync/1.0", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def collect_cvelist_v5_records(max_delta_records: int = 250) -> list[dict]:
    records_by_id: dict[str, dict] = {}

    # 1. Fetch curated high-impact CVE v5 JSON files from CVEProject/cvelistV5
    print(f"[1/2] Fetching curated CVE v5 JSON files from {CVELIST_RAW_BASE} ...")
    for rel_path in CURATED_V5_PATHS:
        url = f"{CVELIST_RAW_BASE}/{rel_path}"
        try:
            doc = fetch_json(url)
            parsed = parse_cve_v5_json(doc)
            if parsed:
                records_by_id[parsed["id"]] = parsed
        except Exception as exc:
            print(f"  - Skipped {rel_path}: {exc}")

    # 2. Download the latest delta bundle from CVEProject/cvelistV5 releases
    print("[2/2] Fetching latest delta CVE bundle from CVEProject/cvelistV5 releases ...")
    try:
        releases = fetch_json(CVELIST_RELEASES_API)
        delta_url = None
        for rel in releases:
            for asset in rel.get("assets") or []:
                if "delta" in asset.get("name", "") and asset.get("name", "").endswith(".zip"):
                    delta_url = asset.get("browser_download_url")
                    break
            if delta_url:
                break

        if delta_url:
            print(f"  - Downloading {delta_url} ...")
            req = urllib.request.Request(
                delta_url, headers={"User-Agent": "Buzz-CVEListV5-Sync/1.0"}
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                zip_bytes = resp.read()

            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                json_names = [n for n in zf.namelist() if n.endswith(".json") and "CVE-" in n]
                print(f"  - Archive contains {len(json_names)} CVE v5 JSON files; parsing up to {max_delta_records}...")
                count = 0
                for name in json_names:
                    if count >= max_delta_records:
                        break
                    try:
                        doc = json.loads(zf.read(name).decode("utf-8"))
                        parsed = parse_cve_v5_json(doc)
                        if parsed:
                            records_by_id[parsed["id"]] = parsed
                            count += 1
                    except Exception:
                        continue
    except Exception as exc:
        print(f"  - Release delta fetch warning: {exc}")

    return list(records_by_id.values())


def upsert_to_supabase(records: list[dict]):
    supabase_url = os.environ.get("SUPABASE_URL", "").rstrip("/")
    api_key = (
        os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
        or os.environ.get("SUPABASE_SECRET_KEY")
        or os.environ.get("NEXT_PUBLIC_SUPABASE_ANON_KEY")
        or os.environ.get("SUPABASE_ANON_KEY")
    )
    if not supabase_url or not api_key:
        raise RuntimeError("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in environment / .env.local")

    endpoint = f"{supabase_url}/rest/v1/cves?on_conflict=id"
    batch_size = 50
    total_upserted = 0

    for i in range(0, len(records), batch_size):
        batch = records[i : i + batch_size]
        payload = json.dumps(batch).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=payload,
            method="POST",
            headers={
                "apikey": api_key,
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Prefer": "resolution=merge-duplicates,return=minimal",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            if resp.status in (200, 201, 204):
                total_upserted += len(batch)

    print(f"✓ Upserted {total_upserted} CVE v5 records from CVEProject/cvelistV5 into {supabase_url}/rest/v1/cves")


if __name__ == "__main__":
    load_env_local()
    cves = collect_cvelist_v5_records(max_delta_records=250)
    print(f"Collected {len(cves)} normalized CVE v5 records.")
    upsert_to_supabase(cves)
