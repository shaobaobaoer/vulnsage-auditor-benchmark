#!/usr/bin/env python3
"""
Generate fixtures/ and examples/ from sast-bench-filtered.json (single source of truth).

Usage:
    python3 scripts/generate-fixtures.py [--dry-run]

This script reads sast-bench-filtered.json and generates:
  - examples/{lang}-sast-{CVE_ID}.json        (task definition)
  - fixtures/{lang}-sast-{CVE_ID}/meta.json   (GT metadata)
  - fixtures/{lang}-sast-{CVE_ID}/expected/vuln_report.json  (expected output)
  - fixtures/{lang}-sast-{CVE_ID}/clone.sh     (clone script)
  - fixtures/{lang}-sast-{CVE_ID}/entrypoint.sh (entrypoint)
  - fixtures/{lang}-sast-{CVE_ID}/Dockerfile    (docker build)
"""

import json
import os
import re
import shutil
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
BENCHMARK_DIR = SCRIPT_DIR.parent
BENCH_FILE = BENCHMARK_DIR / "sast-bench-filtered.json"

VALID_TYPES = {
    "sql-injection", "command-injection", "path-traversal", "ssrf",
    "xss", "insecure-deserialization", "xxe", "dos",
    "prototype-pollution", "header-injection", "code-injection", "open-redirect",
}

# excluded vulnerability types (not source-to-sink injection class)
EXCLUDED_TYPES_ORIGINAL = {
    "authentication_bypass", "privilege_escalation", "nil_pointer_dereference",
    "crypto_weak", "ip spoofing", "server misconfiguration & missing authentication",
    "information", "other",
}

# Language mapping: detected_language -> (fixture_prefix, short_lang, dockerfile_base, extra_deps)
LANG_CONFIG = {
    "go":         ("go-sast",     "go",     "golang:1.21-alpine",                    "git"),
    "java":       ("java-sast",   "java",   "maven:3.9-eclipse-temurin-17-alpine",   "git"),
    "javascript": ("js-sast",     "js",     "node:20-alpine",                        "git python3 make g++"),
    "python":     ("python-sast", "python", "python:3.11-alpine",                    "git gcc musl-dev"),
}


def get_lang_config(detected_language: str) -> tuple:
    """Get language config, defaulting to javascript for unknown languages."""
    return LANG_CONFIG.get(detected_language, LANG_CONFIG["javascript"])


def make_fixture_name(cve_id: str, prefix: str) -> str:
    """Build fixture directory name: {prefix}-{CVE_ID}"""
    return f"{prefix}-{cve_id}"


def extract_cwe_id(cwe_list: list) -> str:
    """Extract first CWE ID from cve_info.CWE list."""
    if not cwe_list:
        return ""
    first = cwe_list[0]
    cwe_id = first.get("ID", "")
    if cwe_id and not cwe_id.startswith("CWE-"):
        return cwe_id
    return cwe_id


def extract_cwe_full(cwe_list: list) -> str:
    """Extract full CWE description from cve_info.CWE list."""
    if not cwe_list:
        return ""
    first = cwe_list[0]
    return first.get("Description", first.get("ID", ""))


def build_vulnerable_files(nodes: list) -> list:
    """Extract unique file paths from Nodes."""
    files = []
    seen = set()
    for node in nodes:
        f = node.get("File", "")
        if f and f not in seen:
            files.append(f)
            seen.add(f)
    return files


def build_source_sink(nodes: list) -> tuple:
    """Extract source and sink info from Nodes list."""
    source = {"file": "", "function": "", "line": 0, "description": ""}
    sink = {"file": "", "function": "", "line": 0, "description": ""}

    for node in nodes:
        ntype = node.get("Type", "")
        if ntype == "Source" and not source["file"]:
            source = {
                "file": node.get("File", ""),
                "function": "",
                "line": node.get("StartLine", 0),
                "description": node.get("Desc", ""),
            }
        elif ntype == "Sink":
            sink = {
                "file": node.get("File", ""),
                "function": "",
                "line": node.get("StartLine", 0),
                "description": node.get("Desc", ""),
            }

    # Fallback: if no explicit Source/Sink, use first/last node
    if not source["file"] and nodes:
        n = nodes[0]
        source = {
            "file": n.get("File", ""),
            "function": "",
            "line": n.get("StartLine", 0),
            "description": n.get("Desc", ""),
        }
    if not sink["file"] and nodes:
        n = nodes[-1]
        sink = {
            "file": n.get("File", ""),
            "function": "",
            "line": n.get("StartLine", 0),
            "description": n.get("Desc", ""),
        }

    return source, sink


def build_data_flow(nodes: list) -> list:
    """Build data_flow array from Nodes."""
    flow = []
    for i, node in enumerate(nodes):
        flow.append({
            "step": i + 1,
            "location": f"{node.get('File', '')}:{node.get('StartLine', 0)}",
            "description": node.get("Desc", ""),
        })
    return flow


def severity_to_counts(severity: str, total: int = 1) -> dict:
    """Build summary counts from severity string."""
    s = severity.lower()
    return {
        "total_findings": total,
        "critical": total if s == "critical" else 0,
        "high": total if s == "high" else 0,
        "medium": total if s == "medium" else 0,
        "low": total if s == "low" else 0,
        "info": total if s == "info" else 0,
    }


def generate_example(issue: dict, repo_url: str, parent_hash: str) -> dict:
    """Generate examples/{name}.json content."""
    desc = issue.get("cve_info", {}).get("Description", "")
    if not desc:
        desc = issue.get("basic_info", {}).get("description", "")
    target = f"{repo_url}.git@{parent_hash}" if repo_url and parent_hash else repo_url or ""
    return {
        "target": target,
        "description": desc,
    }


def generate_meta(issue: dict, patch_info: dict, cwe_list: list,
                   short_lang: str, vuln_type: str, nodes: list) -> dict:
    """Generate fixtures/{name}/meta.json content."""
    cve_id = issue["cve_id"]
    owner = patch_info.get("Owner", "")
    repo = patch_info.get("Repo", "")
    project = f"{owner}/{repo}" if owner and repo else repo
    repo_url = patch_info.get("RepoURL", "")
    parent_hash = patch_info.get("ParentHash", "")
    fix_hash = patch_info.get("Hash", "")

    desc = issue.get("cve_info", {}).get("Description", "")
    if not desc:
        desc = issue.get("basic_info", {}).get("description", "")

    severity_str = issue.get("basic_info", {}).get("severity", "high")
    cvss_map = {"critical": 9.0, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 0.0}
    cvss = cvss_map.get(severity_str.lower(), 8.0)

    # Try to get finding-level cvss
    findings = issue.get("path_result", {}).get("findings", [])
    if findings:
        f_conf = findings[0].get("confidence", 0.99)

    meta = {
        "cve_id": cve_id,
        "project": project,
        "repo_url": repo_url,
        "vulnerable_version": parent_hash[:7] if parent_hash else "",
        "fixed_version": fix_hash[:7] if fix_hash else "",
        "vulnerable_ref": parent_hash,
        "language": short_lang,
        "category": "sast",
        "vuln_type": vuln_type,
        "cvss": cvss,
        "description": desc,
        "vulnerable_files": build_vulnerable_files(nodes),
        "cwe": extract_cwe_full(cwe_list),
        "references": [patch_info.get("URL", "")] if patch_info.get("URL") else [],
    }

    return meta


def generate_vuln_report(issue: dict, meta: dict, nodes: list,
                          cwe_list: list) -> dict:
    """Generate fixtures/{name}/expected/vuln_report.json content."""
    cve_id = issue["cve_id"]
    vuln_type = meta["vuln_type"]
    short_lang = meta["language"]

    # pipeline_id
    cve_clean = cve_id.lower().replace("-", "")
    pipeline_id = f"pid-{short_lang}-sast-{cve_clean}"

    source, sink = build_source_sink(nodes)
    data_flow = build_data_flow(nodes)

    severity = issue.get("basic_info", {}).get("severity", "high")

    # Title: "{Type} in {sink_file_basename}"
    sink_basename = os.path.basename(sink["file"]) if sink["file"] else "unknown"
    title = f"{vuln_type.replace('-', ' ').title().replace(' ', '-')} in {sink_basename}"
    # Simplify: capitalize first word only
    parts = vuln_type.split("-")
    title = f"{parts[0].capitalize()}{' ' + ' '.join(parts[1:]) if len(parts) > 1 else ''} in {sink_basename}"
    # Actually match existing format: "Xss in file.js", "Ssrf in webhook.go"
    type_display = vuln_type.replace("-", " ")
    type_display = type_display[0].upper() + type_display[1:] if type_display else ""
    title = f"{type_display} in {sink_basename}"

    cwe_id = extract_cwe_id(cwe_list)

    finding = {
        "id": "VULN-001",
        "title": title,
        "vulnerability_type": vuln_type,
        "severity": severity,
        "cvss": meta["cvss"],
        "cve_id": cve_id,
        "cwe_id": cwe_id,
        "source": source,
        "sink": sink,
        "data_flow": data_flow,
        "recommendation": f"Apply the fix from commit {meta['fixed_version']} or upgrade to the patched version.",
        "confidence": 0.99,
    }

    report = {
        "pipeline_id": pipeline_id,
        "scan_metadata": {
            "target": meta["project"],
            "version": meta["vulnerable_version"],
            "language": short_lang,
            "scanner": "vulnsage-vulnerability-analysis",
        },
        "findings": [finding],
        "summary": severity_to_counts(severity),
    }

    return report


def generate_clone_sh(cve_id: str, project: str, repo_url: str,
                       vulnerable_ref: str) -> str:
    """Generate clone.sh content."""
    return f"""#!/usr/bin/env bash
# Clone the vulnerable version for {cve_id}
# Project: {project}

set -euo pipefail

REPO_URL="{repo_url}.git"
VULNERABLE_REF="{vulnerable_ref}"
TARGET_DIR="source"

if [[ -d "$TARGET_DIR" ]]; then
  echo "[clone] Source already exists at ${{TARGET_DIR}}, skipping"
  exit 0
fi

echo "[clone] Cloning {project} at ${{VULNERABLE_REF:0:7}}..."
git clone --depth 1 "$REPO_URL" "$TARGET_DIR"
cd "$TARGET_DIR"
git fetch --depth 1 origin "$VULNERABLE_REF"
git checkout FETCH_HEAD

echo "[clone] Done. Source at: ${{TARGET_DIR}}/"
"""


def generate_entrypoint_sh(cve_id: str, vuln_type: str,
                            short_lang: str) -> str:
    """Generate entrypoint.sh content."""
    return f"""#!/bin/bash
set -e

echo "=== VulnSage SAST Benchmark: {cve_id} ==="
echo "Vulnerability type: {vuln_type}"
echo "Language: {short_lang}"

# Clone the vulnerable version
/workspace/clone.sh

echo ""
echo "Source code ready for SAST analysis."
echo "Target directory: /workspace/source/"
"""


def generate_dockerfile(cve_id: str, project: str, short_lang: str,
                         docker_base: str, extra_deps: str) -> str:
    """Generate Dockerfile content."""
    return f"""# Dockerfile for {cve_id} ({project})
# Language: {short_lang}

FROM {docker_base}

WORKDIR /workspace

# Install dependencies
RUN apk add --no-cache {extra_deps}

# Copy clone script
COPY clone.sh /workspace/clone.sh
RUN chmod +x /workspace/clone.sh

# Copy entrypoint
COPY entrypoint.sh /workspace/entrypoint.sh
RUN chmod +x /workspace/entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/workspace/entrypoint.sh"]
"""


def main():
    dry_run = "--dry-run" in sys.argv

    if not BENCH_FILE.exists():
        print(f"ERROR: {BENCH_FILE} not found", file=sys.stderr)
        sys.exit(1)

    with open(BENCH_FILE, encoding="utf-8") as f:
        data = json.load(f)

    issues = data["issues"]
    print(f"Loaded {len(issues)} issues from {BENCH_FILE.name}")

    fixtures_dir = BENCHMARK_DIR / "fixtures"
    examples_dir = BENCHMARK_DIR / "examples"

    if not dry_run:
        # Clean old directories
        if fixtures_dir.exists():
            shutil.rmtree(fixtures_dir)
            print(f"Removed old {fixtures_dir.name}/")
        if examples_dir.exists():
            shutil.rmtree(examples_dir)
            print(f"Removed old {examples_dir.name}/")

        fixtures_dir.mkdir(exist_ok=True)
        examples_dir.mkdir(exist_ok=True)

    stats = {"total": 0, "generated": 0, "excluded": 0, "errors": []}

    for issue in issues:
        cve_id = issue["cve_id"]
        stats["total"] += 1

        detected_lang = issue.get("detected_language", "javascript")
        prefix, short_lang, docker_base, extra_deps = get_lang_config(detected_lang)
        fixture_name = make_fixture_name(cve_id, prefix)

        cve_info = issue.get("cve_info", {})
        patch_info = cve_info.get("PatchInfo", {})
        cwe_list = cve_info.get("CWE", [])

        vuln_type = issue.get("normalized_type", issue.get("basic_info", {}).get("vulnerability_type", ""))
        repo_url = patch_info.get("RepoURL", "")
        parent_hash = patch_info.get("ParentHash", "")
        project = f"{patch_info.get('Owner', '')}/{patch_info.get('Repo', '')}"
        if project == "/":
            project = ""

        # Get Nodes
        findings = issue.get("path_result", {}).get("findings", [])
        nodes = findings[0].get("Nodes", []) if findings else []

        # Check if this is an excluded type
        is_excluded = vuln_type not in VALID_TYPES

        if is_excluded:
            stats["excluded"] += 1

        if dry_run:
            status = "EXCLUDED" if is_excluded else "OK"
            print(f"  [{status}] {fixture_name}: type={vuln_type}, lang={short_lang}")
            continue

        # --- Generate files ---

        # 1. example
        example = generate_example(issue, repo_url, parent_hash)
        example_path = examples_dir / f"{fixture_name}.json"
        with open(example_path, "w", encoding="utf-8") as f:
            json.dump(example, f, ensure_ascii=False, indent=2)
            f.write("\n")

        # 2. fixture directory
        fixture_dir = fixtures_dir / fixture_name
        fixture_dir.mkdir(parents=True, exist_ok=True)
        expected_dir = fixture_dir / "expected"
        expected_dir.mkdir(exist_ok=True)

        # 3. meta.json
        meta = generate_meta(issue, patch_info, cwe_list, short_lang, vuln_type, nodes)
        if is_excluded:
            meta["excluded"] = True
            meta["exclude_reason"] = f"Type '{vuln_type}' is not in VulnSage SAST scope"

        meta_path = fixture_dir / "meta.json"
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)
            f.write("\n")

        # 4. expected/vuln_report.json
        vuln_report = generate_vuln_report(issue, meta, nodes, cwe_list)
        report_path = expected_dir / "vuln_report.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(vuln_report, f, ensure_ascii=False, indent=2)
            f.write("\n")

        # 5. clone.sh
        clone_content = generate_clone_sh(cve_id, project, repo_url, parent_hash)
        clone_path = fixture_dir / "clone.sh"
        with open(clone_path, "w", encoding="utf-8") as f:
            f.write(clone_content)
        os.chmod(clone_path, 0o755)

        # 6. entrypoint.sh
        entry_content = generate_entrypoint_sh(cve_id, vuln_type, short_lang)
        entry_path = fixture_dir / "entrypoint.sh"
        with open(entry_path, "w", encoding="utf-8") as f:
            f.write(entry_content)
        os.chmod(entry_path, 0o755)

        # 7. Dockerfile
        docker_content = generate_dockerfile(cve_id, project, short_lang, docker_base, extra_deps)
        docker_path = fixture_dir / "Dockerfile"
        with open(docker_path, "w", encoding="utf-8") as f:
            f.write(docker_content)

        stats["generated"] += 1

    # Summary
    print(f"\n{'='*60}")
    print(f"Total issues:     {stats['total']}")
    print(f"Generated:        {stats['generated']}")
    print(f"Excluded (in GT): {stats['excluded']}")
    if stats["errors"]:
        print(f"Errors:           {len(stats['errors'])}")
        for e in stats["errors"]:
            print(f"  {e}")
    print(f"{'='*60}")

    # Verify counts
    if not dry_run:
        actual_fixtures = len([d for d in fixtures_dir.iterdir() if d.is_dir()])
        actual_examples = len([f for f in examples_dir.iterdir() if f.suffix == ".json"])
        print(f"\nVerification:")
        print(f"  fixtures/ directories: {actual_fixtures}")
        print(f"  examples/ json files:  {actual_examples}")
        if actual_fixtures == stats["total"] and actual_examples == stats["total"]:
            print("  ✅ Counts match")
        else:
            print("  ❌ Count mismatch!")


if __name__ == "__main__":
    main()
