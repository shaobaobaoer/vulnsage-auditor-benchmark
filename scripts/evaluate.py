#!/usr/bin/env python3
"""
VulnSage Benchmark Evaluation Script
=====================================
Evaluates auditor results against ground truth (GT) fixtures.

Matching logic (aligned with external benchmark methodology):
  1. Build GT path points from vuln_report.json: all nodes in data_flow,
     plus source and sink fields -> set of (file, line) pairs.
  2. File paths are matched EXACTLY after normalization (strip "source/",
     "./", normalize separators).
  3. For each actual finding's sink (file, line), check if it lands on ANY
     GT path point within ±N lines (configurable, default 5).
  4. If ANY finding's sink hits ANY GT path point -> sample is HIT.
  5. Otherwise -> MISS.

Usage:
    python3 scripts/evaluate.py \\
        --workspace-dir <path-to-workspaces> \\
        --batch-log-dir <path-to-batch-logs> \\
        [--line-tolerance 5] \\
        [--output-dir reports/] \\
        [--examples-dir <path-to-examples>] \\
        [--format table|csv|markdown|all]
"""

import argparse
import csv
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
BENCHMARK_DIR = SCRIPT_DIR.parent
FIXTURES_DIR = BENCHMARK_DIR / "fixtures"

DEFAULT_LINE_TOLERANCE = 5

# 12 supported vulnerability types
SUPPORTED_VULN_TYPES = {
    "sql-injection", "command-injection", "path-traversal", "ssrf",
    "xss", "insecure-deserialization", "xxe", "dos",
    "prototype-pollution", "header-injection", "code-injection", "open-redirect",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PathPoint:
    """A single point on a GT data-flow path."""
    file: str
    line: int


@dataclass
class SampleResult:
    """Evaluation result for a single sample."""
    sample_name: str
    language: str
    vuln_type: str
    hit: bool = False
    has_results_file: bool = False
    has_findings: bool = False
    excluded: bool = False
    exclude_reason: str = ""
    gt_path_points: list = field(default_factory=list)
    matched_gt_point: Optional[PathPoint] = None
    matched_finding_sink_file: str = ""
    matched_finding_sink_line: int = 0
    matched_line_distance: Optional[int] = None
    vuln_type_match: bool = False
    actual_vuln_type: str = ""
    num_findings: int = 0
    workspace_dir: str = ""
    detail: str = ""
    issues: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Path normalization
# ---------------------------------------------------------------------------

def normalize_path(p: str) -> str:
    """Normalize a file path for exact comparison.

    Strips common prefixes added by workspace cloning:
      - "source/" prefix
      - "./" prefix
    Normalizes path separators to "/".
    """
    if not p:
        return ""
    p = p.replace("\\", "/")
    if p.startswith("source/"):
        p = p[7:]
    if p.startswith("./"):
        p = p[2:]
    return p


# ---------------------------------------------------------------------------
# Vulnerability type normalization (auxiliary info only)
# ---------------------------------------------------------------------------

# Comprehensive alias mapping — merged from both legacy scripts
_VULN_TYPE_ALIASES = {
    # Path Traversal
    "path-traversal": "path-traversal",
    "path_traversal": "path-traversal",
    "directory-traversal": "path-traversal",
    "directory_traversal": "path-traversal",
    "unauthorized file read": "path-traversal",
    # SSRF
    "ssrf": "ssrf",
    "server-side request forgery": "ssrf",
    "server_side_request_forgery": "ssrf",
    "protocol validation bypass": "ssrf",
    # XSS
    "xss": "xss",
    "cross-site scripting": "xss",
    "cross_site_scripting": "xss",
    "cross-site scripting (xss)": "xss",
    "cross_site scripting (xss)": "xss",
    "cross site scripting": "xss",
    "reflected-xss": "xss",
    "stored-xss": "xss",
    "html_injection": "xss",
    "html-injection": "xss",
    "html injection": "xss",
    "css injection": "xss",
    "css_injection": "xss",
    "css injection / class attribute manipulation": "xss",
    "iframe_injection": "xss",
    "iframe-injection": "xss",
    "iframe injection": "xss",
    # SQL Injection
    "sql-injection": "sql-injection",
    "sql_injection": "sql-injection",
    "sqli": "sql-injection",
    # Command Injection
    "command-injection": "command-injection",
    "command_injection": "command-injection",
    "command injection": "command-injection",
    "os-command-injection": "command-injection",
    "os_command_injection": "command-injection",
    "cmd-injection": "command-injection",
    # Code Injection / RCE
    "code-injection": "code-injection",
    "code_injection": "code-injection",
    "remote-code-execution": "code-injection",
    "remote_code_execution": "code-injection",
    "rce": "code-injection",
    "server_side_template_injection": "code-injection",
    "server-side template injection": "code-injection",
    "ssti": "code-injection",
    "template-injection": "code-injection",
    "template_injection": "code-injection",
    "workflow-code-execution": "code-injection",
    "workflow_code_execution": "code-injection",
    # Open Redirect
    "open-redirect": "open-redirect",
    "open_redirect": "open-redirect",
    "open redirect": "open-redirect",
    "url-redirect": "open-redirect",
    "url_redirect": "open-redirect",
    # Insecure Deserialization
    "insecure-deserialization": "insecure-deserialization",
    "insecure_deserialization": "insecure-deserialization",
    "deserialization": "insecure-deserialization",
    "unsafe-deserialization": "insecure-deserialization",
    # XXE
    "xxe": "xxe",
    "xml-injection": "xxe",
    "xml_injection": "xxe",
    "xml-external-entity": "xxe",
    "xml_external_entity": "xxe",
    # Prototype Pollution
    "prototype-pollution": "prototype-pollution",
    "prototype_pollution": "prototype-pollution",
    # DoS
    "dos": "dos",
    "regex-dos": "dos",
    "regex_dos": "dos",
    "redos": "dos",
    "denial-of-service": "dos",
    # Header Injection
    "header-injection": "header-injection",
    "header_injection": "header-injection",
    # Information Disclosure
    "information-disclosure": "information-disclosure",
    "information_disclosure": "information-disclosure",
    "info-disclosure": "information-disclosure",
    # LDAP
    "ldap-injection": "ldap-injection",
    "ldap_injection": "ldap-injection",
    # Log Injection
    "log-injection": "log-injection",
    "log_injection": "log-injection",
    "log-forging": "log-injection",
    # Access Control
    "idor": "idor",
    "insecure-direct-object-reference": "idor",
    "authorization-bypass": "authorization-bypass",
    "authorization_bypass": "authorization-bypass",
    "auth-bypass": "authorization-bypass",
    "authentication-bypass": "authentication-bypass",
    "privilege_escalation": "privilege-escalation",
    "privilege-escalation": "privilege-escalation",
    "improper-access-control": "improper-access-control",
    "improper_access_control": "improper-access-control",
    "access-control": "improper-access-control",
}


def normalize_vuln_type(vt: str) -> str:
    """Normalize vulnerability type string to a canonical form."""
    vt = vt.lower().strip()
    # Strip parenthetical suffixes like "Cross-Site Scripting (XSS)"
    vt = re.sub(r"\s*\(.*?\)\s*$", "", vt)
    vt = vt.strip("'\"")
    return _VULN_TYPE_ALIASES.get(vt, vt.replace("_", "-"))


# ---------------------------------------------------------------------------
# GT path point extraction
# ---------------------------------------------------------------------------

def _parse_location(location: str) -> tuple[str, int]:
    """Parse a 'file:line' location string into (file, line).

    Handles edge cases like Windows paths with drive letters (C:\...) or
    missing line numbers.
    """
    if not location:
        return "", 0
    # Split on the LAST colon to handle paths like "C:\foo\bar.py:42"
    idx = location.rfind(":")
    if idx <= 0:
        return location, 0
    file_part = location[:idx]
    line_part = location[idx + 1:]
    try:
        line = int(line_part)
    except ValueError:
        return location, 0
    return file_part, line


def build_gt_path_points(vuln_report: dict) -> list[PathPoint]:
    """Extract all GT path points from a vuln_report.json.

    Sources:
      1. Each finding's `source` field -> (file, line)
      2. Each finding's `sink` field -> (file, line)
      3. Each finding's `data_flow` array -> parse `location` as "file:line"

    Deduplicates by (normalized_file, line).
    """
    points = []
    seen = set()

    def _add(file: str, line: int):
        nf = normalize_path(file)
        if not nf or line <= 0:
            return
        key = (nf, line)
        if key not in seen:
            seen.add(key)
            points.append(PathPoint(file=nf, line=line))

    for finding in vuln_report.get("findings", []):
        # Source
        src = finding.get("source", {})
        if src:
            _add(src.get("file", ""), src.get("line", 0))

        # Sink
        sink = finding.get("sink", {})
        if sink:
            _add(sink.get("file", ""), sink.get("line", 0))

        # Data flow
        for step in finding.get("data_flow", []):
            loc = step.get("location", "")
            f, l = _parse_location(loc)
            _add(f, l)

    return points


# ---------------------------------------------------------------------------
# Core evaluation logic
# ---------------------------------------------------------------------------

def evaluate_sample(
    gt_path_points: list[PathPoint],
    actual_findings: list[dict],
    line_tolerance: int,
    gt_vuln_type: str,
) -> SampleResult:
    """Evaluate a single sample.

    For each actual finding's sink, check if it lands on any GT path point
    within ±line_tolerance lines.  If ANY finding's sink hits -> HIT.

    Returns a partially filled SampleResult (caller fills sample_name etc.).
    """
    result = SampleResult(sample_name="", language="", vuln_type=gt_vuln_type)
    result.gt_path_points = gt_path_points

    if not actual_findings:
        result.detail = "EMPTY FINDINGS"
        return result

    result.has_findings = True
    result.num_findings = len(actual_findings)

    gt_type_norm = normalize_vuln_type(gt_vuln_type)

    best_distance = None

    for finding in actual_findings:
        # Extract sink from actual finding
        sink = finding.get("sink", {})
        act_file = normalize_path(sink.get("file", ""))
        act_line = sink.get("line", 0)

        if not act_file or act_line <= 0:
            continue

        # Check vuln type match (auxiliary)
        act_type_raw = finding.get("vulnerability_type", finding.get("type", ""))
        act_type_norm = normalize_vuln_type(act_type_raw)

        # Check against all GT path points
        for gp in gt_path_points:
            # Exact file match
            if act_file != gp.file:
                continue

            dist = abs(act_line - gp.line)
            if dist <= line_tolerance:
                # HIT!
                if best_distance is None or dist < best_distance:
                    best_distance = dist
                    result.hit = True
                    result.matched_gt_point = gp
                    result.matched_finding_sink_file = act_file
                    result.matched_finding_sink_line = act_line
                    result.matched_line_distance = dist
                    result.actual_vuln_type = act_type_raw
                    result.vuln_type_match = (gt_type_norm == act_type_norm)

    if result.hit:
        parts = []
        if result.vuln_type_match:
            parts.append(f"Type: \u2713 {gt_type_norm}")
        else:
            parts.append(f"Type: {gt_vuln_type}\u2192{result.actual_vuln_type}")
        parts.append(f"File: \u2713 {result.matched_finding_sink_file}")
        parts.append(f"Line: \u2713 \u0394{result.matched_line_distance}")
        result.detail = " | ".join(parts)
    else:
        # Find closest miss for diagnostics
        closest_file_miss = None
        closest_line_dist = None
        for finding in actual_findings:
            sink = finding.get("sink", {})
            af = normalize_path(sink.get("file", ""))
            al = sink.get("line", 0)
            if not af:
                continue
            for gp in gt_path_points:
                if af == gp.file:
                    d = abs(al - gp.line)
                    if closest_line_dist is None or d < closest_line_dist:
                        closest_line_dist = d
                        closest_file_miss = af
            if closest_file_miss is None:
                # Track file-level miss
                act_type_raw = finding.get("vulnerability_type", finding.get("type", ""))
                result.actual_vuln_type = act_type_raw

        if closest_line_dist is not None:
            result.detail = f"MISS (file match but line \u0394{closest_line_dist} > {line_tolerance})"
            result.issues.append(f"closest_line_distance={closest_line_dist}")
        else:
            # No file match at all
            act_files = set()
            for f in actual_findings:
                sf = normalize_path(f.get("sink", {}).get("file", ""))
                if sf:
                    act_files.add(sf)
            gt_files = set(gp.file for gp in gt_path_points)
            result.detail = f"MISS (no file match: actual={act_files}, gt={gt_files})"
            result.issues.append("no_file_match")

    return result


# ---------------------------------------------------------------------------
# Sample discovery & workspace resolution
# ---------------------------------------------------------------------------

def discover_samples_from_batch_log(batch_log_dir: Path) -> dict[str, str]:
    """Discover samples and their status from batch log directory.

    Returns {sample_name: status} where status is "PASS", "FAIL", or "UNKNOWN".
    """
    samples = {}

    # Try summary.log first
    summary_file = batch_log_dir / "summary.log"
    if summary_file.exists():
        with open(summary_file) as f:
            for line in f:
                line = line.strip()
                m = re.match(r"^\s*([\w-]+-sast-CVE-[\w-]+)\s+(PASS|FAIL)\s*$", line)
                if m:
                    samples[m.group(1)] = m.group(2)
        if samples:
            return samples

    # Fall back to individual log files
    for lf in sorted(batch_log_dir.glob("*.log")):
        sample_name = lf.stem
        if not re.match(r"^[\w-]+-sast-CVE-", sample_name):
            continue
        content = lf.read_text(errors="replace")
        if '"overall_status":"PASS"' in content or re.search(r"Status:.*PASS", content):
            samples[sample_name] = "PASS"
        elif '"overall_status":"FAIL"' in content or re.search(r"Status:.*FAIL", content):
            samples[sample_name] = "FAIL"
        else:
            samples[sample_name] = "UNKNOWN"

    return samples


def discover_samples_from_examples(examples_dir: Path) -> dict[str, str]:
    """Discover samples from examples directory (all treated as candidates)."""
    samples = {}
    for f in sorted(examples_dir.glob("*.json")):
        sample_name = f.stem
        samples[sample_name] = "CANDIDATE"
    return samples


def find_workspace_for_sample(
    sample_name: str,
    workspaces_dir: Path,
    examples_dir: Optional[Path] = None,
    batch_date_hint: str = "",
) -> Optional[Path]:
    """Find the workspace directory for a sample.

    Strategy:
      1. Read meta.json from fixture to get vulnerable_ref.
      2. Optionally read example JSON for target URL parsing.
      3. Search workspaces_dir for matching directories.
    """
    fixture_dir = FIXTURES_DIR / sample_name
    meta_file = fixture_dir / "meta.json"

    if not meta_file.exists():
        return None

    with open(meta_file) as f:
        meta = json.load(f)

    ref = meta.get("vulnerable_ref", "")
    if not ref:
        return None

    # Find workspace dirs containing this ref
    candidates = []
    for d in workspaces_dir.iterdir():
        if not d.is_dir():
            continue
        if ref in d.name:
            if batch_date_hint and batch_date_hint not in d.name:
                continue
            candidates.append(d)

    if not candidates:
        # Try short ref prefix
        short_ref = ref[:12]
        for d in workspaces_dir.iterdir():
            if not d.is_dir():
                continue
            if short_ref in d.name:
                if batch_date_hint and batch_date_hint not in d.name:
                    continue
                candidates.append(d)

    if not candidates:
        return None

    # Return the latest one
    candidates.sort(key=lambda x: x.name)
    return candidates[-1]


def is_excluded_fixture(sample_name: str) -> tuple[bool, str]:
    """Check if fixture is marked as excluded in meta.json."""
    meta_path = FIXTURES_DIR / sample_name / "meta.json"
    if not meta_path.exists():
        return False, ""
    with open(meta_path, encoding="utf-8") as f:
        meta = json.load(f)
    if meta.get("excluded", False):
        return True, meta.get("exclude_reason", "excluded in meta.json")
    return False, ""


def load_gt(sample_name: str) -> tuple[Optional[dict], str]:
    """Load ground truth vuln_report.json for a sample.

    Returns (report_dict, vuln_type) or (None, "").
    """
    report_path = FIXTURES_DIR / sample_name / "expected" / "vuln_report.json"
    if not report_path.exists():
        return None, ""

    with open(report_path) as f:
        report = json.load(f)

    # Get vuln_type from meta.json
    meta_path = FIXTURES_DIR / sample_name / "meta.json"
    vuln_type = ""
    if meta_path.exists():
        with open(meta_path) as f:
            meta = json.load(f)
        vuln_type = meta.get("vuln_type", "")

    return report, vuln_type


def load_actual_findings(workspace_dir: Path) -> Optional[list[dict]]:
    """Load actual findings from vulnsage_results.json."""
    results_file = workspace_dir / "vulnsage_results.json"
    if not results_file.exists():
        return None

    with open(results_file) as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return None

    return data.get("findings", [])


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def _lang_from_sample(name: str) -> str:
    parts = name.split("-sast-")
    return parts[0] if len(parts) >= 2 else "unknown"


def print_table(results: list[SampleResult], line_tolerance: int):
    """Print results as a terminal table."""
    header = (
        f"{'#':>3} | {'Sample':<42} | {'HIT':^5} | {'Type':^5} | "
        f"{'\u0394':>5} | {'Findings':>8} | Detail"
    )
    print(header)
    print("-" * (len(header) + 40))

    for i, r in enumerate(results, 1):
        if r.excluded:
            print(f"{i:>3} | {r.sample_name:<42} | {'-':^5} | {'-':^5} | "
                  f"{'':>5} | {'':>8} | EXCLUDED: {r.exclude_reason}")
            continue

        hit_sym = "\u2713" if r.hit else "\u2717"
        type_sym = "\u2713" if r.vuln_type_match else "\u2717"
        dist_str = str(r.matched_line_distance) if r.matched_line_distance is not None else "-"
        findings_str = str(r.num_findings) if r.has_results_file else "N/A"

        if not r.has_results_file:
            detail = "NO RESULTS FILE"
        else:
            detail = r.detail

        print(f"{i:>3} | {r.sample_name:<42} | {hit_sym:^5} | {type_sym:^5} | "
              f"{dist_str:>5} | {findings_str:>8} | {detail}")


def print_summary(results: list[SampleResult], line_tolerance: int):
    """Print summary statistics."""
    effective = [r for r in results if not r.excluded]
    total = len(effective)
    if total == 0:
        print("No effective samples to evaluate.")
        return

    has_results = sum(1 for r in effective if r.has_results_file)
    has_findings = sum(1 for r in effective if r.has_findings)
    hit_count = sum(1 for r in effective if r.hit)
    type_match = sum(1 for r in effective if r.vuln_type_match)
    excluded_count = sum(1 for r in results if r.excluded)

    print()
    print("=" * 70)
    print("  SUMMARY")
    print("=" * 70)
    print(f"  Total samples:              {len(results)}")
    print(f"  Excluded:                   {excluded_count}")
    print(f"  Effective:                  {total}")
    print(f"  Has results file:           {has_results}/{total}")
    print(f"  Has non-empty findings:     {has_findings}/{total}")
    print(f"  HIT (path match \u00b1{line_tolerance}):      {hit_count}/{total} "
          f"({100 * hit_count / total:.1f}%)")
    print(f"  Vuln type also matched:     {type_match}/{total} "
          f"({100 * type_match / total:.1f}%)")
    print()

    # By language
    print("  BY LANGUAGE:")
    lang_groups: dict[str, list[SampleResult]] = {}
    for r in effective:
        lang = r.language
        lang_groups.setdefault(lang, []).append(r)

    for lang in sorted(lang_groups.keys()):
        group = lang_groups[lang]
        g_total = len(group)
        g_hit = sum(1 for r in group if r.hit)
        rate = 100 * g_hit / g_total if g_total > 0 else 0
        print(f"    {lang:<10}  {g_hit}/{g_total} ({rate:.1f}%)")

    # By vuln type
    print()
    print("  BY VULN TYPE:")
    type_groups: dict[str, list[SampleResult]] = {}
    for r in effective:
        vt = r.vuln_type or "unknown"
        type_groups.setdefault(vt, []).append(r)

    for vt in sorted(type_groups.keys()):
        group = type_groups[vt]
        g_total = len(group)
        g_hit = sum(1 for r in group if r.hit)
        rate = 100 * g_hit / g_total if g_total > 0 else 0
        print(f"    {vt:<25}  {g_hit}/{g_total} ({rate:.1f}%)")

    print()


def export_csv(results: list[SampleResult], output_path: Path):
    """Export results to CSV."""
    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "sample_name", "language", "vuln_type", "excluded",
            "has_results_file", "has_findings", "num_findings",
            "hit", "vuln_type_match",
            "matched_gt_file", "matched_gt_line",
            "matched_sink_file", "matched_sink_line", "line_distance",
            "actual_vuln_type", "workspace_dir",
            "gt_path_points_count", "detail", "issues",
        ])
        for r in results:
            writer.writerow([
                r.sample_name, r.language, r.vuln_type, r.excluded,
                r.has_results_file, r.has_findings, r.num_findings,
                r.hit, r.vuln_type_match,
                r.matched_gt_point.file if r.matched_gt_point else "",
                r.matched_gt_point.line if r.matched_gt_point else "",
                r.matched_finding_sink_file, r.matched_finding_sink_line,
                r.matched_line_distance if r.matched_line_distance is not None else "",
                r.actual_vuln_type, r.workspace_dir,
                len(r.gt_path_points), r.detail,
                "; ".join(r.issues),
            ])
    print(f"  CSV saved: {output_path}")


def export_markdown(results: list[SampleResult], line_tolerance: int, output_path: Path):
    """Export results to Markdown report."""
    effective = [r for r in results if not r.excluded]
    total = len(effective)
    hit_count = sum(1 for r in effective if r.hit)

    with open(output_path, "w") as f:
        f.write("# VulnSage Benchmark Evaluation Report\n\n")
        f.write(f"**Line tolerance**: \u00b1{line_tolerance}\n")
        f.write(f"**Total effective samples**: {total}\n")
        f.write(f"**HIT rate**: {hit_count}/{total} "
                f"({100 * hit_count / total:.1f}%)\n\n" if total > 0 else "")

        # Summary table
        f.write("## Summary\n\n")
        f.write("| Metric | Count | Rate |\n")
        f.write("|--------|-------|------|\n")
        has_results = sum(1 for r in effective if r.has_results_file)
        has_findings = sum(1 for r in effective if r.has_findings)
        type_match = sum(1 for r in effective if r.vuln_type_match)
        if total > 0:
            f.write(f"| Has results file | {has_results}/{total} | "
                    f"{100 * has_results / total:.1f}% |\n")
            f.write(f"| Has non-empty findings | {has_findings}/{total} | "
                    f"{100 * has_findings / total:.1f}% |\n")
            f.write(f"| **HIT (path match)** | **{hit_count}/{total}** | "
                    f"**{100 * hit_count / total:.1f}%** |\n")
            f.write(f"| Vuln type also matched | {type_match}/{total} | "
                    f"{100 * type_match / total:.1f}% |\n\n")

        # By language
        f.write("## By Language\n\n")
        f.write("| Language | Total | HIT | Rate |\n")
        f.write("|----------|-------|-----|------|\n")
        lang_groups: dict[str, list[SampleResult]] = {}
        for r in effective:
            lang_groups.setdefault(r.language, []).append(r)
        for lang in sorted(lang_groups.keys()):
            group = lang_groups[lang]
            g_total = len(group)
            g_hit = sum(1 for r in group if r.hit)
            rate = 100 * g_hit / g_total if g_total > 0 else 0
            f.write(f"| {lang} | {g_total} | {g_hit} | {rate:.1f}% |\n")

        # Detailed results
        f.write("\n## Detailed Results\n\n")
        f.write("| # | Sample | HIT | Type | \u0394 | Detail |\n")
        f.write("|---|--------|-----|------|---|--------|\n")
        for i, r in enumerate(results, 1):
            if r.excluded:
                f.write(f"| {i} | {r.sample_name} | - | - | - | EXCLUDED |\n")
                continue
            hit_sym = "\u2713" if r.hit else "\u2717"
            type_sym = "\u2713" if r.vuln_type_match else "\u2717"
            dist_str = str(r.matched_line_distance) if r.matched_line_distance is not None else "-"
            detail = r.detail.replace("|", "\\|") if r.has_results_file else "NO RESULTS"
            f.write(f"| {i} | {r.sample_name} | {hit_sym} | {type_sym} | "
                    f"{dist_str} | {detail} |\n")

        # MISS analysis
        misses = [r for r in effective if not r.hit and r.has_results_file]
        if misses:
            f.write(f"\n## MISS Analysis ({len(misses)} samples)\n\n")
            for r in misses:
                f.write(f"### {r.sample_name}\n\n")
                f.write(f"- **Language**: {r.language}\n")
                f.write(f"- **GT vuln type**: {r.vuln_type}\n")
                f.write(f"- **GT path points**: {len(r.gt_path_points)}\n")
                for gp in r.gt_path_points:
                    f.write(f"  - `{gp.file}:{gp.line}`\n")
                f.write(f"- **Detail**: {r.detail}\n")
                f.write(f"- **Issues**: {', '.join(r.issues)}\n\n")

    print(f"  Markdown saved: {output_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="VulnSage Benchmark Evaluation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--workspace-dir", required=True,
        help="Path to the workspaces directory containing auditor output",
    )
    parser.add_argument(
        "--batch-log-dir",
        help="Path to batch log directory (contains summary.log or per-sample .log files)",
    )
    parser.add_argument(
        "--examples-dir",
        help="Path to examples directory (alternative to --batch-log-dir for sample discovery)",
    )
    parser.add_argument(
        "--line-tolerance", type=int, default=DEFAULT_LINE_TOLERANCE,
        help=f"Line offset tolerance for path point matching (default: {DEFAULT_LINE_TOLERANCE})",
    )
    parser.add_argument(
        "--output-dir", default="reports",
        help="Directory for output reports (default: reports/)",
    )
    parser.add_argument(
        "--format", choices=["table", "csv", "markdown", "all"], default="table",
        help="Output format (default: table)",
    )
    parser.add_argument(
        "--batch-date-hint",
        help="Date hint for workspace matching, e.g., '20260429' (narrows workspace search)",
    )
    parser.add_argument(
        "--status-filter", choices=["PASS", "FAIL", "ALL"], default="PASS",
        help="Filter samples by status (default: PASS, only evaluate PASS samples)",
    )

    args = parser.parse_args()

    workspace_dir = Path(args.workspace_dir)
    if not workspace_dir.exists():
        print(f"ERROR: Workspace directory not found: {workspace_dir}", file=sys.stderr)
        sys.exit(1)

    # Discover samples
    samples: dict[str, str] = {}
    if args.batch_log_dir:
        batch_log_dir = Path(args.batch_log_dir)
        if not batch_log_dir.exists():
            print(f"ERROR: Batch log directory not found: {batch_log_dir}", file=sys.stderr)
            sys.exit(1)
        samples = discover_samples_from_batch_log(batch_log_dir)
    elif args.examples_dir:
        examples_dir = Path(args.examples_dir)
        if not examples_dir.exists():
            print(f"ERROR: Examples directory not found: {examples_dir}", file=sys.stderr)
            sys.exit(1)
        samples = discover_samples_from_examples(examples_dir)
    else:
        # Default: use benchmark's own examples dir
        default_examples = BENCHMARK_DIR / "examples"
        if default_examples.exists():
            samples = discover_samples_from_examples(default_examples)
        else:
            print("ERROR: Must specify --batch-log-dir or --examples-dir", file=sys.stderr)
            sys.exit(1)

    if not samples:
        print("ERROR: No samples found", file=sys.stderr)
        sys.exit(1)

    # Filter by status
    if args.status_filter != "ALL":
        if args.batch_log_dir:
            samples = {k: v for k, v in samples.items() if v == args.status_filter}

    print("=" * 70)
    print(f"  VulnSage Benchmark Evaluation")
    print("=" * 70)
    print(f"  Samples discovered:  {len(samples)}")
    print(f"  Line tolerance:      \u00b1{args.line_tolerance}")
    print(f"  Workspace dir:       {workspace_dir}")
    print()

    # Evaluate each sample
    results: list[SampleResult] = []
    examples_path = Path(args.examples_dir) if args.examples_dir else None

    for sample_name in sorted(samples.keys()):
        lang = _lang_from_sample(sample_name)

        # Check exclusion
        excluded, reason = is_excluded_fixture(sample_name)
        if excluded:
            r = SampleResult(
                sample_name=sample_name, language=lang, vuln_type="",
                excluded=True, exclude_reason=reason,
            )
            results.append(r)
            continue

        # Load GT
        gt_report, vuln_type = load_gt(sample_name)
        if gt_report is None:
            r = SampleResult(
                sample_name=sample_name, language=lang, vuln_type="",
                detail="NO GROUND TRUTH",
            )
            r.issues.append("no_ground_truth")
            results.append(r)
            continue

        gt_points = build_gt_path_points(gt_report)

        # Find workspace
        ws = find_workspace_for_sample(
            sample_name, workspace_dir,
            examples_dir=examples_path,
            batch_date_hint=args.batch_date_hint or "",
        )

        if ws is None:
            r = SampleResult(
                sample_name=sample_name, language=lang, vuln_type=vuln_type,
                gt_path_points=gt_points,
                detail="NO WORKSPACE FOUND",
            )
            r.issues.append("no_workspace")
            results.append(r)
            continue

        # Load actual findings
        actual = load_actual_findings(ws)
        if actual is None:
            r = SampleResult(
                sample_name=sample_name, language=lang, vuln_type=vuln_type,
                gt_path_points=gt_points, workspace_dir=ws.name,
                detail="NO RESULTS FILE",
            )
            r.issues.append("no_results_file")
            results.append(r)
            continue

        # Evaluate
        r = evaluate_sample(gt_points, actual, args.line_tolerance, vuln_type)
        r.sample_name = sample_name
        r.language = lang
        r.has_results_file = True
        r.workspace_dir = ws.name
        results.append(r)

    # Output
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    fmt = args.format

    if fmt in ("table", "all"):
        print_table(results, args.line_tolerance)
        print_summary(results, args.line_tolerance)

    if fmt in ("csv", "all"):
        csv_path = output_dir / "evaluation_results.csv"
        export_csv(results, csv_path)

    if fmt in ("markdown", "all"):
        md_path = output_dir / "evaluation_report.md"
        export_markdown(results, args.line_tolerance, md_path)

    # Print final hit rate
    effective = [r for r in results if not r.excluded]
    if effective:
        hit_count = sum(1 for r in effective if r.hit)
        total = len(effective)
        print(f"\n  >>> HIT RATE: {hit_count}/{total} ({100 * hit_count / total:.1f}%) <<<")
    print()


if __name__ == "__main__":
    main()
