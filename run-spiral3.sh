#!/usr/bin/env bash
# ============================================================================
# VulnSage Benchmark — Spiral 3: Run 16 CVEs (Stage 1 + Stage 2)
# Skips CVEs that already have valid output from previous spirals
# ============================================================================
set -uo pipefail
# Note: NOT using set -e because bash arithmetic ((var++)) returns exit 1
# when incrementing from 0, which would kill the script.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FIXTURES_DIR="${SCRIPT_DIR}/fixtures"
REPORT_FILE="${SCRIPT_DIR}/reports/spiral3_$(date +%Y%m%d_%H%M%S).md"
mkdir -p "${SCRIPT_DIR}/reports"

# Spiral 3 CVE list (16 CVEs: 4 per language, 1 per category)
CVES=(
  "python-lib-CVE-2024-36039"
  "python-cli-CVE-2020-14343"
  "python-service-CVE-2023-24329"
  "python-webapp-CVE-2024-27351"
  "js-lib-CVE-2019-11358"
  "js-cli-CVE-2021-3807"
  "js-service-CVE-2022-24999"
  "js-webapp-CVE-2022-29078"
  "java-lib-CVE-2022-1471"
  "java-cli-CVE-2022-25857"
  "java-service-CVE-2019-17571"
  "java-webapp-CVE-2020-17530"
  "go-lib-CVE-2023-44487"
  "go-cli-CVE-2022-29526"
  "go-service-CVE-2023-39325"
  "go-webapp-CVE-2023-24538"
)

TOTAL=${#CVES[@]}
PASS=0
FAIL=0
SKIP=0

echo "# Spiral 3 Benchmark Report" > "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "Start: $(date)" >> "$REPORT_FILE"
echo "Total CVEs: ${TOTAL}" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "| # | CVE | Stage 1 | Stage 2 | Time | Notes |" >> "$REPORT_FILE"
echo "|---|-----|---------|---------|------|-------|" >> "$REPORT_FILE"

run_cve() {
  local fixture_name="$1"
  local idx="$2"
  local fixture_dir="${FIXTURES_DIR}/${fixture_name}"
  local workspace="${fixture_dir}/workspace"
  local source_dir="${workspace}/source"
  local pi_file="${workspace}/product_identification.json"
  local vr_file="${workspace}/vulnsage_results.json"

  echo ""
  echo "========================================"
  echo "[${idx}/${TOTAL}] ${fixture_name}"
  echo "========================================"

  # Check if source exists
  if [[ ! -d "${source_dir}" ]]; then
    echo "SKIP: No source directory"
    echo "| ${idx} | ${fixture_name} | SKIP | SKIP | - | No source |" >> "$REPORT_FILE"
    ((SKIP++))
    return
  fi

  # Read meta
  local cve_id vuln_type
  cve_id=$(jq -r '.cve_id // "unknown"' "${fixture_dir}/meta.json")
  vuln_type=$(jq -r '.vuln_type // "unknown"' "${fixture_dir}/meta.json")

  local start_ts=$(date +%s)

  # --- Check if Stage 1 already done (REAL run only, not fallback) ---
  local s1_status="SKIP"
  local s1_log="${workspace}/stage1_cursor_output.log"
  if [[ -f "${pi_file}" ]] && [[ -f "${s1_log}" ]] && jq -e '.A_language and .B_category' "${pi_file}" &>/dev/null; then
    echo "Stage 1: Already has valid REAL output (cursor log exists), skipping"
    s1_status="PASS(cached)"
  else
    echo "Stage 1: Running Cursor Agent..."
    rm -f "${pi_file}" "${workspace}/stage1_cursor_output.log"

    cursor agent --print --approve-mcps --trust \
      --workspace "${workspace}" \
      "Analyze the source code at ${source_dir} and produce a product identification JSON file.

You MUST create a file called ${pi_file} with the following structure:
{
  \"pipeline_id\": \"pid-XXXXXXXX\",
  \"A_language\": { \"primary\": \"<detected language>\", \"confidence\": 0.95, \"evidence\": [...] },
  \"B_category\": { \"type\": \"<webapp|service|cli|library>\", \"confidence\": 0.95, \"evidence\": [...] },
  \"C_entry_points\": [{ \"kind\": \"...\", \"symbol\": \"...\", \"location\": \"...\", \"description\": \"...\" }],
  \"D_build\": { \"system\": \"...\", \"commands\": {...}, \"dependencies\": [...] },
  \"E_security_profile\": { \"vuln_classes\": [...] }
}

Analyze the project structure, build config files, and source code to fill in real values.
The file MUST be written to disk as valid JSON." \
      > "${workspace}/stage1_cursor_output.log" 2>&1 || true

    if [[ -f "${pi_file}" ]] && jq -e '.A_language' "${pi_file}" &>/dev/null; then
      s1_status="PASS"
      echo "Stage 1: SUCCESS"
    else
      # Search workspace
      local found=$(find "${workspace}" -name "product_identification.json" -not -path "*/expected/*" 2>/dev/null | head -1)
      if [[ -n "$found" && "$found" != "${pi_file}" ]]; then
        cp "$found" "${pi_file}"
        s1_status="PASS"
        echo "Stage 1: SUCCESS (found at ${found})"
      else
        s1_status="FAIL"
        echo "Stage 1: FAILED"
      fi
    fi
  fi

  # --- Stage 2 ---
  local s2_status="SKIP"
  if [[ "${s1_status}" == *"FAIL"* ]]; then
    s2_status="SKIP(s1 failed)"
    echo "Stage 2: Skipped (Stage 1 failed)"
  elif [[ -f "${vr_file}" ]] && [[ -f "${workspace}/stage2_cursor_output.log" ]] && jq -e '.findings' "${vr_file}" &>/dev/null; then
    echo "Stage 2: Already has valid REAL output (cursor log exists), skipping"
    s2_status="PASS(cached)"
  else
    echo "Stage 2: Running Cursor Agent..."
    rm -f "${vr_file}" "${workspace}/stage2_cursor_output.log"

    cursor agent --print --approve-mcps --trust \
      --workspace "${workspace}" \
      "Perform a vulnerability analysis on the source code.

Read the product identification from ${pi_file} to understand the project.
The source code is at ${source_dir}/.

You are looking for ${cve_id}, a ${vuln_type} vulnerability.

Analyze the source code for security vulnerabilities, focusing on data-flow paths from sources (user inputs) to sinks (dangerous operations).

You MUST create a file called ${vr_file} with the following structure:
{
  \"pipeline_id\": \"pid-XXXXXXXX\",
  \"findings\": [
    {
      \"id\": \"F001\",
      \"vulnerability_type\": \"${vuln_type}\",
      \"severity\": \"high\",
      \"confidence\": \"confirmed\",
      \"title\": \"<descriptive title>\",
      \"description\": \"<detailed description>\",
      \"source\": { \"file\": \"...\", \"line\": 0, \"function\": \"...\" },
      \"sink\": { \"file\": \"...\", \"line\": 0, \"function\": \"...\" },
      \"data_flow_trace\": [ \"step1\", \"step2\", \"...\" ],
      \"remediation\": \"<how to fix>\"
    }
  ],
  \"stats\": { \"files_analyzed\": 0, \"paths_checked\": 0 }
}

Focus on finding the actual vulnerable code paths. The file MUST be written to disk as valid JSON." \
      > "${workspace}/stage2_cursor_output.log" 2>&1 || true

    if [[ -f "${vr_file}" ]] && jq -e '.findings' "${vr_file}" &>/dev/null; then
      s2_status="PASS"
      local count=$(jq '.findings | length' "${vr_file}")
      echo "Stage 2: SUCCESS (${count} findings)"
    else
      local found=$(find "${workspace}" -name "vulnsage_results.json" -not -path "*/expected/*" 2>/dev/null | head -1)
      if [[ -n "$found" && "$found" != "${vr_file}" ]]; then
        cp "$found" "${vr_file}"
        s2_status="PASS"
        echo "Stage 2: SUCCESS (found at ${found})"
      else
        s2_status="FAIL"
        echo "Stage 2: FAILED"
      fi
    fi
  fi

  local end_ts=$(date +%s)
  local elapsed=$(( end_ts - start_ts ))

  # Count results
  if [[ "${s1_status}" == *"PASS"* && "${s2_status}" == *"PASS"* ]]; then
    ((PASS++))
  elif [[ "${s1_status}" == *"SKIP"* || "${s2_status}" == *"SKIP"* ]]; then
    ((SKIP++))
  else
    ((FAIL++))
  fi

  echo "| ${idx} | ${fixture_name} | ${s1_status} | ${s2_status} | ${elapsed}s | |" >> "$REPORT_FILE"
}

# Run all CVEs
for i in "${!CVES[@]}"; do
  run_cve "${CVES[$i]}" "$((i+1))"
done

# Summary
echo "" >> "$REPORT_FILE"
echo "## Summary" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "- **PASS**: ${PASS}/${TOTAL}" >> "$REPORT_FILE"
echo "- **FAIL**: ${FAIL}/${TOTAL}" >> "$REPORT_FILE"
echo "- **SKIP**: ${SKIP}/${TOTAL}" >> "$REPORT_FILE"
echo "- **End**: $(date)" >> "$REPORT_FILE"

echo ""
echo "========================================"
echo "SPIRAL 3 COMPLETE"
echo "PASS: ${PASS}/${TOTAL}"
echo "FAIL: ${FAIL}/${TOTAL}"
echo "SKIP: ${SKIP}/${TOTAL}"
echo "Report: ${REPORT_FILE}"
echo "========================================"
