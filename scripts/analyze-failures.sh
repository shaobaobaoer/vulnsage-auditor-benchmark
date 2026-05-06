#!/usr/bin/env bash
# ============================================================================
# VulnSage Failure Analysis Script
#
# Analyzes batch test results and generates a comprehensive failure report.
#
# Usage:
#   ./scripts/analyze-failures.sh <batch-log-dir> <workspaces-dir> [output-dir]
#
# Example:
#   ./scripts/analyze-failures.sh \
#       ../vulnsage-auditor-cursor-orchestrator/logs/batch/20260428_200639 \
#       ../vulnsage-auditor-cursor-orchestrator/workspaces \
#       reports/
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
BENCHMARK_DIR="$(dirname "$SCRIPT_DIR")"
FIXTURES_DIR="${BENCHMARK_DIR}/fixtures"

# ---- Arguments ----
BATCH_LOG_DIR="${1:?Usage: analyze-failures.sh <batch-log-dir> <workspaces-dir> [output-dir]}"
WORKSPACES_DIR="${2:?Usage: analyze-failures.sh <batch-log-dir> <workspaces-dir> [output-dir]}"
OUTPUT_DIR="${3:-${BENCHMARK_DIR}/reports}"

# Resolve to absolute paths
if [[ ! "$BATCH_LOG_DIR" = /* ]]; then
  BATCH_LOG_DIR="$(cd "$BATCH_LOG_DIR" && pwd)"
fi
if [[ ! "$WORKSPACES_DIR" = /* ]]; then
  WORKSPACES_DIR="$(cd "$WORKSPACES_DIR" && pwd)"
fi
mkdir -p "$OUTPUT_DIR"

SUMMARY_FILE="${BATCH_LOG_DIR}/summary.log"

REPORT_FILE="${OUTPUT_DIR}/failure_analysis_$(date +%Y%m%d_%H%M%S).md"
CSV_FILE="${OUTPUT_DIR}/failure_analysis_$(date +%Y%m%d_%H%M%S).csv"

# ---- Collect failed tasks from summary ----
echo "Analyzing batch results from: ${BATCH_LOG_DIR}"
echo "Workspaces directory:         ${WORKSPACES_DIR}"
echo ""

FAIL_TASKS=()
while IFS= read -r line; do
  task_name="$(echo "$line" | awk '{print $1}')"
  status="$(echo "$line" | awk '{print $NF}')"
  if [[ "$status" == "FAIL" ]]; then
    FAIL_TASKS+=("$task_name")
  fi
done < <(grep -E '^\s+\S+-sast-CVE-' "$SUMMARY_FILE" || true)

TOTAL_FAIL=${#FAIL_TASKS[@]}
echo "Found ${TOTAL_FAIL} failed tasks"
echo ""

# ---- CSV Header ----
echo "sample_name,language,vuln_type,cve_id,project,failure_mode,stage2_tool_calls,has_pi_json,has_results_json,expected_vuln_title,expected_severity,workspace_dir" > "$CSV_FILE"

# ---- Markdown Header ----
cat > "$REPORT_FILE" << 'EOF'
# VulnSage Failure Analysis Report

## Overview
EOF

echo "" >> "$REPORT_FILE"
echo "- **Batch**: $(basename "$BATCH_LOG_DIR")" >> "$REPORT_FILE"
echo "- **Total Failed**: ${TOTAL_FAIL}" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# ---- Statistics counters ----
declare -A FAIL_MODE_COUNT
declare -A VULN_TYPE_COUNT
declare -A LANG_COUNT

FAIL_MODE_COUNT["output_not_produced"]=0
FAIL_MODE_COUNT["empty_findings"]=0
FAIL_MODE_COUNT["agent_exit_error"]=0
FAIL_MODE_COUNT["other"]=0

# ---- Analyze each failed task ----
echo "## Detailed Failure Analysis" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "| # | Sample | Lang | Vuln Type | Failure Mode | Stage2 Tools | Has PI | Has Results | Expected Title |" >> "$REPORT_FILE"
echo "|---|--------|------|-----------|-------------|--------------|--------|-------------|----------------|" >> "$REPORT_FILE"

idx=0
for task_name in "${FAIL_TASKS[@]}"; do
  idx=$((idx + 1))
  task_log="${BATCH_LOG_DIR}/${task_name}.log"

  # Extract language from task name
  lang=""
  case "$task_name" in
    go-sast-*)     lang="go" ;;
    java-sast-*)   lang="java" ;;
    js-sast-*)     lang="js" ;;
    python-sast-*) lang="python" ;;
  esac
  LANG_COUNT["$lang"]=$(( ${LANG_COUNT["$lang"]:-0} + 1 ))

  # Read meta.json from fixture
  meta_file="${FIXTURES_DIR}/${task_name}/meta.json"
  vuln_type=""
  cve_id=""
  project=""
  if [[ -f "$meta_file" ]]; then
    vuln_type="$(jq -r '.vuln_type // "unknown"' "$meta_file" 2>/dev/null || echo "unknown")"
    cve_id="$(jq -r '.cve_id // "unknown"' "$meta_file" 2>/dev/null || echo "unknown")"
    project="$(jq -r '.project // "unknown"' "$meta_file" 2>/dev/null || echo "unknown")"
  fi
  VULN_TYPE_COUNT["$vuln_type"]=$(( ${VULN_TYPE_COUNT["$vuln_type"]:-0} + 1 ))

  # Read expected vuln report
  expected_file="${FIXTURES_DIR}/${task_name}/expected/vuln_report.json"
  expected_title=""
  expected_severity=""
  if [[ -f "$expected_file" ]]; then
    expected_title="$(jq -r '.findings[0].title // "N/A"' "$expected_file" 2>/dev/null || echo "N/A")"
    expected_severity="$(jq -r '.findings[0].severity // "N/A"' "$expected_file" 2>/dev/null || echo "N/A")"
  fi

  # Determine failure mode from log
  failure_mode="other"
  stage2_tool_calls="N/A"

  if [[ -f "$task_log" ]]; then
    # Check for specific failure patterns
    if grep -q 'Output file not produced' "$task_log" 2>/dev/null; then
      failure_mode="output_not_produced"
    elif grep -q 'Output has empty findings' "$task_log" 2>/dev/null; then
      failure_mode="empty_findings"
    elif grep -qE 'Cursor Agent exited with code|Cursor agent failed|Claude agent failed|exit code.*[1-9]' "$task_log" 2>/dev/null; then
      failure_mode="agent_exit_error"
    elif grep -qE 'stage1.*FAIL|Stage 1.*FAIL' "$task_log" 2>/dev/null; then
      failure_mode="stage1_fail"
    fi

    # Extract stage2 tool calls count
    stage2_tool_calls="$(grep -oE '[0-9]+ tool calls' "$task_log" | tail -1 | grep -oE '[0-9]+' || echo "N/A")"
  fi
  FAIL_MODE_COUNT["$failure_mode"]=$(( ${FAIL_MODE_COUNT["$failure_mode"]:-0} + 1 ))

  # Find workspace directory for this task
  workspace_dir=""
  has_pi_json="no"
  has_results_json="no"

  # Try to find workspace by matching pipeline log patterns in the task log
  if [[ -f "$task_log" ]]; then
    ws_match="$(grep -oE 'workspaces/[^ /]+' "$task_log" | head -1 || echo "")"
    if [[ -n "$ws_match" ]]; then
      workspace_dir="${WORKSPACES_DIR}/$(basename "$ws_match")"
      if [[ -f "${workspace_dir}/product_identification.json" ]]; then
        has_pi_json="yes"
      fi
      if [[ -f "${workspace_dir}/vulnsage_results.json" ]]; then
        has_results_json="yes"
      fi
    fi
  fi

  # Write to CSV
  echo "\"${task_name}\",\"${lang}\",\"${vuln_type}\",\"${cve_id}\",\"${project}\",\"${failure_mode}\",\"${stage2_tool_calls}\",\"${has_pi_json}\",\"${has_results_json}\",\"${expected_title}\",\"${expected_severity}\",\"${workspace_dir}\"" >> "$CSV_FILE"

  # Write to Markdown table
  echo "| ${idx} | ${task_name} | ${lang} | ${vuln_type} | ${failure_mode} | ${stage2_tool_calls} | ${has_pi_json} | ${has_results_json} | ${expected_title:0:50} |" >> "$REPORT_FILE"

  # Progress indicator
  if (( idx % 10 == 0 )); then
    echo "  Analyzed ${idx}/${TOTAL_FAIL} ..."
  fi
done

# ---- Summary Statistics ----
echo "" >> "$REPORT_FILE"
echo "## Summary Statistics" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo "### By Failure Mode" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "| Failure Mode | Count | Percentage |" >> "$REPORT_FILE"
echo "|-------------|-------|------------|" >> "$REPORT_FILE"
for mode in "output_not_produced" "empty_findings" "agent_exit_error" "stage1_fail" "other"; do
  count=${FAIL_MODE_COUNT["$mode"]:-0}
  if (( count > 0 )); then
    pct=$(( count * 100 / TOTAL_FAIL ))
    echo "| ${mode} | ${count} | ${pct}% |" >> "$REPORT_FILE"
  fi
done

echo "" >> "$REPORT_FILE"
echo "### By Language" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "| Language | Failed | Percentage |" >> "$REPORT_FILE"
echo "|---------|--------|------------|" >> "$REPORT_FILE"
for l in "go" "java" "js" "python"; do
  count=${LANG_COUNT["$l"]:-0}
  if (( count > 0 )); then
    pct=$(( count * 100 / TOTAL_FAIL ))
    echo "| ${l} | ${count} | ${pct}% |" >> "$REPORT_FILE"
  fi
done

echo "" >> "$REPORT_FILE"
echo "### By Vulnerability Type" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "| Vulnerability Type | Count | Percentage |" >> "$REPORT_FILE"
echo "|--------------------|-------|------------|" >> "$REPORT_FILE"
for vtype in $(echo "${!VULN_TYPE_COUNT[@]}" | tr ' ' '\n' | sort); do
  count=${VULN_TYPE_COUNT["$vtype"]:-0}
  if (( count > 0 )); then
    pct=$(( count * 100 / TOTAL_FAIL ))
    echo "| ${vtype} | ${count} | ${pct}% |" >> "$REPORT_FILE"
  fi
done

echo "" >> "$REPORT_FILE"
echo "---" >> "$REPORT_FILE"
echo "Generated: $(date)" >> "$REPORT_FILE"

echo ""
echo "Analysis complete!"
echo "  Report: ${REPORT_FILE}"
echo "  CSV:    ${CSV_FILE}"
echo "  Total failures analyzed: ${TOTAL_FAIL}"
