#!/usr/bin/env bash
# ============================================================================
# Generate example JSON files for failed samples from failure analysis CSV.
#
# Reads the failure analysis CSV and creates JSON task files from benchmark
# fixture meta.json files.
#
# Usage:
#   ./scripts/generate-examples.sh <csv-file> [output-dir]
#
# Example:
#   ./scripts/generate-examples.sh reports/failure_analysis_20260429_101726.csv
#   ./scripts/generate-examples.sh reports/failure_analysis_20260429_101726.csv examples/
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
BENCHMARK_DIR="$(cd -- "${SCRIPT_DIR}/.." &>/dev/null && pwd)"
FIXTURES_DIR="${BENCHMARK_DIR}/fixtures"

# ---- Arguments ----
CSV_FILE="${1:?Usage: generate-examples.sh <csv-file> [output-dir]}"
EXAMPLES_DIR="${2:-${BENCHMARK_DIR}/examples}"

# Resolve CSV to absolute path
if [[ ! "$CSV_FILE" = /* ]]; then
  CSV_FILE="$(cd "$(dirname "$CSV_FILE")" && pwd)/$(basename "$CSV_FILE")"
fi

mkdir -p "$EXAMPLES_DIR"

if [[ ! -f "$CSV_FILE" ]]; then
  echo "ERROR: CSV file not found: $CSV_FILE"
  exit 1
fi

echo "=== Generating example JSON files for failed samples ==="
echo "Source: $CSV_FILE"
echo "Output: $EXAMPLES_DIR"
echo ""

count=0
errors=0

# Skip header line, read each CSV row
tail -n +2 "$CSV_FILE" | while IFS=',' read -r sample_name language vuln_type cve_id project failure_mode tool_calls has_pi has_results expected_title expected_severity workspace_dir; do
  # Remove quotes
  sample_name="${sample_name//\"/}"
  language="${language//\"/}"
  vuln_type="${vuln_type//\"/}"
  cve_id="${cve_id//\"/}"
  project="${project//\"/}"
  expected_title="${expected_title//\"/}"

  # Find meta.json for this sample
  meta_file="${FIXTURES_DIR}/${sample_name}/meta.json"

  if [[ ! -f "$meta_file" ]]; then
    echo "WARN: meta.json not found for ${sample_name}, skipping"
    ((errors++)) || true
    continue
  fi

  # Read target info from meta.json using jq
  repo_url=$(jq -r '.repo_url // empty' "$meta_file" 2>/dev/null)
  vulnerable_ref=$(jq -r '.vulnerable_ref // empty' "$meta_file" 2>/dev/null)
  desc=$(jq -r '.description // empty' "$meta_file" 2>/dev/null)

  if [[ -z "$repo_url" || -z "$vulnerable_ref" ]]; then
    echo "WARN: Missing repo_url/vulnerable_ref in ${meta_file}, skipping"
    ((errors++)) || true
    continue
  fi

  # Build target string: repo_url.git@vulnerable_ref
  target="${repo_url}.git@${vulnerable_ref}"

  # Use description from meta.json, fallback to expected_title
  if [[ -z "$desc" ]]; then
    desc="${expected_title}"
  fi

  # Create example JSON using jq for proper escaping
  example_file="${EXAMPLES_DIR}/${sample_name}.json"
  jq -n --arg target "$target" --arg desc "$desc" \
    '{"target": $target, "description": $desc}' > "$example_file"

  ((count++)) || true
  echo "  Created: ${sample_name}.json"
done

echo ""
echo "=== Done ==="
echo "Generated: ${count} example file(s)"
echo "Errors: ${errors}"
echo "Output directory: ${EXAMPLES_DIR}"
