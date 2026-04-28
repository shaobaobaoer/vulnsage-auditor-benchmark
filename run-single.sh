#!/usr/bin/env bash
# ============================================================================
# VulnSage Benchmark — Run Single CVE E2E Test
# Usage: ./run-single.sh <fixture-directory>
# Example: ./run-single.sh fixtures/python-lib-CVE-2024-36039/
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

# Load libraries
source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/stage1.sh"
source "${SCRIPT_DIR}/lib/stage2.sh"
source "${SCRIPT_DIR}/lib/stage3.sh"
source "${SCRIPT_DIR}/lib/validate.sh"

# ---- Parse arguments -------------------------------------------------------
FIXTURE_DIR="${1:-}"
SKIP_CLONE="${SKIP_CLONE:-false}"
STAGE_ONLY="${STAGE_ONLY:-}"    # e.g., "stage1", "stage2", "stage3"

if [[ -z "$FIXTURE_DIR" ]]; then
  echo "Usage: $0 <fixture-directory>"
  echo "Example: $0 fixtures/python-lib-CVE-2024-36039/"
  exit 1
fi

# Resolve to absolute path
if [[ ! "$FIXTURE_DIR" = /* ]]; then
  FIXTURE_DIR="${BENCHMARK_ROOT}/${FIXTURE_DIR}"
fi

# Remove trailing slash
FIXTURE_DIR="${FIXTURE_DIR%/}"

if [[ ! -d "$FIXTURE_DIR" ]]; then
  die "Fixture directory not found: ${FIXTURE_DIR}"
fi

FIXTURE_NAME="$(basename "$FIXTURE_DIR")"

# ---- Validate fixture structure --------------------------------------------
log_stage "VulnSage Benchmark — ${FIXTURE_NAME}"

if ! validate_fixture "$FIXTURE_DIR"; then
  die "Fixture validation failed for ${FIXTURE_NAME}"
fi

# ---- Read meta info --------------------------------------------------------
CVE_ID=$(fixture_meta "$FIXTURE_DIR" "cve_id")
PROJECT=$(fixture_meta "$FIXTURE_DIR" "project")
LANGUAGE=$(fixture_meta "$FIXTURE_DIR" "language")
CATEGORY=$(fixture_meta "$FIXTURE_DIR" "category")
VULN_TYPE=$(fixture_meta "$FIXTURE_DIR" "vuln_type")

log_info "CVE:      ${CVE_ID}"
log_info "Project:  ${PROJECT}"
log_info "Language: ${LANGUAGE}"
log_info "Category: ${CATEGORY}"
log_info "Type:     ${VULN_TYPE}"

# ---- Initialize results tracking -------------------------------------------
init_results

# ---- Prepare workspace ----------------------------------------------------
WORKSPACE="${FIXTURE_DIR}/workspace"
mkdir -p "$WORKSPACE"

# Only clean workspace output files, preserve source/ if SKIP_CLONE
if [[ "$SKIP_CLONE" != "true" ]]; then
  rm -rf "$WORKSPACE"
  mkdir -p "$WORKSPACE"
else
  # Clean outputs but keep source/
  rm -f "$WORKSPACE/product_identification.json" \
        "$WORKSPACE/vulnsage_results.json" \
        "$WORKSPACE/stage1_command.md" \
        "$WORKSPACE/stage2_command.md" \
        "$WORKSPACE/stage3_command.md" \
        "$WORKSPACE/Dockerfile"
  rm -rf "$WORKSPACE/report" "$WORKSPACE/poc_scripts"
fi

log_info "Workspace prepared: ${WORKSPACE}"
TOTAL_START=$(timer_start)

# ---- Step 0: Clone source code --------------------------------------------
if [[ "$SKIP_CLONE" != "true" ]]; then
  log_step "Cloning vulnerable source code..."

  CLONE_SCRIPT="${FIXTURE_DIR}/clone.sh"
  if [[ -f "$CLONE_SCRIPT" ]]; then
    (cd "$WORKSPACE" && bash "$CLONE_SCRIPT") || die "Clone failed"
    log_ok "Source code cloned to: ${WORKSPACE}/source/"
  else
    die "Clone script not found: ${CLONE_SCRIPT}"
  fi
else
  log_info "Skipping clone (SKIP_CLONE=true)"
  # If source was cloned at fixture level, symlink it
  if [[ -d "${FIXTURE_DIR}/source" && ! -d "${WORKSPACE}/source" ]]; then
    ln -s "${FIXTURE_DIR}/source" "${WORKSPACE}/source"
    log_info "Linked source from fixture directory"
  fi
fi

# ---- Run stages ------------------------------------------------------------
OVERALL_STATUS="PASS"

run_or_skip_stage() {
  local stage_name="$1"
  local stage_func="$2"

  if [[ -n "$STAGE_ONLY" && "$STAGE_ONLY" != "$stage_name" ]]; then
    log_info "Skipping ${stage_name} (STAGE_ONLY=${STAGE_ONLY})"
    return 0
  fi

  if ! "$stage_func" "$FIXTURE_DIR" "$WORKSPACE"; then
    OVERALL_STATUS="FAIL"
    log_error "${stage_name} FAILED"
    # Continue to next stage even on failure (collect all results)
  fi
}

run_or_skip_stage "stage1" run_stage1
run_or_skip_stage "stage2" run_stage2
run_or_skip_stage "stage3" run_stage3

# ---- Validate outputs ------------------------------------------------------
if [[ -z "$STAGE_ONLY" ]]; then
  log_step "Validating outputs..."
  validate_all_stages "$FIXTURE_DIR" "$WORKSPACE" || true
fi

# ---- Summary ---------------------------------------------------------------
TOTAL_ELAPSED=$(timer_elapsed "$TOTAL_START")

echo ""
log_stage "Test Complete: ${FIXTURE_NAME}"
echo -e "  ${BOLD}CVE:${NC}     ${CVE_ID}"
echo -e "  ${BOLD}Status:${NC}  $(if [[ "$OVERALL_STATUS" == "PASS" ]]; then echo -e "${GREEN}PASS${NC}"; else echo -e "${RED}FAIL${NC}"; fi)"
echo -e "  ${BOLD}Time:${NC}    $(timer_format "$TOTAL_ELAPSED")"
echo -e "  ${BOLD}Results:${NC} ${RESULTS_FILE}"
echo ""

if [[ "$OVERALL_STATUS" == "FAIL" ]]; then
  exit 1
fi
