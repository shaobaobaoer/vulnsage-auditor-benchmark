#!/usr/bin/env bash
# ============================================================================
# VulnSage Benchmark — Full E2E Benchmark Runner
#
# Usage:
#   ./run-benchmark.sh              # Run all 64 CVEs
#   ./run-benchmark.sh --spiral=1   # Spiral 1 only (1 CVE)
#   ./run-benchmark.sh --spiral=2   # Spiral 1+2 (4 CVEs)
#   ./run-benchmark.sh --spiral=3   # Spiral 1+2+3 (16 CVEs)
#   ./run-benchmark.sh --check      # Validate fixture structure only
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

# Load libraries
source "${SCRIPT_DIR}/lib/common.sh"

# ---- Parse arguments -------------------------------------------------------
MAX_SPIRAL=4
CHECK_ONLY=false

for arg in "$@"; do
  case "$arg" in
    --spiral=*)
      MAX_SPIRAL="${arg#*=}"
      ;;
    --check)
      CHECK_ONLY=true
      ;;
    --help|-h)
      echo "Usage: $0 [--spiral=N] [--check]"
      echo ""
      echo "Options:"
      echo "  --spiral=N   Run spirals 1..N (default: 4 = all 64 CVEs)"
      echo "  --check      Validate fixture structure only (no E2E execution)"
      echo "  --help       Show this help"
      echo ""
      echo "Spiral levels:"
      echo "  1  →  1 CVE  (python-lib-CVE-2024-36039)"
      echo "  2  →  4 CVEs (one per language, all Library)"
      echo "  3  → 16 CVEs (one per language×category)"
      echo "  4  → 64 CVEs (full 4×4×4 matrix)"
      exit 0
      ;;
    *)
      die "Unknown argument: $arg"
      ;;
  esac
done

# ---- Header ----------------------------------------------------------------
TOTAL_CVES=$(count_spiral_cves "$MAX_SPIRAL")
log_stage "VulnSage Benchmark — Spiral ${MAX_SPIRAL} (${TOTAL_CVES} CVEs)"

# ---- Check-only mode -------------------------------------------------------
if $CHECK_ONLY; then
  log_step "Validating fixture structure..."
  PASS=0
  FAIL=0

  while IFS= read -r fixture_name; do
    fixture_path="${FIXTURES_DIR}/${fixture_name}"
    if [[ ! -d "$fixture_path" ]]; then
      log_error "Fixture directory missing: ${fixture_name}"
      FAIL=$((FAIL + 1))
      continue
    fi

    if validate_fixture "$fixture_path"; then
      log_ok "  ${fixture_name}"
      PASS=$((PASS + 1))
    else
      FAIL=$((FAIL + 1))
    fi
  done < <(get_spiral_fixtures "$MAX_SPIRAL")

  echo ""
  log_info "Check complete: ${PASS} OK, ${FAIL} failed (out of ${TOTAL_CVES})"

  if [[ $FAIL -gt 0 ]]; then
    exit 1
  fi
  exit 0
fi

# ---- Pre-flight checks -----------------------------------------------------
log_step "Pre-flight checks"
require_jq
require_cmd "git"

# Docker is only required for Stage 3
if docker info &>/dev/null 2>&1; then
  log_ok "Docker daemon is running"
else
  log_warn "Docker daemon is not running — Stage 3 tests will fail"
fi

# ---- Run all fixtures ------------------------------------------------------
log_step "Running ${TOTAL_CVES} CVE tests..."

TOTAL_START=$(timer_start)
PASSED=0
FAILED=0
SKIPPED=0
FAILED_LIST=()

while IFS= read -r fixture_name; do
  fixture_path="${FIXTURES_DIR}/${fixture_name}"

  if [[ ! -d "$fixture_path" ]]; then
    log_warn "Fixture not found: ${fixture_name} — skipping"
    SKIPPED=$((SKIPPED + 1))
    continue
  fi

  echo ""
  log_info "━━━ [$(( PASSED + FAILED + SKIPPED + 1 ))/${TOTAL_CVES}] ${fixture_name} ━━━"

  if "${SCRIPT_DIR}/run-single.sh" "$fixture_path"; then
    PASSED=$((PASSED + 1))
    print_summary_line "$fixture_name" "PASS" "0"
  else
    FAILED=$((FAILED + 1))
    FAILED_LIST+=("$fixture_name")
    print_summary_line "$fixture_name" "FAIL" "0"
  fi
done < <(get_spiral_fixtures "$MAX_SPIRAL")

TOTAL_ELAPSED=$(timer_elapsed "$TOTAL_START")

# ---- Generate report ------------------------------------------------------
log_step "Generating report..."
source "${SCRIPT_DIR}/lib/report.sh"
generate_report "$MAX_SPIRAL" "$PASSED" "$FAILED" "$SKIPPED" "$TOTAL_ELAPSED" "${FAILED_LIST[*]:-}"

# ---- Final summary ---------------------------------------------------------
echo ""
log_stage "Benchmark Complete — Spiral ${MAX_SPIRAL}"

echo -e "  ${BOLD}Total:${NC}   ${TOTAL_CVES}"
echo -e "  ${GREEN}${BOLD}Passed:${NC}  ${PASSED}"
echo -e "  ${RED}${BOLD}Failed:${NC}  ${FAILED}"
echo -e "  ${YELLOW}${BOLD}Skipped:${NC} ${SKIPPED}"
echo -e "  ${BOLD}Time:${NC}    $(timer_format "$TOTAL_ELAPSED")"
echo ""

if [[ ${#FAILED_LIST[@]} -gt 0 ]]; then
  echo -e "${RED}${BOLD}Failed tests:${NC}"
  for f in "${FAILED_LIST[@]}"; do
    echo -e "  ${RED}✗${NC} ${f}"
  done
  echo ""
fi

if [[ $FAILED -eq 0 && $SKIPPED -eq 0 ]]; then
  log_ok "All ${TOTAL_CVES} tests PASSED! 🎉"
else
  exit 1
fi
