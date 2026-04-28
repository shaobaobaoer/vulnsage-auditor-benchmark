#!/usr/bin/env bash
# ============================================================================
# VulnSage Benchmark — Common Library
# Shared functions for logging, colors, JSON parsing, error handling
# ============================================================================

set -euo pipefail

# ---- Colors ----------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ---- Paths -----------------------------------------------------------------
BENCHMARK_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &>/dev/null && pwd)"
CONFIG_DIR="${BENCHMARK_ROOT}/config"
FIXTURES_DIR="${BENCHMARK_ROOT}/fixtures"
RESULTS_DIR="${BENCHMARK_ROOT}/results"
REPORTS_DIR="${BENCHMARK_ROOT}/reports"
LIB_DIR="${BENCHMARK_ROOT}/lib"

MATRIX_FILE="${CONFIG_DIR}/matrix.json"

# Upstream plugin paths (relative to benchmark root)
PLUGIN1_DIR="$(cd "${BENCHMARK_ROOT}/../vulnsage-product-identification-plugin" 2>/dev/null && pwd || echo "")"
PLUGIN2_DIR="$(cd "${BENCHMARK_ROOT}/../vulnsage-vulnerability-analysis-plugin" 2>/dev/null && pwd || echo "")"
PLUGIN3_DIR="$(cd "${BENCHMARK_ROOT}/../vulnsage-vulnerability-proof-plugin" 2>/dev/null && pwd || echo "")"

# ---- Logging ---------------------------------------------------------------
log_info()    { echo -e "${BLUE}[INFO]${NC}  $(date '+%H:%M:%S') $*"; }
log_ok()      { echo -e "${GREEN}[OK]${NC}    $(date '+%H:%M:%S') $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}  $(date '+%H:%M:%S') $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $(date '+%H:%M:%S') $*" >&2; }
log_step()    { echo -e "${CYAN}[STEP]${NC}  $(date '+%H:%M:%S') ${BOLD}$*${NC}"; }
log_stage()   { echo -e "\n${BOLD}═══════════════════════════════════════════════${NC}"; \
                echo -e "${BOLD}  $*${NC}"; \
                echo -e "${BOLD}═══════════════════════════════════════════════${NC}\n"; }

# ---- Error handling --------------------------------------------------------
die() {
  log_error "$@"
  exit 1
}

# ---- Dependency checks -----------------------------------------------------
require_cmd() {
  local cmd="$1"
  local min_version="${2:-}"
  if ! command -v "$cmd" &>/dev/null; then
    die "Required command not found: $cmd"
  fi
  if [[ -n "$min_version" ]]; then
    log_info "$cmd found: $(command -v "$cmd")"
  fi
}

require_jq() {
  require_cmd "jq"
}

require_docker() {
  require_cmd "docker"
  if ! docker info &>/dev/null; then
    die "Docker daemon is not running. Please start Docker Desktop."
  fi
}

# ---- JSON helpers ----------------------------------------------------------
# Read a field from a JSON file using jq
json_get() {
  local file="$1"
  local query="$2"
  jq -r "$query" "$file" 2>/dev/null || echo ""
}

# Read meta.json from a fixture directory
fixture_meta() {
  local fixture_dir="$1"
  local field="$2"
  json_get "${fixture_dir}/meta.json" ".$field"
}

# ---- Matrix helpers --------------------------------------------------------
# Get fixtures for a given spiral level (cumulative)
get_spiral_fixtures() {
  local max_spiral="$1"
  local spirals=()

  case "$max_spiral" in
    1) spirals=("S1") ;;
    2) spirals=("S1" "S2") ;;
    3) spirals=("S1" "S2" "S3") ;;
    4) spirals=("S1" "S2" "S3" "S4") ;;
    *) die "Invalid spiral level: $max_spiral (must be 1-4)" ;;
  esac

  local filter
  filter=$(printf '"%s",' "${spirals[@]}")
  filter="[${filter%,}]"

  jq -r --argjson s "$filter" '.cves[] | select(.spiral as $sp | $s | index($sp)) | .fixture' "$MATRIX_FILE"
}

# Count CVEs for a spiral level
count_spiral_cves() {
  local max_spiral="$1"
  get_spiral_fixtures "$max_spiral" | wc -l | tr -d ' '
}

# ---- Fixture helpers -------------------------------------------------------
# Ensure fixture directory exists and has required files
validate_fixture() {
  local fixture_dir="$1"
  local fixture_name
  fixture_name="$(basename "$fixture_dir")"
  local errors=0

  for required_file in meta.json clone.sh Dockerfile; do
    if [[ ! -f "${fixture_dir}/${required_file}" ]]; then
      log_error "  Missing ${required_file} in ${fixture_name}"
      ((errors++))
    fi
  done

  if [[ ! -d "${fixture_dir}/expected" ]]; then
    log_error "  Missing expected/ directory in ${fixture_name}"
    ((errors++))
  fi

  return $errors
}

# ---- Timing helpers --------------------------------------------------------
timer_start() {
  echo "$(date +%s)"
}

timer_elapsed() {
  local start="$1"
  local now
  now="$(date +%s)"
  echo $((now - start))
}

timer_format() {
  local seconds="$1"
  printf '%02d:%02d:%02d' $((seconds/3600)) $(((seconds%3600)/60)) $((seconds%60))
}

# ---- Result tracking -------------------------------------------------------
RESULTS_FILE=""

init_results() {
  local run_id
  run_id="$(date '+%Y%m%d_%H%M%S')"
  RESULTS_FILE="${RESULTS_DIR}/run_${run_id}.json"
  mkdir -p "$RESULTS_DIR"
  echo '{"run_id":"'"$run_id"'","started_at":"'"$(date -u '+%Y-%m-%dT%H:%M:%SZ')"'","results":[]}' > "$RESULTS_FILE"
  log_info "Results file: ${RESULTS_FILE}"
}

record_result() {
  local fixture="$1"
  local stage="$2"
  local status="$3"  # PASS | FAIL | SKIP
  local elapsed="$4"
  local detail="${5:-}"

  if [[ -z "$RESULTS_FILE" ]]; then
    log_warn "Results file not initialized, skipping record"
    return
  fi

  local tmp
  tmp="$(mktemp)"
  jq --arg f "$fixture" --arg s "$stage" --arg st "$status" \
     --arg el "$elapsed" --arg d "$detail" \
     '.results += [{"fixture":$f,"stage":$s,"status":$st,"elapsed_seconds":($el|tonumber),"detail":$d}]' \
     "$RESULTS_FILE" > "$tmp" && mv "$tmp" "$RESULTS_FILE"
}

# ---- Workspace helpers -----------------------------------------------------
# Prepare workspace for a fixture run
prepare_workspace() {
  local fixture_dir="$1"
  local workspace="${fixture_dir}/workspace"

  rm -rf "$workspace"
  mkdir -p "$workspace"

  log_info "Workspace prepared: ${workspace}"
  echo "$workspace"
}

# ---- Summary helpers -------------------------------------------------------
print_summary_line() {
  local fixture="$1"
  local status="$2"
  local elapsed="$3"

  if [[ "$status" == "PASS" ]]; then
    echo -e "  ${GREEN}✓${NC} ${fixture} $(timer_format "$elapsed")"
  elif [[ "$status" == "FAIL" ]]; then
    echo -e "  ${RED}✗${NC} ${fixture} $(timer_format "$elapsed")"
  else
    echo -e "  ${YELLOW}⊘${NC} ${fixture} (skipped)"
  fi
}
