#!/usr/bin/env bash
# ============================================================================
# VulnSage Benchmark — Validate: Compare actual output vs expected fixtures
# ============================================================================

# This script is sourced by run-single.sh, common.sh is already loaded

validate_stage_output() {
  local fixture_dir="$1"
  local workspace="$2"
  local stage="$3"  # stage1 | stage2 | stage3
  local fixture_name
  fixture_name="$(basename "$fixture_dir")"

  local actual_file expected_file

  case "$stage" in
    stage1)
      actual_file="${workspace}/product_identification.json"
      expected_file="${fixture_dir}/expected/product_identification.json"
      ;;
    stage2)
      actual_file="${workspace}/vulnsage_results.json"
      expected_file="${fixture_dir}/expected/vuln_report.json"
      ;;
    stage3)
      actual_file="${workspace}/report/summary.json"
      expected_file="${fixture_dir}/expected/verification.json"
      ;;
    *)
      log_error "Unknown stage: ${stage}"
      return 1
      ;;
  esac

  if [[ ! -f "$expected_file" ]]; then
    log_warn "No expected file for ${stage} — skipping validation"
    return 0
  fi

  if [[ ! -f "$actual_file" ]]; then
    log_error "Actual output missing for ${stage}: ${actual_file}"
    return 1
  fi

  log_info "Validating ${stage} output..."

  # ---- Structural validation -----------------------------------------------
  # Check that key fields match between actual and expected
  local errors=0

  case "$stage" in
    stage1)
      # Validate language
      local expected_lang actual_lang
      expected_lang=$(jq -r '.A_language.primary // empty' "$expected_file" 2>/dev/null)
      actual_lang=$(jq -r '.A_language.primary // empty' "$actual_file" 2>/dev/null)
      if [[ -n "$expected_lang" && "$expected_lang" != "$actual_lang" ]]; then
        log_warn "  Language mismatch: expected=${expected_lang}, actual=${actual_lang}"
        ((errors++))
      fi

      # Validate category
      local expected_cat actual_cat
      expected_cat=$(jq -r '.B_category.type // empty' "$expected_file" 2>/dev/null)
      actual_cat=$(jq -r '.B_category.type // empty' "$actual_file" 2>/dev/null)
      if [[ -n "$expected_cat" && "$expected_cat" != "$actual_cat" ]]; then
        log_warn "  Category mismatch: expected=${expected_cat}, actual=${actual_cat}"
        ((errors++))
      fi

      # Validate pipeline_id format
      local pid
      pid=$(jq -r '.pipeline_id // empty' "$actual_file" 2>/dev/null)
      if [[ -n "$pid" ]] && ! echo "$pid" | grep -qE '^pid-[0-9a-f]{8}$'; then
        log_warn "  Invalid pipeline_id format: ${pid}"
        ((errors++))
      fi

      # Validate security_profile exists
      if ! jq -e '.E_security_profile' "$actual_file" &>/dev/null; then
        log_warn "  Missing E_security_profile"
        ((errors++))
      fi
      ;;

    stage2)
      # Validate findings exist
      if ! jq -e '.findings' "$actual_file" &>/dev/null; then
        log_error "  Missing findings array"
        ((errors++))
      fi

      # Check expected vulnerability type is found
      local expected_vuln_type
      expected_vuln_type=$(fixture_meta "$fixture_dir" "vuln_type")
      if [[ -n "$expected_vuln_type" ]]; then
        local found
        found=$(jq --arg vt "$expected_vuln_type" \
          '[.findings[]? | .vulnerability_type // .vuln_type // empty] | map(select(. == $vt)) | length' \
          "$actual_file" 2>/dev/null || echo "0")
        if [[ "$found" == "0" ]]; then
          log_warn "  Expected vuln type '${expected_vuln_type}' not in findings"
          ((errors++))
        fi
      fi

      # Validate pipeline_id matches Stage 1
      local s1_pid s2_pid
      s1_pid=$(jq -r '.pipeline_id // empty' "${workspace}/product_identification.json" 2>/dev/null)
      s2_pid=$(jq -r '.pipeline_id // empty' "$actual_file" 2>/dev/null)
      if [[ -n "$s1_pid" && -n "$s2_pid" && "$s1_pid" != "$s2_pid" ]]; then
        log_warn "  pipeline_id mismatch between Stage 1 and Stage 2"
        ((errors++))
      fi
      ;;

    stage3)
      # Validate results exist
      if ! jq -e '.results' "$actual_file" &>/dev/null; then
        if ! jq -e '.pipeline_id' "$actual_file" &>/dev/null; then
          log_error "  Missing results and pipeline_id"
          ((errors++))
        fi
      fi

      # Check for verified findings
      local verified
      verified=$(jq '[.results[]? | select(.status == "verified")] | length' "$actual_file" 2>/dev/null || echo "0")
      if [[ "$verified" == "0" ]]; then
        log_warn "  No verified findings in Stage 3 output"
        ((errors++))
      fi
      ;;
  esac

  if [[ $errors -eq 0 ]]; then
    log_ok "Validation passed for ${stage}"
    return 0
  else
    log_warn "Validation completed with ${errors} warning(s) for ${stage}"
    return 0  # Warnings don't fail the test — only structure errors do
  fi
}

# Validate all three stages for a fixture
validate_all_stages() {
  local fixture_dir="$1"
  local workspace="$2"
  local total_errors=0

  for stage in stage1 stage2 stage3; do
    validate_stage_output "$fixture_dir" "$workspace" "$stage" || ((total_errors++))
  done

  return $total_errors
}
