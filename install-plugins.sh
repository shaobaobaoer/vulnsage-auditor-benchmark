#!/usr/bin/env bash
# ============================================================================
# VulnSage Benchmark — Install Plugins to Cursor
# One-click installation of all three VulnSage plugins into Cursor IDE
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

DRY_RUN=false
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

log_stage "VulnSage Plugin Installer"

# ---- Step 1: Check dependencies -------------------------------------------
log_step "1/6 Checking dependencies"

check_version() {
  local cmd="$1"
  local label="$2"
  if command -v "$cmd" &>/dev/null; then
    local ver
    ver=$("$cmd" --version 2>&1 | head -1 || echo "unknown")
    log_ok "$label: $ver"
    return 0
  else
    log_error "$label: NOT FOUND"
    return 1
  fi
}

MISSING=0
check_version node   "Node.js"   || ((MISSING++))
check_version python3 "Python"   || ((MISSING++))
check_version docker "Docker"    || ((MISSING++))
check_version git    "Git"       || ((MISSING++))
check_version jq     "jq"        || ((MISSING++))

# uv is optional but recommended
if command -v uv &>/dev/null; then
  log_ok "uv: $(uv --version 2>&1 | head -1)"
else
  log_warn "uv not found — will fall back to pip for Plugin 3"
fi

if [[ $MISSING -gt 0 ]]; then
  die "Missing $MISSING required dependencies. Install them and re-run."
fi

# Check Docker daemon
if ! docker info &>/dev/null 2>&1; then
  log_warn "Docker daemon is not running. Stage 3 tests will fail."
fi

if $DRY_RUN; then
  log_info "Dry run complete — all dependencies OK"
  exit 0
fi

# ---- Step 2: Locate plugins -----------------------------------------------
log_step "2/6 Locating plugins"

AUDITOR_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PLUGINS=(
  "vulnsage-product-identification-plugin"
  "vulnsage-vulnerability-analysis-plugin"
  "vulnsage-vulnerability-proof-plugin"
)

for plugin in "${PLUGINS[@]}"; do
  plugin_path="${AUDITOR_ROOT}/${plugin}"
  if [[ -d "$plugin_path" ]]; then
    log_ok "Found: ${plugin}"
  else
    die "Plugin not found: ${plugin_path}"
  fi
done

# ---- Step 3: Symlink plugins to Cursor ------------------------------------
log_step "3/6 Installing plugins to Cursor"

CURSOR_PLUGINS_DIR="${HOME}/.cursor/plugins/local"
mkdir -p "$CURSOR_PLUGINS_DIR"

for plugin in "${PLUGINS[@]}"; do
  src="${AUDITOR_ROOT}/${plugin}"
  dest="${CURSOR_PLUGINS_DIR}/${plugin}"

  if [[ -L "$dest" ]]; then
    log_info "Removing existing symlink: ${dest}"
    rm -f "$dest"
  elif [[ -e "$dest" ]]; then
    log_warn "${dest} exists and is not a symlink — skipping (move it manually)"
    continue
  fi

  ln -s "$src" "$dest"
  log_ok "Linked: ${plugin}"
done

# ---- Step 4: Configure MCP servers ----------------------------------------
log_step "4/6 Configuring MCP servers"

CURSOR_MCP="${HOME}/.cursor/mcp.json"
MCP_TEMPLATE="${SCRIPT_DIR}/config/cursor-mcp.json"

# Generate MCP config with resolved absolute paths
PLUGIN2_MCP_SERVER="${AUDITOR_ROOT}/vulnsage-vulnerability-analysis-plugin/engines/codeql-mcp/dist/server.js"

cat > "$CURSOR_MCP" <<EOF
{
  "mcpServers": {
    "context7": {
      "command": "npx",
      "args": ["-y", "@upstash/context7-mcp"]
    },
    "vulnsage-codeql": {
      "command": "node",
      "args": ["${PLUGIN2_MCP_SERVER}"]
    }
  }
}
EOF

log_ok "MCP config written to: ${CURSOR_MCP}"

# ---- Step 5: Build Plugin 2 (TypeScript MCP server) -----------------------
log_step "5/6 Building Plugin 2 (CodeQL MCP server)"

PLUGIN2_ENGINE="${AUDITOR_ROOT}/vulnsage-vulnerability-analysis-plugin/engines/codeql-mcp"

if [[ -d "$PLUGIN2_ENGINE" ]]; then
  if [[ -f "${PLUGIN2_ENGINE}/package.json" ]]; then
    (cd "$PLUGIN2_ENGINE" && npm install && npm run build 2>&1) && \
      log_ok "Plugin 2 MCP server built successfully" || \
      log_warn "Plugin 2 MCP server build failed — Stage 2 may not work"
  else
    log_warn "Plugin 2 engine directory found but no package.json — skipping build"
  fi
else
  log_warn "Plugin 2 engine directory not found: ${PLUGIN2_ENGINE}"
fi

# ---- Step 6: Install Plugin 3 (Python dependencies) -----------------------
log_step "6/6 Installing Plugin 3 (Python dependencies)"

PLUGIN3_ROOT="${AUDITOR_ROOT}/vulnsage-vulnerability-proof-plugin"

if command -v uv &>/dev/null; then
  # Create venv if not exists, then install deps into it
  if [[ ! -d "${PLUGIN3_ROOT}/.venv" ]]; then
    (cd "$PLUGIN3_ROOT" && uv venv .venv 2>&1)
  fi
  (cd "$PLUGIN3_ROOT" && uv pip install --python .venv/bin/python requests pytest pytest-cov ruff mypy 2>&1) && \
    log_ok "Plugin 3 dependencies installed via uv (venv: .venv)" || \
    log_warn "Plugin 3 installation failed"
else
  (cd "$PLUGIN3_ROOT" && python3 -m venv .venv && .venv/bin/pip install requests pytest pytest-cov 2>&1) && \
    log_ok "Plugin 3 dependencies installed via pip (venv: .venv)" || \
    log_warn "Plugin 3 installation failed"
fi

# ---- Done ------------------------------------------------------------------
log_stage "Installation Complete"

echo -e "${BOLD}Installed plugins:${NC}"
for plugin in "${PLUGINS[@]}"; do
  echo -e "  ${GREEN}✓${NC} ${plugin} → ${CURSOR_PLUGINS_DIR}/${plugin}"
done

echo ""
echo -e "${BOLD}MCP servers:${NC}"
echo -e "  ${GREEN}✓${NC} context7 (npx @upstash/context7-mcp)"
echo -e "  ${GREEN}✓${NC} vulnsage-codeql (${PLUGIN2_MCP_SERVER})"

echo ""
echo -e "${YELLOW}${BOLD}Next step:${NC} Restart Cursor (or run 'Developer: Reload Window') to activate plugins."
echo ""
