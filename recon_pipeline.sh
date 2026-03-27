#!/usr/bin/env bash
set -Eeuo pipefail

# =========================================================
# Recon Pipeline
# - Collect subdomains: subfinder + crt.sh + assetfinder(optional)
# - Deduplicate
# - Validate with dnsx
# - Probe with httpx
# - Scan with nuclei
#
# Usage:
#   ./recon_pipeline.sh <domain> [output_dir] [provider_config]
#
# Example:
#   ./recon_pipeline.sh neu.edu.vn
#   ./recon_pipeline.sh neu.edu.vn recon_neu
#   ./recon_pipeline.sh neu.edu.vn recon_neu ~/.config/subfinder/provider-config.yaml
# =========================================================

DOMAIN="${1:-}"
OUTDIR="${2:-}"
PROVIDER_CONFIG="${3:-}"

if [[ -z "$DOMAIN" ]]; then
  echo "Usage: $0 <domain> [output_dir] [provider_config]"
  exit 1
fi

if [[ -z "$OUTDIR" ]]; then
  OUTDIR="recon_${DOMAIN}"
fi

mkdir -p "$OUTDIR"/{sources,http,nuclei,logs}

# =========================================================
# Output Files
# =========================================================
RAW_ALL="$OUTDIR/all_raw.txt"
UNIQ_ALL="$OUTDIR/all_unique.txt"
DNS_CLEAN="$OUTDIR/dns_clean.txt"

SUBFINDER_OUT="$OUTDIR/sources/subfinder.txt"
CRT_OUT="$OUTDIR/sources/crtsh.txt"
ASSETFINDER_OUT="$OUTDIR/sources/assetfinder.txt"

HTTP_JSON="$OUTDIR/http/alive.jsonl"
HTTP_TXT="$OUTDIR/http/alive.txt"

NUCLEI_TXT="$OUTDIR/nuclei/nuclei.txt"
NUCLEI_JSON="$OUTDIR/nuclei/nuclei.jsonl"

LOGFILE="$OUTDIR/logs/run.log"

CRTSH_ENABLED="no"
ASSETFINDER_ENABLED="no"

# =========================================================
# Logging
# =========================================================
log() {
  echo "[$(date '+%F %T')] $*" | tee -a "$LOGFILE"
}

warn() {
  echo "[$(date '+%F %T')] [WARN] $*" | tee -a "$LOGFILE" >&2
}

die() {
  echo "[$(date '+%F %T')] [ERROR] $*" | tee -a "$LOGFILE" >&2
  exit 1
}

# =========================================================
# Dependency Checks
# =========================================================
need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required tool: $1"
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

check_requirements() {
  need_cmd subfinder
  need_cmd dnsx
  need_cmd httpx
  need_cmd nuclei
  need_cmd sort
  need_cmd sed
  need_cmd grep
  need_cmd tee

  if has_cmd curl && has_cmd jq; then
    CRTSH_ENABLED="yes"
  fi

  if has_cmd assetfinder; then
    ASSETFINDER_ENABLED="yes"
  fi
}

# =========================================================
# Init Files
# =========================================================
init_files() {
  : > "$RAW_ALL"
  : > "$UNIQ_ALL"
  : > "$DNS_CLEAN"
  : > "$SUBFINDER_OUT"
  : > "$CRT_OUT"
  : > "$ASSETFINDER_OUT"
  : > "$HTTP_JSON"
  : > "$HTTP_TXT"
  : > "$NUCLEI_TXT"
  : > "$NUCLEI_JSON"
  : > "$LOGFILE"
}

# =========================================================
# Helpers
# =========================================================
cleanup_and_filter_domain() {
  sed 's/\*\.//g' \
  | sed 's/\r//g' \
  | tr '[:upper:]' '[:lower:]' \
  | sed 's/[[:space:]]*$//' \
  | sed '/^$/d' \
  | grep -E "(^|[.])${DOMAIN//./\\.}$" \
  | sort -u
}

append_if_exists() {
  local file="$1"
  [[ -s "$file" ]] && cat "$file" >> "$RAW_ALL"
}

# =========================================================
# Source Collection
# =========================================================
run_subfinder() {
  log "Running subfinder..."

  if [[ -n "$PROVIDER_CONFIG" ]]; then
    if [[ ! -f "$PROVIDER_CONFIG" ]]; then
      die "Provider config not found: $PROVIDER_CONFIG"
    fi

    if ! subfinder -d "$DOMAIN" -all -silent -pc "$PROVIDER_CONFIG" 2>>"$LOGFILE" \
        | cleanup_and_filter_domain \
        | tee "$SUBFINDER_OUT" >/dev/null; then
      warn "subfinder failed"
    fi
  else
    if ! subfinder -d "$DOMAIN" -all -silent 2>>"$LOGFILE" \
        | cleanup_and_filter_domain \
        | tee "$SUBFINDER_OUT" >/dev/null; then
      warn "subfinder failed"
    fi
  fi

  append_if_exists "$SUBFINDER_OUT"
}

run_crtsh() {
  if [[ "$CRTSH_ENABLED" != "yes" ]]; then
    warn "crt.sh skipped because curl/jq is missing"
    return 0
  fi

  log "Querying crt.sh..."

  if ! curl -fsSL "https://crt.sh/?q=%25.${DOMAIN}&output=json" 2>>"$LOGFILE" \
      | jq -r '.[].name_value' 2>>"$LOGFILE" \
      | tr '\r' '\n' \
      | cleanup_and_filter_domain \
      | tee "$CRT_OUT" >/dev/null; then
    warn "crt.sh failed"
  fi

  append_if_exists "$CRT_OUT"
}

run_assetfinder() {
  if [[ "$ASSETFINDER_ENABLED" != "yes" ]]; then
    warn "assetfinder not installed, skipped"
    return 0
  fi

  log "Running assetfinder..."

  if ! assetfinder --subs-only "$DOMAIN" 2>>"$LOGFILE" \
      | cleanup_and_filter_domain \
      | tee "$ASSETFINDER_OUT" >/dev/null; then
    warn "assetfinder failed"
  fi

  append_if_exists "$ASSETFINDER_OUT"
}

# =========================================================
# Processing
# =========================================================
dedupe_all() {
  log "Deduplicating collected subdomains..."
  sort -fu "$RAW_ALL" > "$UNIQ_ALL"
}

run_dnsx() {
  if [[ ! -s "$UNIQ_ALL" ]]; then
    die "No unique subdomains found to send into dnsx"
  fi

  log "Running dnsx..."

  if ! dnsx -silent -wd "$DOMAIN" -l "$UNIQ_ALL" 2>>"$LOGFILE" \
      | sort -fu \
      | tee "$DNS_CLEAN" >/dev/null; then
    die "dnsx failed"
  fi
}

run_httpx() {
  if [[ ! -s "$DNS_CLEAN" ]]; then
    warn "No valid DNS records found, httpx skipped"
    return 0
  fi

  log "Running httpx..."

  if ! httpx -silent -l "$DNS_CLEAN" \
      -sc -title -td -cl -json -fpt parked,captcha \
      -o "$HTTP_JSON" 2>>"$LOGFILE"; then
    die "httpx failed"
  fi

  if [[ -s "$HTTP_JSON" ]]; then
    if ! jq -r '.url' "$HTTP_JSON" 2>>"$LOGFILE" | sort -fu > "$HTTP_TXT"; then
      die "Failed to extract URLs from httpx output"
    fi
  else
    warn "httpx produced no output"
  fi
}

run_nuclei() {
  if [[ ! -s "$HTTP_TXT" ]]; then
    warn "No alive URLs found, nuclei skipped"
    return 0
  fi

  log "Running nuclei..."

  if ! nuclei -l "$HTTP_TXT" \
      -silent \
      -o "$NUCLEI_TXT" \
      -jsonl -je "$NUCLEI_JSON" 2>>"$LOGFILE"; then
    warn "nuclei finished with warnings/errors"
  fi
}

print_summary() {
  echo
  echo "==================== SUMMARY ===================="
  echo "Domain            : $DOMAIN"
  echo "Output Directory  : $OUTDIR"
  echo "Raw Collected     : $(wc -l < "$RAW_ALL" 2>/dev/null || echo 0)"
  echo "Unique Subdomains : $(wc -l < "$UNIQ_ALL" 2>/dev/null || echo 0)"
  echo "DNS Valid         : $(wc -l < "$DNS_CLEAN" 2>/dev/null || echo 0)"
  echo "Alive URLs        : $(wc -l < "$HTTP_TXT" 2>/dev/null || echo 0)"
  echo "Nuclei Findings   : $(wc -l < "$NUCLEI_TXT" 2>/dev/null || echo 0)"
  echo "================================================="
  echo
  echo "Files:"
  echo "  $SUBFINDER_OUT"
  echo "  $CRT_OUT"
  echo "  $ASSETFINDER_OUT"
  echo "  $RAW_ALL"
  echo "  $UNIQ_ALL"
  echo "  $DNS_CLEAN"
  echo "  $HTTP_JSON"
  echo "  $HTTP_TXT"
  echo "  $NUCLEI_TXT"
  echo "  $NUCLEI_JSON"
  echo "  $LOGFILE"
}

main() {
  init_files
  check_requirements

  log "Domain: $DOMAIN"
  log "Output: $OUTDIR"

  if [[ -n "$PROVIDER_CONFIG" ]]; then
    log "Provider Config: $PROVIDER_CONFIG"
  else
    log "Provider Config: default/none"
  fi

  run_subfinder
  run_crtsh
  run_assetfinder

  if [[ ! -s "$RAW_ALL" ]]; then
    die "No subdomains collected from any source"
  fi

  dedupe_all
  run_dnsx
  run_httpx
  run_nuclei
  print_summary
}

main "$@"