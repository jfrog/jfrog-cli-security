#!/bin/bash
set -euo pipefail

BOLD="\033[1m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
CYAN="\033[0;36m"
RED="\033[0;31m"
RESET="\033[0m"

GOMOD="go.mod"
COMMENT_REPLACE=true

usage() {
    echo -e "${BOLD}Usage:${RESET} $0 [OPTIONS] [dep1 dep2 ...]"
    echo
    echo "Update JFrog Go dependencies to their latest versions."
    echo
    echo -e "${BOLD}Options:${RESET}"
    echo "  -a, --all            Update all JFrog dependencies (branch + tagged)"
    echo "  -b, --branch         Update only branch-tracked dependencies (master/main)"
    echo "  -t, --tagged         Update only tagged dependencies (latest release)"
    echo "  --keep-replace       Don't comment out active 'replace' directives (default: comment them out)"
    echo "  -h, --help           Show this help message"
    echo
    echo -e "${BOLD}Individual dependencies (pass one or more):${RESET}"
    echo "  client-go        github.com/jfrog/jfrog-client-go        @master"
    echo "  cli-core         github.com/jfrog/jfrog-cli-core/v2      @master"
    echo "  cli-artifactory  github.com/jfrog/jfrog-cli-artifactory  @main"
    echo "  build-info-go    github.com/jfrog/build-info-go          @main"
    echo "  froggit-go       github.com/jfrog/froggit-go             @latest (tag)"
    echo "  gofrog           github.com/jfrog/gofrog                 @latest (tag)"
    echo
    echo -e "${BOLD}Examples:${RESET}"
    echo "  $0 --all                          # Update everything"
    echo "  $0 --branch                       # Update only branch-tracked deps"
    echo "  $0 client-go cli-core             # Update specific deps"
    echo "  $0 --all --keep-replace           # Update all, leave replace directives as-is"
}

log_info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${RESET}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
log_error() { echo -e "${RED}[ERROR]${RESET} $*"; }

BRANCH_KEYS="client-go cli-core cli-artifactory build-info-go"
TAGGED_KEYS="froggit-go gofrog"
ALL_KEYS="$BRANCH_KEYS $TAGGED_KEYS"

resolve_dep() {
    case "$1" in
        client-go)       echo "github.com/jfrog/jfrog-client-go|master" ;;
        cli-core)        echo "github.com/jfrog/jfrog-cli-core/v2|master" ;;
        cli-artifactory) echo "github.com/jfrog/jfrog-cli-artifactory|main" ;;
        build-info-go)   echo "github.com/jfrog/build-info-go|main" ;;
        froggit-go)      echo "github.com/jfrog/froggit-go|latest" ;;
        gofrog)          echo "github.com/jfrog/gofrog|latest" ;;
        *)               return 1 ;;
    esac
}

comment_out_jfrog_replaces() {
    if [[ ! -f "$GOMOD" ]]; then
        log_error "Cannot find $GOMOD"
        return 1
    fi

    local count
    count=$(grep -cE '^[[:space:]]*replace[[:space:]]+github\.com/jfrog/' "$GOMOD" 2>/dev/null || true)

    if [[ "$count" -eq 0 ]]; then
        log_info "No active jfrog replace directives found"
        return 0
    fi

    log_warn "Found ${BOLD}${count}${RESET} active jfrog replace directive(s) — commenting out"

    # macOS sed requires '' after -i; use a temp file for portability
    local tmp
    tmp=$(mktemp)
    while IFS= read -r line; do
        if echo "$line" | grep -qE '^[[:space:]]*replace[[:space:]]+github\.com/jfrog/'; then
            log_info "  Commenting: ${line}"
            echo "// ${line}" >> "$tmp"
        else
            echo "$line" >> "$tmp"
        fi
    done < "$GOMOD"
    mv "$tmp" "$GOMOD"
    log_ok "Replace directives commented out"
}

update_dep() {
    local key="$1"
    local entry
    entry=$(resolve_dep "$key") || { log_error "Unknown dependency: ${key} (known: ${ALL_KEYS})"; return 1; }
    local module="${entry%%|*}"
    local ref="${entry##*|}"
    log_info "Updating ${BOLD}${key}${RESET} → ${module}@${ref}"
    if go get "${module}@${ref}"; then
        log_ok "${key} updated"
    else
        log_error "Failed to update ${key}"
        return 1
    fi
}

# --- Main ---

if [[ $# -eq 0 ]]; then
    mode="all"
else
    mode=""
fi
specifics=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -a|--all)           mode="all"; shift ;;
        -b|--branch)        mode="branch"; shift ;;
        -t|--tagged)        mode="tagged"; shift ;;
        --keep-replace)     COMMENT_REPLACE=false; shift ;;
        -h|--help)          usage; exit 0 ;;
        -*)                 log_error "Unknown option: $1"; usage; exit 1 ;;
        *)                  specifics="${specifics} $1"; shift ;;
    esac
done

# Comment out active replace directives before updating
if [[ "$COMMENT_REPLACE" == true ]]; then
    comment_out_jfrog_replaces
    echo
fi

failed=0
keys_to_update=""

case "$mode" in
    all)
        log_info "Updating ${BOLD}all${RESET} JFrog dependencies…"
        echo
        keys_to_update="$ALL_KEYS"
        ;;
    branch)
        log_info "Updating ${BOLD}branch-tracked${RESET} dependencies…"
        echo
        keys_to_update="$BRANCH_KEYS"
        ;;
    tagged)
        log_info "Updating ${BOLD}tagged${RESET} dependencies…"
        echo
        keys_to_update="$TAGGED_KEYS"
        ;;
esac

for dep in $keys_to_update $specifics; do
    update_dep "$dep" || ((failed++)) || true
done

echo
if [[ $failed -gt 0 ]]; then
    log_warn "${failed} update(s) failed"
else
    log_ok "All updates succeeded"
fi

log_info "Running go mod tidy…"
GOPROXY=direct go mod tidy
log_ok "Done"

exit "$failed"
