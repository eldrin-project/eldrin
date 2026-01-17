#!/usr/bin/env bash
#
# Eldrin Submodule Status Check Script
#
# This script displays the status of all Git submodules in the Eldrin project.
# It shows commit information, branch state, and any uncommitted changes.
#
# Usage:
#   ./scripts/status.sh [OPTIONS] [SUBMODULE...]
#
# Options:
#   --full          Show detailed status including file changes
#   --fetch         Fetch remotes before checking status (slower but accurate)
#   --json          Output status in JSON format
#   --quiet         Only show submodules with issues
#   --help          Show this help message
#

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
GRAY='\033[0;90m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Submodules list
SUBMODULES=(
    "eldrin-core"
    "eldrin-app-core"
    "eldrin-invoicing"
    "eldrin-catalog"
    "eldrin-crm"
    "eldrin-website"
    "eldrin-docs"
    "eldrin-templates"
    "eldrin-marketplace-dist"
    "eldrin-app-angular"
    "eldrin-app-react"
    "eldrin-app-svelte"
    "eldrin-app-vue"
)

# Default options
FULL_STATUS=false
FETCH_REMOTES=false
JSON_OUTPUT=false
QUIET_MODE=false
SELECTED_SUBMODULES=()

# Counters
CLEAN_COUNT=0
DIRTY_COUNT=0
AHEAD_COUNT=0
BEHIND_COUNT=0
DETACHED_COUNT=0
NOT_INITIALIZED_COUNT=0

#######################################
# Print colored message
#######################################
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

print_info() {
    if [[ "$QUIET_MODE" != true ]]; then
        print_status "$BLUE" "[INFO] $1"
    fi
}

print_success() {
    if [[ "$QUIET_MODE" != true ]]; then
        print_status "$GREEN" "[OK] $1"
    fi
}

print_warning() {
    print_status "$YELLOW" "[WARN] $1"
}

print_error() {
    print_status "$RED" "[ERROR] $1"
}

print_header() {
    if [[ "$JSON_OUTPUT" != true ]] && [[ "$QUIET_MODE" != true ]]; then
        echo ""
        echo "========================================"
        print_status "$BLUE" "$1"
        echo "========================================"
    fi
}

#######################################
# Show usage information
#######################################
show_help() {
    cat << EOF
Eldrin Submodule Status Check Script

Usage: ./scripts/status.sh [OPTIONS] [SUBMODULE...]

Options:
    --full          Show detailed status including file changes
    --fetch         Fetch remotes before checking status (slower but accurate)
    --json          Output status in JSON format (for scripting)
    --quiet         Only show submodules with issues (dirty, ahead/behind, etc.)
    --help          Show this help message

Arguments:
    SUBMODULE...    Optional list of specific submodules to check
                    If not specified, all submodules are checked

Available Submodules:
$(printf '    - %s\n' "${SUBMODULES[@]}")

Examples:
    # Check status of all submodules
    ./scripts/status.sh

    # Show detailed status with file changes
    ./scripts/status.sh --full

    # Check specific submodules
    ./scripts/status.sh eldrin-core eldrin-invoicing

    # Fetch and show accurate ahead/behind counts
    ./scripts/status.sh --fetch

    # Only show submodules with issues
    ./scripts/status.sh --quiet

    # Get JSON output for scripting
    ./scripts/status.sh --json

Status Indicators:
    [CLEAN]         No uncommitted changes
    [DIRTY]         Has uncommitted changes
    [AHEAD n]       n commits ahead of remote
    [BEHIND n]      n commits behind remote
    [DETACHED]      HEAD is detached (not on a branch)
    [NOT INIT]      Submodule not initialized

EOF
    exit 0
}

#######################################
# Parse command line arguments
#######################################
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --full)
                FULL_STATUS=true
                shift
                ;;
            --fetch)
                FETCH_REMOTES=true
                shift
                ;;
            --json)
                JSON_OUTPUT=true
                shift
                ;;
            --quiet)
                QUIET_MODE=true
                shift
                ;;
            --help|-h)
                show_help
                ;;
            -*)
                print_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
            *)
                # Assume it's a submodule name
                if is_valid_submodule "$1"; then
                    SELECTED_SUBMODULES+=("$1")
                else
                    print_error "Unknown submodule: $1"
                    echo "Use --help to see available submodules"
                    exit 1
                fi
                shift
                ;;
        esac
    done

    # If no specific submodules selected, use all
    if [[ ${#SELECTED_SUBMODULES[@]} -eq 0 ]]; then
        SELECTED_SUBMODULES=("${SUBMODULES[@]}")
    fi
}

#######################################
# Check if submodule name is valid
#######################################
is_valid_submodule() {
    local name=$1
    for sm in "${SUBMODULES[@]}"; do
        if [[ "$sm" == "$name" ]]; then
            return 0
        fi
    done
    return 1
}

#######################################
# Check if we're in the project root
#######################################
check_project_root() {
    cd "$PROJECT_ROOT"

    if [[ ! -f ".gitmodules" ]]; then
        print_error "Cannot find .gitmodules file. Are you in the Eldrin project root?"
        exit 1
    fi
}

#######################################
# Get submodule status details
#######################################
get_submodule_status() {
    local submodule=$1
    local path="$PROJECT_ROOT/$submodule"

    # Initialize status variables
    local initialized=true
    local commit=""
    local short_commit=""
    local branch=""
    local is_detached=false
    local is_dirty=false
    local staged_count=0
    local unstaged_count=0
    local untracked_count=0
    local ahead=0
    local behind=0
    local tracking_branch=""
    local last_commit_msg=""
    local last_commit_date=""

    # Check if directory exists
    if [[ ! -d "$path" ]]; then
        initialized=false
        echo "initialized=false"
        return
    fi

    # Check if it's a valid git repo
    if [[ ! -d "$path/.git" ]] && [[ ! -f "$path/.git" ]]; then
        initialized=false
        echo "initialized=false"
        return
    fi

    cd "$path"

    # Get commit info
    commit=$(git rev-parse HEAD 2>/dev/null || echo "")
    short_commit=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

    # Get branch info
    branch=$(git symbolic-ref --short HEAD 2>/dev/null || echo "")
    if [[ -z "$branch" ]]; then
        is_detached=true
        branch="HEAD"
    fi

    # Get tracking branch
    if [[ "$is_detached" != true ]]; then
        tracking_branch=$(git rev-parse --abbrev-ref --symbolic-full-name "@{u}" 2>/dev/null || echo "")
    fi

    # Check for uncommitted changes
    staged_count=$(git diff --cached --numstat 2>/dev/null | wc -l | tr -d ' ')
    unstaged_count=$(git diff --numstat 2>/dev/null | wc -l | tr -d ' ')
    untracked_count=$(git ls-files --others --exclude-standard 2>/dev/null | wc -l | tr -d ' ')

    if [[ $staged_count -gt 0 ]] || [[ $unstaged_count -gt 0 ]] || [[ $untracked_count -gt 0 ]]; then
        is_dirty=true
    fi

    # Get ahead/behind counts
    if [[ -n "$tracking_branch" ]]; then
        local counts
        counts=$(git rev-list --left-right --count "$tracking_branch...HEAD" 2>/dev/null || echo "0	0")
        behind=$(echo "$counts" | cut -f1)
        ahead=$(echo "$counts" | cut -f2)
    fi

    # Get last commit info
    last_commit_msg=$(git log -1 --format="%s" 2>/dev/null | head -c 50)
    last_commit_date=$(git log -1 --format="%cr" 2>/dev/null || echo "unknown")

    cd "$PROJECT_ROOT"

    # Output as key=value pairs
    echo "initialized=true"
    echo "commit=$commit"
    echo "short_commit=$short_commit"
    echo "branch=$branch"
    echo "is_detached=$is_detached"
    echo "is_dirty=$is_dirty"
    echo "staged_count=$staged_count"
    echo "unstaged_count=$unstaged_count"
    echo "untracked_count=$untracked_count"
    echo "ahead=$ahead"
    echo "behind=$behind"
    echo "tracking_branch=$tracking_branch"
    echo "last_commit_msg=$last_commit_msg"
    echo "last_commit_date=$last_commit_date"
}

#######################################
# Fetch remote for a submodule
#######################################
fetch_submodule_remote() {
    local submodule=$1
    local path="$PROJECT_ROOT/$submodule"

    if [[ -d "$path/.git" ]] || [[ -f "$path/.git" ]]; then
        git -C "$path" fetch --quiet 2>/dev/null || true
    fi
}

#######################################
# Print status for a single submodule
#######################################
print_submodule_status() {
    local submodule=$1

    # Get status as variables
    local status_output
    status_output=$(get_submodule_status "$submodule")

    # Parse status into variables
    local initialized=false
    local commit=""
    local short_commit=""
    local branch=""
    local is_detached=false
    local is_dirty=false
    local staged_count=0
    local unstaged_count=0
    local untracked_count=0
    local ahead=0
    local behind=0
    local tracking_branch=""
    local last_commit_msg=""
    local last_commit_date=""

    while IFS='=' read -r key value; do
        case "$key" in
            initialized) initialized="$value" ;;
            commit) commit="$value" ;;
            short_commit) short_commit="$value" ;;
            branch) branch="$value" ;;
            is_detached) is_detached="$value" ;;
            is_dirty) is_dirty="$value" ;;
            staged_count) staged_count="$value" ;;
            unstaged_count) unstaged_count="$value" ;;
            untracked_count) untracked_count="$value" ;;
            ahead) ahead="$value" ;;
            behind) behind="$value" ;;
            tracking_branch) tracking_branch="$value" ;;
            last_commit_msg) last_commit_msg="$value" ;;
            last_commit_date) last_commit_date="$value" ;;
        esac
    done <<< "$status_output"

    # Build status line
    local status_indicators=()
    local has_issues=false

    if [[ "$initialized" != "true" ]]; then
        status_indicators+=("${RED}NOT INIT${NC}")
        ((NOT_INITIALIZED_COUNT++))
        has_issues=true
    else
        # Dirty status
        if [[ "$is_dirty" == "true" ]]; then
            status_indicators+=("${YELLOW}DIRTY${NC}")
            ((DIRTY_COUNT++))
            has_issues=true
        else
            ((CLEAN_COUNT++))
        fi

        # Detached HEAD
        if [[ "$is_detached" == "true" ]]; then
            status_indicators+=("${MAGENTA}DETACHED${NC}")
            ((DETACHED_COUNT++))
            has_issues=true
        fi

        # Ahead/behind
        if [[ $ahead -gt 0 ]]; then
            status_indicators+=("${CYAN}AHEAD $ahead${NC}")
            ((AHEAD_COUNT++))
            has_issues=true
        fi

        if [[ $behind -gt 0 ]]; then
            status_indicators+=("${YELLOW}BEHIND $behind${NC}")
            ((BEHIND_COUNT++))
            has_issues=true
        fi

        # Clean status (only if no other indicators)
        if [[ ${#status_indicators[@]} -eq 0 ]]; then
            status_indicators+=("${GREEN}CLEAN${NC}")
        fi
    fi

    # Skip if quiet mode and no issues
    if [[ "$QUIET_MODE" == true ]] && [[ "$has_issues" != true ]]; then
        return
    fi

    # Print the status line
    local status_str=""
    for indicator in "${status_indicators[@]}"; do
        if [[ -n "$status_str" ]]; then
            status_str+=", "
        fi
        status_str+="$indicator"
    done

    printf "${BOLD}%-25s${NC} " "$submodule"
    printf "[%b] " "$status_str"

    if [[ "$initialized" == "true" ]]; then
        printf "${GRAY}%s${NC} " "$short_commit"

        if [[ "$is_detached" == "true" ]]; then
            printf "${GRAY}(detached)${NC}"
        else
            printf "${CYAN}%s${NC}" "$branch"
        fi
    fi

    echo ""

    # Full status - show more details
    if [[ "$FULL_STATUS" == true ]] && [[ "$initialized" == "true" ]]; then
        if [[ -n "$last_commit_msg" ]]; then
            printf "    ${GRAY}Last commit: %s (%s)${NC}\n" "$last_commit_msg" "$last_commit_date"
        fi

        if [[ -n "$tracking_branch" ]]; then
            printf "    ${GRAY}Tracking: %s${NC}\n" "$tracking_branch"
        fi

        if [[ "$is_dirty" == "true" ]]; then
            if [[ $staged_count -gt 0 ]]; then
                printf "    ${GREEN}Staged: %d file(s)${NC}\n" "$staged_count"
            fi
            if [[ $unstaged_count -gt 0 ]]; then
                printf "    ${YELLOW}Modified: %d file(s)${NC}\n" "$unstaged_count"
            fi
            if [[ $untracked_count -gt 0 ]]; then
                printf "    ${RED}Untracked: %d file(s)${NC}\n" "$untracked_count"
            fi
        fi

        echo ""
    fi
}

#######################################
# Output JSON status for a submodule
#######################################
json_submodule_status() {
    local submodule=$1
    local status_output
    status_output=$(get_submodule_status "$submodule")

    # Parse status
    local initialized=false commit="" short_commit="" branch=""
    local is_detached=false is_dirty=false
    local staged_count=0 unstaged_count=0 untracked_count=0
    local ahead=0 behind=0 tracking_branch=""
    local last_commit_msg="" last_commit_date=""

    while IFS='=' read -r key value; do
        case "$key" in
            initialized) initialized="$value" ;;
            commit) commit="$value" ;;
            short_commit) short_commit="$value" ;;
            branch) branch="$value" ;;
            is_detached) is_detached="$value" ;;
            is_dirty) is_dirty="$value" ;;
            staged_count) staged_count="$value" ;;
            unstaged_count) unstaged_count="$value" ;;
            untracked_count) untracked_count="$value" ;;
            ahead) ahead="$value" ;;
            behind) behind="$value" ;;
            tracking_branch) tracking_branch="$value" ;;
            last_commit_msg) last_commit_msg="$value" ;;
            last_commit_date) last_commit_date="$value" ;;
        esac
    done <<< "$status_output"

    # Escape quotes in commit message
    last_commit_msg="${last_commit_msg//\"/\\\"}"

    cat << EOF
    {
      "name": "$submodule",
      "initialized": $initialized,
      "commit": "$commit",
      "shortCommit": "$short_commit",
      "branch": "$branch",
      "isDetached": $is_detached,
      "isDirty": $is_dirty,
      "stagedCount": $staged_count,
      "unstagedCount": $unstaged_count,
      "untrackedCount": $untracked_count,
      "ahead": $ahead,
      "behind": $behind,
      "trackingBranch": "$tracking_branch",
      "lastCommitMessage": "$last_commit_msg",
      "lastCommitDate": "$last_commit_date"
    }
EOF
}

#######################################
# Print summary
#######################################
print_summary() {
    if [[ "$JSON_OUTPUT" == true ]]; then
        return
    fi

    print_header "Summary"

    local total=${#SELECTED_SUBMODULES[@]}

    echo ""
    echo "Total submodules checked: $total"
    echo ""

    if [[ $NOT_INITIALIZED_COUNT -gt 0 ]]; then
        print_status "$RED" "  Not initialized: $NOT_INITIALIZED_COUNT"
    fi

    print_status "$GREEN" "  Clean: $CLEAN_COUNT"

    if [[ $DIRTY_COUNT -gt 0 ]]; then
        print_status "$YELLOW" "  Dirty: $DIRTY_COUNT"
    fi

    if [[ $DETACHED_COUNT -gt 0 ]]; then
        print_status "$MAGENTA" "  Detached HEAD: $DETACHED_COUNT"
    fi

    if [[ $AHEAD_COUNT -gt 0 ]]; then
        print_status "$CYAN" "  Ahead of remote: $AHEAD_COUNT"
    fi

    if [[ $BEHIND_COUNT -gt 0 ]]; then
        print_status "$YELLOW" "  Behind remote: $BEHIND_COUNT"
    fi

    echo ""

    # Suggestions
    if [[ $NOT_INITIALIZED_COUNT -gt 0 ]]; then
        print_info "Run './scripts/init.sh' to initialize missing submodules"
    fi

    if [[ $DIRTY_COUNT -gt 0 ]]; then
        print_info "Some submodules have uncommitted changes"
    fi

    if [[ $BEHIND_COUNT -gt 0 ]]; then
        print_info "Run './scripts/update-submodules.sh --remote' to update behind submodules"
    fi

    if [[ $DETACHED_COUNT -gt 0 ]]; then
        print_info "Run './scripts/update-submodules.sh --checkout' to exit detached HEAD state"
    fi

    echo ""
}

#######################################
# Main entry point
#######################################
main() {
    parse_args "$@"
    check_project_root

    if [[ "$JSON_OUTPUT" == true ]]; then
        # JSON output mode
        echo "{"
        echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
        echo "  \"projectRoot\": \"$PROJECT_ROOT\","
        echo "  \"submodules\": ["

        local first=true
        for submodule in "${SELECTED_SUBMODULES[@]}"; do
            if [[ "$FETCH_REMOTES" == true ]]; then
                fetch_submodule_remote "$submodule"
            fi

            if [[ "$first" == true ]]; then
                first=false
            else
                echo ","
            fi

            json_submodule_status "$submodule"
        done

        echo ""
        echo "  ]"
        echo "}"
    else
        # Normal output mode
        print_header "Eldrin Submodule Status"

        if [[ "$FETCH_REMOTES" == true ]]; then
            print_info "Fetching remotes (this may take a moment)..."
            echo ""
        fi

        for submodule in "${SELECTED_SUBMODULES[@]}"; do
            if [[ "$FETCH_REMOTES" == true ]]; then
                fetch_submodule_remote "$submodule"
            fi

            print_submodule_status "$submodule"
        done

        print_summary
    fi
}

# Run main function
main "$@"
