#!/usr/bin/env bash
#
# Eldrin Submodule Update Helper Script
#
# This script helps update Git submodules in the Eldrin project.
# It supports updating all submodules or specific ones, with options
# for updating to remote HEAD or a specific branch.
#
# Usage:
#   ./scripts/update-submodules.sh [OPTIONS] [SUBMODULE...]
#
# Options:
#   --remote        Update submodules to their remote tracking branch HEAD
#   --branch NAME   Update submodules to a specific branch
#   --pull          Pull latest changes within each submodule (requires branch checkout)
#   --checkout      Checkout the tracked branch in each submodule (exit detached HEAD)
#   --verbose       Show detailed output
#   --dry-run       Show what would be done without making changes
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
UPDATE_REMOTE=false
BRANCH=""
PULL_CHANGES=false
CHECKOUT_BRANCH=false
VERBOSE=false
DRY_RUN=false
SELECTED_SUBMODULES=()

# Counters
SUCCESS_COUNT=0
FAILED_COUNT=0
SKIPPED_COUNT=0
FAILED_MODULES=()

#######################################
# Print colored message
#######################################
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

print_info() {
    print_status "$BLUE" "[INFO] $1"
}

print_success() {
    print_status "$GREEN" "[OK] $1"
}

print_warning() {
    print_status "$YELLOW" "[WARN] $1"
}

print_error() {
    print_status "$RED" "[ERROR] $1"
}

print_dry_run() {
    print_status "$CYAN" "[DRY-RUN] $1"
}

print_header() {
    echo ""
    echo "========================================"
    print_status "$BLUE" "$1"
    echo "========================================"
}

#######################################
# Show usage information
#######################################
show_help() {
    cat << EOF
Eldrin Submodule Update Helper Script

Usage: ./scripts/update-submodules.sh [OPTIONS] [SUBMODULE...]

Options:
    --remote        Update submodules to their remote tracking branch HEAD
                    (equivalent to git submodule update --remote)
    --branch NAME   Update submodules to a specific branch
    --pull          Pull latest changes within each submodule
                    (requires submodules to be on a branch, not detached HEAD)
    --checkout      Checkout the tracked branch in each submodule
                    (useful to exit detached HEAD state)
    --verbose       Show detailed output
    --dry-run       Show what would be done without making changes
    --help          Show this help message

Arguments:
    SUBMODULE...    Optional list of specific submodules to update
                    If not specified, all submodules are updated

Available Submodules:
$(printf '    - %s\n' "${SUBMODULES[@]}")

Examples:
    # Update all submodules to their recorded commits
    ./scripts/update-submodules.sh

    # Update all submodules to remote HEAD
    ./scripts/update-submodules.sh --remote

    # Update specific submodules to remote HEAD
    ./scripts/update-submodules.sh --remote eldrin-core eldrin-invoicing

    # Update all submodules to 'develop' branch
    ./scripts/update-submodules.sh --branch develop

    # Checkout tracked branch and pull latest in all submodules
    ./scripts/update-submodules.sh --checkout --pull

    # Preview what would be updated
    ./scripts/update-submodules.sh --remote --dry-run

Git Submodule Concepts:
    - Submodules are "pinned" to specific commits in the parent repo
    - Without --remote, submodules update to their recorded (pinned) commits
    - With --remote, submodules update to the latest commit on their tracking branch
    - Use --checkout to work on a branch instead of detached HEAD state

EOF
    exit 0
}

#######################################
# Parse command line arguments
#######################################
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --remote)
                UPDATE_REMOTE=true
                shift
                ;;
            --branch)
                if [[ -z "$2" ]] || [[ "$2" == --* ]]; then
                    print_error "--branch requires a branch name"
                    exit 1
                fi
                BRANCH="$2"
                shift 2
                ;;
            --pull)
                PULL_CHANGES=true
                shift
                ;;
            --checkout)
                CHECKOUT_BRANCH=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
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

    if [[ "$VERBOSE" == true ]]; then
        print_info "Project root: $PROJECT_ROOT"
    fi
}

#######################################
# Get tracking branch for a submodule
#######################################
get_tracking_branch() {
    local submodule=$1
    local branch

    # Try to get branch from .gitmodules
    branch=$(git config -f .gitmodules --get "submodule.$submodule.branch" 2>/dev/null || echo "")

    if [[ -z "$branch" ]]; then
        # Default to main, then master
        if git -C "$submodule" rev-parse --verify origin/main &>/dev/null; then
            branch="main"
        elif git -C "$submodule" rev-parse --verify origin/master &>/dev/null; then
            branch="master"
        else
            branch=""
        fi
    fi

    echo "$branch"
}

#######################################
# Get current commit info for a submodule
#######################################
get_submodule_info() {
    local submodule=$1
    local path="$PROJECT_ROOT/$submodule"

    if [[ ! -d "$path/.git" ]] && [[ ! -f "$path/.git" ]]; then
        echo "not-initialized"
        return
    fi

    local commit branch
    commit=$(cd "$path" && git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    branch=$(cd "$path" && git symbolic-ref --short HEAD 2>/dev/null || echo "detached")

    echo "$commit:$branch"
}

#######################################
# Fetch updates for a submodule
#######################################
fetch_submodule() {
    local submodule=$1
    local path="$PROJECT_ROOT/$submodule"

    if [[ "$DRY_RUN" == true ]]; then
        print_dry_run "Would fetch: $submodule"
        return 0
    fi

    if [[ "$VERBOSE" == true ]]; then
        print_info "Fetching $submodule..."
        git -C "$path" fetch --all --prune
    else
        git -C "$path" fetch --all --prune --quiet 2>/dev/null || git -C "$path" fetch --all --prune
    fi
}

#######################################
# Update a single submodule
#######################################
update_submodule() {
    local submodule=$1
    local path="$PROJECT_ROOT/$submodule"

    # Check if directory exists
    if [[ ! -d "$path" ]]; then
        print_error "$submodule: Directory not found"
        ((FAILED_COUNT++))
        FAILED_MODULES+=("$submodule")
        return 1
    fi

    # Get current state
    local info before_commit
    info=$(get_submodule_info "$submodule")
    before_commit=$(echo "$info" | cut -d: -f1)

    if [[ "$info" == "not-initialized" ]]; then
        print_warning "$submodule: Not initialized. Run ./scripts/init.sh first"
        ((SKIPPED_COUNT++))
        return 0
    fi

    if [[ "$VERBOSE" == true ]]; then
        local current_branch
        current_branch=$(echo "$info" | cut -d: -f2)
        print_info "$submodule: Currently at $before_commit ($current_branch)"
    fi

    # Fetch first
    fetch_submodule "$submodule" || true

    # Determine update strategy
    if [[ "$CHECKOUT_BRANCH" == true ]]; then
        checkout_submodule_branch "$submodule"
    fi

    if [[ -n "$BRANCH" ]]; then
        # Update to specific branch
        update_to_branch "$submodule" "$BRANCH"
    elif [[ "$UPDATE_REMOTE" == true ]]; then
        # Update to remote HEAD
        update_to_remote "$submodule"
    elif [[ "$PULL_CHANGES" == true ]]; then
        # Pull on current branch
        pull_submodule "$submodule"
    else
        # Default: update to recorded commit
        update_to_recorded "$submodule"
    fi

    # Show result
    local after_info after_commit
    after_info=$(get_submodule_info "$submodule")
    after_commit=$(echo "$after_info" | cut -d: -f1)

    if [[ "$before_commit" != "$after_commit" ]]; then
        print_success "$submodule: Updated $before_commit -> $after_commit"
    else
        if [[ "$VERBOSE" == true ]]; then
            print_success "$submodule: Already up to date ($after_commit)"
        else
            print_success "$submodule: Up to date"
        fi
    fi

    ((SUCCESS_COUNT++))
    return 0
}

#######################################
# Update submodule to recorded commit
#######################################
update_to_recorded() {
    local submodule=$1

    if [[ "$DRY_RUN" == true ]]; then
        print_dry_run "Would update $submodule to recorded commit"
        return 0
    fi

    cd "$PROJECT_ROOT"

    if [[ "$VERBOSE" == true ]]; then
        git submodule update "$submodule"
    else
        git submodule update "$submodule" 2>/dev/null || git submodule update "$submodule"
    fi
}

#######################################
# Update submodule to remote HEAD
#######################################
update_to_remote() {
    local submodule=$1

    if [[ "$DRY_RUN" == true ]]; then
        print_dry_run "Would update $submodule to remote HEAD"
        return 0
    fi

    cd "$PROJECT_ROOT"

    if [[ "$VERBOSE" == true ]]; then
        git submodule update --remote "$submodule"
    else
        git submodule update --remote "$submodule" 2>/dev/null || git submodule update --remote "$submodule"
    fi
}

#######################################
# Update submodule to specific branch
#######################################
update_to_branch() {
    local submodule=$1
    local branch=$2
    local path="$PROJECT_ROOT/$submodule"

    if [[ "$DRY_RUN" == true ]]; then
        print_dry_run "Would checkout $submodule to branch '$branch'"
        return 0
    fi

    # Check if branch exists on remote
    if ! git -C "$path" rev-parse --verify "origin/$branch" &>/dev/null; then
        print_warning "$submodule: Branch 'origin/$branch' not found, skipping"
        ((SKIPPED_COUNT++))
        ((SUCCESS_COUNT--)) # Adjust counter
        return 0
    fi

    cd "$path"

    # Checkout and track the branch
    if git show-ref --verify --quiet "refs/heads/$branch"; then
        # Branch exists locally, checkout and pull
        git checkout "$branch" 2>/dev/null || git checkout "$branch"
        git pull origin "$branch" 2>/dev/null || git pull origin "$branch"
    else
        # Branch doesn't exist locally, create tracking branch
        git checkout -b "$branch" "origin/$branch" 2>/dev/null || \
            git checkout -b "$branch" --track "origin/$branch"
    fi

    cd "$PROJECT_ROOT"
}

#######################################
# Checkout tracked branch in submodule
#######################################
checkout_submodule_branch() {
    local submodule=$1
    local path="$PROJECT_ROOT/$submodule"

    local branch
    branch=$(get_tracking_branch "$submodule")

    if [[ -z "$branch" ]]; then
        print_warning "$submodule: Could not determine tracking branch"
        return 0
    fi

    if [[ "$DRY_RUN" == true ]]; then
        print_dry_run "Would checkout $submodule to branch '$branch'"
        return 0
    fi

    cd "$path"

    # Check if we're already on the branch
    local current_branch
    current_branch=$(git symbolic-ref --short HEAD 2>/dev/null || echo "")

    if [[ "$current_branch" == "$branch" ]]; then
        if [[ "$VERBOSE" == true ]]; then
            print_info "$submodule: Already on branch '$branch'"
        fi
        cd "$PROJECT_ROOT"
        return 0
    fi

    # Checkout the branch
    if git show-ref --verify --quiet "refs/heads/$branch"; then
        git checkout "$branch" 2>/dev/null || git checkout "$branch"
    else
        # Create tracking branch if it doesn't exist locally
        if git rev-parse --verify "origin/$branch" &>/dev/null; then
            git checkout -b "$branch" --track "origin/$branch" 2>/dev/null || \
                git checkout "$branch"
        fi
    fi

    if [[ "$VERBOSE" == true ]]; then
        print_info "$submodule: Checked out branch '$branch'"
    fi

    cd "$PROJECT_ROOT"
}

#######################################
# Pull changes in submodule
#######################################
pull_submodule() {
    local submodule=$1
    local path="$PROJECT_ROOT/$submodule"

    # Check if on a branch
    local current_branch
    current_branch=$(cd "$path" && git symbolic-ref --short HEAD 2>/dev/null || echo "")

    if [[ -z "$current_branch" ]]; then
        print_warning "$submodule: Detached HEAD - cannot pull. Use --checkout first"
        ((SKIPPED_COUNT++))
        ((SUCCESS_COUNT--)) # Adjust counter
        return 0
    fi

    if [[ "$DRY_RUN" == true ]]; then
        print_dry_run "Would pull $submodule (branch: $current_branch)"
        return 0
    fi

    cd "$path"

    if [[ "$VERBOSE" == true ]]; then
        git pull
    else
        git pull --quiet 2>/dev/null || git pull
    fi

    cd "$PROJECT_ROOT"
}

#######################################
# Print summary
#######################################
print_summary() {
    print_header "Update Summary"

    echo ""
    echo "Results:"
    echo "  - Updated successfully: $SUCCESS_COUNT"

    if [[ $SKIPPED_COUNT -gt 0 ]]; then
        echo "  - Skipped: $SKIPPED_COUNT"
    fi

    if [[ $FAILED_COUNT -gt 0 ]]; then
        echo "  - Failed: $FAILED_COUNT"
        echo ""
        print_warning "Failed submodules:"
        for module in "${FAILED_MODULES[@]}"; do
            echo "    - $module"
        done
    fi

    if [[ "$DRY_RUN" == true ]]; then
        echo ""
        print_info "This was a dry run. No changes were made."
        print_info "Remove --dry-run to apply changes."
    fi

    if [[ "$UPDATE_REMOTE" == true ]] && [[ "$DRY_RUN" != true ]]; then
        echo ""
        print_info "Submodules updated to remote HEAD."
        print_info "Don't forget to commit the submodule reference changes:"
        echo "    git add -A && git commit -m 'Update submodules to latest'"
    fi

    echo ""
}

#######################################
# Main entry point
#######################################
main() {
    print_header "Eldrin Submodule Update Helper"

    parse_args "$@"

    if [[ "$DRY_RUN" == true ]]; then
        print_info "Running in dry-run mode"
    fi

    check_project_root

    echo ""
    local total=${#SELECTED_SUBMODULES[@]}
    print_info "Updating $total submodule(s)..."
    echo ""

    for submodule in "${SELECTED_SUBMODULES[@]}"; do
        update_submodule "$submodule" || true
    done

    print_summary

    # Exit with error if any submodules failed
    if [[ $FAILED_COUNT -gt 0 ]]; then
        exit 1
    fi

    exit 0
}

# Run main function
main "$@"
