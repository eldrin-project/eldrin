#!/usr/bin/env bash
#
# Eldrin Project Initialization Script
#
# This script initializes a fresh clone of the Eldrin project for development.
# It handles submodule initialization, validation, and optional dependency installation.
#
# Usage:
#   ./scripts/init.sh [OPTIONS]
#
# Options:
#   --skip-deps     Skip npm dependency installation
#   --verbose       Show detailed output
#   --help          Show this help message
#

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
MIN_GIT_VERSION="2.13"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Submodules list (order matters for dependencies)
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
SKIP_DEPS=false
VERBOSE=false

# Counters
SUCCESS_COUNT=0
FAILED_COUNT=0
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
Eldrin Project Initialization Script

Usage: ./scripts/init.sh [OPTIONS]

Options:
    --skip-deps     Skip npm dependency installation
    --verbose       Show detailed output
    --help          Show this help message

Description:
    This script initializes the Eldrin development environment by:
    1. Validating Git version requirements
    2. Initializing and updating all Git submodules
    3. Checking submodule connectivity and status
    4. Optionally installing npm dependencies for each component

Examples:
    # Full initialization with dependencies
    ./scripts/init.sh

    # Initialize without installing dependencies
    ./scripts/init.sh --skip-deps

    # Verbose output for debugging
    ./scripts/init.sh --verbose

EOF
    exit 0
}

#######################################
# Parse command line arguments
#######################################
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-deps)
                SKIP_DEPS=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --help|-h)
                show_help
                ;;
            *)
                print_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
}

#######################################
# Check Git version
#######################################
check_git_version() {
    print_header "Checking Prerequisites"

    if ! command -v git &> /dev/null; then
        print_error "Git is not installed. Please install Git $MIN_GIT_VERSION or higher."
        exit 1
    fi

    local git_version
    git_version=$(git --version | sed 's/git version //' | cut -d. -f1-2)

    if [[ "$VERBOSE" == true ]]; then
        print_info "Git version: $git_version"
    fi

    # Compare versions
    local min_major min_minor current_major current_minor
    min_major=$(echo "$MIN_GIT_VERSION" | cut -d. -f1)
    min_minor=$(echo "$MIN_GIT_VERSION" | cut -d. -f2)
    current_major=$(echo "$git_version" | cut -d. -f1)
    current_minor=$(echo "$git_version" | cut -d. -f2)

    if [[ $current_major -lt $min_major ]] || \
       [[ $current_major -eq $min_major && $current_minor -lt $min_minor ]]; then
        print_error "Git version $git_version is too old. Please upgrade to Git $MIN_GIT_VERSION or higher."
        exit 1
    fi

    print_success "Git version $git_version (meets requirement >= $MIN_GIT_VERSION)"
}

#######################################
# Check if we're in the project root
#######################################
check_project_root() {
    cd "$PROJECT_ROOT"

    if [[ ! -f ".gitmodules" ]]; then
        print_error "Cannot find .gitmodules file. Are you in the Eldrin project root?"
        print_error "Expected location: $PROJECT_ROOT/.gitmodules"
        exit 1
    fi

    if [[ "$VERBOSE" == true ]]; then
        print_info "Project root: $PROJECT_ROOT"
    fi

    print_success "Project root validated"
}

#######################################
# Initialize submodules
#######################################
init_submodules() {
    print_header "Initializing Git Submodules"

    cd "$PROJECT_ROOT"

    print_info "Running git submodule update --init --recursive..."

    if [[ "$VERBOSE" == true ]]; then
        git submodule update --init --recursive
    else
        if git submodule update --init --recursive 2>&1; then
            print_success "Submodules initialized"
        else
            print_warning "Some submodules may have failed to initialize"
            print_info "Continuing with individual submodule verification..."
        fi
    fi
}

#######################################
# Verify individual submodule
#######################################
verify_submodule() {
    local submodule=$1
    local path="$PROJECT_ROOT/$submodule"

    if [[ ! -d "$path" ]]; then
        print_error "$submodule: Directory not found"
        ((FAILED_COUNT++))
        FAILED_MODULES+=("$submodule")
        return 1
    fi

    if [[ ! -d "$path/.git" ]] && [[ ! -f "$path/.git" ]]; then
        print_error "$submodule: Not a valid Git repository"
        ((FAILED_COUNT++))
        FAILED_MODULES+=("$submodule")
        return 1
    fi

    # Check if submodule has content (not empty)
    local file_count
    file_count=$(find "$path" -maxdepth 1 -type f | wc -l | tr -d ' ')

    if [[ "$file_count" -eq 0 ]]; then
        print_warning "$submodule: Initialized but appears empty"
        ((SUCCESS_COUNT++))
        return 0
    fi

    if [[ "$VERBOSE" == true ]]; then
        local commit
        commit=$(cd "$path" && git rev-parse --short HEAD 2>/dev/null || echo "unknown")
        print_success "$submodule: OK (commit: $commit)"
    else
        print_success "$submodule: OK"
    fi

    ((SUCCESS_COUNT++))
    return 0
}

#######################################
# Verify all submodules
#######################################
verify_submodules() {
    print_header "Verifying Submodules"

    for submodule in "${SUBMODULES[@]}"; do
        verify_submodule "$submodule"
    done

    echo ""
    print_info "Submodule verification complete: $SUCCESS_COUNT succeeded, $FAILED_COUNT failed"
}

#######################################
# Install npm dependencies for a submodule
#######################################
install_deps_for_submodule() {
    local submodule=$1
    local path="$PROJECT_ROOT/$submodule"

    # Check if package.json exists
    if [[ ! -f "$path/package.json" ]]; then
        if [[ "$VERBOSE" == true ]]; then
            print_info "$submodule: No package.json found, skipping"
        fi
        return 0
    fi

    print_info "Installing dependencies for $submodule..."

    cd "$path"

    # Use pnpm if available and pnpm-lock.yaml exists, otherwise npm
    if [[ -f "pnpm-lock.yaml" ]] && command -v pnpm &> /dev/null; then
        if [[ "$VERBOSE" == true ]]; then
            pnpm install
        else
            pnpm install --silent 2>/dev/null || pnpm install
        fi
    elif [[ -f "package-lock.json" ]] || [[ -f "package.json" ]]; then
        if command -v npm &> /dev/null; then
            if [[ "$VERBOSE" == true ]]; then
                npm install
            else
                npm install --silent 2>/dev/null || npm install
            fi
        else
            print_warning "$submodule: npm not found, skipping dependency installation"
            return 0
        fi
    fi

    print_success "$submodule: Dependencies installed"
    return 0
}

#######################################
# Install dependencies for all submodules
#######################################
install_all_deps() {
    print_header "Installing Dependencies"

    if [[ "$SKIP_DEPS" == true ]]; then
        print_info "Skipping dependency installation (--skip-deps flag)"
        return 0
    fi

    if ! command -v npm &> /dev/null && ! command -v pnpm &> /dev/null; then
        print_warning "Neither npm nor pnpm found. Skipping dependency installation."
        print_info "Please install Node.js 20+ to install dependencies later."
        return 0
    fi

    for submodule in "${SUBMODULES[@]}"; do
        install_deps_for_submodule "$submodule" || true
    done

    cd "$PROJECT_ROOT"
}

#######################################
# Configure Git settings for submodules
#######################################
configure_git_settings() {
    print_header "Configuring Git Settings"

    cd "$PROJECT_ROOT"

    # Set recommended submodule settings
    git config --local submodule.recurse true 2>/dev/null || true
    git config --local diff.submodule log 2>/dev/null || true
    git config --local status.submodulesummary 1 2>/dev/null || true

    print_success "Git submodule settings configured"

    if [[ "$VERBOSE" == true ]]; then
        print_info "  submodule.recurse = true"
        print_info "  diff.submodule = log"
        print_info "  status.submodulesummary = 1"
    fi
}

#######################################
# Print summary and next steps
#######################################
print_summary() {
    print_header "Initialization Complete"

    echo ""
    echo "Summary:"
    echo "  - Submodules initialized: $SUCCESS_COUNT"

    if [[ $FAILED_COUNT -gt 0 ]]; then
        echo "  - Submodules failed: $FAILED_COUNT"
        echo ""
        print_warning "The following submodules failed to initialize:"
        for module in "${FAILED_MODULES[@]}"; do
            echo "    - $module"
        done
        echo ""
        print_info "This may be due to access permissions. Check your SSH key configuration:"
        echo "    ssh -T git@github.com"
        echo ""
        print_info "To retry a specific submodule:"
        echo "    git submodule update --init <submodule-name>"
    fi

    echo ""
    print_info "Next Steps:"
    echo ""
    echo "  1. Start the core platform:"
    echo "     cd eldrin-core && npm run dev"
    echo ""
    echo "  2. Start an app (in a new terminal):"
    echo "     cd eldrin-invoicing && npm run dev"
    echo ""
    echo "  3. View documentation:"
    echo "     cd eldrin-docs && npm run dev"
    echo ""
    echo "  For more information, see README.md"
    echo ""
}

#######################################
# Main entry point
#######################################
main() {
    echo ""
    echo "  ______  _      _      _       "
    echo " |  ____|| |    | |    (_)      "
    echo " | |__   | |  __| |_ __ _ _ __  "
    echo " |  __|  | | / _\` | '__| | '_ \\ "
    echo " | |____ | || (_| | |  | | | | |"
    echo " |______||_| \\__,_|_|  |_|_| |_|"
    echo ""
    echo "  Project Initialization Script"
    echo ""

    parse_args "$@"

    check_git_version
    check_project_root
    init_submodules
    verify_submodules
    configure_git_settings
    install_all_deps
    print_summary

    # Exit with error if any submodules failed
    if [[ $FAILED_COUNT -gt 0 ]]; then
        exit 1
    fi

    exit 0
}

# Run main function
main "$@"
