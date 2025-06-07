#!/bin/bash
#
# HaxUnit Bootstrapper
#
# A robust, secure, and intelligent script to initialize the HaxUnit environment.
# It ensures all prerequisites are met, uses modern Docker commands, and provides
# clear, actionable feedback to the user.
#

# --- Script Configuration and Best Practices ---

# Exit immediately if a command exits with a non-zero status.
# Exit immediately if a pipeline returns a non-zero status.
# Treat unset variables as an error when substituting.
# The '-o pipefail' is crucial for catching errors in pipelines.
set -euo pipefail

# --- Color Definitions for Better Readability ---
# Use tput for POSIX-compliant color handling, which is more portable than raw escape codes.
# It gracefully fails if the terminal doesn't support colors.
if tput setaf 1 >&/dev/null; then
    C_BLUE=$(tput setaf 4)
    C_GREEN=$(tput setaf 2)
    C_YELLOW=$(tput setaf 3)
    C_RED=$(tput setaf 1)
    C_BOLD=$(tput bold)
    C_RESET=$(tput sgr0)
else
    # If tput is not available, fall back to empty strings.
    C_BLUE=""
    C_GREEN=""
    C_YELLOW=""
    C_RED=""
    C_BOLD=""
    C_RESET=""
fi

# --- Helper Functions for Cleanliness and Reusability ---

# A standardized logging function.
# Usage: log_info "Your message here"
log_info() {
    echo "${C_BLUE}${C_BOLD}[HaxUnit]${C_RESET} ${C_BLUE}$1${C_RESET}"
}

log_success() {
    echo "${C_GREEN}${C_BOLD}[HaxUnit]${C_RESET} ${C_GREEN}$1${C_RESET}"
}

log_warn() {
    echo "${C_YELLOW}${C_BOLD}[HaxUnit]${C_RESET} ${C_YELLOW}$1${C_RESET}"
}

# A standardized error function that exits the script.
# Usage: log_error "Your error message"
log_error() {
    echo "${C_RED}${C_BOLD}[HaxUnit] ERROR:${C_RESET} ${C_RED}$1${C_RESET}" >&2
    exit 1
}

# Function to check if a command exists. More reliable than 'command -v'.
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# --- Prerequisite Checks ---

log_info "Starting prerequisite checks..."

# Check 1: Docker Engine
if ! command_exists docker; then
    log_error "Docker is not installed. Please install Docker before running this script. See: https://docs.docker.com/engine/install/"
fi

log_info "Docker is installed."

# Check 2: Docker Compose Plugin (modern 'docker compose')
# The script now uses the integrated 'docker compose' command, which is the modern standard.
# It checks if the 'compose' plugin is available for the docker command.
if ! docker compose version >/dev/null 2>&1; then
    log_warn "The modern 'docker compose' plugin is not available."
    log_info "Attempting to install Docker Compose plugin..."
    # This installation method is more robust and fetches the latest version.
    # We avoid hardcoding versions.
    LATEST_COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    if [ -z "$LATEST_COMPOSE_VERSION" ]; then
        log_error "Could not determine the latest Docker Compose version. Please install it manually."
    fi
    # Create the plugin directory if it doesn't exist.
    mkdir -p ~/.docker/cli-plugins
    log_info "Downloading Docker Compose ${LATEST_COMPOSE_VERSION}..."
    curl -SL "https://github.com/docker/compose/releases/download/${LATEST_COMPOSE_VERSION}/docker-compose-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)" -o ~/.docker/cli-plugins/docker-compose
    chmod +x ~/.docker/cli-plugins/docker-compose

    # Verify installation
    if docker compose version >/dev/null 2>&1; then
        log_success "Docker Compose plugin installed successfully."
    else
        log_error "Failed to install the Docker Compose plugin. Please install it manually."
    fi
fi

log_info "Docker Compose plugin is available."

# --- Environment Initialization ---

# Check for the existence of the .env file and secrets, as they are now crucial.
if [ ! -f .env ] || [ ! -d secrets ]; then
    log_warn "Configuration files are missing."
    log_info "Please ensure you have a '.env' file for environment variables and a 'secrets/' directory for API keys as per the docker-compose.yml setup."
    # Optionally, create templates here if they don't exist.
fi

log_info "Shutting down any existing HaxUnit services to ensure a clean slate..."
# The '--timeout 0' makes the shutdown immediate.
docker compose down --volumes --remove-orphans --timeout 0

log_info "Building the HaxUnit image... This may take a while on the first run."
# The || construct for error handling is good, but our 'set -e' handles this automatically.
# We wrap it in a block for a cleaner error message.
docker compose build || log_error "Failed to build the Docker image."

log_info "Starting HaxUnit services in detached mode..."
docker compose up -d || log_error "Failed to start Docker containers."

# --- Post-Start Verification and User Instructions ---

log_info "Verifying that the 'haxunit' container is running and healthy..."

# A more robust check:
# 1. Check if the container is running.
# 2. Check if it is healthy (based on the healthcheck in the compose file).
if ! docker ps --filter "name=haxunit" --filter "status=running" --quiet | grep -q .; then
    log_error "'haxunit' container is not running. Check the logs above or run 'docker compose logs haxunit'."
fi

log_info "Waiting for the 'haxunit' container to become healthy..."
# This loop waits for the health status to be 'healthy'.
# Timeout after 60 seconds.
for i in {1..20}; do
    if [[ "$(docker inspect --format '{{.State.Health.Status}}' haxunit 2>/dev/null)" == "healthy" ]]; then
        clear
        log_success "🎉 Installation Complete! HaxUnit is now ready to rock! 🎉"
        echo ""
        echo "${C_BOLD}HaxUnit is now running and healthy.${C_RESET}"
        echo "Time to find those vulnerabilities and patch them like a pro! 🕵️‍♂️🔍"
        echo ""
        echo "🚀 ${C_BOLD}To enter the HaxUnit shell, run the following command:${C_RESET}"
        echo "   docker exec -it haxunit /bin/bash"
        echo ""
        echo "🚀 ${C_BOLD}To start a scan directly, run:${C_RESET}"
        echo "   haxunit -d <domain>"
        exit 0
    fi
    sleep 3
done

log_error "The 'haxunit' container started but did not become healthy in time. Check the logs with 'docker compose logs haxunit'."