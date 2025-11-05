#!/bin/bash

# Check for dialog or whiptail
if ! command -v dialog &> /dev/null && ! command -v whiptail &> /dev/null;
then
    echo "dialog or whiptail is not installed. Please install it to use the TUI."
    # Ask user if they want to install dialog
    read -p "Do you want to install dialog? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Check for sudo
        if ! command -v sudo &> /dev/null;
            then
            echo "sudo not found. Please install dialog manually."
            exit 1
        fi
        # Check for apt
        if command -v apt &> /dev/null;
            then
            sudo apt update && sudo apt install -y dialog
        # Check for yum
        elif command -v yum &> /dev/null;
            then
            sudo yum install -y dialog
        # Check for dnf
        elif command -v dnf &> /dev/null;
            then
            sudo dnf install -y dialog
        # Check for pacman
        elif command -v pacman &> /dev/null;
            then
            sudo pacman -S --noconfirm dialog
        else
            echo "Could not find a package manager to install dialog. Please install it manually."
            exit 1
        fi
    else
        exit 1
    fi
fi

# Use dialog or whiptail
if command -v dialog &> /dev/null;
    then
    DIALOG=dialog
else
    DIALOG=whiptail
fi

# --- Default values ---
URLS_FILE=${URLS_FILE:-"urls.txt"}
MODE=${MODE:-"parallel"}
NETWORK=${NETWORK:-"tor"}
TOR_PROXY=${TOR_PROXY:-"9050"}
TOR_CTL=${TOR_CTL:-"9051"}
TOR_PASS=${TOR_PASS:-""}
I2P_PROXY=${I2P_PROXY:-""}
OUT_DIR=${OUT_DIR:-"artifacts"}
QUAR_DIR=${QUAR_DIR:-"quarantine"}
LOG_DIR=${LOG_DIR:-"logs"}
AUDIT_LOG=${AUDIT_LOG:-"logs/audit.jsonl"}
MAX_WORKERS=${MAX_WORKERS:-"3"}
PER_HOST_CAP=${PER_HOST_CAP:-"2"}
MAX_RETRIES=${MAX_RETRIES:-"3"}
RETRY_BASE_DELAY=${RETRY_BASE_DELAY:-"3.0"}
MAX_FILE_MB=${MAX_FILE_MB:-"1024"}
ALLOW_DOMAINS=${ALLOW_DOMAINS:-""}
DENY_TLDS=${DENY_TLDS:-""}
ENFORCE_MIME=${ENFORCE_MIME:-"1"}
YARA_DIR=${YARA_DIR:-"yara_rules"}

# --- Descriptions for environment variables ---
declare -A DESCRIPTIONS
DESCRIPTIONS["URLS_FILE"]="Path to the file containing URLs to download."
DESCRIPTIONS["MODE"]="parallel or sequential."
DESCRIPTIONS["NETWORK"]="tor, i2p, or clearnet."
DESCRIPTIONS["TOR_PROXY"]="Tor SOCKS proxy port."
DESCRIPTIONS["TOR_CTL"]="Tor control port."
DESCRIPTIONS["TOR_PASS"]="Tor control port password."
DESCRIPTIONS["I2P_PROXY"]="I2P HTTP proxy URL."
DESCRIPTIONS["OUT_DIR"]="Output directory for downloaded files."
DESCRIPTIONS["QUAR_DIR"]="Quarantine directory for downloaded files before they are moved to OUT_DIR."
DESCRIPTIONS["LOG_DIR"]="Directory for log files."
DESCRIPTIONS["AUDIT_LOG"]="Path to the audit log file (JSONL format)."
DESCRIPTIONS["MAX_WORKERS"]="Maximum number of download threads in parallel mode."
DESCRIPTIONS["PER_HOST_CAP"]="Maximum number of concurrent downloads per host."
DESCRIPTIONS["MAX_RETRIES"]="Maximum number of retries for a failed download."
DESCRIPTIONS["RETRY_BASE_DELAY"]="Base delay in seconds for retries."
DESCRIPTIONS["MAX_FILE_MB"]="Maximum file size in megabytes."
DESCRIPTIONS["ALLOW_DOMAINS"]="Comma-separated list of allowed domains."
DESCRIPTIONS["DENY_TLDS"]="Comma-separated list of denied TLDs."
DESCRIPTIONS["ENFORCE_MIME"]="Enforce MIME type matching between Content-Type header and file content."
DESCRIPTIONS["YARA_DIR"]="Directory containing YARA rules."

# --- TUI functions ---
edit_var() {
    local var_name="$1"
    local current_value="${!var_name}"
    local description="${DESCRIPTIONS[$var_name]}"
    local new_value=$($DIALOG --inputbox "$description\n\nEnter new value for $var_name" 10 78 "$current_value" 3>&1 1>&2 2>&3)
    if [ $? -eq 0 ]; then
        eval "$var_name=\"$new_value\""
    fi
}

main_menu() {
    while true; do
        choice=$($DIALOG --menu "KAPLAN Environment Variables" 25 78 18 \
            1 "URLS_FILE: $URLS_FILE (${DESCRIPTIONS[URLS_FILE]})" \
            2 "MODE: $MODE (${DESCRIPTIONS[MODE]})" \
            3 "NETWORK: $NETWORK (${DESCRIPTIONS[NETWORK]})" \
            4 "TOR_PROXY: $TOR_PROXY (${DESCRIPTIONS[TOR_PROXY]})" \
            5 "TOR_CTL: $TOR_CTL (${DESCRIPTIONS[TOR_CTL]})" \
            6 "TOR_PASS: $TOR_PASS (${DESCRIPTIONS[TOR_PASS]})" \
            7 "I2P_PROXY: $I2P_PROXY (${DESCRIPTIONS[I2P_PROXY]})" \
            8 "OUT_DIR: $OUT_DIR (${DESCRIPTIONS[OUT_DIR]})" \
            9 "QUAR_DIR: $QUAR_DIR (${DESCRIPTIONS[QUAR_DIR]})" \
            10 "LOG_DIR: $LOG_DIR (${DESCRIPTIONS[LOG_DIR]})" \
            11 "AUDIT_LOG: $AUDIT_LOG (${DESCRIPTIONS[AUDIT_LOG]})" \
            12 "MAX_WORKERS: $MAX_WORKERS (${DESCRIPTIONS[MAX_WORKERS]})" \
            13 "PER_HOST_CAP: $PER_HOST_CAP (${DESCRIPTIONS[PER_HOST_CAP]})" \
            14 "MAX_RETRIES: $MAX_RETRIES (${DESCRIPTIONS[MAX_RETRIES]})" \
            15 "RETRY_BASE_DELAY: $RETRY_BASE_DELAY (${DESCRIPTIONS[RETRY_BASE_DELAY]})" \
            16 "MAX_FILE_MB: $MAX_FILE_MB (${DESCRIPTIONS[MAX_FILE_MB]})" \
            17 "ALLOW_DOMAINS: $ALLOW_DOMAINS (${DESCRIPTIONS[ALLOW_DOMAINS]})" \
            18 "DENY_TLDS: $DENY_TLDS (${DESCRIPTIONS[DENY_TLDS]})" \
            19 "ENFORCE_MIME: $ENFORCE_MIME (${DESCRIPTIONS[ENFORCE_MIME]})" \
            20 "YARA_DIR: $YARA_DIR (${DESCRIPTIONS[YARA_DIR]})" \
            "Run" "Run KAPLAN with these settings" 
            3>&1 1>&2 2>&3)

        case "$choice" in
            1) edit_var URLS_FILE ;;
            2) edit_var MODE ;;
            3) edit_var NETWORK ;;
            4) edit_var TOR_PROXY ;;
            5) edit_var TOR_CTL ;;
            6) edit_var TOR_PASS ;;
            7) edit_var I2P_PROXY ;;
            8) edit_var OUT_DIR ;;
            9) edit_var QUAR_DIR ;;
            10) edit_var LOG_DIR ;;
            11) edit_var AUDIT_LOG ;;
            12) edit_var MAX_WORKERS ;;
            13) edit_var PER_HOST_CAP ;;
            14) edit_var MAX_RETRIES ;;
            15) edit_var RETRY_BASE_DELAY ;;
            16) edit_var MAX_FILE_MB ;;
            17) edit_var ALLOW_DOMAINS ;;
            18) edit_var DENY_TLDS ;;
            19) edit_var ENFORCE_MIME ;;
            20) edit_var YARA_DIR ;;
            "Run") break ;;
            *) break ;;
        esac
    done
}

# --- Main script ---

# Show TUI if no arguments are passed
if [ $# -eq 0 ]; then
    main_menu
fi

# Check if the virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate the virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Export variables
export URLS_FILE
export MODE
export NETWORK
export TOR_PROXY
export TOR_CTL
export TOR_PASS
export I2P_PROXY
export OUT_DIR
export QUAR_DIR
export LOG_DIR
export AUDIT_LOG
export MAX_WORKERS
export PER_HOST_CAP
export MAX_RETRIES
export RETRY_BASE_DELAY
export MAX_FILE_MB
export ALLOW_DOMAINS
export DENY_TLDS
export ENFORCE_MIME
export YARA_DIR

# Run the script
python kaplan.py "$@"
