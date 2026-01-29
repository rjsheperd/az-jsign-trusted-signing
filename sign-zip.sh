#!/usr/bin/env bash

set -euo pipefail

# Azure Code Signing Tool
# Signs Windows executables (.exe, .dll) and Java archives (.jar) in a ZIP file
# using Azure Trusted Signing service

readonly SCRIPT_NAME="$(basename "$0")"
readonly JSIGN_VERSION="7.4"
readonly JSIGN_JAR="jsign-${JSIGN_VERSION}.jar"
readonly TIMESTAMP_URL="http://timestamp.acs.microsoft.com"
readonly DEFAULT_PARALLEL_JOBS=8
readonly DEFAULT_EXTRACT_DIR="signing-temp"

# Default values
PARALLEL_JOBS="${DEFAULT_PARALLEL_JOBS}"
EXTRACT_DIR="${DEFAULT_EXTRACT_DIR}"
VERBOSE=false
KEEP_TEMP=false

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME [OPTIONS] -f ZIP_FILE [-v VERSION] -a ALIAS -r REGION

Signs Windows executables and Java archives in a ZIP file using Azure Trusted Signing.

Required Arguments:
  -f, --file FILE          Path to the ZIP file to sign
  -a, --alias ALIAS        Azure Trusted Signing alias (or set TS_ALIAS env var)
  -r, --region REGION      Azure region domain (or set AZURE_REGION_DOMAIN env var)

Optional Arguments:
  -v, --version VERSION    Version string for output file (auto-detected from filename if not provided)
  -j, --jobs NUM           Number of parallel signing jobs (default: $DEFAULT_PARALLEL_JOBS)
  -d, --extract-dir DIR    Directory to extract ZIP (default: $DEFAULT_EXTRACT_DIR)
  -k, --keep-temp          Keep temporary extracted files after signing
  -V, --verbose            Enable verbose output
  -h, --help               Show this help message

Environment Variables:
  TS_ALIAS                 Default alias if not provided via -a
  AZURE_REGION_DOMAIN      Default Azure region if not provided via -r

Version Detection:
  If -v is not provided, the script will attempt to extract the version from the filename.
  Supported patterns:
    - app-1.0.0.zip         -> 1.0.0
    - app-v1.0.0.zip        -> 1.0.0
    - app-1.0.0-beta.zip    -> 1.0.0-beta
    - app_v2.1.3.zip        -> 2.1.3

Examples:
  # Auto-detect version from filename
  $SCRIPT_NAME -f my-app-v1.0.0.zip -a my-alias -r eastus.codesigning.azure.net

  # Explicit version
  $SCRIPT_NAME -f app.zip -v 1.0.0 -a my-alias -r eastus.codesigning.azure.net

  # Using environment variables
  export TS_ALIAS=my-alias
  export AZURE_REGION_DOMAIN=eastus.codesigning.azure.net
  $SCRIPT_NAME -f my-app-v2.3.1.zip

  # With custom parallel jobs and verbose output
  $SCRIPT_NAME -f app-1.0.0.zip -V -j 16 -a my-alias -r eastus.codesigning.azure.net

EOF
    exit 0
}

error() {
    echo "Error: $*" >&2
    exit 1
}

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

log_verbose() {
    if [[ "$VERBOSE" == true ]]; then
        log "$@"
    fi
}

extract_version_from_filename() {
    local filename="$1"
    local basename
    basename="$(basename "$filename" .zip)"

    # Try to extract version using various patterns
    # Patterns supported:
    #   - app-v1.0.0
    #   - app-1.0.0
    #   - app_v1.0.0
    #   - app_1.0.0
    #   - 1.0.0 (just the version)
    #   - With prerelease: 1.0.0-beta, 1.0.0-alpha.1, etc.

    local version=""

    # Pattern 1: Extract vX.Y.Z or X.Y.Z with optional prerelease
    if [[ "$basename" =~ -v?([0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?)$ ]]; then
        version="${BASH_REMATCH[1]}"
    elif [[ "$basename" =~ _v?([0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?)$ ]]; then
        version="${BASH_REMATCH[1]}"
    # Pattern 2: Try X.Y format (shorter version)
    elif [[ "$basename" =~ -v?([0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?)$ ]]; then
        version="${BASH_REMATCH[1]}"
    elif [[ "$basename" =~ _v?([0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?)$ ]]; then
        version="${BASH_REMATCH[1]}"
    fi

    echo "$version"
}

check_dependencies() {
    local deps=("az" "java" "jarsigner" "unzip" "zip")
    local missing=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Missing required dependencies: ${missing[*]}"
    fi

    if [[ ! -f "$JSIGN_JAR" ]]; then
        error "JSSign JAR not found: $JSIGN_JAR"
    fi
}

get_access_token() {
    az account get-access-token \
        --resource https://codesigning.azure.net \
        --query accessToken \
        --output tsv || error "Failed to get Azure access token"
}

sign_windows_binary() {
    local file="$1"
    local storepass="$2"

    log_verbose "Signing $file"
    log_verbose "Signing with: $PWD/$JSIGN_JAR"

    java -jar "$PWD/$JSIGN_JAR" \
        --storetype TRUSTEDSIGNING \
        --keystore "https://${AZURE_REGION_DOMAIN}" \
        --storepass $storepass \
        --alias "$TS_ALIAS" \
        "$PWD/$file"
}

sign_windows_binaries() {
    local storepass="$1"
    local count=0

    log "Signing Windows executables and libraries..."

    # Find all .exe and .dll files
    while IFS= read -r -d '' file; do
        (
          sign_windows_binary "$file" "$storepass"
        ) &

        # Limit parallel jobs
        if [[ $(jobs -r -p | wc -l) -ge $PARALLEL_JOBS ]]; then
          wait -n
        fi
    done < <(find "$EXTRACT_DIR" -type f \( -name "*.exe" -o -name "*.dll" \) -print0)

    # Wait for all background jobs to complete
    wait

    log "Signed Windows binaries"
}

sign_jar_files() {
    local storepass="$1"
    local jar_count=0

    log "Signing JAR files..."

    while IFS= read -r -d '' jar_file; do
        ((jar_count++))
        log_verbose "Signing JAR: $jar_file"

        jarsigner \
            -J-cp -J"$PWD/$JSIGN_JAR" \
            -J--add-modules -Jjava.sql \
            -providerClass net.jsign.jca.JsignJcaProvider \
            -providerArg "$AZURE_REGION_DOMAIN" \
            -storepass "$storepass" \
            -tsadigestalg SHA-256 \
            -sigalg SHA256withRSA \
            -digestalg SHA-256 \
            -tsa "$TIMESTAMP_URL" \
            ${VERBOSE:+-verbose} \
            -keystore NONE \
            -storetype TRUSTEDSIGNING \
            "$jar_file" "$TS_ALIAS"

        log_verbose "Verifying JAR signature: $jar_file"
        jarsigner -verify "$jar_file" || error "JAR signature verification failed: $jar_file"
    done < <(find "$EXTRACT_DIR" -type f -name "*.jar" -print0)

    log "Signed and verified $jar_count JAR files"
}

main() {
    local zip_file=""
    local version=""

    # Parse command-line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -f|--file)
                zip_file="$2"
                shift 2
                ;;
            -v|--version)
                version="$2"
                shift 2
                ;;
            -a|--alias)
                TS_ALIAS="$2"
                shift 2
                ;;
            -r|--region)
                AZURE_REGION_DOMAIN="$2"
                shift 2
                ;;
            -j|--jobs)
                PARALLEL_JOBS="$2"
                shift 2
                ;;
            -d|--extract-dir)
                EXTRACT_DIR="$2"
                shift 2
                ;;
            -k|--keep-temp)
                KEEP_TEMP=true
                shift
                ;;
            -V|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                usage
                ;;
            *)
                error "Unknown option: $1. Use -h for help."
                ;;
        esac
    done

    # Validate required arguments
    [[ -z "$zip_file" ]] && error "ZIP file is required (-f). Use -h for help."
    [[ -z "${TS_ALIAS:-}" ]] && error "Alias is required (-a or TS_ALIAS env var). Use -h for help."
    [[ -z "${AZURE_REGION_DOMAIN:-}" ]] && error "Azure region domain is required (-r or AZURE_REGION_DOMAIN env var). Use -h for help."

    # Validate file exists
    [[ ! -f "$zip_file" ]] && error "ZIP file not found: $zip_file"

    # Auto-detect version from filename if not provided
    if [[ -z "$version" ]]; then
        version=$(extract_version_from_filename "$zip_file")
        if [[ -z "$version" ]]; then
            error "Version could not be detected from filename. Please specify with -v. Use -h for help."
        fi
        log "Auto-detected version from filename: $version"
    fi

    # Check dependencies
    check_dependencies

    log "Starting Azure Code Signing"
    log "  ZIP file: $zip_file"
    log "  Version: $version"
    log "  Alias: $TS_ALIAS"
    log "  Region: $AZURE_REGION_DOMAIN"
    log "  Parallel jobs: $PARALLEL_JOBS"

    # Get Azure access token
    local storepass
    storepass=$(get_access_token)

    # Clean up existing extraction directory
    if [[ -d "$EXTRACT_DIR" ]]; then
        log "Removing existing extraction directory: $EXTRACT_DIR"
        rm -rf "$EXTRACT_DIR"
    fi

    # Extract ZIP file
    log "Extracting ZIP file to $EXTRACT_DIR..."
    unzip -q "$zip_file" -d "$EXTRACT_DIR" || error "Failed to extract ZIP file"

    # Sign Windows binaries
    sign_windows_binaries "$storepass"

    # Sign JAR files
    sign_jar_files "$storepass"

    # Create signed ZIP
    local output_file
    if [[ -z $(extract_version_from_filename) ]]; then
        output_file="$(basename "$zip_file" .zip)-signed.zip"
    else
        output_file="$(basename "$zip_file" .zip)-${version}-signed.zip"
    fi

    log "Creating signed ZIP: $output_file"
    (cd "$EXTRACT_DIR" && zip -qr "../$output_file" .) || error "Failed to create signed ZIP"

    # Clean up temporary files
    if [[ "$KEEP_TEMP" != true ]]; then
        log "Cleaning up temporary files..."
        rm -rf "$EXTRACT_DIR"
    else
        log "Keeping temporary files in: $EXTRACT_DIR"
    fi

    log "✓ Signing complete: $output_file"
}

# Run main function
main "$@"
