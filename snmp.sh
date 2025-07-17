#!/bin/bash
#
# SNMP.sh Beast Mode – Ultimate OSCP Edition (Enhanced++)
# Author: BlackLotus 
# Version: 3.0
#

# ================== REQUIRED TOOLS CHECK ==================
REQUIRED_TOOLS=(snmpwalk snmpbulkwalk snmpget snmpset grep timeout sed awk sort uniq parallel jq)
MISSING_TOOLS=()

for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" &>/dev/null; then
        MISSING_TOOLS+=("$tool")
    fi
done

if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    echo -e "\e[1;31m[!] Missing required tools: ${MISSING_TOOLS[*]}\e[0m"
    echo -e "\e[1;33m[*] Install with: apt-get install snmp snmp-mibs-downloader parallel jq\e[0m"
    # Don't exit - allow script to run with reduced functionality
    NO_PARALLEL=1
fi

# ================== CONFIG DEFAULTS ==================
TARGET=""
COMMUNITY="public"
VERSION="2c"
OUTPUT_BASE_DIR="output"
BRUTE=0
EXTRAS=0
WRITE_TEST=0
HTML_REPORT=0
JSON_OUTPUT=0
THREADS=10
VERBOSE=0

# SNMPv3 defaults
V3_USER=""
V3_LEVEL=""
V3_AUTH_PROTO=""
V3_AUTH_PASS=""
V3_PRIV_PROTO=""
V3_PRIV_PASS=""

# Wordlists
WORDLIST="/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt"
CUSTOM_WORDLIST=""

# Timeouts (in seconds)
TIMEOUT_PING=5
TIMEOUT_WALK=60
TIMEOUT_FULL_DUMP=120
RETRY_COUNT=3

# ================== COLORS ==================
RED="\033[1;31m"
GREEN="\033[1;32m"
BLUE="\033[1;34m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
MAGENTA="\033[1;35m"
NC="\033[0m"

# ================== HELPER FUNCTIONS ==================
print_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
   _____ _   _ __  __ _____    ____                 _     __  __           _      
  / ____| \ | |  \/  |  __ \  |  _ \               | |   |  \/  |         | |     
 | (___ |  \| | \  / | |__) | | |_) | ___  __ _ ___| |_  | \  / | ___   __| | ___ 
  \___ \| . ` | |\/| |  ___/  |  _ < / _ \/ _` / __| __| | |\/| |/ _ \ / _` |/ _ \
  ____) | |\  | |  | | |      | |_) |  __/ (_| \__ \ |_  | |  | | (_) | (_| |  __/
 |_____/|_| \_|_|  |_|_|      |____/ \___|\__,_|___/\__| |_|  |_|\___/ \__,_|\___|
                                                                          
EOF
    echo -e "${NC}"
}

print_header() {
    echo -e "\n${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "┃ $1"
    echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_good() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warn() {
    echo -e "${RED}[!]${NC} $1"
}

print_debug() {
    if [[ "$VERBOSE" == "1" ]]; then
        echo -e "${MAGENTA}[DEBUG]${NC} $1"
    fi
}

# Progress bar for long operations
show_progress() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# Sanitize TARGET for directory names
sanitize_target() {
    local raw="$1"
    echo "$raw" | sed 's/[^A-Za-z0-9._-]/_/g'
}

# Get timestamp
get_timestamp() {
    date "+%Y%m%d_%H%M%S"
}

# ================== ENHANCED SNMP FUNCTIONS ==================
# Test if SNMP is accessible with retry logic
test_snmp_access() {
    local retries=0
    while [ $retries -lt $RETRY_COUNT ]; do
        print_debug "Testing SNMP access (attempt $((retries+1))/$RETRY_COUNT)"
        
        if [[ "$VERSION" == "3" ]]; then
            timeout "$TIMEOUT_PING" snmpget -v3 \
                -u "$V3_USER" -l "$V3_LEVEL" \
                -a "$V3_AUTH_PROTO" -A "$V3_AUTH_PASS" \
                -x "$V3_PRIV_PROTO" -X "$V3_PRIV_PASS" \
                "$TARGET" 1.3.6.1.2.1.1.1.0 &>/dev/null
        else
            timeout "$TIMEOUT_PING" snmpget -v"$VERSION" -c "$COMMUNITY" "$TARGET" 1.3.6.1.2.1.1.1.0 &>/dev/null
        fi
        
        if [ $? -eq 0 ]; then
            return 0
        fi
        
        retries=$((retries + 1))
        [ $retries -lt $RETRY_COUNT ] && sleep 2
    done
    return 1
}

# Enhanced SNMP command with automatic fallback
snmp_cmd() {
    local cmd_type="$1"   # "walk", "bulkwalk", "get", "set"
    local mib="$2"
    local outfile="$3"
    local extra_args="${4:-}"
    
    print_debug "Running $cmd_type on $mib"
    
    if [[ "$VERSION" == "3" ]]; then
        case "$cmd_type" in
            "walk")
                timeout "$TIMEOUT_WALK" snmpwalk -v3 \
                    -u "$V3_USER" -l "$V3_LEVEL" \
                    -a "$V3_AUTH_PROTO" -A "$V3_AUTH_PASS" \
                    -x "$V3_PRIV_PROTO" -X "$V3_PRIV_PASS" \
                    $extra_args "$TARGET" "$mib" > "$outfile" 2>&1
                ;;
            "bulkwalk")
                timeout "$TIMEOUT_WALK" snmpbulkwalk -v3 \
                    -u "$V3_USER" -l "$V3_LEVEL" \
                    -a "$V3_AUTH_PROTO" -A "$V3_AUTH_PASS" \
                    -x "$V3_PRIV_PROTO" -X "$V3_PRIV_PASS" \
                    -Cr25 $extra_args "$TARGET" "$mib" > "$outfile" 2>&1
                ;;
            "get")
                timeout "$TIMEOUT_PING" snmpget -v3 \
                    -u "$V3_USER" -l "$V3_LEVEL" \
                    -a "$V3_AUTH_PROTO" -A "$V3_AUTH_PASS" \
                    -x "$V3_PRIV_PROTO" -X "$V3_PRIV_PASS" \
                    $extra_args "$TARGET" "$mib" > "$outfile" 2>&1
                ;;
        esac
    else
        case "$cmd_type" in
            "walk")
                timeout "$TIMEOUT_WALK" snmpwalk -v"$VERSION" -c "$COMMUNITY" \
                    $extra_args "$TARGET" "$mib" > "$outfile" 2>&1
                ;;
            "bulkwalk")
                timeout "$TIMEOUT_WALK" snmpbulkwalk -v"$VERSION" -c "$COMMUNITY" \
                    -Cr25 $extra_args "$TARGET" "$mib" > "$outfile" 2>&1
                ;;
            "get")
                timeout "$TIMEOUT_PING" snmpget -v"$VERSION" -c "$COMMUNITY" \
                    $extra_args "$TARGET" "$mib" > "$outfile" 2>&1
                ;;
            "set")
                timeout "$TIMEOUT_PING" snmpset -v"$VERSION" -c "$COMMUNITY" \
                    $extra_args "$TARGET" "$mib" > "$outfile" 2>&1
                ;;
        esac
    fi
    return $?
}

# Smart SNMP walk with automatic fallback
safe_snmpwalk() {
    local desc="$1"
    local mib="$2"
    local outfile="$3"
    local extra_args="${4:-}"
    
    print_info "$desc"
    
    # Try walk first
    snmp_cmd "walk" "$mib" "$outfile" "$extra_args"
    if [ $? -ne 0 ] || [ ! -s "$outfile" ]; then
        print_debug "snmpwalk failed, trying snmpbulkwalk..."
        snmp_cmd "bulkwalk" "$mib" "$outfile" "$extra_args"
        if [ $? -ne 0 ] || [ ! -s "$outfile" ]; then
            # Try numeric OID if symbolic failed
            if [[ "$mib" =~ ^[A-Z] ]]; then
                local numeric_oid=$(get_numeric_oid "$mib")
                if [ -n "$numeric_oid" ]; then
                    print_debug "Trying numeric OID: $numeric_oid"
                    snmp_cmd "bulkwalk" "$numeric_oid" "$outfile" "$extra_args"
                    if [ $? -eq 0 ] && [ -s "$outfile" ]; then
                        print_good "$desc succeeded with numeric OID"
                        return 0
                    fi
                fi
            fi
            print_warn "Failed: $desc"
            echo "$desc ($mib)" >> "$OUTPUT_DIR/snmp-failures.txt"
            return 1
        else
            print_good "$desc succeeded with bulkwalk"
        fi
    else
        print_good "$desc succeeded"
    fi
    return 0
}

# Get numeric OID from symbolic name
get_numeric_oid() {
    local symbolic="$1"
    case "$symbolic" in
        "HOST-RESOURCES-MIB::hrSWRunName") echo "1.3.6.1.2.1.25.4.2.1.2" ;;
        "HOST-RESOURCES-MIB::hrSWRunPath") echo "1.3.6.1.2.1.25.4.2.1.4" ;;
        "HOST-RESOURCES-MIB::hrSWRunParameters") echo "1.3.6.1.2.1.25.4.2.1.5" ;;
        "UCD-SNMP-MIB::dskPath") echo "1.3.6.1.4.1.2021.9.1.2" ;;
        "UCD-SNMP-MIB::memAvailReal") echo "1.3.6.1.4.1.2021.4.6" ;;
        "NET-SNMP-EXTEND-MIB::nsExtendOutputFull") echo "1.3.6.1.4.1.8072.1.3.2.3.1.2" ;;
        *) echo "" ;;
    esac
}

# ================== ENHANCED ENUMERATION FUNCTIONS ==================
# Extract and analyze credentials with enhanced patterns
extract_credentials() {
    print_header "Advanced Credential Extraction"
    
    # Extended patterns for credential detection
    local patterns=(
        'pass(word)?[[:space:]]*[:=][[:space:]]*[^[:space:]]+'
        'pwd[[:space:]]*[:=][[:space:]]*[^[:space:]]+'
        'user(name)?[[:space:]]*[:=][[:space:]]*[^[:space:]]+'
        'login[[:space:]]*[:=][[:space:]]*[^[:space:]]+'
        'token[[:space:]]*[:=][[:space:]]*[^[:space:]]+'
        'api[_-]?key[[:space:]]*[:=][[:space:]]*[^[:space:]]+'
        'secret[[:space:]]*[:=][[:space:]]*[^[:space:]]+'
        'private[_-]?key'
        'BEGIN RSA PRIVATE KEY'
        'BEGIN OPENSSH PRIVATE KEY'
        'BEGIN DSA PRIVATE KEY'
        'BEGIN EC PRIVATE KEY'
        'mysql://[^[:space:]]+'
        'postgres://[^[:space:]]+'
        'mongodb://[^[:space:]]+'
        'redis://[^[:space:]]+'
        'ftp://[^[:space:]]+'
        'ssh://[^[:space:]]+'
        'ldap://[^[:space:]]+'
        '--password[[:space:]]+[^[:space:]]+'
        '-p[[:space:]]+[^[:space:]]+'
        'AKIA[0-9A-Z]{16}'  # AWS Access Key
        '[0-9a-zA-Z/+=]{40}'  # AWS Secret Key pattern
        'AIza[0-9A-Za-z_-]{35}'  # Google API Key
        'sk_live_[0-9a-zA-Z]{24}'  # Stripe API Key
        'xox[baprs]-[0-9a-zA-Z-]+'  # Slack Token
    )
    
    # Create comprehensive credential search
    > "$OUTPUT_DIR/snmp-creds-enhanced.txt"
    
    for pattern in "${patterns[@]}"; do
        print_debug "Searching for pattern: $pattern"
        grep -EHin "$pattern" "$OUTPUT_DIR"/snmp-*.txt 2>/dev/null | \
            grep -v "snmp-creds" >> "$OUTPUT_DIR/snmp-creds-enhanced.txt"
    done
    
    # Extract unique credentials and categorize
    if [ -s "$OUTPUT_DIR/snmp-creds-enhanced.txt" ]; then
        print_good "Found potential credentials"
        
        # Categorize findings
        grep -i "password\|pwd" "$OUTPUT_DIR/snmp-creds-enhanced.txt" > "$OUTPUT_DIR/creds-passwords.txt"
        grep -i "key\|token" "$OUTPUT_DIR/snmp-creds-enhanced.txt" > "$OUTPUT_DIR/creds-keys.txt"
        grep -i "user\|login" "$OUTPUT_DIR/snmp-creds-enhanced.txt" > "$OUTPUT_DIR/creds-users.txt"
        grep -E "mysql://|postgres://|mongodb://" "$OUTPUT_DIR/snmp-creds-enhanced.txt" > "$OUTPUT_DIR/creds-databases.txt"
        
        # Create JSON output if requested
        if [[ "$JSON_OUTPUT" == "1" ]]; then
            create_json_credentials
        fi
    else
        print_warn "No credentials found in SNMP data"
    fi
}

# Enhanced PID correlation with process tree analysis
analyze_processes() {
    print_header "Advanced Process Analysis"
    
    # Create process map
    > "$OUTPUT_DIR/process-map.txt"
    
    # Extract all PIDs with their info
    while IFS= read -r pid; do
        local name=$(grep "hrSWRunName\.$pid " "$OUTPUT_DIR/snmp-process-names.txt" 2>/dev/null | cut -d'"' -f2)
        local path=$(grep "hrSWRunPath\.$pid " "$OUTPUT_DIR/snmp-process-paths.txt" 2>/dev/null | cut -d'"' -f2)
        local args=$(grep "hrSWRunParameters\.$pid " "$OUTPUT_DIR/snmp-process-args.txt" 2>/dev/null | cut -d'"' -f2)
        
        if [ -n "$name" ]; then
            echo "PID:$pid|NAME:$name|PATH:$path|ARGS:$args" >> "$OUTPUT_DIR/process-map.txt"
        fi
    done < <(grep -Eo 'hrSWRunName\.[0-9]+' "$OUTPUT_DIR/snmp-process-names.txt" 2>/dev/null | sed 's/hrSWRunName\.//' | sort -u)
    
    # Identify interesting processes
    print_info "Identifying high-value targets..."
    
    # Database processes
    grep -Ei "mysql|postgres|mongodb|redis|oracle|mssql|mariadb" "$OUTPUT_DIR/process-map.txt" > "$OUTPUT_DIR/processes-databases.txt"
    
    # Web servers
    grep -Ei "apache|nginx|httpd|tomcat|jetty|iis|node|gunicorn|uwsgi" "$OUTPUT_DIR/process-map.txt" > "$OUTPUT_DIR/processes-webservers.txt"
    
    # Programming languages/interpreters
    grep -Ei "python|ruby|perl|php|java|dotnet" "$OUTPUT_DIR/process-map.txt" > "$OUTPUT_DIR/processes-interpreters.txt"
    
    # Security tools
    grep -Ei "nmap|burp|metasploit|nikto|sqlmap|hydra|john|hashcat" "$OUTPUT_DIR/process-map.txt" > "$OUTPUT_DIR/processes-security.txt"
    
    # Admin/Management tools
    grep -Ei "ssh|telnet|vnc|rdp|teamviewer|anydesk" "$OUTPUT_DIR/process-map.txt" > "$OUTPUT_DIR/processes-admin.txt"
    
    # Container/Virtualization
    grep -Ei "docker|containerd|lxc|qemu|vmware|virtualbox|hyperv|podman|kubectl" "$OUTPUT_DIR/process-map.txt" > "$OUTPUT_DIR/processes-containers.txt"
    
    # Create process summary
    create_process_summary
}

# Create process summary report
create_process_summary() {
    local summary="$OUTPUT_DIR/process-summary.txt"
    > "$summary"
    
    echo "=== Process Analysis Summary ===" >> "$summary"
    echo "Total processes: $(wc -l < "$OUTPUT_DIR/process-map.txt")" >> "$summary"
    echo "" >> "$summary"
    
    local categories=("databases" "webservers" "interpreters" "security" "admin" "containers")
    for cat in "${categories[@]}"; do
        local file="$OUTPUT_DIR/processes-$cat.txt"
        if [ -s "$file" ]; then
            echo "[$cat] Found $(wc -l < "$file") processes:" >> "$summary"
            awk -F'|' '{split($2,n,":");split($4,a,":");printf "  - %s: %s\n",n[2],a[2]}' "$file" | head -5 >> "$summary"
            [ $(wc -l < "$file") -gt 5 ] && echo "  ... and $(($(wc -l < "$file") - 5)) more" >> "$summary"
            echo "" >> "$summary"
        fi
    done
}

# Check for vulnerable software versions
check_vulnerabilities() {
    print_header "Vulnerability Analysis"
    
    > "$OUTPUT_DIR/potential-vulns.txt"
    
    # Extract version information
    grep -Eo '(Apache/[0-9.]+|nginx/[0-9.]+|OpenSSH_[0-9.]+|mysql\s+[0-9.]+|postgres\s+[0-9.]+)' \
        "$OUTPUT_DIR"/snmp-*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/software-versions.txt"
    
    # Check against known vulnerable versions
    while IFS= read -r version; do
        case "$version" in
            Apache/2.4.[0-9]|Apache/2.4.[0-3][0-9])
                echo "Apache < 2.4.46 - Multiple CVEs including CVE-2020-11984" >> "$OUTPUT_DIR/potential-vulns.txt"
                ;;
            nginx/1.[0-9].*|nginx/1.1[0-7].*)
                echo "nginx < 1.18 - Multiple CVEs including CVE-2019-9511" >> "$OUTPUT_DIR/potential-vulns.txt"
                ;;
            OpenSSH_[1-6].*)
                echo "OpenSSH < 7.0 - Multiple CVEs, consider enumeration with ssh-audit" >> "$OUTPUT_DIR/potential-vulns.txt"
                ;;
            mysql*5.[0-6].*)
                echo "MySQL < 5.7 - Multiple CVEs, check for UDF exploitation" >> "$OUTPUT_DIR/potential-vulns.txt"
                ;;
        esac
    done < "$OUTPUT_DIR/software-versions.txt"
    
    if [ -s "$OUTPUT_DIR/potential-vulns.txt" ]; then
        print_good "Found potential vulnerabilities"
        cat "$OUTPUT_DIR/potential-vulns.txt"
    fi
}

# Test SNMP write access
test_write_access() {
    if [[ "$WRITE_TEST" != "1" ]]; then
        return
    fi
    
    print_header "Testing SNMP Write Access"
    print_warn "Testing write access - this may modify target configuration!"
    
    # Test OID for write access (sysLocation)
    local test_oid="1.3.6.1.2.1.1.6.0"
    local original_value=""
    local test_value="SNMP_WRITE_TEST_$(date +%s)"
    
    # Get original value
    if [[ "$VERSION" == "3" ]]; then
        original_value=$(snmpget -v3 -u "$V3_USER" -l "$V3_LEVEL" \
            -a "$V3_AUTH_PROTO" -A "$V3_AUTH_PASS" \
            -x "$V3_PRIV_PROTO" -X "$V3_PRIV_PASS" \
            "$TARGET" "$test_oid" 2>/dev/null | cut -d'"' -f2)
    else
        original_value=$(snmpget -v"$VERSION" -c "$COMMUNITY" "$TARGET" "$test_oid" 2>/dev/null | cut -d'"' -f2)
    fi
    
    if [ -z "$original_value" ]; then
        print_warn "Could not retrieve original sysLocation value"
        return
    fi
    
    print_info "Original sysLocation: $original_value"
    
    # Attempt write
    if [[ "$VERSION" == "3" ]]; then
        snmpset -v3 -u "$V3_USER" -l "$V3_LEVEL" \
            -a "$V3_AUTH_PROTO" -A "$V3_AUTH_PASS" \
            -x "$V3_PRIV_PROTO" -X "$V3_PRIV_PASS" \
            "$TARGET" "$test_oid" s "$test_value" &>/dev/null
    else
        snmpset -v"$VERSION" -c "$COMMUNITY" "$TARGET" "$test_oid" s "$test_value" &>/dev/null
    fi
    
    if [ $? -eq 0 ]; then
        print_good "SNMP WRITE ACCESS CONFIRMED! This is a critical finding!"
        echo "CRITICAL: SNMP Write Access Confirmed" >> "$OUTPUT_DIR/critical-findings.txt"
        echo "Community: $COMMUNITY" >> "$OUTPUT_DIR/critical-findings.txt"
        echo "Exploit suggestion: snmpset for configuration changes" >> "$OUTPUT_DIR/critical-findings.txt"
        
        # Restore original value
        if [[ "$VERSION" == "3" ]]; then
            snmpset -v3 -u "$V3_USER" -l "$V3_LEVEL" \
                -a "$V3_AUTH_PROTO" -A "$V3_AUTH_PASS" \
                -x "$V3_PRIV_PROTO" -X "$V3_PRIV_PASS" \
                "$TARGET" "$test_oid" s "$original_value" &>/dev/null
        else
            snmpset -v"$VERSION" -c "$COMMUNITY" "$TARGET" "$test_oid" s "$original_value" &>/dev/null
        fi
        print_info "Restored original value"
    else
        print_info "No SNMP write access with current credentials"
    fi
}

# Create JSON output
create_json_output() {
    if [[ "$JSON_OUTPUT" != "1" ]]; then
        return
    fi
    
    print_header "Creating JSON Output"
    
    local json_file="$OUTPUT_DIR/snmp-enum-results.json"
    
    # Start JSON structure
    cat > "$json_file" << EOF
{
    "target": "$TARGET",
    "scan_time": "$(date -Iseconds)",
    "snmp_version": "$VERSION",
    "community": "$COMMUNITY",
    "system_info": {
EOF
    
    # Add system info if available
    if [ -s "$OUTPUT_DIR/snmp-system-info.txt" ]; then
        echo '        "raw": [' >> "$json_file"
        while IFS= read -r line; do
            echo "            \"$(echo "$line" | sed 's/"/\\"/g')\"," >> "$json_file"
        done < "$OUTPUT_DIR/snmp-system-info.txt"
        sed -i '$ s/,$//' "$json_file"  # Remove last comma
        echo '        ]' >> "$json_file"
    fi
    
    echo '    },' >> "$json_file"
    
    # Add credentials section
    echo '    "credentials": {' >> "$json_file"
    if [ -s "$OUTPUT_DIR/snmp-creds-enhanced.txt" ]; then
        echo '        "found": true,' >> "$json_file"
        echo '        "count": '$(wc -l < "$OUTPUT_DIR/snmp-creds-enhanced.txt")',' >> "$json_file"
        echo '        "items": [' >> "$json_file"
        head -20 "$OUTPUT_DIR/snmp-creds-enhanced.txt" | while IFS= read -r line; do
            echo "            \"$(echo "$line" | sed 's/"/\\"/g')\"," >> "$json_file"
        done
        sed -i '$ s/,$//' "$json_file"
        echo '        ]' >> "$json_file"
    else
        echo '        "found": false' >> "$json_file"
    fi
    echo '    },' >> "$json_file"
    
    # Add process summary
    echo '    "processes": {' >> "$json_file"
    echo '        "total": '$(wc -l < "$OUTPUT_DIR/process-map.txt" 2>/dev/null || echo 0)',' >> "$json_file"
    echo '        "interesting": {' >> "$json_file"
    
    local first=1
    for cat in databases webservers interpreters security admin containers; do
        local count=$(wc -l < "$OUTPUT_DIR/processes-$cat.txt" 2>/dev/null || echo 0)
        [ $first -eq 0 ] && echo ',' >> "$json_file"
        echo -n "            \"$cat\": $count" >> "$json_file"
        first=0
    done
    
    echo '' >> "$json_file"
    echo '        }' >> "$json_file"
    echo '    },' >> "$json_file"
    
    # Add vulnerabilities
    echo '    "vulnerabilities": [' >> "$json_file"
    if [ -s "$OUTPUT_DIR/potential-vulns.txt" ]; then
        while IFS= read -r vuln; do
            echo "        \"$vuln\"," >> "$json_file"
        done < "$OUTPUT_DIR/potential-vulns.txt"
        sed -i '$ s/,$//' "$json_file"
    fi
    echo '    ]' >> "$json_file"
    
    echo '}' >> "$json_file"
    
    print_good "JSON output saved to: $json_file"
}

# Create HTML report
create_html_report() {
    if [[ "$HTML_REPORT" != "1" ]]; then
        return
    fi
    
    print_header "Creating HTML Report"
    
    local html_file="$OUTPUT_DIR/snmp-enum-report.html"
    
    cat > "$html_file" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>SNMP Enumeration Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .info-box { background-color: #e7f3ff; border-left: 4px solid #007bff; padding: 10px; margin: 10px 0; }
        .warning-box { background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 10px 0; }
        .danger-box { background-color: #f8d7da; border-left: 4px solid #dc3545; padding: 10px; margin: 10px 0; }
        .success-box { background-color: #d4edda; border-left: 4px solid #28a745; padding: 10px; margin: 10px 0; }
        pre { background-color: #f4f4f4; padding: 10px; border-radius: 4px; overflow-x: auto; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #007bff; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .cred-item { background-color: #ffe6e6; padding: 5px; margin: 2px 0; border-radius: 3px; }
        .process-category { margin: 20px 0; }
        .vuln-item { color: #dc3545; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>SNMP Enumeration Report</h1>
EOF
    
    # Add target info
    echo "        <div class='info-box'>" >> "$html_file"
    echo "            <h3>Target Information</h3>" >> "$html_file"
    echo "            <p><strong>Target:</strong> $TARGET</p>" >> "$html_file"
    echo "            <p><strong>SNMP Version:</strong> $VERSION</p>" >> "$html_file"
    [ -n "$COMMUNITY" ] && echo "            <p><strong>Community:</strong> $COMMUNITY</p>" >> "$html_file"
    echo "            <p><strong>Scan Time:</strong> $(date)</p>" >> "$html_file"
    echo "        </div>" >> "$html_file"
    
    # Add system information
    if [ -s "$OUTPUT_DIR/snmp-system-info.txt" ]; then
        echo "        <h2>System Information</h2>" >> "$html_file"
        echo "        <pre>" >> "$html_file"
        head -20 "$OUTPUT_DIR/snmp-system-info.txt" | sed 's/</\&lt;/g;s/>/\&gt;/g' >> "$html_file"
        echo "        </pre>" >> "$html_file"
    fi
    
    # Add credentials if found
    if [ -s "$OUTPUT_DIR/snmp-creds-enhanced.txt" ]; then
        echo "        <h2>Discovered Credentials</h2>" >> "$html_file"
        echo "        <div class='danger-box'>" >> "$html_file"
        echo "            <h3>⚠️ Sensitive Information Found!</h3>" >> "$html_file"
        echo "            <p>The following potential credentials were discovered:</p>" >> "$html_file"
        while IFS= read -r cred; do
            echo "            <div class='cred-item'>$(echo "$cred" | sed 's/</\&lt;/g;s/>/\&gt;/g')</div>" >> "$html_file"
        done < <(head -20 "$OUTPUT_DIR/snmp-creds-enhanced.txt")
        echo "        </div>" >> "$html_file"
    fi
    
    # Add process analysis
    echo "        <h2>Process Analysis</h2>" >> "$html_file"
    if [ -s "$OUTPUT_DIR/process-summary.txt" ]; then
        echo "        <pre>" >> "$html_file"
        cat "$OUTPUT_DIR/process-summary.txt" | sed 's/</\&lt;/g;s/>/\&gt;/g' >> "$html_file"
        echo "        </pre>" >> "$html_file"
    fi
    
    # Add vulnerabilities
    if [ -s "$OUTPUT_DIR/potential-vulns.txt" ]; then
        echo "        <h2>Potential Vulnerabilities</h2>" >> "$html_file"
        echo "        <div class='warning-box'>" >> "$html_file"
        echo "            <h3>⚠️ Vulnerable Software Detected</h3>" >> "$html_file"
        echo "            <ul>" >> "$html_file"
        while IFS= read -r vuln; do
            echo "                <li class='vuln-item'>$vuln</li>" >> "$html_file"
        done < "$OUTPUT_DIR/potential-vulns.txt"
        echo "            </ul>" >> "$html_file"
        echo "        </div>" >> "$html_file"
    fi
    
    # Add recommendations
    echo "        <h2>Recommendations</h2>" >> "$html_file"
    echo "        <div class='success-box'>" >> "$html_file"
    echo "            <h3>Next Steps</h3>" >> "$html_file"
    echo "            <ol>" >> "$html_file"
    
    # Dynamic recommendations based on findings
    [ -s "$OUTPUT_DIR/snmp-creds-enhanced.txt" ] && echo "                <li>Review discovered credentials</li>" >> "$html_file"
    [ -s "$OUTPUT_DIR/processes-databases.txt" ] && echo "                <li>Investigate database services</li>" >> "$html_file"
    [ -s "$OUTPUT_DIR/processes-webservers.txt" ] && echo "                <li>Enumerate web services</li>" >> "$html_file"
    [ -s "$OUTPUT_DIR/processes-containers.txt" ] && echo "                <li>Check container configurations</li>" >> "$html_file"
    [ -s "$OUTPUT_DIR/potential-vulns.txt" ] && echo "                <li>Research identified software versions</li>" >> "$html_file"
    
    echo "                <li>Analyze network topology from discovered routes</li>" >> "$html_file"
    echo "                <li>Review all enumerated data for sensitive information</li>" >> "$html_file"
    echo "            </ol>" >> "$html_file"
    echo "        </div>" >> "$html_file"
    
    # Close HTML
    echo "    </div>" >> "$html_file"
    echo "</body>" >> "$html_file"
    echo "</html>" >> "$html_file"
    
    print_good "HTML report saved to: $html_file"
}

# Parallel brute force function
parallel_brute_force() {
    print_header "Parallel Community String Brute Force"
    
    if [ ! -f "$WORDLIST" ]; then
        print_warn "Wordlist not found: $WORDLIST"
        return 1
    fi
    
    # Create temp directory for parallel results
    local temp_dir="$OUTPUT_DIR/brute_temp"
    mkdir -p "$temp_dir"
    
    # Function to test a single community string
    test_community() {
        local community="$1"
        local target="$2"
        local version="$3"
        local temp_dir="$4"
        
        if timeout 3 snmpget -v"$version" -c "$community" "$target" 1.3.6.1.2.1.1.1.0 &>/dev/null; then
            echo "$community" > "$temp_dir/found_$community"
            return 0
        fi
        return 1
    }
    
    export -f test_community
    
    # Use parallel if available, otherwise fall back to sequential
    if command -v parallel &>/dev/null && [ "$NO_PARALLEL" != "1" ]; then
        print_info "Running parallel brute force with $THREADS threads..."
        
        cat "$WORDLIST" | parallel -j "$THREADS" --bar test_community {} "$TARGET" "$VERSION" "$temp_dir"
        
        # Check results
        if ls "$temp_dir"/found_* 1> /dev/null 2>&1; then
            COMMUNITY=$(cat "$temp_dir"/found_* | head -1)
            print_good "Found valid community: $COMMUNITY"
            # Clean up
            rm -rf "$temp_dir"
            return 0
        fi
    else
        print_info "Running sequential brute force..."
        while IFS= read -r word; do
            if test_community "$word" "$TARGET" "$VERSION" "$temp_dir"; then
                COMMUNITY="$word"
                print_good "Found valid community: $COMMUNITY"
                rm -rf "$temp_dir"
                return 0
            fi
        done < "$WORDLIST"
    fi
    
    rm -rf "$temp_dir"
    print_warn "No valid community strings found"
    return 1
}



# ================== MAIN EXECUTION ==================
print_usage() {
    cat <<EOF
Usage: $0 -t <target> [OPTIONS]

Required:
  -t, --target <IP/HOST>   Target IP or hostname

SNMP Options:
  -c, --community <STR>    SNMP community string (default: public)
  -v, --version <VER>      SNMP version: 1, 2c, or 3 (default: 2c)
  --v3-user <USER>         SNMPv3 username
  --v3-level <LEVEL>       SNMPv3 security level (noAuthNoPriv|authNoPriv|authPriv)
  --v3-auth-proto <PROTO>  SNMPv3 auth protocol (MD5|SHA)
  --v3-auth-pass <PASS>    SNMPv3 auth password
  --v3-priv-proto <PROTO>  SNMPv3 privacy protocol (DES|AES)
  --v3-priv-pass <PASS>    SNMPv3 privacy password

Enumeration Options:
  --brute                  Brute-force community strings
  --wordlist <FILE>        Custom wordlist for brute-force
  --threads <NUM>          Number of threads for parallel operations (default: 10)
  --extras                 Enable extra enumeration modules
  --write-test            Test SNMP write access (DANGEROUS!)

Output Options:
  --output-dir <DIR>       Output directory (default: output)
  --json                   Generate JSON output
  --html                   Generate HTML report
  --verbose               Enable verbose output

Examples:
  # Basic scan
  $0 -t 10.10.10.100

  # Comprehensive scan with all features
  $0 -t 10.10.10.100 --brute --extras --json --html

  # SNMPv3 scan
  $0 -t 10.10.10.100 -v 3 --v3-user admin --v3-level authPriv \\
     --v3-auth-proto SHA --v3-auth-pass MyAuthPass \\
     --v3-priv-proto AES --v3-priv-pass MyPrivPass

EOF
    exit 1
}

# Parse arguments
TEMP=$(getopt -o t:c:v:h \
    --long target:,community:,version:,help,brute,extras,write-test,json,html,verbose,\
threads:,wordlist:,output-dir:,\
v3-user:,v3-level:,v3-auth-proto:,v3-auth-pass:,v3-priv-proto:,v3-priv-pass: \
    -n "$0" -- "$@")

if [ $? != 0 ]; then
    print_usage
fi

eval set -- "$TEMP"

while true; do
    case "$1" in
        -t|--target) TARGET="$2"; shift 2 ;;
        -c|--community) COMMUNITY="$2"; shift 2 ;;
        -v|--version) VERSION="$2"; shift 2 ;;
        --brute) BRUTE=1; shift ;;
        --extras) EXTRAS=1; shift ;;
        --write-test) WRITE_TEST=1; shift ;;
        --json) JSON_OUTPUT=1; shift ;;
        --html) HTML_REPORT=1; shift ;;
        --verbose) VERBOSE=1; shift ;;
        --threads) THREADS="$2"; shift 2 ;;
        --wordlist) CUSTOM_WORDLIST="$2"; shift 2 ;;
        --output-dir) OUTPUT_BASE_DIR="$2"; shift 2 ;;
        --v3-user) V3_USER="$2"; shift 2 ;;
        --v3-level) V3_LEVEL="$2"; shift 2 ;;
        --v3-auth-proto) V3_AUTH_PROTO="$2"; shift 2 ;;
        --v3-auth-pass) V3_AUTH_PASS="$2"; shift 2 ;;
        --v3-priv-proto) V3_PRIV_PROTO="$2"; shift 2 ;;
        --v3-priv-pass) V3_PRIV_PASS="$2"; shift 2 ;;
        -h|--help) print_usage ;;
        --) shift; break ;;
        *) echo "Internal error!"; exit 1 ;;
    esac
done

# Validate inputs
if [[ -z "$TARGET" ]]; then
    print_usage
fi

# Use custom wordlist if provided
if [[ -n "$CUSTOM_WORDLIST" ]]; then
    WORDLIST="$CUSTOM_WORDLIST"
fi

# Setup output directory
SANITIZED_TARGET=$(sanitize_target "$TARGET")
TIMESTAMP=$(get_timestamp)
OUTPUT_DIR="$OUTPUT_BASE_DIR/${SANITIZED_TARGET}_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

# Start enumeration
print_banner
print_header "Starting SNMP Enumeration"
print_info "Target: $TARGET"
print_info "Version: $VERSION"
print_info "Output: $OUTPUT_DIR"

# Brute force if requested
if [[ "$BRUTE" == "1" && "$VERSION" != "3" ]]; then
    parallel_brute_force
fi

# Validate SNMP access
print_header "Validating SNMP Access"
if test_snmp_access; then
    print_good "SNMP access confirmed"
else
    print_warn "SNMP access failed - check credentials/connectivity"
    exit 1
fi

# Core enumeration
print_header "Core SNMP Enumeration"

# System information
safe_snmpwalk "System Information" "1.3.6.1.2.1.1" "$OUTPUT_DIR/snmp-system-info.txt"

# Network information
safe_snmpwalk "Network Interfaces" "1.3.6.1.2.1.2.2.1" "$OUTPUT_DIR/snmp-interfaces.txt"
safe_snmpwalk "IP Addresses" "1.3.6.1.2.1.4.20.1" "$OUTPUT_DIR/snmp-ip-addresses.txt"
safe_snmpwalk "Routing Table" "1.3.6.1.2.1.4.21" "$OUTPUT_DIR/snmp-routes.txt"
safe_snmpwalk "ARP Table" "1.3.6.1.2.1.4.22" "$OUTPUT_DIR/snmp-arp.txt"

# Process information
safe_snmpwalk "Process Names" "HOST-RESOURCES-MIB::hrSWRunName" "$OUTPUT_DIR/snmp-process-names.txt"
safe_snmpwalk "Process Paths" "HOST-RESOURCES-MIB::hrSWRunPath" "$OUTPUT_DIR/snmp-process-paths.txt"
safe_snmpwalk "Process Parameters" "HOST-RESOURCES-MIB::hrSWRunParameters" "$OUTPUT_DIR/snmp-process-args.txt" "-Cr50"

# Storage information
safe_snmpwalk "Storage Units" "1.3.6.1.2.1.25.2.3.1" "$OUTPUT_DIR/snmp-storage.txt"
safe_snmpwalk "Software Installed" "1.3.6.1.2.1.25.6.3.1" "$OUTPUT_DIR/snmp-software.txt"

# TCP/UDP connections
safe_snmpwalk "TCP Connections" "1.3.6.1.2.1.6.13" "$OUTPUT_DIR/snmp-tcp-conns.txt"
safe_snmpwalk "UDP Endpoints" "1.3.6.1.2.1.7.5" "$OUTPUT_DIR/snmp-udp-endpoints.txt"

# Users
safe_snmpwalk "User Accounts" "1.3.6.1.4.1.77.1.2.25" "$OUTPUT_DIR/snmp-users.txt"

# Extra enumeration if requested
if [[ "$EXTRAS" == "1" ]]; then
    print_header "Extended SNMP Enumeration"
    
    # UCD-SNMP MIB
    safe_snmpwalk "UCD Disk Info" "1.3.6.1.4.1.2021.9" "$OUTPUT_DIR/snmp-ucd-disk.txt"
    safe_snmpwalk "UCD Memory Info" "1.3.6.1.4.1.2021.4" "$OUTPUT_DIR/snmp-ucd-memory.txt"
    safe_snmpwalk "UCD Load Average" "1.3.6.1.4.1.2021.10" "$OUTPUT_DIR/snmp-ucd-load.txt"
    safe_snmpwalk "UCD System Stats" "1.3.6.1.4.1.2021.11" "$OUTPUT_DIR/snmp-ucd-systemstats.txt"
    
    # NET-SNMP Extensions
    safe_snmpwalk "NET-SNMP Extend" "1.3.6.1.4.1.8072.1.3.2" "$OUTPUT_DIR/snmp-netsnmp-extend.txt"
    
    # Enterprise MIBs
    safe_snmpwalk "Enterprise OIDs" "1.3.6.1.4.1" "$OUTPUT_DIR/snmp-enterprise.txt" "-t 10"
fi

# Test write access if requested
test_write_access

# Analysis phase
print_header "Analyzing SNMP Data"

# Extract credentials
extract_credentials

# Analyze processes
analyze_processes

# Check for vulnerabilities
check_vulnerabilities

# Generate reports
create_json_output
create_html_report

# Final summary
print_header "SNMP Enumeration Complete"
echo
print_good "Results saved to: $OUTPUT_DIR"
echo
echo "Key files:"
echo "  • System Info: snmp-system-info.txt"
echo "  • Credentials: snmp-creds-enhanced.txt"
echo "  • Processes: process-summary.txt"
echo "  • Vulnerabilities: potential-vulns.txt"
[ "$JSON_OUTPUT" == "1" ] && echo "  • JSON Report: snmp-enum-results.json"
[ "$HTML_REPORT" == "1" ] && echo "  • HTML Report: snmp-enum-report.html"
echo
print_info "Happy hunting! 🎯"
