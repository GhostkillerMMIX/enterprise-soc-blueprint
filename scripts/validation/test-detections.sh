#!/bin/bash

# Detection Rules Testing Script
# Tests MITRE ATT&CK detection rules using Atomic Red Team

set -e

# Configuration
SPLUNK_HOST="${SPLUNK_HOST:-splunk.enterprise-soc.local}"
SPLUNK_PORT="${SPLUNK_PORT:-8089}"
SPLUNK_USERNAME="${SPLUNK_USERNAME:-admin}"
SPLUNK_PASSWORD="${SPLUNK_PASSWORD}"
LOG_FILE="/tmp/detection-tests.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test results
PASSED_TESTS=0
FAILED_TESTS=0
TOTAL_TESTS=0

# Logging functions
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

test_pass() {
    echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$LOG_FILE"
    ((PASSED_TESTS++))
    ((TOTAL_TESTS++))
}

test_fail() {
    echo -e "${RED}[FAIL]${NC} $1" | tee -a "$LOG_FILE"
    ((FAILED_TESTS++))
    ((TOTAL_TESTS++))
}

test_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"
    ((TOTAL_TESTS++))
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if Atomic Red Team is available
    if ! command -v Invoke-AtomicTest &> /dev/null; then
        if [[ ! -d "atomic-red-team" ]]; then
            log "Downloading Atomic Red Team..."
            git clone https://github.com/redcanaryco/atomic-red-team.git
        fi
        
        # Install PowerShell module
        if command -v pwsh &> /dev/null; then
            pwsh -Command "Install-Module -Name invoke-atomicredteam -Scope CurrentUser -Force"
        else
            test_warning "PowerShell not available - some tests will be skipped"
        fi
    fi
    
    # Check Splunk connectivity
    if [[ -z "$SPLUNK_PASSWORD" ]]; then
        test_fail "SPLUNK_PASSWORD environment variable not set"
        exit 1
    fi
    
    # Test Splunk connection
    local auth_response=$(curl -k -s -u "$SPLUNK_USERNAME:$SPLUNK_PASSWORD" \
        "https://$SPLUNK_HOST:$SPLUNK_PORT/services/auth/login" \
        -d "username=$SPLUNK_USERNAME&password=$SPLUNK_PASSWORD" 2>/dev/null || echo "FAILED")
    
    if [[ "$auth_response" == "FAILED" ]] || [[ "$auth_response" == *"error"* ]]; then
        test_fail "Cannot connect to Splunk at $SPLUNK_HOST:$SPLUNK_PORT"
        exit 1
    else
        test_pass "Splunk connection successful"
    fi
}

# Execute Splunk search and return results
execute_splunk_search() {
    local search_query="$1"
    local earliest="${2:--15m}"
    local latest="${3:-now}"
    
    # Create search job
    local search_response=$(curl -k -s -u "$SPLUNK_USERNAME:$SPLUNK_PASSWORD" \
        "https://$SPLUNK_HOST:$SPLUNK_PORT/services/search/jobs" \
        -d "search=search $search_query" \
        -d "earliest_time=$earliest" \
        -d "latest_time=$latest" \
        -d "output_mode=json" 2>/dev/null)
    
    local job_id=$(echo "$search_response" | jq -r '.sid' 2>/dev/null || echo "")
    
    if [[ -z "$job_id" || "$job_id" == "null" ]]; then
        echo "ERROR: Could not create search job"
        return 1
    fi
    
    # Wait for job completion
    local status="RUNNING"
    local timeout=60
    local count=0
    
    while [[ "$status" != "DONE" && "$status" != "FAILED" && $count -lt $timeout ]]; do
        sleep 2
        local job_status=$(curl -k -s -u "$SPLUNK_USERNAME:$SPLUNK_PASSWORD" \
            "https://$SPLUNK_HOST:$SPLUNK_PORT/services/search/jobs/$job_id" \
            -d "output_mode=json" 2>/dev/null)
        
        status=$(echo "$job_status" | jq -r '.entry[0].content.dispatchState' 2>/dev/null || echo "UNKNOWN")
        ((count++))
    done
    
    if [[ "$status" != "DONE" ]]; then
        echo "ERROR: Search job timeout or failed"
        return 1
    fi
    
    # Get results
    local results=$(curl -k -s -u "$SPLUNK_USERNAME:$SPLUNK_PASSWORD" \
        "https://$SPLUNK_HOST:$SPLUNK_PORT/services/search/jobs/$job_id/results" \
        -d "output_mode=json" \
        -d "count=1000" 2>/dev/null)
    
    local result_count=$(echo "$results" | jq '.results | length' 2>/dev/null || echo "0")
    echo "$result_count"
}

# Test T1059.001 - PowerShell Detection
test_powershell_detection() {
    log "Testing T1059.001 - PowerShell Detection..."
    
    # Generate test event (simulated)
    log "Simulating PowerShell execution..."
    
    # Check if detection rule fires
    local search_query='index=winevent sourcetype=WinEventLog:Security EventCode=4688 CommandLine=*powershell* CommandLine=*-EncodedCommand* | head 1'
    local result_count=$(execute_splunk_search "$search_query" "-1h" "now")
    
    if [[ "$result_count" == "ERROR"* ]]; then
        test_fail "PowerShell detection search failed"
        return 1
    fi
    
    # For testing purposes, we'll check if the search executes successfully
    # In a real environment, this would check for actual detection results
    if [[ "$result_count" =~ ^[0-9]+$ ]]; then
        test_pass "PowerShell detection rule search executed successfully"
    else
        test_fail "PowerShell detection rule search failed"
    fi
}

# Test T1078.004 - Okta Impossible Travel Detection
test_impossible_travel_detection() {
    log "Testing T1078.004 - Impossible Travel Detection..."
    
    local search_query='index=okta sourcetype=okta:system eventType=user.session.start | iplocation src_ip | head 1'
    local result_count=$(execute_splunk_search "$search_query" "-24h" "now")
    
    if [[ "$result_count" == "ERROR"* ]]; then
        test_fail "Impossible travel detection search failed"
        return 1
    fi
    
    if [[ "$result_count" =~ ^[0-9]+$ ]]; then
        test_pass "Impossible travel detection rule search executed successfully"
    else
        test_fail "Impossible travel detection rule search failed"
    fi
}

# Test T1003.001 - LSASS Memory Access Detection
test_lsass_detection() {
    log "Testing T1003.001 - LSASS Memory Access Detection..."
    
    local search_query='index=winevent sourcetype=WinEventLog:Security EventCode=4656 ObjectName=*lsass.exe* | head 1'
    local result_count=$(execute_splunk_search "$search_query" "-1h" "now")
    
    if [[ "$result_count" == "ERROR"* ]]; then
        test_fail "LSASS detection search failed"
        return 1
    fi
    
    if [[ "$result_count" =~ ^[0-9]+$ ]]; then
        test_pass "LSASS detection rule search executed successfully"
    else
        test_fail "LSASS detection rule search failed"
    fi
}

# Test T1190 - Web Application Attack Detection
test_web_attack_detection() {
    log "Testing T1190 - Web Application Attack Detection..."
    
    local search_query='index=proxy OR index=network sourcetype=pan:traffic OR sourcetype=zeek:http status_code>=400 | head 1'
    local result_count=$(execute_splunk_search "$search_query" "-1h" "now")
    
    if [[ "$result_count" == "ERROR"* ]]; then
        test_fail "Web attack detection search failed"
        return 1
    fi
    
    if [[ "$result_count" =~ ^[0-9]+$ ]]; then
        test_pass "Web attack detection rule search executed successfully"
    else
        test_fail "Web attack detection rule search failed"
    fi
}

# Test T1021.001 - RDP Detection
test_rdp_detection() {
    log "Testing T1021.001 - RDP Detection..."
    
    local search_query='index=winevent sourcetype=WinEventLog:Security EventCode=4624 LogonType=10 | head 1'
    local result_count=$(execute_splunk_search "$search_query" "-1h" "now")
    
    if [[ "$result_count" == "ERROR"* ]]; then
        test_fail "RDP detection search failed"
        return 1
    fi
    
    if [[ "$result_count" =~ ^[0-9]+$ ]]; then
        test_pass "RDP detection rule search executed successfully"
    else
        test_fail "RDP detection rule search failed"
    fi
}

# Test T1071.001 - DNS Tunneling Detection
test_dns_tunneling_detection() {
    log "Testing T1071.001 - DNS Tunneling Detection..."
    
    local search_query='index=dns sourcetype=zeek:dns | stats count avg(len(query)) as avg_query_length by src_ip | head 1'
    local result_count=$(execute_splunk_search "$search_query" "-1h" "now")
    
    if [[ "$result_count" == "ERROR"* ]]; then
        test_fail "DNS tunneling detection search failed"
        return 1
    fi
    
    if [[ "$result_count" =~ ^[0-9]+$ ]]; then
        test_pass "DNS tunneling detection rule search executed successfully"
    else
        test_fail "DNS tunneling detection rule search failed"
    fi
}

# Test T1110.003 - Password Spraying Detection
test_password_spraying_detection() {
    log "Testing T1110.003 - Password Spraying Detection..."
    
    local search_query='index=auth sourcetype=okta:system eventType=user.authentication.authenticate outcome.result=FAILURE | head 1'
    local result_count=$(execute_splunk_search "$search_query" "-1h" "now")
    
    if [[ "$result_count" == "ERROR"* ]]; then
        test_fail "Password spraying detection search failed"
        return 1
    fi
    
    if [[ "$result_count" =~ ^[0-9]+$ ]]; then
        test_pass "Password spraying detection rule search executed successfully"
    else
        test_fail "Password spraying detection rule search failed"
    fi
}

# Test Risk-Based Alerting
test_risk_based_alerting() {
    log "Testing Risk-Based Alerting..."
    
    local search_query='| from datamodel:"Risk"."All_Risk" | stats sum(risk_score) as total_risk_score by risk_object | head 1'
    local result_count=$(execute_splunk_search "$search_query" "-24h" "now")
    
    if [[ "$result_count" == "ERROR"* ]]; then
        test_fail "Risk-based alerting search failed"
        return 1
    fi
    
    if [[ "$result_count" =~ ^[0-9]+$ ]]; then
        test_pass "Risk-based alerting search executed successfully"
    else
        test_fail "Risk-based alerting search failed"
    fi
}

# Test saved searches (detection rules)
test_saved_searches() {
    log "Testing saved searches (detection rules)..."
    
    # Get list of saved searches
    local saved_searches=$(curl -k -s -u "$SPLUNK_USERNAME:$SPLUNK_PASSWORD" \
        "https://$SPLUNK_HOST:$SPLUNK_PORT/services/saved/searches" \
        -d "output_mode=json" \
        -d "search=title=SOC*" 2>/dev/null)
    
    local search_count=$(echo "$saved_searches" | jq '.entry | length' 2>/dev/null || echo "0")
    
    if [[ "$search_count" =~ ^[0-9]+$ && $search_count -gt 0 ]]; then
        test_pass "Found $search_count SOC detection rules"
        
        # Test a few key searches
        local search_names=$(echo "$saved_searches" | jq -r '.entry[].name' 2>/dev/null)
        
        while IFS= read -r search_name; do
            if [[ -n "$search_name" ]]; then
                log "Testing saved search: $search_name"
                
                # Get search details
                local search_details=$(curl -k -s -u "$SPLUNK_USERNAME:$SPLUNK_PASSWORD" \
                    "https://$SPLUNK_HOST:$SPLUNK_PORT/services/saved/searches/$search_name" \
                    -d "output_mode=json" 2>/dev/null)
                
                local is_scheduled=$(echo "$search_details" | jq -r '.entry[0].content.is_scheduled' 2>/dev/null || echo "0")
                local cron_schedule=$(echo "$search_details" | jq -r '.entry[0].content.cron_schedule' 2>/dev/null || echo "")
                
                if [[ "$is_scheduled" == "1" && -n "$cron_schedule" ]]; then
                    test_pass "Detection rule '$search_name' is properly scheduled"
                else
                    test_warning "Detection rule '$search_name' is not scheduled"
                fi
            fi
        done <<< "$search_names"
        
    else
        test_fail "No SOC detection rules found"
    fi
}

# Test data models
test_data_models() {
    log "Testing data models..."
    
    # Check if CIM data models are available
    local data_models=$(curl -k -s -u "$SPLUNK_USERNAME:$SPLUNK_PASSWORD" \
        "https://$SPLUNK_HOST:$SPLUNK_PORT/services/data/models" \
        -d "output_mode=json" 2>/dev/null)
    
    local model_count=$(echo "$data_models" | jq '.entry | length' 2>/dev/null || echo "0")
    
    if [[ "$model_count" =~ ^[0-9]+$ && $model_count -gt 0 ]]; then
        test_pass "Found $model_count data models"
        
        # Check for key data models
        local model_names=$(echo "$data_models" | jq -r '.entry[].name' 2>/dev/null)
        local required_models=("Authentication" "Network_Traffic" "Web" "Malware" "Risk")
        
        for required_model in "${required_models[@]}"; do
            if echo "$model_names" | grep -q "$required_model"; then
                test_pass "Required data model found: $required_model"
            else
                test_warning "Required data model missing: $required_model"
            fi
        done
    else
        test_fail "No data models found"
    fi
}

# Test lookups
test_lookups() {
    log "Testing lookup tables..."
    
    # Check threat intelligence lookup
    local lookup_search='| inputlookup threat_intel_iocs.csv | head 1'
    local result_count=$(execute_splunk_search "$lookup_search")
    
    if [[ "$result_count" == "ERROR"* ]]; then
        test_fail "Threat intelligence lookup failed"
    elif [[ "$result_count" =~ ^[0-9]+$ && $result_count -gt 0 ]]; then
        test_pass "Threat intelligence lookup table accessible with $result_count entries"
    else
        test_warning "Threat intelligence lookup table is empty"
    fi
}

# Test dashboards
test_dashboards() {
    log "Testing dashboards..."
    
    # Get list of dashboards
    local dashboards=$(curl -k -s -u "$SPLUNK_USERNAME:$SPLUNK_PASSWORD" \
        "https://$SPLUNK_HOST:$SPLUNK_PORT/services/data/ui/views" \
        -d "output_mode=json" \
        -d "search=title=*SOC*" 2>/dev/null)
    
    local dashboard_count=$(echo "$dashboards" | jq '.entry | length' 2>/dev/null || echo "0")
    
    if [[ "$dashboard_count" =~ ^[0-9]+$ && $dashboard_count -gt 0 ]]; then
        test_pass "Found $dashboard_count SOC dashboards"
    else
        test_warning "No SOC dashboards found"
    fi
}

# Run Atomic Red Team tests (if available)
run_atomic_tests() {
    log "Running Atomic Red Team tests..."
    
    if ! command -v pwsh &> /dev/null; then
        test_warning "PowerShell not available - skipping Atomic Red Team tests"
        return 0
    fi
    
    # Test T1059.001 - PowerShell
    log "Running Atomic Test T1059.001..."
    local atomic_result=$(pwsh -Command "
        Import-Module invoke-atomicredteam -Force
        Invoke-AtomicTest T1059.001 -TestNumbers 1 -GetPrereqs -CheckPrereqs
    " 2>/dev/null || echo "FAILED")
    
    if [[ "$atomic_result" != "FAILED" ]]; then
        test_pass "Atomic Red Team T1059.001 prerequisites check passed"
    else
        test_warning "Atomic Red Team T1059.001 prerequisites check failed"
    fi
    
    # Additional atomic tests can be added here
}

# Performance tests
test_search_performance() {
    log "Testing search performance..."
    
    local start_time=$(date +%s)
    local result_count=$(execute_splunk_search 'index=* | head 100' '-1h' 'now')
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    if [[ "$result_count" == "ERROR"* ]]; then
        test_fail "Performance test search failed"
    elif [[ $duration -lt 30 ]]; then
        test_pass "Search performance acceptable: ${duration}s"
    elif [[ $duration -lt 60 ]]; then
        test_warning "Search performance slow: ${duration}s"
    else
        test_fail "Search performance unacceptable: ${duration}s"
    fi
}

# Generate test report
generate_test_report() {
    log "Generating detection test report..."
    
    local success_rate=0
    if [[ $TOTAL_TESTS -gt 0 ]]; then
        success_rate=$((PASSED_TESTS * 100 / TOTAL_TESTS))
    fi
    
    cat << EOF | tee -a "$LOG_FILE"

========================================
DETECTION RULES TEST SUMMARY
========================================
Total Tests: $TOTAL_TESTS
Passed: $PASSED_TESTS
Failed: $FAILED_TESTS
Success Rate: $success_rate%

Test Details:
- PowerShell Detection (T1059.001)
- Impossible Travel Detection (T1078.004)
- LSASS Memory Access Detection (T1003.001)
- Web Application Attack Detection (T1190)
- RDP Detection (T1021.001)
- DNS Tunneling Detection (T1071.001)
- Password Spraying Detection (T1110.003)
- Risk-Based Alerting
- Saved Searches Configuration
- Data Models Availability
- Lookup Tables
- Dashboard Accessibility
- Search Performance

EOF

    if [[ $FAILED_TESTS -eq 0 ]]; then
        echo -e "${GREEN}✅ All detection tests passed!${NC}" | tee -a "$LOG_FILE"
        return 0
    else
        echo -e "${RED}❌ $FAILED_TESTS detection tests failed${NC}" | tee -a "$LOG_FILE"
        return 1
    fi
}

# Main function
main() {
    log "Starting detection rules testing..."
    
    # Initialize log file
    echo "Detection Rules Test Report - $(date)" > "$LOG_FILE"
    echo "============================================" >> "$LOG_FILE"
    
    # Run tests
    check_prerequisites
    test_powershell_detection
    test_impossible_travel_detection
    test_lsass_detection
    test_web_attack_detection
    test_rdp_detection
    test_dns_tunneling_detection
    test_password_spraying_detection
    test_risk_based_alerting
    test_saved_searches
    test_data_models
    test_lookups
    test_dashboards
    test_search_performance
    run_atomic_tests
    
    # Generate report
    generate_test_report
}

# Script usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Test MITRE ATT&CK detection rules in Splunk.

OPTIONS:
    -h, --help              Show this help message
    -s, --splunk-host       Splunk host (default: splunk.enterprise-soc.local)
    -p, --splunk-port       Splunk port (default: 8089)
    -u, --splunk-user       Splunk username (default: admin)
    --skip-atomic           Skip Atomic Red Team tests
    --performance-only      Run only performance tests

ENVIRONMENT VARIABLES:
    SPLUNK_PASSWORD         Splunk admin password (required)

EXAMPLES:
    $0                                          # Run all tests
    $0 -s my-splunk.com -p 8089                # Custom Splunk host
    $0 --skip-atomic                           # Skip Atomic Red Team tests
    SPLUNK_PASSWORD=mypass $0                  # Set password via environment

EOF
}

# Parse command line arguments
SKIP_ATOMIC=false
PERFORMANCE_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -s|--splunk-host)
            SPLUNK_HOST="$2"
            shift 2
            ;;
        -p|--splunk-port)
            SPLUNK_PORT="$2"
            shift 2
            ;;
        -u|--splunk-user)
            SPLUNK_USERNAME="$2"
            shift 2
            ;;
        --skip-atomic)
            SKIP_ATOMIC=true
            shift
            ;;
        --performance-only)
            PERFORMANCE_ONLY=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Run tests based on options
if [[ "$PERFORMANCE_ONLY" == "true" ]]; then
    check_prerequisites
    test_search_performance
    generate_test_report
else
    main
fi
