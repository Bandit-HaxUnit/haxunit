#!/bin/bash

# DNS Cache Monitoring Script for Unbound
# This script provides insights into DNS cache performance

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

print_info() {
    echo -e "${GREEN}$1${NC}"
}

print_warning() {
    echo -e "${YELLOW}$1${NC}"
}

# Function to check if Unbound is running
check_unbound_status() {
    print_header "Unbound Status"
    
    if pgrep unbound > /dev/null; then
        print_info "✓ Unbound is running"
        print_info "  PID: $(pgrep unbound)"
    else
        print_warning "✗ Unbound is not running"
        return 1
    fi
}

# Function to test DNS resolution
test_dns_resolution() {
    print_header "DNS Resolution Test"
    
    local test_domains=("google.com" "github.com" "cloudflare.com" "example.com")
    
    for domain in "${test_domains[@]}"; do
        print_info "Testing $domain..."
        
        # Test with local Unbound cache
        local_time=$(time (nslookup $domain 127.0.0.1 > /dev/null 2>&1) 2>&1 | grep real | awk '{print $2}')
        
        if [ $? -eq 0 ]; then
            print_info "  ✓ Local cache: $local_time"
        else
            print_warning "  ✗ Local cache failed"
        fi
        
        # Small delay between tests
        sleep 0.5
    done
}

# Function to get Unbound statistics
get_unbound_stats() {
    print_header "Unbound Cache Statistics"
    
    if command -v unbound-control &> /dev/null; then
        # Try to get statistics using unbound-control
        if sudo unbound-control stats 2>/dev/null; then
            print_info "Cache statistics retrieved successfully"
        else
            print_warning "Could not retrieve statistics via unbound-control"
            print_info "This is normal if remote control is not configured"
        fi
    else
        print_warning "unbound-control not available"
    fi
}

# Function to show cache hit ratio test
test_cache_efficiency() {
    print_header "Cache Efficiency Test"
    
    local test_domain="google.com"
    print_info "Testing cache efficiency with repeated queries to $test_domain"
    
    # First query (cold cache)
    print_info "First query (cold cache):"
    time nslookup $test_domain 127.0.0.1 > /dev/null
    
    # Second query (should be cached)
    print_info "Second query (should be from cache):"
    time nslookup $test_domain 127.0.0.1 > /dev/null
    
    # Third query (should be cached)
    print_info "Third query (should be from cache):"
    time nslookup $test_domain 127.0.0.1 > /dev/null
}

# Function to show DNS configuration
show_dns_config() {
    print_header "DNS Configuration"
    
    print_info "Current DNS settings:"
    if [ -f "/etc/resolv.conf" ]; then
        cat /etc/resolv.conf | grep -v "^#" | grep -v "^$"
    else
        print_warning "/etc/resolv.conf not found"
    fi
    
    print_info "\nUnbound configuration:"
    if [ -f "/etc/unbound/unbound.conf" ]; then
        print_info "Configuration file exists at /etc/unbound/unbound.conf"
    else
        print_warning "Unbound configuration not found"
    fi
}

# Function to check log files
check_logs() {
    print_header "Recent Unbound Logs"
    
    if [ -f "/var/log/unbound/unbound.log" ]; then
        print_info "Last 10 log entries:"
        tail -n 10 /var/log/unbound/unbound.log 2>/dev/null || print_warning "Could not read log file"
    else
        print_warning "Unbound log file not found"
    fi
}

# Main execution
main() {
    echo -e "${BLUE}DNS Cache Monitor - $(date)${NC}\n"
    
    check_unbound_status
    echo
    
    show_dns_config
    echo
    
    test_dns_resolution
    echo
    
    test_cache_efficiency
    echo
    
    get_unbound_stats
    echo
    
    check_logs
    echo
    
    print_info "Monitoring complete!"
}

# Run the monitoring script
main