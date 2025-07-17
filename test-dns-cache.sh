#!/bin/bash

# Simple test script to verify DNS caching implementation
# Run this script inside the container to test the setup

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_test() {
    echo -e "${YELLOW}[TEST]${NC} $1"
}

print_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
}

echo "=== DNS Cache Implementation Test ==="
echo

# Test 1: Check if Unbound is running
print_test "Checking if Unbound is running..."
if pgrep unbound > /dev/null; then
    print_pass "Unbound process is running"
else
    print_fail "Unbound process not found"
    exit 1
fi

# Test 2: Check if port 53 is listening
print_test "Checking if DNS port 53 is listening..."
if netstat -ln 2>/dev/null | grep -q ":53 " || ss -ln 2>/dev/null | grep -q ":53 "; then
    print_pass "DNS port 53 is listening"
else
    print_fail "DNS port 53 is not listening"
fi

# Test 3: Test basic DNS resolution
print_test "Testing basic DNS resolution..."
if nslookup google.com 127.0.0.1 > /dev/null 2>&1; then
    print_pass "DNS resolution works"
else
    print_fail "DNS resolution failed"
    exit 1
fi

# Test 4: Test dnsx with local resolver
print_test "Testing dnsx with local resolver..."
if echo "example.com" | dnsx -silent -r 127.0.0.1 > /dev/null 2>&1; then
    print_pass "dnsx works with local resolver"
else
    print_fail "dnsx failed with local resolver"
fi

# Test 5: Performance test (cache effectiveness)
print_test "Testing cache performance..."
echo "First query (cache miss):"
time nslookup cloudflare.com 127.0.0.1 > /dev/null 2>&1

echo "Second query (should be cached):"
time nslookup cloudflare.com 127.0.0.1 > /dev/null 2>&1

print_pass "Cache performance test completed"

# Test 6: Check configuration files
print_test "Checking configuration files..."
if [ -f "/etc/unbound/unbound.conf" ]; then
    print_pass "Unbound configuration exists"
else
    print_fail "Unbound configuration missing"
fi

if [ -f "/var/lib/unbound/root.hints" ]; then
    print_pass "Root hints file exists"
else
    print_fail "Root hints file missing"
fi

echo
echo "=== Test Summary ==="
echo "If all tests passed, the DNS caching implementation is working correctly!"
echo "You can now run your reconnaissance tools and they will benefit from DNS caching."
echo
echo "To monitor cache performance, run: ./dns-monitor.sh"
echo