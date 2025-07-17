#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[UNBOUND]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[UNBOUND]${NC} $1"
}

print_error() {
    echo -e "${RED}[UNBOUND]${NC} $1"
}

# Create necessary directories
print_status "Creating directories..."
sudo mkdir -p /var/lib/unbound
sudo mkdir -p /var/log/unbound
sudo mkdir -p /etc/unbound

# Copy configuration file
print_status "Installing Unbound configuration..."
sudo cp /app/unbound.conf /etc/unbound/unbound.conf

# Download root hints if not present
if [ ! -f "/var/lib/unbound/root.hints" ]; then
    print_status "Downloading root hints..."
    sudo wget -q -O /var/lib/unbound/root.hints https://www.internic.net/domain/named.cache
fi

# Initialize trust anchor if not present
if [ ! -f "/var/lib/unbound/root.key" ]; then
    print_status "Initializing DNSSEC trust anchor..."
    sudo unbound-anchor -a /var/lib/unbound/root.key
fi

# Set proper permissions
print_status "Setting permissions..."
sudo chown -R unbound:unbound /var/lib/unbound
sudo chown -R unbound:unbound /var/log/unbound
sudo chmod 644 /etc/unbound/unbound.conf

# Test configuration
print_status "Testing Unbound configuration..."
if sudo unbound-checkconf /etc/unbound/unbound.conf; then
    print_status "Configuration is valid"
else
    print_error "Configuration validation failed"
    exit 1
fi

# Start Unbound
print_status "Starting Unbound DNS resolver..."
sudo unbound -c /etc/unbound/unbound.conf

print_status "Unbound is now running on localhost:53"

# Test DNS resolution
sleep 2
print_status "Testing DNS resolution..."
if nslookup google.com 127.0.0.1; then
    print_status "DNS resolution test successful"
else
    print_warning "DNS resolution test failed, but Unbound may still be working"
fi