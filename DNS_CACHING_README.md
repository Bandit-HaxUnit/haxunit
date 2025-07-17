# Unbound DNS Caching Implementation

This document describes the implementation of Unbound DNS caching for the HaxUnit reconnaissance tool.

## Overview

Unbound is a validating, recursive, caching DNS resolver that has been integrated into the Docker container to provide:

- **DNS Caching**: Reduces DNS query latency by caching responses
- **Performance**: Faster subdomain enumeration and DNS lookups
- **Privacy**: Local DNS resolution reduces exposure to external DNS providers
- **Security**: DNSSEC validation and query minimization
- **Reliability**: Fallback to multiple upstream DNS servers

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   HaxUnit       │───▶│   Unbound       │───▶│  Upstream DNS   │
│   (dnsx, etc.)  │    │   DNS Cache     │    │  (1.1.1.1, etc)│
│   Port: Any     │    │   Port: 53      │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Files Added/Modified

### New Files

1. **`unbound.conf`** - Unbound configuration file
   - Optimized cache settings (512MB total cache)
   - Security hardening (DNSSEC, query minimization)
   - Performance tuning (2 threads, prefetching)
   - Forward zones to reliable upstream servers

2. **`start-unbound.sh`** - Unbound initialization script
   - Downloads root hints
   - Initializes DNSSEC trust anchor
   - Starts Unbound daemon
   - Performs initial DNS test

3. **`dns-monitor.sh`** - DNS monitoring and testing script
   - Cache performance testing
   - DNS resolution verification
   - Statistics and logging

4. **`DNS_CACHING_README.md`** - This documentation

### Modified Files

1. **`Dockerfile`**
   - Added `unbound`, `dnsutils`, and `wget` packages
   - Added sudo permissions for haxunit user
   - Added `NET_BIND_SERVICE` capability

2. **`docker-entrypoint.sh`**
   - Integrated Unbound startup in tmux session
   - Added health checks for Unbound service

3. **`docker-compose.yml`**
   - Added `NET_BIND_SERVICE` capability for port 53 binding

4. **`main.py`**
   - Changed DNS resolver from `8.8.8.8` to `127.0.0.1` (local Unbound)
   - Updated dnsx commands to use local DNS cache

## Configuration Details

### Cache Configuration
- **Message Cache**: 128MB (fast query responses)
- **RRset Cache**: 256MB (DNS record storage)
- **Key Cache**: 64MB (DNSSEC keys)
- **Negative Cache**: 16MB (failed queries)
- **Total Cache**: ~512MB

### Performance Settings
- **Threads**: 2 (optimal for container environment)
- **Prefetching**: Enabled (proactive cache warming)
- **TTL Limits**: 
  - Max TTL: 24 hours
  - Max Negative TTL: 1 hour

### Security Features
- **DNSSEC Validation**: Enabled
- **Query Minimization**: Enabled (privacy)
- **Identity Hiding**: Enabled
- **Algorithm Downgrade Protection**: Enabled

### Upstream DNS Servers
- Primary: 1.1.1.1, 1.0.0.1 (Cloudflare)
- Secondary: 8.8.8.8, 8.8.4.4 (Google)

## Usage

### Starting the Container

The Unbound DNS cache starts automatically when the container launches:

```bash
docker-compose up -d
```

### Monitoring DNS Cache

Use the monitoring script to check cache performance:

```bash
# Inside the container
./dns-monitor.sh
```

### Manual DNS Testing

Test DNS resolution through the local cache:

```bash
# Query through Unbound cache
nslookup google.com 127.0.0.1

# Compare with direct query
nslookup google.com 8.8.8.8
```

### Accessing Tmux Sessions

View running services:

```bash
# List tmux sessions
tmux list-sessions

# Attach to Unbound session
tmux attach-session -t unbound

# Attach to OpenVPN session (if running)
tmux attach-session -t openvpn
```

## Performance Benefits

### Before (Direct DNS)
- Each DNS query: 20-100ms latency
- No caching between operations
- Dependent on external DNS performance
- Potential rate limiting from DNS providers

### After (Unbound Cache)
- First query: 20-100ms (cache miss)
- Subsequent queries: <1ms (cache hit)
- Reduced external DNS dependencies
- Better performance for repetitive operations

### Expected Improvements
- **Subdomain Enumeration**: 30-50% faster
- **DNS Resolution**: 90%+ cache hit rate after warmup
- **Network Traffic**: Reduced outbound DNS queries
- **Reliability**: Continued operation during DNS outages

## Troubleshooting

### Check Unbound Status
```bash
# Check if Unbound is running
pgrep unbound

# View Unbound logs
sudo tail -f /var/log/unbound/unbound.log

# Test configuration
sudo unbound-checkconf /etc/unbound/unbound.conf
```

### Common Issues

1. **Port 53 Permission Denied**
   - Ensure `NET_BIND_SERVICE` capability is set
   - Check if another DNS service is running

2. **DNS Resolution Fails**
   - Verify upstream DNS connectivity
   - Check firewall rules
   - Restart Unbound service

3. **Cache Not Working**
   - Verify dnsx is using `-r 127.0.0.1`
   - Check Unbound configuration
   - Monitor cache statistics

### Manual Restart

If Unbound needs to be restarted:

```bash
# Stop Unbound
sudo pkill unbound

# Restart via script
./start-unbound.sh

# Or restart tmux session
tmux kill-session -t unbound
tmux new-session -d -s unbound "./start-unbound.sh"
```

## Performance Monitoring

### Cache Hit Rate
Monitor cache effectiveness:
- High hit rate (>80%) indicates good caching
- Low hit rate may suggest configuration issues

### Query Response Time
- Initial queries: Normal upstream latency
- Cached queries: Sub-millisecond response

### Memory Usage
- Monitor container memory usage
- Adjust cache sizes if needed

## Security Considerations

1. **Local DNS Only**: Unbound only accepts queries from localhost
2. **DNSSEC Validation**: Protects against DNS poisoning
3. **Query Minimization**: Reduces information leakage
4. **Secure Upstream**: Uses reputable DNS providers
5. **No External Access**: DNS cache not exposed outside container

## Future Enhancements

Potential improvements:
1. **DNS-over-HTTPS (DoH)**: Encrypted upstream queries
2. **Custom Block Lists**: Ad/malware blocking
3. **Statistics Dashboard**: Web-based monitoring
4. **Advanced Caching**: Application-specific optimizations
5. **Cluster Support**: Shared cache across containers

## References

- [Unbound Documentation](https://nlnetlabs.nl/documentation/unbound/)
- [DNS Caching Best Practices](https://tools.ietf.org/html/rfc2308)
- [DNSSEC Validation](https://tools.ietf.org/html/rfc4033)