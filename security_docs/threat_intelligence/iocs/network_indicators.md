# Network Indicators of Compromise (IOCs)

## Malicious IP Addresses

### Known Attack Sources
```
# APT Groups
185.220.101.0/24    # Associated with APT28/Fancy Bear
198.98.57.0/24      # Cobalt Strike infrastructure
45.147.231.0/24     # Ransomware C2 servers
```

### Suspicious Activity Patterns
- **High-frequency scanning**: >1000 requests/minute from single IP
- **Port scanning**: Sequential access to multiple ports (21, 22, 23, 80, 443, 3389)
- **Brute force indicators**: Multiple failed login attempts from same source
- **Geolocation anomalies**: Access from high-risk countries

### Response Actions
1. **Immediate blocking** at firewall/WAF level
2. **SIEM alert generation** for future occurrences
3. **Threat intelligence correlation** with known IOCs
4. **Network traffic analysis** for lateral movement

## Malicious Domains

### Command & Control (C2) Domains
```
evil-domain[.]com
malware-c2[.]net
phishing-site[.]org
fake-bank[.]info
```

### Domain Generation Algorithms (DGA)
- **Length patterns**: Random 8-16 character domains
- **Character distribution**: High entropy, random consonant/vowel mix
- **TLD patterns**: .tk, .ml, .ga, .cf (free TLDs commonly abused)
- **Registration timing**: Recently registered domains (<30 days)

### Detection Signatures
- DNS queries to suspicious TLDs
- High-entropy domain names
- Uncommon character patterns in domain names
- DNS tunneling indicators (TXT record queries)

### Mitigation Steps
1. **DNS sinkholing** for known malicious domains
2. **DNS filtering** implementation
3. **Monitor DNS logs** for suspicious patterns
4. **Implement DNS over HTTPS (DoH) controls**

## Network Traffic Anomalies

### Bandwidth Indicators
- **Data exfiltration**: Unusual outbound traffic volumes
- **Beacon patterns**: Regular, periodic communication intervals
- **Off-hours activity**: Network traffic during non-business hours
- **Geographic anomalies**: Traffic to/from unexpected countries

### Protocol Abuse
- **HTTP tunneling**: Non-HTTP protocols over port 80/443
- **DNS tunneling**: Large DNS queries with unusual record types
- **ICMP tunneling**: Data hidden in ping packets
- **Protocol mismatches**: Wrong protocol for assigned ports

### Connection Patterns
```
# Suspicious connection behaviors
- Long-duration connections (>24 hours)
- High-frequency short connections
- Connections to multiple sequential IPs
- Unusual port combinations
```

### Detection Rules
```yaml
# Suricata rule examples
alert tcp any any -> any 80 (msg:"Possible HTTP tunneling"; content:"CONNECT"; http_method; sid:1001;)
alert dns any any -> any 53 (msg:"DNS tunneling detected"; dsize:>512; sid:1002;)
alert icmp any any -> any any (msg:"ICMP tunnel detected"; dsize:>64; sid:1003;)
```

## SSL/TLS Anomalies

### Certificate Indicators
- **Self-signed certificates** on production systems
- **Expired certificates** still in use
- **Weak encryption algorithms** (MD5, SHA1)
- **Invalid certificate chains**
- **Domain mismatches** in certificates

### JA3/JA4 Fingerprints
```
# Known malware SSL fingerprints
775bf8e0bdbf6ad21b9d53c75699ef2d  # Cobalt Strike
06cd13bfd02ba3c4e372e45e2940acb2  # Metasploit
```

### TLS Traffic Analysis
- **Uncommon cipher suites** usage
- **Certificate pinning bypass** attempts
- **SNI anomalies** (Server Name Indication)
- **ALPN protocol negotiation** irregularities

### Response Procedures
1. **Certificate transparency monitoring**
2. **SSL/TLS inspection** at network boundaries
3. **JA3 fingerprint logging** and analysis
4. **Certificate revocation checking**

## Network Infrastructure IOCs

### Compromised Infrastructure
- **Open proxies** and SOCKS servers
- **Compromised legitimate websites** hosting malware
- **Fast-flux networks** with rapidly changing IPs
- **Bulletproof hosting** providers

### Infrastructure Patterns
```
# ASN numbers associated with malicious activity
AS13335  # Cloudflare (often abused for hiding C2)
AS16509  # Amazon (compromised instances)
AS14061  # DigitalOcean (popular for C2 hosting)
```

### Hosting Indicators
- **Recently registered domains** with hosting
- **Shared hosting** with multiple malicious domains
- **VPS providers** with poor abuse handling
- **Free hosting services** commonly abused

### Monitoring Strategies
1. **Passive DNS monitoring** for infrastructure changes
2. **WHOIS data analysis** for registration patterns
3. **BGP monitoring** for routing anomalies
4. **CDN abuse detection** mechanisms

## Email-based IOCs

### Sender Reputation
- **Newly registered domains** sending email
- **SPF/DKIM/DMARC failures** in authentication
- **IP reputation scores** below threshold
- **Sender frequency anomalies**

### Content Indicators
```
# Suspicious email patterns
- Attachment types: .scr, .pif, .com, .bat, .vbs
- Archive passwords: "infected", "malware", "123456"
- URL shorteners: bit.ly, tinyurl.com, t.co
- Unicode spoofing: Mixed character sets
```

### Phishing Indicators
- **Brand impersonation** attempts
- **Urgency language** patterns
- **Suspicious attachment** types
- **URL redirection** chains

### Email Security Measures
1. **DMARC policy enforcement**
2. **Attachment sandboxing**
3. **URL rewriting** and analysis
4. **Sender reputation scoring**

## File-based IOCs

### Hash Signatures
```md5
d41d8cd98f00b204e9800998ecf8427e  # Known malware hash
5d41402abc4b2a76b9719d911017c592  # Ransomware sample
```

```sha256
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  # Suspicious binary
```

### File Behavior Indicators
- **Persistence mechanisms**: Registry modifications, scheduled tasks
- **Network communications**: Outbound connections from executables
- **File system changes**: Unusual file creation patterns
- **Process injection**: Code injection into legitimate processes

### Static Analysis IOCs
- **Packer signatures**: UPX, ASPack, Themida
- **Suspicious imports**: VirtualAlloc, WriteProcessMemory
- **String artifacts**: Hard-coded IPs, domain names
- **Code patterns**: Encryption routines, keyloggers

### Dynamic Analysis Indicators
1. **API call patterns** characteristic of malware
2. **Memory usage anomalies**
3. **Mutex creation** for infection markers
4. **Registry key modifications**

## Response Automation

### SIEM Integration
```yaml
# Example SIEM rule for IOC detection
- rule: Malicious IP Communication
  condition: |
    network_connection and 
    (dest_ip in malicious_ips or src_ip in malicious_ips)
  action: |
    - generate_alert
    - block_connection
    - quarantine_host
```

### Threat Hunting Queries
```sql
-- Detect communication with known bad IPs
SELECT timestamp, src_ip, dest_ip, bytes_out 
FROM network_logs 
WHERE dest_ip IN (SELECT ip FROM threat_intel_ips)
AND timestamp > NOW() - INTERVAL 24 HOUR;

-- Find domains with DGA characteristics  
SELECT domain, query_count, first_seen
FROM dns_logs
WHERE LENGTH(domain) BETWEEN 8 AND 16
AND domain REGEXP '^[a-z0-9]{8,16}\.(tk|ml|ga|cf)$'
ORDER BY first_seen DESC;
```

### Automated Response
1. **IOC feed integration** with security tools
2. **Automatic blocking** rules for high-confidence IOCs
3. **Alert escalation** based on IOC severity
4. **Threat intelligence sharing** with industry peers