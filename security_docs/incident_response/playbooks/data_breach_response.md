# Data Breach Incident Response Playbook

## Incident Classification: Data Breach

### Breach Severity Matrix
| Data Type | Records Affected | Severity | Notification Timeline |
|-----------|------------------|----------|----------------------|
| PII/PHI | >500 | Critical | 1 hour |
| PII/PHI | 100-500 | High | 4 hours |
| PII/PHI | <100 | Medium | 8 hours |
| Internal Data | Any | Medium | 12 hours |
| Public Data | Any | Low | 24 hours |

### Regulatory Requirements
- **GDPR**: 72 hours to supervisory authority
- **HIPAA**: 60 days for breach notification
- **PCI DSS**: Immediate notification to card brands
- **State Laws**: Varies by jurisdiction (CA, NY, etc.)

## Phase 1: Immediate Response (0-1 Hour)

### Critical First Steps
```yaml
IMMEDIATE ACTIONS (First 15 minutes):
1. Activate incident response team
2. Preserve all logs and evidence
3. Document discovery time and method
4. Assess ongoing data access/exfiltration
5. Implement immediate containment if possible
```

### Initial Assessment Checklist
- [ ] **What data was accessed?**
  - Personal Identifiable Information (PII)
  - Protected Health Information (PHI)
  - Financial data (credit cards, bank accounts)
  - Intellectual property
  - Trade secrets

- [ ] **How many records affected?**
  - Exact count if available
  - Estimated range if exact unknown
  - Categories of data subjects

- [ ] **Who had unauthorized access?**
  - External threat actor
  - Malicious insider
  - Accidental exposure
  - Third-party vendor

- [ ] **How was data accessed?**
  - Cyberattack (malware, phishing)
  - System vulnerability
  - Human error
  - Physical theft/loss

### Evidence Preservation
```bash
# Preserve system logs immediately
sudo tar -czf evidence_$(date +%Y%m%d_%H%M%S).tar.gz \
  /var/log/ \
  /var/audit/ \
  /etc/passwd \
  /etc/shadow

# Database audit logs
mysqldump --single-transaction --routines --triggers mysql > mysql_audit.sql

# Web server access logs
cp /var/log/apache2/access.log* /evidence/
cp /var/log/nginx/access.log* /evidence/
```

## Phase 2: Containment and Assessment (1-4 Hours)

### Technical Containment
1. **Database Access Control**
   ```sql
   -- Revoke suspicious database access
   REVOKE ALL PRIVILEGES ON sensitive_db.* FROM 'suspicious_user'@'%';
   -- Enable additional logging
   SET GLOBAL general_log = 'ON';
   SET GLOBAL log_output = 'TABLE';
   ```

2. **Network Segmentation**
   ```bash
   # Isolate affected database servers
   iptables -A INPUT -s [AFFECTED_SUBNET] -j DROP
   # Block external data transfer
   iptables -A OUTPUT -p tcp --dport 21,22,3389 -j REJECT
   ```

3. **Account Security**
   - Disable compromised accounts immediately
   - Force password resets for all privileged users
   - Review and revoke API keys/tokens
   - Audit recent account activities

### Data Impact Assessment
```sql
-- Identify accessed sensitive data
SELECT table_name, column_name 
FROM information_schema.columns 
WHERE column_name LIKE '%ssn%' 
   OR column_name LIKE '%credit%'
   OR column_name LIKE '%social%'
   OR column_name LIKE '%dob%';

-- Check recent data access patterns
SELECT user, query_time, argument 
FROM mysql.general_log 
WHERE command_type = 'Query' 
  AND argument LIKE '%SELECT%'
  AND query_time >= '2024-01-01 00:00:00'
ORDER BY query_time DESC;
```

### Legal and Compliance Assessment
- [ ] Determine notification requirements
- [ ] Assess potential regulatory violations
- [ ] Calculate potential fines and penalties
- [ ] Document breach classification
- [ ] Engage legal counsel if required

## Phase 3: Investigation and Analysis (4-24 Hours)

### Forensic Investigation
```bash
# Timeline analysis with log2timeline
log2timeline.py --storage-file timeline.plaso /evidence/disk_image.dd

# Convert to human-readable format
psort.py -o dynamic timeline.plaso > investigation_timeline.csv

# Search for specific IOCs
grep -r "suspicious_ip\|malicious_domain" /var/log/
```

### Database Forensics
```sql
-- Analyze unusual data access patterns
SELECT 
    DATE(query_time) as date,
    user_host,
    COUNT(*) as query_count,
    GROUP_CONCAT(DISTINCT LEFT(argument, 100)) as sample_queries
FROM mysql.general_log 
WHERE command_type = 'Query'
  AND query_time >= DATE_SUB(NOW(), INTERVAL 30 DAY)
GROUP BY DATE(query_time), user_host
HAVING query_count > 1000
ORDER BY query_count DESC;

-- Check for bulk data exports
SELECT 
    user_host,
    query_time,
    argument
FROM mysql.general_log 
WHERE argument LIKE '%SELECT%*%FROM%'
  AND argument LIKE '%LIMIT%'
  AND CHAR_LENGTH(argument) > 200;
```

### Data Exfiltration Analysis
- **Network traffic analysis** for large outbound transfers
- **Email logs** for data sent via email
- **Cloud storage** access logs review
- **USB/removable media** audit logs
- **Print job logs** for physical data theft

### Attack Vector Analysis
```yaml
Common Data Breach Vectors:
1. SQL Injection: Check for SQLi patterns in logs
2. Compromised Credentials: Review authentication logs
3. Insider Threat: Audit privileged user activities
4. Malware: Scan for data-stealing malware
5. Social Engineering: Review phishing attempts
6. Third-party Breach: Check vendor access
7. Misconfigured Systems: Audit access controls
```

## Phase 4: Notification and Reporting

### Regulatory Notifications

#### GDPR Notification Template
```
To: [Data Protection Authority]
Subject: Personal Data Breach Notification - [Reference Number]

1. NATURE OF THE BREACH:
   - Type: [Confidentiality/Integrity/Availability breach]
   - Discovery Date: [DATE TIME]
   - Categories of data: [SPECIFY]
   - Number of records: [APPROXIMATE NUMBER]

2. LIKELY CONSEQUENCES:
   - [Describe potential harm to data subjects]

3. MEASURES TAKEN:
   - [Containment actions]
   - [Mitigation measures]
   - [Prevention of future breaches]

4. CONTACT INFORMATION:
   - DPO: [Name, Email, Phone]
   - Organization: [Details]
```

#### HIPAA Breach Report
```
COVERED ENTITY INFORMATION:
- Entity Name: [ORGANIZATION]
- Contact: [NAME, TITLE, PHONE, EMAIL]

BREACH DETAILS:
- Date of Discovery: [DATE]
- Date of Breach: [DATE]
- Location: [GEOGRAPHIC LOCATION]
- Type of Media: [Electronic/Paper/Other]

INDIVIDUALS AFFECTED:
- Number: [COUNT]
- Information Involved: [PHI TYPES]

SAFEGUARDS: [Describe safeguards in place]
BREACH DESCRIPTION: [Detailed description]
```

### Data Subject Notification
```
SUBJECT: Important Security Notice - Your Personal Information

Dear [NAME],

We are writing to inform you of a security incident that may have affected your personal information.

WHAT HAPPENED:
[Brief description of the incident]

INFORMATION INVOLVED:
[Specific data types affected for this individual]

WHAT WE ARE DOING:
- [Immediate response actions]
- [Additional security measures]
- [Law enforcement involvement if applicable]

WHAT YOU CAN DO:
- Monitor your accounts for unusual activity
- Consider placing fraud alerts on credit files
- Report suspicious activity immediately

We sincerely apologize for this incident and any inconvenience it may cause.

Contact: [DEDICATED HELPLINE]
Reference: [CASE NUMBER]
```

### Media Response Strategy
```yaml
Media Response Guidelines:
1. Designate single spokesperson
2. Prepare key messages in advance
3. Focus on response actions, not blame
4. Avoid technical jargon
5. Express genuine concern for affected individuals
6. Highlight security improvements being made

Key Messages:
- "We take the security of personal information very seriously"
- "We acted immediately upon discovery"
- "We are working with law enforcement"
- "We are providing free credit monitoring services"
```

## Phase 5: Remediation and Recovery

### Technical Remediation
1. **Access Control Hardening**
   ```sql
   -- Implement stricter database permissions
   CREATE ROLE 'limited_access';
   GRANT SELECT ON public_tables.* TO 'limited_access';
   -- Remove unnecessary privileges
   REVOKE ALL PRIVILEGES ON *.* FROM 'application_user'@'%';
   ```

2. **Encryption Implementation**
   ```python
   # Encrypt sensitive data at rest
   from cryptography.fernet import Fernet
   
   key = Fernet.generate_key()
   cipher_suite = Fernet(key)
   
   # Encrypt PII fields
   encrypted_ssn = cipher_suite.encrypt(ssn.encode())
   ```

3. **Monitoring Enhancement**
   ```yaml
   # Enhanced SIEM rules
   - rule: Unusual Data Access
     condition: |
       database_query and 
       (query contains "SELECT * FROM users" or
        row_count > 1000) and
       time_of_day not in business_hours
   ```

### Process Improvements
- **Data Classification**: Implement formal data classification
- **Access Reviews**: Regular privilege reviews and recertification
- **Monitoring**: Enhanced logging and alerting
- **Training**: Security awareness for all staff
- **Vendor Management**: Third-party security assessments

### Victim Support Services
```yaml
Support Services to Provide:
1. Free Credit Monitoring (12-24 months)
2. Identity Theft Protection
3. Dedicated Call Center
4. Identity Restoration Services
5. Fraud Alerts Setup Assistance

Service Providers:
- Experian IdentityWorks
- Equifax ID Patrol
- TransUnion TrueIdentity
- AllClear ID
```

## Phase 6: Legal and Financial Management

### Insurance Claims
```yaml
Cyber Insurance Checklist:
- [ ] Immediate notification to carrier
- [ ] Preserve all documentation
- [ ] Coordinate with approved vendors
- [ ] Document all costs incurred
- [ ] Obtain pre-approval for major expenses

Covered Costs May Include:
- Forensic investigation
- Legal fees
- Notification costs
- Credit monitoring
- Business interruption
- Regulatory fines
- Third-party liability
```

### Litigation Preparedness
- **Legal Hold**: Preserve all relevant documents
- **Privilege Protection**: Engage counsel early
- **Expert Witnesses**: Identify potential experts
- **Discovery Planning**: Prepare for document requests
- **Settlement Strategy**: Evaluate resolution options

## Phase 7: Long-term Monitoring

### Ongoing Monitoring (90+ Days)
```sql
-- Monitor for signs of continued unauthorized access
SELECT 
    DATE(query_time) as access_date,
    user_host,
    COUNT(DISTINCT table_name) as tables_accessed
FROM information_schema.processlist p
JOIN mysql.general_log l ON p.user = SUBSTRING_INDEX(l.user_host, '@', 1)
WHERE l.query_time >= DATE_SUB(NOW(), INTERVAL 7 DAY)
GROUP BY DATE(query_time), user_host
HAVING tables_accessed > 10;
```

### Dark Web Monitoring
- Monitor underground forums for data sales
- Set up alerts for organization/domain mentions
- Track cryptocurrency transactions if relevant
- Coordinate with law enforcement for investigations

### Regulatory Follow-up
- Respond to regulatory inquiries promptly
- Provide updates on remediation progress
- Submit final incident reports
- Participate in regulatory examinations

## Key Performance Indicators

### Response Metrics
- **Discovery Time**: How long from breach to discovery?
- **Notification Time**: How long to notify authorities/victims?
- **Containment Time**: How long to stop ongoing exposure?
- **Recovery Time**: How long to full operational recovery?

### Success Criteria
- [ ] All unauthorized access stopped
- [ ] All regulatory notifications completed
- [ ] All affected individuals notified
- [ ] Remediation measures implemented
- [ ] Monitoring systems enhanced

## Cost Tracking Template

| Category | Description | Estimated Cost | Actual Cost |
|----------|-------------|----------------|-------------|
| **Investigation** | Forensics, legal | $50,000 | $ |
| **Notification** | Letters, call center | $25,000 | $ |
| **Monitoring** | Credit monitoring | $100,000 | $ |
| **Remediation** | System improvements | $75,000 | $ |
| **Legal** | Litigation, settlements | $500,000 | $ |
| **Regulatory** | Fines, penalties | $250,000 | $ |
| **Business Impact** | Lost revenue | $200,000 | $ |
| **TOTAL** | | $1,200,000 | $ |

## Emergency Contacts

### Internal Escalation
- **Incident Commander**: [PHONE] [EMAIL]
- **Legal Counsel**: [PHONE] [EMAIL]
- **Privacy Officer/DPO**: [PHONE] [EMAIL]
- **Communications**: [PHONE] [EMAIL]
- **Executive Team**: [PHONE] [EMAIL]

### External Resources
- **Cyber Insurance**: [POLICY] [PHONE]
- **Law Enforcement**: FBI, Secret Service
- **Forensics Firm**: [CONTACT INFO]
- **Outside Counsel**: [FIRM] [CONTACT]
- **Notification Vendor**: [COMPANY] [CONTACT]