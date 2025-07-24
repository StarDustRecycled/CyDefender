# Web Application Attack Patterns

## SQL Injection (SQLi)

### Attack Description
SQL injection attacks occur when malicious SQL statements are inserted into an entry field for execution, allowing attackers to view data that they are not normally able to retrieve.

### Common Indicators
- Single quotes (') or double quotes (") in input fields
- SQL keywords in URL parameters or form data: `UNION`, `SELECT`, `INSERT`, `UPDATE`, `DELETE`
- Time delays in application responses indicating time-based SQLi
- Database error messages exposed to users
- Unusual database query patterns in logs

### Attack Vectors
1. **Union-based SQLi**: `' UNION SELECT username, password FROM users--`
2. **Boolean-based blind SQLi**: `' AND 1=1--` vs `' AND 1=2--`
3. **Time-based blind SQLi**: `'; WAITFOR DELAY '00:00:05'--`
4. **Error-based SQLi**: `' AND (SELECT COUNT(*) FROM information_schema.tables)>0--`

### Immediate Response Actions
1. **Block malicious IPs** identified in logs
2. **Disable affected endpoints** if possible
3. **Check database integrity** and recent modifications
4. **Review access logs** for unauthorized data access
5. **Implement WAF rules** to filter SQL injection attempts

### Detection Queries
```sql
-- Check for suspicious database queries
SELECT query_time, query, user_host 
FROM mysql.general_log 
WHERE command_type = 'Query' 
AND (query LIKE '%UNION%' OR query LIKE '%SELECT%password%' OR query LIKE '%information_schema%')
ORDER BY query_time DESC;
```

### Mitigation Strategies
- Implement parameterized queries/prepared statements
- Use stored procedures with proper input validation
- Apply principle of least privilege to database accounts
- Enable database query logging and monitoring
- Implement Web Application Firewall (WAF) rules

## Cross-Site Scripting (XSS)

### Attack Description
XSS attacks involve injecting malicious scripts into web pages viewed by other users, potentially stealing session cookies, redirecting users, or performing actions on their behalf.

### Common Indicators
- JavaScript code in input fields: `<script>`, `javascript:`, `onerror=`
- Encoded payloads: `%3Cscript%3E`, `&#60;script&#62;`
- DOM manipulation attempts: `document.cookie`, `window.location`
- Unusual HTTP requests with script tags in parameters

### Attack Types
1. **Stored XSS**: Malicious script stored in database and served to users
2. **Reflected XSS**: Script reflected back in immediate response
3. **DOM-based XSS**: Client-side script manipulation

### Immediate Response Actions
1. **Sanitize stored data** containing malicious scripts
2. **Implement Content Security Policy (CSP)** headers
3. **Review and validate** all user input handling
4. **Check session management** for compromised accounts
5. **Notify affected users** to clear browser cache/cookies

### Detection Patterns
- Script tags in request parameters
- Base64 encoded JavaScript
- Event handlers in HTML attributes
- Attempts to access `document.cookie` or `localStorage`

### Mitigation Strategies
- Implement output encoding for all user data
- Use Content Security Policy (CSP) headers
- Validate and sanitize all user inputs
- Use HTTP-only cookies for session management
- Implement X-XSS-Protection headers

## Cross-Site Request Forgery (CSRF)

### Attack Description
CSRF attacks trick authenticated users into performing unwanted actions on web applications where they're authenticated.

### Common Indicators
- Requests without proper CSRF tokens
- Suspicious referrer headers
- Unexpected state changes for authenticated users
- Requests from external domains to sensitive endpoints

### Attack Examples
1. **State-changing GET requests**: `<img src="http://bank.com/transfer?to=attacker&amount=1000">`
2. **Auto-submitting forms**: Hidden forms that submit automatically
3. **AJAX requests**: Cross-origin requests without proper validation

### Immediate Response Actions
1. **Implement CSRF tokens** for all state-changing operations
2. **Validate referrer headers** for sensitive requests
3. **Review recent account activities** for unauthorized actions
4. **Use SameSite cookie attributes**
5. **Implement double-submit cookies**

### Detection Methods
- Monitor for requests without CSRF tokens
- Check for unusual patterns in user actions
- Analyze referrer headers for external origins
- Look for rapid succession of state-changing requests

### Mitigation Strategies
- Implement CSRF tokens for all forms
- Use SameSite cookie attributes
- Validate referrer and origin headers
- Implement re-authentication for sensitive operations
- Use POST requests for state-changing operations

## Command Injection

### Attack Description
Command injection attacks allow execution of arbitrary operating system commands on the host system through vulnerable applications.

### Common Indicators
- System command separators: `;`, `|`, `&`, `&&`, `||`
- Command execution keywords: `exec`, `system`, `eval`, `cmd`
- File system navigation: `../`, `..\\`, `/etc/passwd`, `%SYSTEMROOT%`
- Network reconnaissance commands: `ping`, `nslookup`, `wget`, `curl`

### Attack Vectors
1. **Direct injection**: `; rm -rf /`
2. **Command chaining**: `& net user attacker password /add`
3. **Command substitution**: `$(whoami)`, `` `id` ``
4. **File inclusion**: `; cat /etc/passwd`

### Immediate Response Actions
1. **Isolate affected systems** from network
2. **Check system integrity** and file modifications
3. **Review system logs** for unauthorized command execution
4. **Disable vulnerable functionality** temporarily
5. **Scan for malware** and backdoors

### Detection Patterns
- Shell metacharacters in input parameters
- System command names in application logs
- Unusual process execution patterns
- File system access outside application directories

### Mitigation Strategies
- Avoid system command execution in applications
- Use allowlists for permitted characters and commands
- Implement proper input validation and sanitization
- Run applications with minimal privileges
- Use containerization and sandboxing

## Directory Traversal

### Attack Description
Directory traversal attacks allow access to files and directories outside the web root folder by manipulating file path references.

### Common Indicators
- Path traversal sequences: `../`, `..\\`, `....//`
- Encoded traversal patterns: `%2e%2e%2f`, `%252e%252e%252f`
- Absolute path references: `/etc/passwd`, `C:\Windows\System32\`
- Null byte injection: `%00`, `\0`

### Attack Examples
1. **Basic traversal**: `../../../etc/passwd`
2. **Encoded traversal**: `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`
3. **Double encoding**: `%252e%252e%252f`
4. **Null byte bypass**: `../../../etc/passwd%00.jpg`

### Immediate Response Actions
1. **Restrict file access permissions** on web server
2. **Implement path validation** and canonicalization
3. **Check for unauthorized file access** in server logs
4. **Use chroot jails** or containerization
5. **Audit file system permissions** regularly

### Detection Methods
- Monitor for file access outside web directories
- Look for encoded traversal sequences in requests
- Check for access to sensitive system files
- Analyze unusual file read patterns

### Mitigation Strategies
- Implement strict input validation for file paths
- Use allowlists for permitted file extensions
- Canonicalize file paths before processing
- Run web applications in restricted environments
- Implement proper access controls on file system