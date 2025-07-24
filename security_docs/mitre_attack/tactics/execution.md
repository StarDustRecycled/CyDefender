# MITRE ATT&CK Tactic: Execution (TA0002)

## Tactic Overview

**Tactic ID**: TA0002  
**Tactic Name**: Execution  
**Description**: The adversary is trying to run malicious code on your system.

Execution consists of techniques that result in adversary-controlled code running on a local or remote system. Techniques that run malicious code are often paired with techniques from all other tactics to achieve broader goals, like exploring a network or stealing data.

## Key Techniques

### Primary Execution Methods

#### T1059: Command and Scripting Interpreter
- **PowerShell** (T1059.001)
- **AppleScript** (T1059.002)  
- **Windows Command Shell** (T1059.003)
- **Unix Shell** (T1059.004)
- **Visual Basic** (T1059.005)
- **Python** (T1059.006)
- **JavaScript/JScript** (T1059.007)
- **Network Device CLI** (T1059.008)

#### T1204: User Execution
- **Malicious Link** (T1204.001)
- **Malicious File** (T1204.002)
- **Malicious Image** (T1204.003)

#### T1203: Exploitation for Client Execution
- Browser exploits
- Office document exploits
- PDF exploits
- Media file exploits

#### T1569: System Services
- **Service Execution** (T1569.001)
- **Launchctl** (T1569.002)

## Attack Scenarios

### Scenario 1: Phishing Email Execution Chain
```yaml
Initial Vector: Email Attachment
1. T1566.001 - Spearphishing Attachment
2. T1204.002 - User Execution: Malicious File
3. T1059.001 - PowerShell execution
4. T1055 - Process Injection (Defense Evasion)
5. T1543.003 - Create Service (Persistence)
```

### Scenario 2: Web-based Compromise
```yaml
Initial Vector: Drive-by Download
1. T1189 - Drive-by Compromise
2. T1203 - Exploitation for Client Execution
3. T1059.007 - JavaScript execution
4. T1105 - Ingress Tool Transfer
5. T1218 - Signed Binary Proxy Execution
```

### Scenario 3: Living off the Land
```yaml
Technique Chain:
1. T1078 - Valid Accounts (Initial Access)
2. T1059.003 - Windows Command Shell
3. T1047 - Windows Management Instrumentation
4. T1053.005 - Scheduled Task/Job
```

## Detection Strategies

### Process Monitoring
```yaml
Key Process Events to Monitor:
- Process creation (Event ID 4688)
- Command line arguments
- Parent-child process relationships
- Process injection activities
- Unsigned or suspicious binaries

Critical Parent-Child Relationships:
- Office applications spawning cmd.exe/powershell.exe
- Browser processes creating unexpected children
- System processes spawning user applications
```

### Command Line Analysis
```sql
-- Detect suspicious command executions
SELECT 
    timestamp,
    hostname,
    username,
    process_name,
    command_line,
    parent_process
FROM process_logs 
WHERE (
    -- PowerShell with suspicious parameters
    (process_name LIKE '%powershell%' AND 
     (command_line LIKE '%-enc%' OR 
      command_line LIKE '%-bypass%' OR
      command_line LIKE '%downloadstring%')) OR
    
    -- Command shell with system commands
    (process_name LIKE '%cmd.exe%' AND 
     (command_line LIKE '%net user%' OR
      command_line LIKE '%sc create%' OR
      command_line LIKE '%reg add%')) OR
    
    -- Scripting engines from unusual parents
    (process_name IN ('wscript.exe', 'cscript.exe', 'python.exe') AND
     parent_process IN ('outlook.exe', 'winword.exe', 'excel.exe'))
)
ORDER BY timestamp DESC;
```

### Behavioral Analytics
```python
# Anomaly detection for execution patterns
import pandas as pd
from sklearn.ensemble import IsolationForest

def detect_execution_anomalies(process_data):
    """
    Detect unusual execution patterns using machine learning
    """
    features = [
        'process_frequency',  # How often this process runs
        'parent_diversity',   # Number of different parent processes
        'command_length',     # Length of command line
        'time_of_day',        # Hour of execution
        'user_diversity'      # Number of different users running it
    ]
    
    # Train isolation forest on baseline data
    clf = IsolationForest(contamination=0.1, random_state=42)
    clf.fit(process_data[features])
    
    # Detect anomalies
    anomalies = clf.predict(process_data[features])
    return process_data[anomalies == -1]  # Return anomalous processes
```

## Prevention Techniques

### Application Control
```yaml
Windows Defender Application Control (WDAC):
Purpose: Control which applications and scripts can run
Configuration:
  - Block unsigned PowerShell scripts
  - Allow only signed executables
  - Implement audit mode first
  - Use managed installer for authorized software

AppLocker Rules:
Executable Rules:
  - Path: %PROGRAMFILES%\* (Allow)
  - Path: %WINDIR%\* (Allow)  
  - Publisher: Microsoft Corporation (Allow)
  - Hash: Specific approved applications

Script Rules:
  - Path: %PROGRAMFILES%\* (Allow)
  - Publisher: Trusted script publishers (Allow)
  - Default: Deny all others
```

### PowerShell Security
```powershell
# Enable PowerShell Constrained Language Mode
$ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"

# Configure PowerShell logging via Group Policy
# Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell
Enable-PSRemoting -Force
Set-PSSessionConfiguration -Name Microsoft.PowerShell -ShowSecurityDescriptorUI

# PowerShell execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
```

### Endpoint Protection
```yaml
EDR/XDR Capabilities:
- Behavioral analysis of process execution
- Memory protection and injection detection
- Script and macro analysis
- Network behavior correlation
- Threat hunting capabilities

Configuration Priorities:
1. Enable process monitoring and logging
2. Configure behavioral analysis rules
3. Implement file reputation checking
4. Enable cloud-based threat intelligence
5. Set up automated response actions
```

## Response Procedures

### Immediate Containment
```bash
# Linux containment commands
# Kill suspicious processes
sudo kill -9 [PID]

# Block network access for process
sudo iptables -A OUTPUT -m owner --pid-owner [PID] -j DROP

# Prevent process restart
sudo chmod 000 /path/to/malicious/binary

# Windows containment commands
# Terminate process
taskkill /PID [PID] /F

# Block executable
echo. > "C:\path\to\malicious.exe"
attrib +R "C:\path\to\malicious.exe"
```

### Evidence Collection
```powershell
# Collect process information
Get-Process | Export-Csv -Path "C:\temp\processes.csv"
Get-WmiObject -Class Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine | Export-Csv -Path "C:\temp\process_details.csv"

# Collect network connections
netstat -ano > C:\temp\network_connections.txt

# Collect scheduled tasks
schtasks /query /fo csv /v > C:\temp\scheduled_tasks.csv

# PowerShell execution history
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Export-Csv -Path "C:\temp\powershell_logs.csv"
```

### Analysis Workflow
```yaml
Investigation Steps:
1. Process Tree Analysis:
   - Map parent-child relationships
   - Identify initial execution vector
   - Trace lateral movement

2. Timeline Reconstruction:
   - Correlate with authentication logs
   - Map network connections
   - Identify data access patterns

3. Artifact Analysis:
   - Decode obfuscated scripts
   - Analyze dropped files
   - Extract IOCs for blocking

4. Impact Assessment:
   - Determine compromised accounts
   - Identify accessed resources
   - Assess potential data exposure
```

## Mitigation Matrix

| Technique | Prevention | Detection | Response |
|-----------|------------|-----------|----------|
| **T1059.001 PowerShell** | Constrained Language Mode | Script block logging | Process termination |
| **T1059.003 Command Shell** | AppLocker rules | Command line auditing | Network isolation |
| **T1204.002 User Execution** | User training | Email security | User education |
| **T1203 Client Exploitation** | Patch management | Exploit detection | System isolation |
| **T1569.001 Service Execution** | Service hardening | Service monitoring | Service removal |

## Threat Hunting Queries

### Hunt 1: Unusual Process Execution Patterns
```kql
// Azure Sentinel KQL
SecurityEvent
| where EventID == 4688
| where TimeGenerated > ago(7d)
| extend ProcessName = tostring(split(NewProcessName, '\\')[-1])
| summarize ExecutionCount = count(), 
           UniqueParents = dcount(ParentProcessName),
           UniqueUsers = dcount(SubjectUserName),
           FirstSeen = min(TimeGenerated),
           LastSeen = max(TimeGenerated)
           by ProcessName
| where ExecutionCount < 10 or UniqueParents > 5
| order by ExecutionCount asc
```

### Hunt 2: Script Execution from Unusual Locations
```sql
-- Splunk SPL
index=windows source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| rex field=ScriptBlockText "(?<script_path>[C-Z]:\\[^\\s]+\\.ps1)"
| where NOT match(script_path, "^C:\\\\Program Files")
| where NOT match(script_path, "^C:\\\\Windows\\\\System32")
| stats count by script_path, ComputerName, UserId
| where count < 5
```

### Hunt 3: Process Injection Indicators
```python
# Python hunting script for process injection
def hunt_process_injection(process_logs):
    """
    Hunt for potential process injection based on execution patterns
    """
    suspicious_patterns = []
    
    for process in process_logs:
        # Look for processes with unusual memory patterns
        if (process['process_name'] in ['notepad.exe', 'calc.exe', 'svchost.exe'] and
            process['network_connections'] > 0):
            suspicious_patterns.append({
                'type': 'unexpected_network_activity',
                'process': process['process_name'],
                'pid': process['pid'],
                'connections': process['network_connections']
            })
        
        # Look for parent-child anomalies
        if (process['parent_process'] in ['winword.exe', 'excel.exe', 'outlook.exe'] and
            process['process_name'] in ['cmd.exe', 'powershell.exe', 'wscript.exe']):
            suspicious_patterns.append({
                'type': 'suspicious_parent_child',
                'parent': process['parent_process'],
                'child': process['process_name'],
                'command_line': process['command_line']
            })
    
    return suspicious_patterns
```

## Metrics and KPIs

### Detection Metrics
```yaml
Key Performance Indicators:
- Execution Detection Rate: >95%
- False Positive Rate: <5%
- Mean Time to Detection: <5 minutes
- Mean Time to Response: <15 minutes

Measurement Methods:
- Purple team exercises
- Red team simulations  
- Automated testing frameworks
- Baseline deviation analysis
```

### Coverage Assessment
```yaml
Technique Coverage Matrix:
T1059.001 PowerShell: 
  - Detection: High (Script block logging)
  - Prevention: Medium (Constrained mode)
  - Response: High (Process termination)

T1059.003 Command Shell:
  - Detection: High (Command auditing)
  - Prevention: Medium (AppLocker)
  - Response: High (Process isolation)

T1204.002 User Execution:
  - Detection: Medium (Email security)
  - Prevention: High (User training)
  - Response: Medium (User notification)
```

## Integration with Other Tactics

### Execution → Persistence
```yaml
Common Chains:
1. T1059.001 (PowerShell) → T1053.005 (Scheduled Task)
2. T1204.002 (User Execution) → T1547.001 (Registry Run Keys)
3. T1569.001 (Service Execution) → T1543.003 (Windows Service)
```

### Execution → Defense Evasion
```yaml
Common Chains:
1. T1059.001 (PowerShell) → T1027 (Obfuscated Files)
2. T1203 (Client Exploitation) → T1055 (Process Injection)
3. T1204.002 (User Execution) → T1218 (Signed Binary Proxy)
```

### Execution → Discovery
```yaml
Common Chains:
1. T1059.003 (Command Shell) → T1082 (System Information Discovery)
2. T1059.001 (PowerShell) → T1083 (File and Directory Discovery)
3. T1047 (WMI) → T1057 (Process Discovery)
```