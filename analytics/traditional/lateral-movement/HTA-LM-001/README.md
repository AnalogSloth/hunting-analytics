# SMB File Write with Subsequent Local Execution

**ID**: HTA-LM-001  
**Author**: analogsloth  
**Created**: 2025-02-07  
**Updated**: 2025-02-07

## Goal

Detect adversary lateral movement by identifying instances where a file is written to a remote host via SMB and subsequently executed locally on that host. This pattern is commonly used by adversaries to stage malicious payloads and execute them as part of lateral movement operations.

## Categorization

**MITRE ATT&CK**: Lateral Movement / Remote Services / SMB/Windows Admin Shares  
**ATT&CK ID**: T1021.002  
**Related Techniques**: T1570 (Lateral Tool Transfer)  
**Platforms**: Windows

## Data Model Requirements

**OCSF Event Classes**:
- **Primary Class**: process_activity (class_uid: 1007)
- **Secondary Class**: network_activity (class_uid: 4001)

**Required Fields**:
- `process.file.path` - Process image path
- `process.file.name` - Process filename
- `device.hostname` - Host where process executed
- `actor.user.name` - User account
- `dst_endpoint.port` - Network destination port (445)
- `protocol_name` - Network protocol (SMB)
- `file.name` - File transferred via SMB
- `file.path` - Remote file path

**Minimum Data Sources**:
- [x] Windows Security Event Logs (Event ID 4688) OR Sysmon (Event ID 1)
- [x] Network flow data with SMB protocol parsing (Zeek, Suricata, EDR)
- [x] Sysmon Event ID 11 (optional, for file hash correlation)

## Technical Context

**Detection Strategy:**

This analytic correlates SMB file write activity with subsequent process creation events on the destination host. It detects when a file is written to a remote administrative share (ADMIN$, C$) via SMB and then executed within a 5-minute temporal window on that same host.

The detection uses network flow data to identify SMB write operations (SMB2 CREATE with write disposition on port 445), then correlates this with process creation events where the image path matches the remotely written file. False positive minimization includes filtering known deployment servers, excluding system processes, and establishing baselines for expected source-destination pairs.

**Adversary Tradecraft:**

Adversaries frequently use SMB for lateral movement because it's a native Windows protocol that blends with legitimate activity. Administrative shares (ADMIN$, C$) provide direct filesystem access for users with local admin rights, and many offensive tools leverage this (PSExec, Impacket, CrackMapExec, Cobalt Strike).

Common attack patterns:
1. **PSExec-style**: Write executable to ADMIN$, create Windows service, start service remotely
2. **Manual staging**: Copy executable to C$ or ADMIN$, use WMI/scheduled tasks to execute
3. **LOLBin staging**: Stage scripts (PowerShell, VBS) via SMB, execute via WMI/WinRM

Technical prerequisites:
- Valid credentials with local admin rights on target
- SMB accessible (port 445 not blocked)
- Administrative shares enabled (default on Windows)

**Normal vs. Malicious:**

**Legitimate use cases:**
- Software deployment systems (SCCM, Ivanti, PDQ Deploy)
- Remote management tools (RMM platforms)
- Backup solutions writing to remote shares
- IT administrators copying troubleshooting tools

**Malicious indicators:**
- SMB writes from workstation to workstation (not server to workstation)
- Execution from Temp, ProgramData, or ADMIN$ paths
- Unusual filenames (random strings, known offensive tool names)
- Off-hours activity
- Source-destination pairs with no historical communication

## Detection Logic

### Pseudocode
```
// Step 1: Identify SMB file write operations
flow = search Flow:Message
smb_write = filter flow where (
  dest_port == "445" and 
  protocol == "smb.write" or protocol == "smb2.create"
)
smb_write.file_name = smb_write.proto_info.file_name
smb_write.dest_host = smb_write.dest_ip

// Step 2: Search for process creation events
process = search Process:Create

// Step 3: Correlate SMB write with subsequent process execution
remote_exec = join (smb_write, process) where (
  smb_write.dest_host == process.hostname and
  smb_write.file_name == process.image_path.file_name and
  (process.time - smb_write.time) <= 5 minutes and
  (process.time - smb_write.time) >= 0
)

// Step 4: Filter known false positives
remote_exec = filter remote_exec where (
  process.image_path not in [known_legitimate_paths] and
  smb_write.src_ip not in [known_deployment_servers]
)

output remote_exec
```

### SQL Implementation

See [query.sql](./query.sql)

## Blind Spots and Assumptions

**Assumptions**:
- [ ] Network visibility includes SMB protocol parsing (Zeek, Suricata, or EDR)
- [ ] Process creation logging enabled (Sysmon, EDR, or Event ID 4688 with command line)
- [ ] Log correlation occurs within 5-minute temporal window
- [ ] File names remain consistent (no renaming between write and execution)
- [ ] Clock synchronization across logging sources (NTP configured)

**Blind Spots**:
- [ ] **Files renamed before execution** - Correlation fails if file renamed after SMB write
- [ ] **Indirect execution** - DLLs loaded by another process won't show in process creation
- [ ] **Encrypted SMB traffic** - SMB3 encryption or VPN tunnels prevent protocol inspection
- [ ] **Execution delay > 5 minutes** - Adversaries staging files and waiting evade temporal window
- [ ] **Local file copies** - If file copied locally after SMB write, executed path won't match
- [ ] **Alternative lateral movement** - WMI, DCOM, WinRM that don't use SMB for staging
- [ ] **Memory-only execution** - Fileless malware or reflective DLL injection

## False Positives

**Known FP Sources**:

1. **Software Deployment Systems**:
   - *Characteristics*: SCCM, Ivanti, PDQ Deploy copying executables to ADMIN$ and executing
   - *Mitigation*: Whitelist known deployment server IPs

2. **Remote Management Tools**:
   - *Characteristics*: RMM platforms (ConnectWise, N-able) staging tools remotely
   - *Mitigation*: Baseline RMM source IPs and execution patterns

3. **Automated Patching**:
   - *Characteristics*: Windows Update, WSUS writing and executing installers
   - *Mitigation*: Filter executions from C:\Windows\SoftwareDistribution

4. **IT Administrative Activity**:
   - *Characteristics*: Help desk manually copying troubleshooting tools
   - *Mitigation*: Baseline admin workstations, correlate with ticketing systems

5. **Backup Solutions**:
   - *Characteristics*: Backup agents writing to remote systems
   - *Mitigation*: Whitelist backup server IPs and agent executables

**Tuning Recommendations**:
- Baseline period: 30 days minimum to establish normal patterns
- Expected FP rate: 5-15% with active IT administration, <5% in mature environments
- Whitelisting approach: Maintain approved deployment/management server list, track admin workstations

## Validation

### True Positive Generation

**Method 1 - Manual PSExec Simulation**:
```powershell
# From attacking workstation (as admin):
# 1. Copy payload to remote host
Copy-Item -Path "C:\Tools\test.exe" -Destination "\\TARGET-PC\C$\Windows\Temp\test.exe"

# 2. Execute remotely via WMI
$cred = Get-Credential
Invoke-WmiMethod -Class Win32_Process -Name Create `
  -ArgumentList "C:\Windows\Temp\test.exe" `
  -ComputerName "TARGET-PC" -Credential $cred

# Alternative: Use PsExec
# PsExec.exe \\TARGET-PC -u DOMAIN\AdminUser C:\Windows\Temp\test.exe
```

**Method 2 - Atomic Red Team**:
- **Test**: T1021.002 - Remote Services: SMB/Windows Admin Shares
- **Link**: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md
```powershell
Invoke-AtomicTest T1021.002 -TestNumbers 1
```

**Expected Results**:
- **Network logs**: SMB2 CREATE to port 445, path like `\\ADMIN$\Temp\[file].exe`
- **Process logs**: New process with image path matching remotely written file within 5 minutes
- **Analytic output**: Correlation showing SMB write + execution with time delta ~90-120 seconds

## Real-World Context

**Observed In**:
- **APT Groups**: APT29 (Cozy Bear) in government targeting, APT41 in supply chain attacks, FIN7 in hospitality sector
- **Ransomware**: Ryuk lateral movement before encryption, Conti spreading across enterprise, LockBit automated propagation
- **Red Team Tools**: PSExec/PsExec64 (Sysinternals), Impacket psexec.py, CrackMapExec, Cobalt Strike, Metasploit psexec modules
- **Notable Incidents**: NotPetya (2017) lateral spread, WannaCry (2017) SMB-based movement, SolarWinds post-exploitation (2020)

## Additional Resources

**External**:
- [MITRE ATT&CK T1021.002](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE CAR-2013-05-005](https://car.mitre.org/analytics/CAR-2013-05-005/)
- [Microsoft: Detect PsExec](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-psexec)
- [Red Canary: Detecting PSExec](https://redcanary.com/blog/how-to-detect-psexec/)
- [Atomic Red Team T1021.002](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md)

---

**Detection Maturity Level**: 3 (Behavior chain detection - correlates multiple events)  
**Last Validated**: 2025-02-07  
**Validation Result**: Pass (Atomic Red Team T1021.002-1)
