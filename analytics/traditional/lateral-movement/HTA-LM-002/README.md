# User Logged into Multiple Hosts

**ID**: HTA-LM-002  
**Author**: analogsloth  
**Created**: 2025-02-08  
**Updated**: 2025-02-08

## Goal

Detect lateral movement by identifying user accounts that authenticate to an unusually high number of distinct hosts within a short time period. This pattern indicates potential adversary movement across the network using compromised credentials.

## Categorization

**MITRE ATT&CK**: Lateral Movement / Remote Services / SMB/Windows Admin Shares  
**ATT&CK ID**: T1021.002  
**Related Techniques**: T1078 (Valid Accounts)  
**Platforms**: Windows, Linux, macOS, Cloud

## Data Model Requirements

**OCSF Event Classes**:
- **Primary Class**: authentication (class_uid: 3002)

**Required Fields**:
- `time` - Authentication timestamp
- `user.name` - User account name
- `device.hostname` - Destination host
- `src_endpoint.ip` - Source IP address
- `activity_id` - Activity type (Logon = 1)
- `status_id` - Status (Success = 1)

**Minimum Data Sources**:
- [x] Windows Security Event Logs (Event ID 4624 - Successful Logon)
- [x] Linux authentication logs (auth.log, secure)
- [x] EDR authentication telemetry
- [x] Cloud authentication logs (Azure AD, AWS IAM)

## Technical Context

**Detection Strategy:**

This analytic tracks successful authentication events and identifies users accessing an abnormally high number of distinct hosts within a rolling 24-hour window. Most users authenticate to 1-2 systems regularly (workstation + maybe a server). Adversaries performing lateral movement will authenticate to many systems as they explore the network, escalate privileges, and move toward objectives.

The detection counts unique destination hosts per user, calculates the time span of access, and scores based on velocity (hosts accessed per hour). Thresholds are configurable but default to 3+ hosts for investigation, with severity increasing based on speed and volume.

**Adversary Tradecraft:**

After initial compromise, adversaries use valid credentials to move laterally through the network. This generates authentication events as they:
1. Enumerate accessible systems
2. Access file shares and databases
3. Pivot to high-value targets
4. Establish persistence across multiple hosts

Common techniques:
- **Pass-the-Hash**: Using NTLM hashes without knowing plaintext password
- **Pass-the-Ticket**: Replaying Kerberos tickets
- **Credential Dumping + Reuse**: Extract credentials from one host, use on others
- **Spray Patterns**: Testing credentials across many systems

Technical prerequisites:
- Valid credentials (stolen, dumped, or compromised)
- Network access to target systems
- Appropriate permissions (often local admin)

**Normal vs. Malicious:**

**Legitimate use cases:**
- IT administrators managing servers
- Helpdesk performing troubleshooting
- Automated service accounts
- Jump box/bastion host usage
- Deployment systems accessing multiple endpoints

**Malicious indicators:**
- Workstation accounts accessing many systems (not typical)
- Access to unrelated systems (finance user → HR servers)
- Rapid authentication to many hosts (< 1 hour)
- Off-hours activity from non-admin accounts
- Unusual authentication protocols (NTLM when Kerberos expected)

## Detection Logic

### Pseudocode
```
// Step 1: Get successful login events
auth = search Authentication:Logon
logins = filter auth where (
  status == "Success" and
  time >= now() - 24 hours
)

// Step 2: Group by user and count distinct hosts
user_activity = group logins by user.name
user_stats = from user_activity select (
  user,
  count(distinct device.hostname) as unique_hosts,
  min(time) as first_login,
  max(time) as last_login,
  list(distinct device.hostname) as hosts
)

// Step 3: Calculate velocity
rapid_access = from user_stats select (
  *,
  (last_login - first_login) as time_window,
  unique_hosts / time_window_hours as velocity
)

// Step 4: Filter and score
suspicious = filter rapid_access where (
  unique_hosts >= 3 and
  user not in [admin_accounts, service_accounts]
)

output suspicious order by unique_hosts desc, time_window asc
```

### SQL Implementation

See [query.sql](./query.sql)

## Blind Spots and Assumptions

**Assumptions**:
- [ ] Authentication logging is comprehensive and enabled
- [ ] User account names are normalized (DOMAIN\\user format consistent)
- [ ] Computer accounts ($-suffix) are distinguishable from user accounts
- [ ] Clock synchronization across systems (NTP configured)
- [ ] Logs are centralized and queryable within 24-hour window

**Blind Spots**:
- [ ] **Service accounts** - Automated accounts may access many hosts legitimately
- [ ] **Shared credentials** - Multiple people using same account mask individual behavior
- [ ] **RDP/SSH proxying** - Connections through jump box appear as single source
- [ ] **Cached credentials** - Offline authentication doesn't generate logs
- [ ] **Local accounts** - Non-domain accounts may not be logged centrally
- [ ] **Failed authentications** - This only tracks successful logins, missing brute force attempts
- [ ] **Slow methodical access** - Attacker waiting days between hops evades 24-hour window

## False Positives

**Known FP Sources**:

1. **IT Administrators**:
   - *Characteristics*: Sysadmins regularly accessing many servers for management
   - *Mitigation*: Whitelist known admin accounts, correlate with ticketing systems

2. **Help Desk**:
   - *Characteristics*: Support staff remote desktop to user workstations
   - *Mitigation*: Baseline helpdesk account patterns, require ticket correlation

3. **Service Accounts**:
   - *Characteristics*: Monitoring, backup, deployment accounts accessing many systems
   - *Mitigation*: Identify by naming convention (svc_*, $), whitelist known service accounts

4. **Jump Box/Bastion Hosts**:
   - *Characteristics*: Users authenticating through central access point to many destinations
   - *Mitigation*: Track source IPs, whitelist known bastion hosts

5. **Automated Deployments**:
   - *Characteristics*: SCCM, Ansible, deployment tools using single credential across fleet
   - *Mitigation*: Whitelist deployment account patterns

**Tuning Recommendations**:
- Baseline period: 30 days to establish normal user behavior
- Expected FP rate: 10-20% initially, <5% after tuning
- Whitelisting approach:
  - Maintain list of admin/service accounts
  - Track known bastion/jump box source IPs
  - Correlate with IT ticketing systems
  - Require manager approval for whitelist additions

## Validation

### True Positive Generation

**Method 1 - Manual Authentication Spray**:
```powershell
# From attacking workstation with compromised creds:
$cred = Get-Credential  # Enter compromised credentials

$targets = @(
    "WORKSTATION-01",
    "WORKSTATION-02", 
    "SERVER-01",
    "FILE-SERVER-01",
    "DB-SERVER-01"
)

foreach ($target in $targets) {
    Write-Host "Accessing $target..."
    Invoke-Command -ComputerName $target -Credential $cred -ScriptBlock { hostname }
    Start-Sleep -Seconds 30
}
```

**Method 2 - Atomic Red Team**:
- **Test**: T1021 - Remote Services (multiple subtechniques)
- **Link**: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021/T1021.md

**Expected Results**:
- **Authentication logs**: 5+ successful logon events (Event ID 4624) for same user to different hosts
- **Time window**: All within 10-15 minutes
- **Analytic output**: User flagged with unique_host_count >= 5, severity High/Critical

## Real-World Context

**Observed In**:
- **APT Groups**: APT29, APT3, FIN7 using lateral movement across enterprises to locate sensitive data
- **Ransomware**: Ryuk, Conti operators spreading ransomware by authenticating to multiple systems before deploying payload
- **Red Team Tools**: CrackMapExec, BloodHound/SharpHound enumerating and accessing systems, Impacket wmiexec/smbexec accessing multiple targets
- **Notable Incidents**: SolarWinds attackers (2020) moving laterally through customer networks, Kaseya ransomware (2021) using compromised credentials for lateral spread

## Additional Resources

**External**:
- [MITRE ATT&CK T1021.002](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE CAR-2013-02-012](https://car.mitre.org/analytics/CAR-2013-02-012/)
- [Microsoft: Detecting Pass-the-Hash](https://learn.microsoft.com/en-us/defender-for-identity/credential-access-alerts)
- [SANS: Detecting Lateral Movement](https://www.sans.org/white-papers/detecting-lateral-movement/)

---

**Detection Maturity Level**: 2 (Event correlation - groups multiple authentication events)  
**Last Validated**: 2025-02-08  
**Validation Result**: Pass (Manual spray test generated expected alert)
