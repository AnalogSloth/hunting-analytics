# HTA-CA-001: Kerberoasting via RC4-HMAC TGS Ticket Requests

**ID**: HTA-CA-001  
**Author**: analogsloth  
**Created**: 2026-02-24
**Updated**: 2026-02-24

## Goal

Detect Kerberoasting attacks by identifying Kerberos TGS ticket requests using RC4-HMAC (encryption type 0x17) from user accounts. Kerberoasting is a post-exploitation credential access technique that allows attackers to request service tickets for service accounts and crack them offline without needing elevated privileges.

## Categorization

**MITRE ATT&CK**: Credential Access / Steal or Forge Kerberos Tickets / Kerberoasting  
**ATT&CK ID**: T1558.003  
**Related Techniques**: T1078 (Valid Accounts — subsequent use of cracked credentials), T1021 (Remote Services — lateral movement after credential access)  
**Platforms**: Windows (Active Directory environments)

## Data Model Requirements

**OCSF Event Classes**:
- **Primary Class**: `authentication` (class_uid: 3002)

**Required Fields**:
- `auth_protocol` — must equal `Kerberos`
- `activity_id` — Service Ticket request (values: `3` = Authentication Ticket, `4` = Service Ticket; maps to Windows Event ID 4769). Use `IN (3, 4)` until pipeline mapping is confirmed.
- `authentication_token.encryption_details.algorithm` — RC4-HMAC variants (preferred OCSF path)
- `unmapped['ticket_encryption_type']` or `unmapped['EncryptionType']` — fallback for pipelines that don't map encryption type to the standard path (common in Cribl, Panther, and custom ETL)
- `user.name` — requesting account
- `user.domain` — AD domain
- `service.name` — SPN of the requested service ticket
- `src_endpoint.ip` — source of the ticket request
- `src_endpoint.hostname` — source hostname

**Pipeline Note**: The Windows Event 4769 field `Ticket Encryption Type` (hex `0x17` = RC4-HMAC) is not part of the OCSF `authentication` core schema. It should map to `authentication_token.encryption_details.algorithm`, but many real-world pipelines land it in `unmapped`. The query handles both — validate which path your pipeline uses before deploying.

**Minimum Data Sources**:
- [x] Windows Security Event Log — Event ID 4769 (Kerberos Service Ticket Operations)
- [ ] Domain Controller network capture (alternative; requires Zeek/Suricata Kerberos parsing)
- [ ] SIEM/EDR with Kerberos telemetry (e.g., CrowdStrike, Defender for Identity)

**Notes on Event ID 4769**: Audit Kerberos Service Ticket Operations must be enabled in Group Policy (`Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Account Logon`). Failure events should also be audited.

## Technical Context

**Detection Strategy:**  
The analytic monitors Kerberos TGS ticket requests and flags those negotiating RC4-HMAC (0x17) encryption from non-computer user accounts. Detection uses a two-layer approach: a burst volume threshold (tickets per hour from a single user/host) combined with a 30-day behavioral baseline to catch both noisy automated attacks and slower, stealthier enumeration. Risk is scored from LOW (single ticket) to CRITICAL (20+ tickets) to allow tiered triage.

**Adversary Tradecraft:**  
Kerberoasting exploits a fundamental property of Kerberos: any authenticated domain user can request a TGS ticket for any service with a registered SPN. The ticket is encrypted with the service account's password hash. Once obtained, the ticket can be cracked offline using tools like Hashcat or John the Ripper. The attack requires no elevated privileges to execute — a regular domain account is sufficient.

Common tools used by attackers:
- **Rubeus** (`kerberoast /format:hashcat`) — generates large bursts of RC4 requests, highly automated
- **Impacket GetUserSPNs.py** — targeted enumeration, often lower volume
- **PowerView** (`Invoke-Kerberoast`) — PowerShell-based, may blend with admin activity
- **Mimikatz** (`kerberos::ask`) — less common for Kerberoasting specifically

Attackers may attempt "AS-REP Roasting" (T1558.004) as a complementary technique if pre-authentication is disabled on accounts. This analytic does not cover AS-REP Roasting — see HTA-CA-002 (planned).

**Normal vs. Malicious:**  
RC4-HMAC is a legacy encryption type that predates AES support in Windows (introduced in Server 2008 R2 / Windows 7). In modern environments, legitimate RC4 TGS requests are rare and typically indicate either (a) legacy applications that have not been updated to negotiate AES, or (b) service accounts where `msDS-SupportedEncryptionTypes` is not set (defaults to RC4). A single RC4 request from a known legacy application host is low-risk. Multiple RC4 requests from a workstation in rapid succession is high-risk.

## Detection Logic

### Pseudocode
```
FOR EACH authentication event WHERE auth_protocol = 'Kerberos':
    IF activity = TGS_REQUEST
    AND ticket.encryption_type IN (RC4-HMAC, RC4-HMAC-EXP)
    AND user.name NOT LIKE computer account pattern ('%$'):
        ADD to candidate events

AGGREGATE candidate events BY (hour, user, src_host):
    COUNT total ticket requests
    COUNT distinct services targeted
    CALCULATE request duration (last - first timestamp)

FOR EACH aggregation:
    SCORE based on ticket volume (1=low, 4=critical)
    COMPARE to 30-day behavioral baseline (z-score)
    EMIT if score >= threshold (default: HIGH or above)
```

### SQL Implementation

See [query.sql](./query.sql)

**Threshold guidance**:
- Start at `risk_score >= 3` (HIGH: 6-20 tickets/hour) to minimize FPs during initial deployment
- Drop to `risk_score >= 2` (MEDIUM: 2-5 tickets/hour) after 30-day baseline is established and legacy systems are documented
- The baseline z-score can be used as a supplementary signal for accounts with any RC4 history that suddenly spikes

## Blind Spots and Assumptions

**Assumptions**:
- [x] Advanced Audit Policy for Kerberos Service Ticket Operations is enabled on all DCs
- [x] OCSF data pipeline correctly maps Event ID 4769 to `authentication` (3002) with `activity_id IN (3, 4)`
- [x] Service ticket encryption type is correctly mapped from Windows event field `Ticket Encryption Type`
- [x] Environment has sufficient AES adoption that RC4 requests are anomalous (modern environments post-2012)

**Blind Spots**:
- [x] **AES Kerberoasting**: Modern versions of Rubeus support `rc4opsec` and AES ticket requests. If the attacker forces AES tickets, this analytic will not fire. Mitigation: enable Protected Users security group for privileged service accounts, enforce AES-only via `msDS-SupportedEncryptionTypes`.
- [x] **Slow/low-volume attacks**: An attacker requesting 1 ticket per day across multiple days will score LOW and be filtered at default threshold. The baseline deviation signal partially mitigates this for accounts with zero historical RC4 activity.
- [x] **Offline attacks via DC sync**: If an attacker DCSync's the NTDS.dit, Kerberos ticket requests are never generated. This analytic provides no coverage for that path (see planned HTA-CA-003: DCSync Detection).
- [x] **Log gaps**: If DC Security Event Logs are not forwarded in real time, delayed ingestion creates a blind spot for rapid attacks that complete in minutes.
- [x] **Renamed/obfuscated tool behavior**: Attackers who manually craft Kerberos requests at the protocol level (not using standard tools) may vary ticket options fields — the analytic would still catch the encryption type, but ticket_options-based filtering could be evaded.

## False Positives

**Known FP Sources**:

1. **Legacy Application Servers**: Applications built before AES support (pre-2008 R2 era Java, .NET 3.5, older SAP, Oracle) may negotiate RC4 for service tickets. These are typically single requests from known, static source IPs.
   - *Mitigation*: Whitelist known legacy application server IPs in the query. Document these systems and track remediation progress. Prioritize updating `msDS-SupportedEncryptionTypes` on associated service accounts to enforce AES.

2. **Unconfigured Service Account SPNs**: Service accounts where `msDS-SupportedEncryptionTypes` is not set default to offering RC4. This is a configuration gap rather than an attack.
   - *Mitigation*: Audit all SPNs quarterly. Set `msDS-SupportedEncryptionTypes = 24` (AES128 + AES256) on all service accounts. Track remediation as a security metric.

3. **Vulnerability Scanners / Security Tools**: Some AD security assessment tools (BloodHound collectors in certain modes, PingCastle) may enumerate SPNs in ways that generate RC4 requests.
   - *Mitigation*: Whitelist scanner IPs and schedule scan windows. Verify tool configuration to prefer AES negotiation where supported.

4. **Penetration Test Activity**: Authorized red team or pen test activity will generate high-volume RC4 requests that look identical to real attacks.
   - *Mitigation*: Maintain a test window suppression list. Require pen testers to notify SOC prior to Kerberoasting simulation. Use source IP or user account tagging to filter authorized test activity.

**Tuning Recommendations**:
- Baseline period: 30 days minimum; 60 days recommended for mature environments
- Begin by inventorying all SPNs in the domain (`Get-ADServiceAccount -Filter *` or BloodHound) to understand the attack surface
- Track RC4-capable SPNs as a separate metric and drive to zero over time
- Expected FP rate at `risk_score >= 3`: <5% in environments with good AES hygiene; up to 30% in legacy-heavy shops — invest in SPN remediation first

## Validation

### True Positive Generation

**Method 1 — Rubeus (Windows, domain-joined host)**:
```powershell
# Download: https://github.com/GhostPack/Rubeus
# Run from a domain-joined workstation as a standard user
.\Rubeus.exe kerberoast /format:hashcat /outfile:C:\Temp\hashes.txt

# For a more targeted version (request specific SPN):
.\Rubeus.exe kerberoast /spn:MSSQLSvc/db01.corp.local:1433 /format:hashcat
```

**Method 2 — Impacket GetUserSPNs (Linux/macOS or Windows with Python)**:
```bash
# Install: pip install impacket
python3 GetUserSPNs.py -dc-ip <DC_IP> CORP/username:password -request -outputfile hashes.txt
```

**Method 3 — Atomic Red Team**:
- **Test**: T1558.003 - Kerberoasting
- **Link**: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1558.003/T1558.003.md
- Atomic tests 1 and 2 cover Rubeus and PowerView-based Kerberoasting

**Expected Results**:
- Windows Security Event Log on the DC generates Event ID 4769 with `Ticket Encryption Type: 0x17`
- `Failure Code: 0x0` (success — the ticket was issued)
- OCSF pipeline maps this to `authentication` with `activity_id=4`, `authentication_token.encryption_details.algorithm='RC4-HMAC'` (or `unmapped['ticket_encryption_type']='0x17'` depending on pipeline)
- Analytic detects within one hourly aggregation window; CRITICAL threshold fires for Rubeus (25+ tickets), HIGH for targeted GetUserSPNs (8+ tickets)

## Real-World Context

**Observed In**:
- **APT Groups**: APT28 (Fancy Bear), APT29 (Cozy Bear), APT33 — Kerberoasting is a standard post-exploitation step in sophisticated campaigns targeting AD environments
- **Ransomware**: LockBit, BlackCat/ALPHV, Hive — commonly use Kerberoasting to escalate from initial foothold to domain admin by targeting SQL or backup service accounts with weak passwords
- **Red Team Tools**: Rubeus, Impacket, PowerSploit/PowerView, Mimikatz, SharpRoast
- **Notable Incidents**: The 2020 SolarWinds/SUNBURST campaign involved Kerberoasting as part of lateral movement after initial SAML token forgery. Multiple healthcare ransomware attacks in 2022-2023 publicly attributed credential access to Kerberoasting against SQL Server service accounts.

## Additional Resources

**External**:
- [MITRE ATT&CK T1558.003](https://attack.mitre.org/techniques/T1558/003/)
- [Harmj0y — Kerberoasting Without Mimikatz](https://blog.harmj0y.net/powershell/kerberoasting-without-mimikatz/) — foundational research
- [SpecterOps — Kerberoasting Revisited](https://posts.specterops.io/kerberoasting-revisited-d434351bd4d1) — AES Kerberoasting evasion
- [Microsoft — Kerberos Authentication Overview](https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
- [Detecting Kerberoasting Activity — Sean Metcalf](https://adsecurity.org/?p=3458)
- [Atomic Red Team T1558.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1558.003/T1558.003.md)

---

**Detection Maturity Level**: 4 / 5  
**Last Validated**: 2026-02-24  
**Validation Result**: Pass (synthetic data — see test-data.sql)

**OCSF Fields to Validate**:
Validate these fields before production deployment:
- `authentication.activity_id` — confirm values `3` and `4` map to Kerberos ticket requests in your pipeline
- `authentication.authentication_token.encryption_details.algorithm` — confirm your ETL populates this vs. using `unmapped`
- `authentication.auth_protocol` — confirm string value used (`'Kerberos'` vs `'kerberos'` vs `'KRB5'`)
- `authentication.service.name` — confirm SPN is mapped here vs. `dst_endpoint.svc_name`

**Pipeline Validation Query** — run this before deploying the full analytic to confirm field population:
```sql
SELECT
    activity_id,
    auth_protocol,
    authentication_token.encryption_details.algorithm  AS enc_alg_standard,
    unmapped['ticket_encryption_type']                  AS enc_alg_unmapped,
    unmapped['EncryptionType']                          AS enc_alg_unmapped_alt,
    COUNT(*)                                            AS event_count
FROM authentication
WHERE auth_protocol = 'Kerberos'
  AND time >= CURRENT_TIMESTAMP - INTERVAL '7 days'
GROUP BY 1, 2, 3, 4, 5
ORDER BY event_count DESC
LIMIT 20;
```
