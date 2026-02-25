-- =============================================================================
-- HTA-CA-001: Test Data — Kerberoasting Detection
-- Synthetic data for validating true positive and false positive scenarios
-- =============================================================================
-- Usage: Insert into your OCSF-normalized authentication table (or a temp
-- table) and run query.sql to verify expected detection behavior.
-- =============================================================================

-- SCENARIO 1 (TRUE POSITIVE — CRITICAL): Rubeus-style TGS sweep
-- 25 RC4-HMAC ticket requests across unique services in ~90 seconds.
-- Simulates: Rubeus.exe kerberoast /format:hashcat /outfile:hashes.txt
-- Expected: Risk = CRITICAL (risk_score=4), ticket_count=25
-- activity_id=4 = Service Ticket (TGS-REQ), maps to Windows Event ID 4769
-- -----------------------------------------------------------------------
INSERT INTO authentication (
    time, auth_protocol, activity_id, class_uid,
    user.name, user.domain,
    src_endpoint.ip, src_endpoint.hostname,
    service.name,
    authentication_token.encryption_details.algorithm,
    authentication_token.kerberos_flags,
    metadata.product.name, metadata.product.vendor_name
) VALUES
-- Burst of 25 requests — insert with slightly incrementing timestamps
('2025-03-15 02:13:01', 'Kerberos', 4, 3002, 'jsmith',  'CORP.LOCAL', '10.10.1.55', 'WKSTN-055', 'MSSQLSvc/db01.corp.local:1433',    'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 02:13:04', 'Kerberos', 4, 3002, 'jsmith',  'CORP.LOCAL', '10.10.1.55', 'WKSTN-055', 'HTTP/sharepoint.corp.local',        'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 02:13:06', 'Kerberos', 4, 3002, 'jsmith',  'CORP.LOCAL', '10.10.1.55', 'WKSTN-055', 'MSSQLSvc/db02.corp.local:1433',    'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 02:13:08', 'Kerberos', 4, 3002, 'jsmith',  'CORP.LOCAL', '10.10.1.55', 'WKSTN-055', 'TERMSRV/rdp01.corp.local',         'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 02:13:10', 'Kerberos', 4, 3002, 'jsmith',  'CORP.LOCAL', '10.10.1.55', 'WKSTN-055', 'HOST/fileserver01.corp.local',     'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 02:13:12', 'Kerberos', 4, 3002, 'jsmith',  'CORP.LOCAL', '10.10.1.55', 'WKSTN-055', 'SMTP/mail01.corp.local',           'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 02:13:14', 'Kerberos', 4, 3002, 'jsmith',  'CORP.LOCAL', '10.10.1.55', 'WKSTN-055', 'HTTP/intranet.corp.local',         'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 02:13:16', 'Kerberos', 4, 3002, 'jsmith',  'CORP.LOCAL', '10.10.1.55', 'WKSTN-055', 'RestrictedKrbHost/srv01',          'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 02:13:18', 'Kerberos', 4, 3002, 'jsmith',  'CORP.LOCAL', '10.10.1.55', 'WKSTN-055', 'MSSQLSvc/db03.corp.local:1433',    'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 02:13:20', 'Kerberos', 4, 3002, 'jsmith',  'CORP.LOCAL', '10.10.1.55', 'WKSTN-055', 'FTP/ftp01.corp.local',             'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 02:13:22', 'Kerberos', 4, 3002, 'jsmith',  'CORP.LOCAL', '10.10.1.55', 'WKSTN-055', 'LDAP/dc01.corp.local',             'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 02:13:24', 'Kerberos', 4, 3002, 'jsmith',  'CORP.LOCAL', '10.10.1.55', 'WKSTN-055', 'HTTP/app01.corp.local',            'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 02:13:26', 'Kerberos', 4, 3002, 'jsmith',  'CORP.LOCAL', '10.10.1.55', 'WKSTN-055', 'WSMAN/mgmt01.corp.local',          'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 02:13:28', 'Kerberos', 4, 3002, 'jsmith',  'CORP.LOCAL', '10.10.1.55', 'WKSTN-055', 'cifs/nas01.corp.local',            'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 02:13:30', 'Kerberos', 4, 3002, 'jsmith',  'CORP.LOCAL', '10.10.1.55', 'WKSTN-055', 'HOST/print01.corp.local',          'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 02:13:32', 'Kerberos', 4, 3002, 'jsmith',  'CORP.LOCAL', '10.10.1.55', 'WKSTN-055', 'HTTP/wiki.corp.local',             'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 02:13:34', 'Kerberos', 4, 3002, 'jsmith',  'CORP.LOCAL', '10.10.1.55', 'WKSTN-055', 'iSCSI/storage01.corp.local',       'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 02:13:36', 'Kerberos', 4, 3002, 'jsmith',  'CORP.LOCAL', '10.10.1.55', 'WKSTN-055', 'MSSQLSvc/db04.corp.local:1433',    'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 02:13:38', 'Kerberos', 4, 3002, 'jsmith',  'CORP.LOCAL', '10.10.1.55', 'WKSTN-055', 'HTTP/erp.corp.local',              'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 02:13:40', 'Kerberos', 4, 3002, 'jsmith',  'CORP.LOCAL', '10.10.1.55', 'WKSTN-055', 'RestrictedKrbHost/srv02',          'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 02:13:42', 'Kerberos', 4, 3002, 'jsmith',  'CORP.LOCAL', '10.10.1.55', 'WKSTN-055', 'TERMSRV/rdp02.corp.local',         'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 02:13:44', 'Kerberos', 4, 3002, 'jsmith',  'CORP.LOCAL', '10.10.1.55', 'WKSTN-055', 'HTTP/devops.corp.local',           'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 02:13:46', 'Kerberos', 4, 3002, 'jsmith',  'CORP.LOCAL', '10.10.1.55', 'WKSTN-055', 'SMTP/relay01.corp.local',          'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 02:13:48', 'Kerberos', 4, 3002, 'jsmith',  'CORP.LOCAL', '10.10.1.55', 'WKSTN-055', 'MSSQLSvc/db05.corp.local:1433',    'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 02:13:50', 'Kerberos', 4, 3002, 'jsmith',  'CORP.LOCAL', '10.10.1.55', 'WKSTN-055', 'HOST/backup01.corp.local',         'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft');

-- SCENARIO 2 (TRUE POSITIVE — HIGH): Targeted Kerberoast (Impacket GetUserSPNs)
-- 8 targeted RC4-HMAC requests against high-value services.
-- Simulates: GetUserSPNs.py -dc-ip 10.10.1.10 CORP/attacker -request
-- Expected: Risk = HIGH (risk_score=3), ticket_count=8
-- activity_id=4 = Service Ticket (TGS-REQ), maps to Windows Event ID 4769
-- -----------------------------------------------------------------------
INSERT INTO authentication (
    time, auth_protocol, activity_id, class_uid,
    user.name, user.domain,
    src_endpoint.ip, src_endpoint.hostname,
    service.name,
    authentication_token.encryption_details.algorithm,
    authentication_token.kerberos_flags,
    metadata.product.name, metadata.product.vendor_name
) VALUES
('2025-03-15 14:22:01', 'Kerberos', 4, 3002, 'bwilliams', 'CORP.LOCAL', '10.10.5.88', 'JUMPBOX-01', 'MSSQLSvc/db01.corp.local:1433',  'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 14:22:03', 'Kerberos', 4, 3002, 'bwilliams', 'CORP.LOCAL', '10.10.5.88', 'JUMPBOX-01', 'MSSQLSvc/db02.corp.local:1433',  'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 14:22:05', 'Kerberos', 4, 3002, 'bwilliams', 'CORP.LOCAL', '10.10.5.88', 'JUMPBOX-01', 'HTTP/sharepoint.corp.local',      'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 14:22:07', 'Kerberos', 4, 3002, 'bwilliams', 'CORP.LOCAL', '10.10.5.88', 'JUMPBOX-01', 'HOST/fileserver01.corp.local',    'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 14:22:09', 'Kerberos', 4, 3002, 'bwilliams', 'CORP.LOCAL', '10.10.5.88', 'JUMPBOX-01', 'TERMSRV/rdp01.corp.local',        'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 14:22:11', 'Kerberos', 4, 3002, 'bwilliams', 'CORP.LOCAL', '10.10.5.88', 'JUMPBOX-01', 'SMTP/mail01.corp.local',          'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 14:22:13', 'Kerberos', 4, 3002, 'bwilliams', 'CORP.LOCAL', '10.10.5.88', 'JUMPBOX-01', 'WSMAN/mgmt01.corp.local',         'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 14:22:15', 'Kerberos', 4, 3002, 'bwilliams', 'CORP.LOCAL', '10.10.5.88', 'JUMPBOX-01', 'HTTP/intranet.corp.local',        'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft');

-- SCENARIO 3 (FALSE POSITIVE — should NOT trigger at threshold >= 3):
-- Single RC4-HMAC request from an older application with legacy config.
-- Simulates: Old Java app or backup agent that hasn't been updated to AES.
-- Expected: Risk = LOW (risk_score=1), filtered out at WHERE risk_score >= 3
-- -----------------------------------------------------------------------
INSERT INTO authentication (
    time, auth_protocol, activity_id, class_uid,
    user.name, user.domain,
    src_endpoint.ip, src_endpoint.hostname,
    service.name,
    authentication_token.encryption_details.algorithm,
    authentication_token.kerberos_flags,
    metadata.product.name, metadata.product.vendor_name
) VALUES
('2025-03-15 09:00:15', 'Kerberos', 4, 3002, 'svc_backup', 'CORP.LOCAL', '10.10.2.10', 'BACKUP-SRV', 'MSSQLSvc/db01.corp.local:1433', 'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft');

-- SCENARIO 4 (FALSE POSITIVE — computer account, should be filtered):
-- RC4-HMAC request from a computer account. The query excludes user.name LIKE '%$'.
-- Expected: filtered out in rc4_tgs_requests CTE, NOT in output
-- -----------------------------------------------------------------------
INSERT INTO authentication (
    time, auth_protocol, activity_id, class_uid,
    user.name, user.domain,
    src_endpoint.ip, src_endpoint.hostname,
    service.name,
    authentication_token.encryption_details.algorithm,
    authentication_token.kerberos_flags,
    metadata.product.name, metadata.product.vendor_name
) VALUES
('2025-03-15 10:30:00', 'Kerberos', 4, 3002, 'WKSTN-099$', 'CORP.LOCAL', '10.10.1.99', 'WKSTN-099', 'HOST/fileserver01.corp.local', 'RC4-HMAC', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft');

-- SCENARIO 5 (NEGATIVE CONTROL — AES requests, should NOT appear):
-- Normal AES TGS requests. Legitimate Kerberos activity.
-- Expected: filtered out in WHERE clause (algorithm NOT IN RC4 variants)
-- -----------------------------------------------------------------------
INSERT INTO authentication (
    time, auth_protocol, activity_id, class_uid,
    user.name, user.domain,
    src_endpoint.ip, src_endpoint.hostname,
    service.name,
    authentication_token.encryption_details.algorithm,
    authentication_token.kerberos_flags,
    metadata.product.name, metadata.product.vendor_name
) VALUES
('2025-03-15 08:15:00', 'Kerberos', 4, 3002, 'adavis',  'CORP.LOCAL', '10.10.1.20', 'WKSTN-020', 'MSSQLSvc/db01.corp.local:1433', 'AES256-CTS-HMAC-SHA1-96', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 08:17:00', 'Kerberos', 4, 3002, 'mchang',  'CORP.LOCAL', '10.10.1.21', 'WKSTN-021', 'HTTP/sharepoint.corp.local',    'AES256-CTS-HMAC-SHA1-96', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 08:19:00', 'Kerberos', 4, 3002, 'kpatel',  'CORP.LOCAL', '10.10.1.22', 'WKSTN-022', 'TERMSRV/rdp01.corp.local',      'AES256-CTS-HMAC-SHA1-96', '0x40810010', 'Microsoft-Windows-Security-Auditing', 'Microsoft');

-- SCENARIO 6 (TRUE POSITIVE — unmapped fallback path):
-- Pipeline lands encryption type in unmapped rather than authentication_token.
-- Simulates: Cribl/Panther ETL that doesn't map Ticket Encryption Type to OCSF.
-- Expected: Risk = HIGH (risk_score=3), caught via unmapped['ticket_encryption_type']
-- authentication_token.encryption_details.algorithm is NULL in these rows.
-- -----------------------------------------------------------------------
INSERT INTO authentication (
    time, auth_protocol, activity_id, class_uid,
    user.name, user.domain,
    src_endpoint.ip, src_endpoint.hostname,
    service.name,
    unmapped,
    metadata.product.name, metadata.product.vendor_name
) VALUES
('2025-03-15 16:05:01', 'Kerberos', 4, 3002, 'hacker', 'CORP.LOCAL', '10.10.9.99', 'ATTACKER-PC', 'MSSQLSvc/db01.corp.local:1433', {'ticket_encryption_type': '0x17'}, 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 16:05:03', 'Kerberos', 4, 3002, 'hacker', 'CORP.LOCAL', '10.10.9.99', 'ATTACKER-PC', 'HTTP/sharepoint.corp.local',    {'ticket_encryption_type': '0x17'}, 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 16:05:05', 'Kerberos', 4, 3002, 'hacker', 'CORP.LOCAL', '10.10.9.99', 'ATTACKER-PC', 'TERMSRV/rdp01.corp.local',      {'ticket_encryption_type': '0x17'}, 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 16:05:07', 'Kerberos', 4, 3002, 'hacker', 'CORP.LOCAL', '10.10.9.99', 'ATTACKER-PC', 'HOST/fileserver01.corp.local',  {'ticket_encryption_type': '0x17'}, 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 16:05:09', 'Kerberos', 4, 3002, 'hacker', 'CORP.LOCAL', '10.10.9.99', 'ATTACKER-PC', 'SMTP/mail01.corp.local',        {'ticket_encryption_type': '0x17'}, 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 16:05:11', 'Kerberos', 4, 3002, 'hacker', 'CORP.LOCAL', '10.10.9.99', 'ATTACKER-PC', 'WSMAN/mgmt01.corp.local',       {'ticket_encryption_type': '0x17'}, 'Microsoft-Windows-Security-Auditing', 'Microsoft'),
('2025-03-15 16:05:13', 'Kerberos', 4, 3002, 'hacker', 'CORP.LOCAL', '10.10.9.99', 'ATTACKER-PC', 'MSSQLSvc/db02.corp.local:1433', {'ticket_encryption_type': '0x17'}, 'Microsoft-Windows-Security-Auditing', 'Microsoft');

-- =============================================================================
-- Expected Test Results Summary
-- =============================================================================
-- Scenario 1: jsmith     | CRITICAL | 25 tickets | 25 services | ~90s duration
-- Scenario 2: bwilliams  | HIGH     |  8 tickets |  8 services | ~14s duration
-- Scenario 3: svc_backup | LOW      |  1 ticket  | filtered at risk_score >= 3
-- Scenario 4: WKSTN-099$ | n/a      | filtered by computer account exclusion
-- Scenario 5: adavis/mchang/kpatel | n/a | filtered by AES algorithm value
-- Scenario 6: hacker     | HIGH     |  7 tickets | tests unmapped fallback path
-- =============================================================================
