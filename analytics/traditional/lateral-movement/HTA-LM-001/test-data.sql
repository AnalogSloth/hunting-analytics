-- HTA-LM-001 Test Data
-- Generates synthetic true positive scenario for validation

-- True Positive Scenario: PSExec-style lateral movement
-- 1. SMB write to ADMIN$ share
INSERT INTO network_activity (
  class_uid, activity_id, time, 
  src_endpoint, dst_endpoint, 
  protocol_name, file
) VALUES (
  4001, 6, CURRENT_TIMESTAMP,
  JSON_OBJECT('ip', '10.10.10.50'),
  JSON_OBJECT('ip', '10.10.20.100', 'hostname', 'WORKSTATION-02', 'port', 445),
  'SMB',
  JSON_OBJECT('name', 'malicious.exe', 'path', '\\\\ADMIN$\\Temp\\malicious.exe')
);

-- 2. Process execution 90 seconds later
INSERT INTO process_activity (
  class_uid, activity_id, time,
  device, process, actor
) VALUES (
  1007, 1, CURRENT_TIMESTAMP + INTERVAL '90 seconds',
  JSON_OBJECT('hostname', 'WORKSTATION-02'),
  JSON_OBJECT(
    'file', JSON_OBJECT('name', 'malicious.exe', 'path', 'C:\\Windows\\Temp\\malicious.exe'),
    'cmd_line', 'C:\\Windows\\Temp\\malicious.exe',
    'parent_process', JSON_OBJECT('file', JSON_OBJECT('path', 'C:\\Windows\\System32\\services.exe'))
  ),
  JSON_OBJECT('user', JSON_OBJECT('name', 'DOMAIN\\compromised-user'))
);

-- Expected Result: Should return 1 row with:
-- - time_delta_seconds: ~90
-- - severity: 'High' (path contains Temp)
-- - source_ip: 10.10.10.50
-- - dest_host: WORKSTATION-02

-- False Positive Scenario: Legitimate deployment system
-- (Should be filtered out by source IP whitelist)
INSERT INTO network_activity (
  class_uid, activity_id, time,
  src_endpoint, dst_endpoint,
  protocol_name, file
) VALUES (
  4001, 6, CURRENT_TIMESTAMP,
  JSON_OBJECT('ip', '10.1.100.10'),  -- Deployment server
  JSON_OBJECT('ip', '10.10.20.101', 'hostname', 'WORKSTATION-03', 'port', 445),
  'SMB',
  JSON_OBJECT('name', 'installer.exe', 'path', '\\\\ADMIN$\\Temp\\installer.exe')
);

-- Expected: Should NOT appear in results if deployment server is whitelisted
