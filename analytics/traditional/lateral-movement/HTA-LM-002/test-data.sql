-- HTA-LM-002 Test Data
-- Generates synthetic true positive scenario

-- True Positive: Attacker logging into multiple hosts rapidly
-- Simulate compromised user "alice" accessing 5 hosts in 10 minutes

-- Login 1: Workstation-01 at T+0
INSERT INTO authentication (
  class_uid, activity_id, status_id, time,
  user, device, src_endpoint
) VALUES (
  3002, 1, 1, CURRENT_TIMESTAMP,
  JSON_OBJECT('name', 'DOMAIN\\alice'),
  JSON_OBJECT('hostname', 'WORKSTATION-01'),
  JSON_OBJECT('ip', '10.10.10.50')
);

-- Login 2: Workstation-02 at T+2min
INSERT INTO authentication (
  class_uid, activity_id, status_id, time,
  user, device, src_endpoint
) VALUES (
  3002, 1, 1, CURRENT_TIMESTAMP + INTERVAL '2 minutes',
  JSON_OBJECT('name', 'DOMAIN\\alice'),
  JSON_OBJECT('hostname', 'WORKSTATION-02'),
  JSON_OBJECT('ip', '10.10.10.51')
);

-- Login 3: SERVER-01 at T+4min
INSERT INTO authentication (
  class_uid, activity_id, status_id, time,
  user, device, src_endpoint
) VALUES (
  3002, 1, 1, CURRENT_TIMESTAMP + INTERVAL '4 minutes',
  JSON_OBJECT('name', 'DOMAIN\\alice'),
  JSON_OBJECT('hostname', 'SERVER-01'),
  JSON_OBJECT('ip', '10.10.10.52')
);

-- Login 4: SERVER-02 at T+6min
INSERT INTO authentication (
  class_uid, activity_id, status_id, time,
  user, device, src_endpoint
) VALUES (
  3002, 1, 1, CURRENT_TIMESTAMP + INTERVAL '6 minutes',
  JSON_OBJECT('name', 'DOMAIN\\alice'),
  JSON_OBJECT('hostname', 'SERVER-02'),
  JSON_OBJECT('ip', '10.10.10.53')
);

-- Login 5: WORKSTATION-03 at T+10min
INSERT INTO authentication (
  class_uid, activity_id, status_id, time,
  user, device, src_endpoint
) VALUES (
  3002, 1, 1, CURRENT_TIMESTAMP + INTERVAL '10 minutes',
  JSON_OBJECT('name', 'DOMAIN\\alice'),
  JSON_OBJECT('hostname', 'WORKSTATION-03'),
  JSON_OBJECT('ip', '10.10.10.54')
);

-- Expected Result: Should return 1 row for user "alice" with:
-- - unique_host_count: 5
-- - time_window_minutes: 10
-- - severity: 'High' (5 hosts in < 60 minutes)

-- False Positive: IT admin doing legitimate work
-- (Should be filtered by whitelist)
INSERT INTO authentication (
  class_uid, activity_id, status_id, time,
  user, device, src_endpoint
) VALUES (
  3002, 1, 1, CURRENT_TIMESTAMP,
  JSON_OBJECT('name', 'DOMAIN\\admin_bob'),
  JSON_OBJECT('hostname', 'DC-01'),
  JSON_OBJECT('ip', '10.10.1.100')
);

-- Expected: Should NOT appear if admin_bob is whitelisted
