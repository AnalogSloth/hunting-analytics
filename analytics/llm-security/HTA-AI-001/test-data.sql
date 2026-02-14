-- HTA-AI-001 Test Data
-- Generates synthetic scenarios for API access anomalies

-- Scenario 1: Impossible Travel - API key used in US, then China 1 hour later
-- Call 1: San Francisco at T+0
INSERT INTO api_activity (
  class_uid, activity_id, time,
  actor, api, src_endpoint, http_request
) VALUES (
  6003, 0, CURRENT_TIMESTAMP,
  JSON_OBJECT(
    'user', JSON_OBJECT(
      'uid', 'sk-proj-abc123',
      'name', 'developer@company.com'
    )
  ),
  JSON_OBJECT(
    'operation', 'messages.create',
    'service', JSON_OBJECT('name', 'claude-api'),
    'request', JSON_OBJECT('uid', 'req-001')
  ),
  JSON_OBJECT(
    'ip', '198.51.100.10',
    'location', JSON_OBJECT(
      'city', 'San Francisco',
      'country', 'US',
      'coordinates', [37.7749, -122.4194]
    )
  ),
  JSON_OBJECT('user_agent', 'python-anthropic/0.8.0')
);

-- Call 2: Beijing 1 hour later (impossible travel)
INSERT INTO api_activity (
  class_uid, activity_id, time,
  actor, api, src_endpoint, http_request
) VALUES (
  6003, 0, CURRENT_TIMESTAMP + INTERVAL '1 hour',
  JSON_OBJECT(
    'user', JSON_OBJECT(
      'uid', 'sk-proj-abc123',
      'name', 'developer@company.com'
    )
  ),
  JSON_OBJECT(
    'operation', 'messages.create',
    'service', JSON_OBJECT('name', 'claude-api'),
    'request', JSON_OBJECT('uid', 'req-002')
  ),
  JSON_OBJECT(
    'ip', '203.0.113.50',
    'location', JSON_OBJECT(
      'city', 'Beijing',
      'country', 'CN',
      'coordinates', [39.9042, 116.4074]
    )
  ),
  JSON_OBJECT('user_agent', 'curl/7.68.0')
);

-- Expected: Critical severity - Impossible travel from US to China in 1 hour

-- Scenario 2: New Location - API key typically used in US, now in Russia
INSERT INTO api_activity (
  class_uid, activity_id, time,
  actor, api, src_endpoint, http_request
) VALUES (
  6003, 0, CURRENT_TIMESTAMP,
  JSON_OBJECT(
    'user', JSON_OBJECT(
      'uid', 'sk-proj-xyz789',
      'name', 'user@startup.io'
    )
  ),
  JSON_OBJECT(
    'operation', 'completions.create',
    'service', JSON_OBJECT('name', 'claude-api')
  ),
  JSON_OBJECT(
    'ip', '198.18.0.100',
    'location', JSON_OBJECT(
      'city', 'Moscow',
      'country', 'RU',
      'coordinates', [55.7558, 37.6173]
    )
  ),
  JSON_OBJECT('user_agent', 'python-httpx/0.24.0')
);

-- Expected: High severity - New geographic location for this API key
