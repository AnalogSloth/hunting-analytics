-- HTA-AI-001: Unusual Model API Access Pattern
-- Detects anomalous API usage patterns indicating compromised keys or abuse
-- OCSF Class: api_activity (6003)
-- Author: analogsloth
-- Created: 2025-02-08
-- Updated: 2025-02-08
-- Platform: ANSI SQL (OCSF v1.3.0 compliant)

-- Note: This detection requires API access logging with geolocation data
-- Data sources: API gateway logs, CloudTrail, application logs

-- Step 1: Get API calls from last 7 days for baseline
WITH api_calls AS (
  SELECT
    time,
    actor.user.uid AS api_key,
    actor.user.name AS user_name,
    api.operation AS operation,
    api.service.name AS service_name,
    src_endpoint.location.city AS city,
    src_endpoint.location.country AS country,
    src_endpoint.location.coordinates[0] AS latitude,
    src_endpoint.location.coordinates[1] AS longitude,
    src_endpoint.ip AS source_ip,
    http_request.user_agent AS user_agent,
    cloud.provider AS cloud_provider,
    cloud.region AS cloud_region,
    metadata.product.name AS data_source
  FROM api_activity
  WHERE
    class_uid = 6003  -- API Activity
    AND activity_id IN (0, 1)  -- Unknown or other API activities
    AND (api.service.name LIKE '%model%' 
         OR api.service.name LIKE '%claude%'
         OR api.service.name LIKE '%gpt%'
         OR api.operation LIKE '%completion%'
         OR api.operation LIKE '%message%')
    AND time >= CURRENT_TIMESTAMP - INTERVAL '7 days'
),

-- Step 2: Calculate baseline location patterns per API key (last 30 days)
baseline_locations AS (
  SELECT
    actor.user.uid AS api_key,
    src_endpoint.location.country AS country,
    COUNT(*) AS request_count,
    MIN(time) AS first_seen,
    MAX(time) AS last_seen
  FROM api_activity
  WHERE
    class_uid = 6003
    AND time >= CURRENT_TIMESTAMP - INTERVAL '30 days'
    AND time < CURRENT_TIMESTAMP - INTERVAL '24 hours'  -- Exclude recent for baseline
  GROUP BY actor.user.uid, src_endpoint.location.country
),

-- Step 3: Detect new or unusual locations in last 24 hours
recent_activity AS (
  SELECT
    a.*,
    b.request_count AS baseline_requests,
    b.first_seen AS country_first_seen,
    CASE
      WHEN b.api_key IS NULL THEN 'New Location'
      WHEN b.request_count < 5 THEN 'Rare Location'
      ELSE 'Known Location'
    END AS location_status
  FROM api_calls a
  LEFT JOIN baseline_locations b
    ON a.api_key = b.api_key
    AND a.country = b.country
  WHERE a.time >= CURRENT_TIMESTAMP - INTERVAL '24 hours'
),

-- Step 4: Calculate impossible travel (geolocation + time)
travel_analysis AS (
  SELECT
    r1.api_key,
    r1.time AS first_time,
    r2.time AS second_time,
    r1.country AS first_country,
    r2.country AS second_country,
    r1.city AS first_city,
    r2.city AS second_city,
    r1.source_ip AS first_ip,
    r2.source_ip AS second_ip,
    r1.operation AS first_operation,
    r2.operation AS second_operation,
    -- Calculate time difference in hours
    TIMESTAMPDIFF(HOUR, r1.time, r2.time) AS hours_between,
    -- Approximate distance classification
    CASE
      WHEN r1.country != r2.country THEN 'International'
      WHEN r1.city != r2.city THEN 'Domestic'
      ELSE 'Same City'
    END AS travel_type
  FROM recent_activity r1
  JOIN recent_activity r2
    ON r1.api_key = r2.api_key
    AND r1.time < r2.time
  WHERE
    r1.country != r2.country  -- Different countries
    AND TIMESTAMPDIFF(HOUR, r1.time, r2.time) < 4  -- Less than 4 hours apart
)

-- Step 5: Flag suspicious patterns
SELECT
  r.time,
  r.api_key,
  r.user_name,
  r.operation,
  r.service_name,
  r.country,
  r.city,
  r.source_ip,
  r.user_agent,
  r.cloud_provider,
  r.cloud_region,
  r.location_status,
  r.baseline_requests,
  t.first_country,
  t.second_country,
  t.hours_between,
  t.travel_type,
  -- Severity scoring
  CASE
    WHEN t.api_key IS NOT NULL AND t.hours_between < 2 THEN 'Critical'  -- Impossible travel
    WHEN r.location_status = 'New Location' THEN 'High'
    WHEN r.location_status = 'Rare Location' THEN 'Medium'
    ELSE 'Low'
  END AS severity,
  CASE
    WHEN t.api_key IS NOT NULL THEN 'Impossible Travel Detected'
    WHEN r.location_status = 'New Location' THEN 'API Key Used from New Geographic Location'
    WHEN r.location_status = 'Rare Location' THEN 'API Key Used from Rarely-Seen Location'
    ELSE 'Normal Activity'
  END AS finding
FROM recent_activity r
LEFT JOIN travel_analysis t
  ON r.api_key = t.api_key
  AND r.time = t.second_time
WHERE
  r.location_status IN ('New Location', 'Rare Location')
  OR t.api_key IS NOT NULL
ORDER BY severity DESC, r.time DESC;
