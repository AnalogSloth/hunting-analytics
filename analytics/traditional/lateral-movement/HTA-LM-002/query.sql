-- HTA-LM-002: User Logged into Multiple Hosts
-- Detects lateral movement via authentication to multiple systems
-- OCSF Class: authentication (3002)
-- Author: analogsloth
-- Created: 2025-02-08
-- Platform: ANSI SQL (OCSF v1.3.0 compliant)

-- Note: This detection requires authentication logging (successful logins)
-- Data sources: Windows Security Event Logs, authentication logs, EDR

-- Step 1: Get successful login events from last 24 hours
WITH user_logins AS (
  SELECT
    time,
    user.name AS user_name,
    device.hostname AS dest_host,
    src_endpoint.ip AS source_ip,
    metadata.product.name AS data_source
  FROM authentication
  WHERE
    class_uid = 3002  -- Authentication
    AND activity_id = 1  -- Logon
    AND status_id = 1  -- Success
    AND time >= CURRENT_TIMESTAMP - INTERVAL '24 hours'
),

-- Step 2: Group by user and calculate host access patterns
user_activity AS (
  SELECT
    user_name,
    COUNT(DISTINCT dest_host) AS unique_host_count,
    COUNT(*) AS total_login_count,
    MIN(time) AS first_login,
    MAX(time) AS last_login,
    ARRAY_AGG(DISTINCT dest_host) AS hosts_accessed,
    ARRAY_AGG(DISTINCT source_ip) AS source_ips
  FROM user_logins
  GROUP BY user_name
  HAVING COUNT(DISTINCT dest_host) > 1  -- More than 1 host
),

-- Step 3: Calculate time window for rapid access
rapid_access AS (
  SELECT
    *,
    TIMESTAMPDIFF(MINUTE, first_login, last_login) AS time_window_minutes,
    unique_host_count / NULLIF(TIMESTAMPDIFF(HOUR, first_login, last_login), 0) AS hosts_per_hour
  FROM user_activity
)

-- Step 4: Filter and score
SELECT
  *,
  -- Severity scoring
  CASE
    WHEN unique_host_count >= 10 THEN 'Critical'
    WHEN unique_host_count >= 5 AND time_window_minutes < 60 THEN 'High'
    WHEN unique_host_count >= 3 AND time_window_minutes < 30 THEN 'High'
    WHEN unique_host_count >= 5 THEN 'Medium'
    ELSE 'Low'
  END AS severity
FROM rapid_access
WHERE
  unique_host_count >= 3  -- Threshold: 3+ hosts accessed
  -- Add environment-specific filters:
  -- AND user_name NOT IN (SELECT user FROM known_admin_accounts)
  -- AND user_name NOT LIKE '%$'  -- Filter computer accounts
ORDER BY severity DESC, unique_host_count DESC, time_window_minutes ASC;
