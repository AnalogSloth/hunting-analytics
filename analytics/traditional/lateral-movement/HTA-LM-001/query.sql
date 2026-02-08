-- HTA-LM-001: SMB File Write with Subsequent Local Execution
-- Detects lateral movement via SMB file staging and execution
-- OCSF Classes: network_activity (4001), process_activity (1007)
-- Author: analogsloth
-- Created: 2025-02-07
-- Platform: ANSI SQL (tested on Snowflake, BigQuery compatible)

-- Step 1: Identify SMB file write operations
WITH smb_writes AS (
  SELECT 
    time AS smb_time,
    src_endpoint.ip AS source_ip,
    dst_endpoint.ip AS dest_ip,
    dst_endpoint.hostname AS dest_host,
    LOWER(file.name) AS file_name,
    file.path AS remote_path,
    metadata.product.vendor_name AS data_source
  FROM network_activity
  WHERE 
    class_uid = 4001  -- Network Activity
    AND activity_id = 6  -- Traffic
    AND dst_endpoint.port = 445
    AND protocol_name = 'SMB'
    AND file.name IS NOT NULL
    AND time >= CURRENT_TIMESTAMP - INTERVAL '7 days'
),

-- Step 2: Find process creation events
process_creation AS (
  SELECT
    time AS process_time,
    device.hostname AS dest_host,
    LOWER(process.file.name) AS file_name,
    process.file.path AS image_path,
    actor.user.name AS user_account,
    process.cmd_line AS command_line,
    process.parent_process.file.path AS parent_image_path,
    metadata.product.vendor_name AS data_source
  FROM process_activity
  WHERE 
    class_uid = 1007  -- Process Activity
    AND activity_id = 1  -- Launch
    AND time >= CURRENT_TIMESTAMP - INTERVAL '7 days'
),

-- Step 3: Correlate SMB writes with process execution
correlated_events AS (
  SELECT
    s.smb_time,
    p.process_time,
    TIMESTAMPDIFF(SECOND, s.smb_time, p.process_time) AS time_delta_seconds,
    s.source_ip,
    s.dest_host,
    s.file_name,
    s.remote_path,
    p.image_path,
    p.user_account,
    p.command_line,
    p.parent_image_path,
    s.data_source AS network_data_source,
    p.data_source AS endpoint_data_source
  FROM smb_writes s
  INNER JOIN process_creation p
    ON s.dest_host = p.dest_host
    AND s.file_name = p.file_name
  WHERE
    -- Execution within 5 minutes after SMB write
    TIMESTAMPDIFF(SECOND, s.smb_time, p.process_time) BETWEEN 0 AND 300
)

-- Step 4: Filter and output
SELECT 
  *,
  -- Severity scoring based on context
  CASE
    WHEN image_path LIKE '%\\Temp\\%' THEN 'High'
    WHEN image_path LIKE '%\\ProgramData\\%' THEN 'High'
    WHEN image_path LIKE '%\\ADMIN$\\%' THEN 'High'
    WHEN time_delta_seconds < 60 THEN 'Medium'
    ELSE 'Low'
  END AS severity
FROM correlated_events
WHERE
  -- Filter known false positives
  image_path NOT LIKE 'C:\\Windows\\System32%'
  AND image_path NOT LIKE 'C:\\Program Files%'
  AND image_path NOT LIKE 'C:\\Program Files (x86)%'
  -- Add your environment-specific filters here
  -- Example: AND source_ip NOT IN (SELECT ip FROM known_deployment_servers)
ORDER BY severity DESC, time_delta_seconds ASC;
