-- =============================================================================
-- HTA-CA-001: Kerberoasting Detection
-- OCSF Classes: authentication (3002)
-- =============================================================================
-- Detects Kerberos service ticket requests (TGS-REQ) using RC4-HMAC encryption,
-- which is the primary indicator of Kerberoasting activity. Legitimate modern
-- environments use AES encryption exclusively for service tickets.
--
-- FIELD MAPPING NOTE: The Windows Event 4769 "Ticket Encryption Type" field is
-- not part of the OCSF authentication (3002) core schema. Most ETL pipelines
-- land it in one of two places:
--   (a) authentication_token.encryption_details.algorithm  [preferred OCSF path]
--   (b) unmapped['ticket_encryption_type'] or unmapped['EncryptionType']
-- The WHERE clause below handles both. Validate against your pipeline before deploy.
--
-- Compatible with: Snowflake, BigQuery, AWS Athena, Databricks SQL
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Step 1: Identify RC4-HMAC TGS requests (primary Kerberoasting signal)
-- ---------------------------------------------------------------------------
WITH rc4_tgs_requests AS (
    SELECT
        time,
        src_endpoint.ip                 AS src_ip,
        src_endpoint.hostname           AS src_hostname,
        user.name                       AS requesting_user,
        user.domain                     AS user_domain,
        service.name                                        AS target_service,
        -- Encryption type: prefer authentication_token path; fall back to unmapped
        COALESCE(
            authentication_token.encryption_details.algorithm,
            unmapped['ticket_encryption_type'],
            unmapped['EncryptionType']
        )                                                   AS encryption_type,
        authentication_token.kerberos_flags                 AS kerberos_flags,
        auth_protocol,
        class_uid,
        severity_id,
        metadata.product.name           AS event_source,
        metadata.product.vendor_name    AS vendor_name,
        -- Flag computer accounts (typically benign) vs user accounts
        CASE
            WHEN user.name LIKE '%$'    THEN TRUE
            ELSE FALSE
        END AS is_computer_account
    FROM
        authentication  -- Replace with your OCSF-normalized table name
    WHERE
        -- Kerberos service ticket requests only
        -- activity_id 3 = Authentication Ticket, 4 = Service Ticket (TGS-REQ / Event ID 4769)
        -- Use IN (3, 4) until you've confirmed your pipeline's activity_id mapping
        auth_protocol           = 'Kerberos'
        AND activity_id         IN (3, 4)
        -- RC4-HMAC detection: check both standard OCSF path and unmapped fallback
        AND (
            -- Standard path: authentication_token.encryption_details
            authentication_token.encryption_details.algorithm IN (
                'RC4-HMAC',         -- canonical name
                'RC4-HMAC-EXP',     -- legacy export variant
                'ARCFOUR-HMAC'      -- alternate naming in some pipelines
            )
            -- Unmapped fallback: Windows hex values from Event ID 4769
            OR unmapped['ticket_encryption_type'] IN ('0x17', '0x18')
            OR unmapped['EncryptionType']         IN ('0x17', '0x18', '23', '24')
        )
        -- Exclude computer accounts — they legitimately use RC4 in some envs
        AND user.name NOT LIKE '%$'
        -- Exclude well-known service accounts common in legacy infrastructure
        -- Tune this list to your environment
        AND service.name NOT IN (
            'krbtgt',
            'kadmin'
        )
),

-- ---------------------------------------------------------------------------
-- Step 2: Volume aggregation — single-host ticket burst
-- Attackers often request many TGS tickets in rapid succession using
-- tools like Rubeus or GetUserSPNs.py
-- ---------------------------------------------------------------------------
ticket_burst AS (
    SELECT
        DATE_TRUNC('hour', time)        AS detection_window,
        src_ip,
        src_hostname,
        requesting_user,
        user_domain,
        COUNT(*)                        AS ticket_count,
        COUNT(DISTINCT target_service)  AS unique_services_targeted,
        ARRAY_AGG(
            DISTINCT target_service
            ORDER BY target_service
        )                               AS targeted_services,
        MIN(time)                       AS first_request,
        MAX(time)                       AS last_request,
        DATEDIFF(
            'second',
            MIN(time),
            MAX(time)
        )                               AS request_duration_seconds
    FROM
        rc4_tgs_requests
    GROUP BY
        DATE_TRUNC('hour', time),
        src_ip,
        src_hostname,
        requesting_user,
        user_domain
),

-- ---------------------------------------------------------------------------
-- Step 3: Historical baseline — flag accounts with unusual RC4 request volume
-- Requires 30 days of historical data for meaningful baseline
-- ---------------------------------------------------------------------------
historical_baseline AS (
    SELECT
        user.name                           AS requesting_user,
        AVG(daily_rc4_count)                AS avg_daily_rc4_requests,
        STDDEV(daily_rc4_count)             AS stddev_daily_rc4_requests,
        MAX(daily_rc4_count)                AS max_daily_rc4_requests
    FROM (
        SELECT
            DATE_TRUNC('day', time)         AS request_day,
            user.name,
            COUNT(*)                        AS daily_rc4_count
        FROM
            authentication
        WHERE
            auth_protocol                   = 'Kerberos'
            AND activity_id                 IN (3, 4)
            AND (
                authentication_token.encryption_details.algorithm IN (
                    'RC4-HMAC', 'RC4-HMAC-EXP', 'ARCFOUR-HMAC'
                )
                OR unmapped['ticket_encryption_type'] IN ('0x17', '0x18')
                OR unmapped['EncryptionType']         IN ('0x17', '0x18', '23', '24')
            )
            AND user.name NOT LIKE '%$'
            -- 30-day lookback window for baseline
            AND time >= CURRENT_TIMESTAMP - INTERVAL '30 days'
            AND time <  CURRENT_TIMESTAMP - INTERVAL '1 day'
        GROUP BY
            DATE_TRUNC('day', time),
            user.name
    ) daily_counts
    GROUP BY
        user.name
),

-- ---------------------------------------------------------------------------
-- Step 4: Scoring — combine burst volume and baseline deviation
-- ---------------------------------------------------------------------------
scored_detections AS (
    SELECT
        b.detection_window,
        b.src_ip,
        b.src_hostname,
        b.requesting_user,
        b.user_domain,
        b.ticket_count,
        b.unique_services_targeted,
        b.targeted_services,
        b.first_request,
        b.last_request,
        b.request_duration_seconds,
        h.avg_daily_rc4_requests,
        h.stddev_daily_rc4_requests,
        -- Deviation from baseline (z-score approximation)
        CASE
            WHEN h.stddev_daily_rc4_requests > 0
            THEN (b.ticket_count - h.avg_daily_rc4_requests)
                 / h.stddev_daily_rc4_requests
            ELSE NULL
        END                                 AS baseline_deviation_zscore,
        -- Risk scoring: higher = more suspicious
        CASE
            -- Single ticket with RC4: low risk (could be legacy app)
            WHEN b.ticket_count = 1
                THEN 1
            -- 2-5 tickets in an hour: medium — monitor
            WHEN b.ticket_count BETWEEN 2 AND 5
                THEN 2
            -- 6-20 tickets: high — likely automated enumeration
            WHEN b.ticket_count BETWEEN 6 AND 20
                THEN 3
            -- 20+ tickets: critical — Rubeus/Impacket sweep
            WHEN b.ticket_count > 20
                THEN 4
            ELSE 1
        END                                 AS risk_score,
        CASE
            WHEN b.ticket_count = 1         THEN 'LOW'
            WHEN b.ticket_count BETWEEN 2 AND 5  THEN 'MEDIUM'
            WHEN b.ticket_count BETWEEN 6 AND 20 THEN 'HIGH'
            WHEN b.ticket_count > 20        THEN 'CRITICAL'
            ELSE 'LOW'
        END                                 AS risk_label
    FROM
        ticket_burst b
        LEFT JOIN historical_baseline h
            ON b.requesting_user = h.requesting_user
)

-- ---------------------------------------------------------------------------
-- Final output: detections above threshold
-- Tune risk_score threshold based on your environment's FP tolerance
-- Start with >= 3 (HIGH) and lower to >= 2 (MEDIUM) once baselined
-- ---------------------------------------------------------------------------
SELECT
    detection_window,
    risk_label,
    risk_score,
    requesting_user,
    user_domain,
    src_hostname,
    src_ip,
    ticket_count                        AS rc4_ticket_count,
    unique_services_targeted,
    targeted_services,
    first_request,
    last_request,
    request_duration_seconds,
    ROUND(avg_daily_rc4_requests, 2)    AS baseline_avg_daily_rc4,
    ROUND(baseline_deviation_zscore, 2) AS baseline_deviation_zscore,
    -- Investigation pivot fields
    'HTA-CA-001'                        AS analytic_id,
    CURRENT_TIMESTAMP                   AS detection_generated_at
FROM
    scored_detections
WHERE
    risk_score >= 3   -- Start here; lower to 2 after 30-day baseline tuning
ORDER BY
    risk_score DESC,
    ticket_count DESC,
    detection_window DESC;
