# Unusual Model API Access Pattern

**ID**: HTA-AI-001  
**Author**: analogsloth  
**Created**: 2025-02-08  
**Updated**: 2025-02-08

## Goal

Detect compromised or abused LLM API keys by identifying unusual geographic access patterns, including API usage from new locations, rare locations, and impossible travel scenarios that indicate credential theft or sharing.

## Categorization

**MITRE ATT&CK**: Initial Access / Valid Accounts  
**ATT&CK ID**: T1078.004 (Cloud Accounts)  
**Related Techniques**: T1552.001 (Unsecured Credentials), T1078 (Valid Accounts)  
**Platforms**: Cloud, SaaS

**OWASP LLM Top 10**: LLM09 - Overreliance (related to unauthorized usage)

## Data Model Requirements

**OCSF Event Classes**:
- **Primary Class**: api_activity (class_uid: 6003)

**Required Fields**:
- `time` - API call timestamp
- `actor.user.uid` - API key identifier
- `actor.user.name` - User/account name
- `api.operation` - API operation called (e.g., "messages.create")
- `api.service.name` - Service name (e.g., "claude-api")
- `src_endpoint.ip` - Source IP address
- `src_endpoint.location.country` - Country code
- `src_endpoint.location.city` - City name
- `src_endpoint.location.coordinates` - [latitude, longitude]
- `http_request.user_agent` - User agent string
- `cloud.provider` - Cloud provider (optional)
- `cloud.region` - Cloud region (optional)

**Minimum Data Sources**:
- [x] API gateway access logs with geolocation enrichment
- [x] Application logs (Anthropic API, OpenAI API, etc.)
- [x] AWS CloudTrail (for AWS-hosted APIs)
- [x] GCP Cloud Logging (for GCP-hosted APIs)

## Technical Context

**Detection Strategy:**

This analytic establishes baseline geographic usage patterns for each API key over a 30-day period, then identifies deviations in the most recent 24 hours. Detection focuses on three primary patterns:

1. **New Location**: API key used from a country never seen before
2. **Rare Location**: API key used from a country seen fewer than 5 times historically
3. **Impossible Travel**: API key used from two distant geographic locations within a timeframe that makes physical travel impossible

The detection uses IP geolocation data to map API calls to countries and cities, calculates time differences between calls from different locations, and flags scenarios where an API key transitions between distant locations faster than humanly possible (e.g., US to China in 1 hour).

**Adversary Tradecraft:**

LLM API keys are high-value targets for adversaries because they provide:
- Access to expensive compute resources (can be monetized)
- Ability to extract training data or probe model behavior
- Platform for launching attacks (phishing, content generation, etc.)
- Data exfiltration channel (encoding data in prompts/responses)

Common attack patterns:
- **Key Theft**: Stealing API keys from code repositories (GitHub, GitLab)
- **Key Leakage**: Finding keys in logs, error messages, client-side code
- **Credential Stuffing**: Testing leaked keys from other breaches
- **Insider Threats**: Employees sharing or selling API keys
- **Supply Chain**: Compromised dependencies or packages containing keys

Technical prerequisites:
- Valid API key (stolen, leaked, or purchased)
- Internet access to API endpoint
- Understanding of API structure and operations

**Normal vs. Malicious:**

**Legitimate use cases:**
- Developers traveling internationally
- Distributed teams across multiple countries
- VPN usage (may show different locations)
- Cloud functions/Lambda in different regions
- Legitimate API key sharing within organization

**Malicious indicators:**
- Sudden usage from high-risk countries (sanctioned nations, known fraud origins)
- Impossible travel patterns (distant locations in short time)
- Change in user agent after location change (different tools/libraries)
- Spike in usage volume concurrent with new location
- Usage from Tor exit nodes or VPN providers
- Access from countries with no business relationship

## Detection Logic

### Pseudocode
```
// Step 1: Get recent API calls with geolocation
api_calls = search ApiActivity:Call
recent = filter api_calls where (
  service contains "model" or "claude" or "gpt" and
  time >= now() - 7 days
)

// Step 2: Build baseline location profile per API key
baseline = group api_calls by (api_key, country) where (
  time between (now() - 30 days, now() - 24 hours)
)
baseline_profile = from baseline select (
  api_key,
  country,
  count(*) as historical_count,
  min(time) as first_seen
)

// Step 3: Detect new or rare locations
recent_with_baseline = join (recent, baseline_profile)
  on recent.actor.user.uid == baseline.api_key
  and recent.src_endpoint.location.country == baseline.country

new_locations = filter recent_with_baseline where (
  baseline.api_key is null  // Never seen before
  or baseline.historical_count < 5  // Rarely seen
)

// Step 4: Detect impossible travel
travel_events = from recent select pairs where (
  api_key matches and
  country differs and
  time_between < 4 hours
)

// Step 5: Flag and score
suspicious = combine (new_locations, travel_events)
output suspicious order by severity desc
```

### SQL Implementation

See [query.sql](./query.sql)

## Blind Spots and Assumptions

**Assumptions**:
- [ ] IP geolocation data is available and reasonably accurate
- [ ] API logs include source IP addresses
- [ ] API keys are stable identifiers (not rotated mid-baseline period)
- [ ] Clock synchronization across distributed systems
- [ ] Geolocation enrichment happens at log collection time

**Blind Spots**:
- [ ] **VPN Usage** - Legitimate users on VPNs may appear in unexpected locations
- [ ] **Cloud Functions** - Serverless functions deploy globally, may trigger false positives
- [ ] **IP Geolocation Accuracy** - Mobile IPs, ISP proxies can mislocate by hundreds of miles
- [ ] **Shared API Keys** - Organizations sharing keys across teams/regions won't detect abuse
- [ ] **Tor/Proxies** - Attackers using anonymization tools may appear in legitimate countries
- [ ] **API Key Rotation** - New keys have no baseline, generating false positives initially
- [ ] **Low-Volume Abuse** - Attacker making minimal API calls may stay under thresholds

## False Positives

**Known FP Sources**:

1. **International Travel**:
   - *Characteristics*: Developer traveling for conferences, business trips
   - *Mitigation*: Correlate with HR travel records, set higher threshold for rare (not new) locations

2. **VPN Usage**:
   - *Characteristics*: Corporate VPNs or personal VPNs showing variable locations
   - *Mitigation*: Whitelist known VPN provider IP ranges, increase baseline period

3. **Multi-Region Deployments**:
   - *Characteristics*: Applications deployed in multiple AWS/GCP regions
   - *Mitigation*: Tag API keys by deployment type, whitelist infrastructure IPs

4. **Mobile Developers**:
   - *Characteristics*: Developers working from cafes, coworking spaces with variable IPs
   - *Mitigation*: Increase threshold for "rare" from 5 to 10+ occurrences

5. **Geolocation Errors**:
   - *Characteristics*: ISP IP ranges mislocated by geolocation databases
   - *Mitigation*: Use multiple geolocation providers, correlate with ASN data

**Tuning Recommendations**:
- Baseline period: 30 days minimum for stable usage patterns
- Expected FP rate: 15-25% initially (travel, VPNs), <10% after tuning
- Whitelisting approach:
  - Maintain list of known infrastructure IPs (AWS, GCP regions)
  - Tag API keys as "organizational" vs "individual developer"
  - Correlate with employee travel calendars
  - Set per-key thresholds based on typical usage patterns

## Validation

### True Positive Generation

**Method 1 - Simulated Key Compromise**:
```python
import anthropic
import time

# Use API key from one location
client1 = anthropic.Anthropic(api_key="sk-test-key")
response1 = client1.messages.create(
    model="claude-3-5-sonnet-20241022",
    max_tokens=100,
    messages=[{"role": "user", "content": "Hello"}]
)

# Immediately use same key from VPN/proxy in different country
# (simulate by using VPN or cloud function in different region)
time.sleep(60)  # Wait 1 minute

client2 = anthropic.Anthropic(api_key="sk-test-key")  # Same key, different location
response2 = client2.messages.create(
    model="claude-3-5-sonnet-20241022",
    max_tokens=100,
    messages=[{"role": "user", "content": "Test"}]
)
```

**Method 2 - Red Team Key Exfiltration**:
- Intentionally commit API key to public GitHub repo
- Monitor for usage from unexpected geographic locations
- Document time-to-compromise and access patterns

**Expected Results**:
- **API logs**: Two calls from same API key, different countries, <4 hours apart
- **Geolocation data**: Countries separated by >1000 miles
- **Analytic output**: Severity Critical, finding "Impossible Travel Detected"

## Real-World Context

**Observed In**:
- **API Key Leaks**: GitHub, GitLab, and other code repositories regularly leak API keys that get scraped and abused within hours
- **Crypto Mining Abuse**: Stolen OpenAI/Anthropic keys used for generating content that's sold or used in crypto scams
- **Research Abuse**: Academic researchers sharing keys globally, leading to unexpected geographic usage
- **Supply Chain**: Compromised npm/PyPI packages exfiltrating API keys from developer environments
- **Insider Threats**: Employees sharing API keys with external parties or selling access

**Notable Patterns**:
- Stolen keys typically show usage from Eastern Europe, Southeast Asia, or sanctioned countries within 24-48 hours of exposure
- Legitimate keys rarely cross more than 2-3 countries unless organization is highly distributed
- User agent changes concurrent with location changes often indicate different users/tools

## Additional Resources

**External**:
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATT&CK T1078.004](https://attack.mitre.org/techniques/T1078/004/)
- [Anthropic API Best Practices](https://docs.anthropic.com/en/api/security)
- [GitHub: Detecting Leaked API Keys](https://github.blog/2023-04-05-detecting-leaked-api-keys/)

---

**Detection Maturity Level**: 4 (Statistical baseline with behavioral analysis)  
**Last Validated**: 2025-02-08  
**Validation Result**: Pending (requires production API logs with geolocation)
