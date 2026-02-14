# Hunting Analytics - Project Context

## Repository Structure
```
hunting-analytics/
├── analytics/
│   ├── traditional/
│   │   └── lateral-movement/
│   │       ├── HTA-LM-001/ (SMB File Write + Execution)
│   │       └── HTA-LM-002/ (Multiple Host Logins)
│   └── llm-security/
│       └── HTA-AI-001/ (Unusual API Access Pattern)
├── scripts/
│   └── validate-ocsf.sh
├── templates/
│   └── analytic-template.md
└── README.md
```

## OCSF Classes Used

| Class Name | UID | Purpose | Analytics |
|------------|-----|---------|-----------|
| smb_activity | 4006 | SMB protocol events | HTA-LM-001 |
| process_activity | 1007 | Process creation/termination | HTA-LM-001 |
| authentication | 3002 | Login/logout events | HTA-LM-002 |
| api_activity | 6003 | API calls | HTA-AI-001 |

## Key Decisions Log

**2025-02-08**:
- Streamlined template from 500 to 200 lines
- Removed: Sigma rules, Response section, Hunting Workflow, Hunt Chain
- Kept: Pseudocode (for portability), core detection sections
- Validated all analytics against OCSF API

**2025-02-07**:
- Initial repo structure created
- Template based on Palantir ADS framework
- OCSF v1.3.0 chosen as schema standard

## Common Patterns

### Multi-Source Correlation
HTA-LM-001 demonstrates correlating network events (SMB) with endpoint events (process creation).

### Behavioral Baselines
HTA-LM-002 and HTA-AI-001 use 30-day baselines to detect anomalies.

### Temporal Windows
- HTA-LM-001: 5-minute correlation window
- HTA-AI-001: 4-hour impossible travel window

## False Positive Mitigation

**Whitelisting approach**:
- Deployment server IPs
- Service accounts
- Admin accounts with known patterns
- Infrastructure IPs (AWS, GCP regions)

**Baseline periods**:
- Minimum: 30 days
- Recommended: 60-90 days for mature environments

## Validation Strategy

Every analytic includes:
1. Manual TP generation commands
2. Atomic Red Team test references
3. Expected log output
4. Synthetic test data (test-data.sql)

## Git Workflow
```bash
# Standard workflow
git add analytics/[category]/HTA-XX-XXX/
git commit -m "Add HTA-XX-XXX: [Title]

[Description]
- OCSF classes used
- Detection logic summary
- MITRE ATT&CK mapping"
git push origin main
```

## Resources

- OCSF Schema: https://schema.ocsf.io/1.3.0/
- OCSF API: https://schema.ocsf.io/api
- MITRE CAR: https://car.mitre.org/
- MITRE ATT&CK: https://attack.mitre.org/
- OWASP LLM Top 10: https://owasp.org/www-project-top-10-for-large-language-model-applications/
