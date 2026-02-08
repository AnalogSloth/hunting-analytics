# [Analytic Name]

**ID**: HTA-[CATEGORY]-[NUMBER]  
**Author**: [Your Name/Handle]  
**Created**: [YYYY-MM-DD]  
**Updated**: [YYYY-MM-DD]

## Goal

[Single paragraph describing what behavior this analytic detects]

## Categorization

**MITRE ATT&CK**: [Tactic] / [Technique] / [Sub-technique]  
**ATT&CK ID**: T####.###  
**Related Techniques**: T#### (if applicable)  
**Platforms**: [Windows | Linux | macOS | Cloud | Containers]

## Data Model Requirements

**OCSF Event Classes**:
- **Primary Class**: [class_name] (class_uid: ####)
- **Secondary Class**: [class_name] (class_uid: ####)

**Required Fields**:
- `field.path.name`
- `another.field.name`

**Minimum Data Sources**:
- [ ] [Data source 1]
- [ ] [Data source 2]

## Technical Context

**Detection Strategy:**
- High-level approach (what data sources, how they correlate)
- Temporal windows or thresholds used
- False positive minimization approach

**Adversary Tradecraft:**
- How and why adversaries use this technique
- Common attack patterns and variations
- Technical prerequisites

**Normal vs. Malicious:**
- Legitimate use cases for this activity
- Indicators that distinguish malicious from benign

## Detection Logic

### Pseudocode
```
[CAR-style pseudocode using OCSF notation]
```

### SQL Implementation

See [query.sql](./query.sql)

## Blind Spots and Assumptions

**Assumptions**:
- [ ] Assumption 1
- [ ] Assumption 2

**Blind Spots**:
- [ ] Known evasion technique 1
- [ ] Detection gap 2

## False Positives

**Known FP Sources**:

1. **[FP Category]**: [Description]
   - *Mitigation*: [How to filter/tune]

2. **[FP Category 2]**: [Description]
   - *Mitigation*: [Strategy]

**Tuning Recommendations**:
- Baseline period: [X days/weeks]
- Expected FP rate: [X%]
- Whitelisting approach: [Strategy]

## Validation

### True Positive Generation

**Method 1 - Manual**:
```bash
[Commands to generate TP]
```

**Method 2 - Atomic Red Team**:
- **Test**: [Test name/ID]
- **Link**: [URL]

**Expected Results**:
- [What logs should show]
- [What analytic should detect]

## Real-World Context

**Observed In**:
- **APT Groups**: [Names and brief context]
- **Ransomware**: [Family names and context]
- **Red Team Tools**: [Tool names]
- **Notable Incidents**: [Public reporting with dates]

## Additional Resources

**External**:
- [MITRE ATT&CK link]
- [Relevant blog posts or papers]
- [Tool/framework documentation]

---

**Detection Maturity Level**: [1-5]  
**Last Validated**: [YYYY-MM-DD]  
**Validation Result**: [Pass/Fail/Partial]
