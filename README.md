# Threat Hunting Analytics

Vendor-agnostic threat hunting analytics using **SQL over OCSF-normalized security data**.

## 🎯 Philosophy

Modern security programs generate massive volumes of telemetry from diverse sources: endpoints, networks, cloud APIs, SaaS applications, and containers. Traditional SIEM-specific detection content creates vendor lock-in and doesn't scale to data lake architectures.

This repository takes a different approach:

1. **Normalize security data to OCSF** ([Open Cybersecurity Schema Framework](https://github.com/ocsf/ocsf-schema))
2. **Write detections as SQL queries** against OCSF schema
3. **Deploy anywhere** - Snowflake, BigQuery, Athena, Databricks, or any SQL-queryable platform

### Benefits

- ✅ **Portable** across platforms (no vendor lock-in)
- ✅ **Scalable** to petabyte-scale datasets
- ✅ **Testable** and version-controlled
- ✅ **Modern** data engineering workflows
- ✅ **Multi-source correlation** - network, endpoint, cloud, application

## 📚 Analytics Categories

### Traditional Enterprise Threats
- **Lateral Movement** - SMB abuse, RDP patterns, PSExec, WMI execution
- **Credential Access** - Credential dumping, brute force, Kerberoasting
- **Persistence** - Registry Run keys, scheduled tasks, services
- **Defense Evasion** - Process injection, indicator removal

### Cloud-Native Security
- **AWS** - CloudTrail abuse, IAM misuse, EC2/S3 anomalies
- **GCP** - Audit log patterns, GKE security
- **Azure** - Activity log analysis, Azure AD abuse
- **Kubernetes** - Pod-to-pod lateral movement, container escape

### LLM Security
Maps to [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

- **LLM01** - Prompt Injection detection
- **LLM04** - Model Denial of Service
- **LLM06** - Sensitive Information Disclosure
- **LLM10** - Model Theft

## 🚀 Quick Start

### 1. Normalize Your Data to OCSF

See [schema documentation](./schema/README.md) for OCSF implementation guidance.

### 2. Browse Analytics

Each analytic includes:
- **README.md** - Full documentation (detection strategy, blind spots, tuning)
- **query.sql** - Production-ready SQL detection logic
- **test-data.sql** - Synthetic data for validation

Example: [HTA-LM-001: SMB File Write with Execution](./analytics/traditional/lateral-movement/HTA-LM-001/)

### 3. Deploy to Your Environment
```sql
-- Example: Run in Snowflake
USE DATABASE security_data;
USE SCHEMA detections;

-- Load the analytic
SOURCE analytics/traditional/lateral-movement/HTA-LM-001/query.sql;
```

## 📖 Documentation Structure

Each analytic follows the [Palantir ADS framework](https://github.com/palantir/alerting-detection-strategy-framework):

- **Goal** - What behavior is being detected
- **Categorization** - MITRE ATT&CK mapping
- **Strategy Abstract** - High-level detection approach
- **Data Model Requirements** - OCSF classes and fields needed
- **Technical Context** - Deep-dive on the threat
- **Detection Logic** - Pseudocode and SQL implementation
- **Blind Spots** - Known limitations
- **False Positives** - Common FP sources and tuning
- **Validation** - How to generate true positives
- **Response** - Investigation and triage guidance
- **Hunting Workflow** - Proactive hunting methodology

## 🛠️ OCSF Schema

This repository uses [OCSF v1.x](https://github.com/ocsf/ocsf-schema) event classes.

Key classes:
- `authentication` (3002) - Login/logout events
- `process_activity` (1007) - Process creation/termination
- `network_activity` (4001) - Network flows
- `file_activity` (4010) - File operations
- `cloud_api` (3005) - Cloud service API calls

See [OCSF reference documentation](./schema/ocsf-reference.md) for details.

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## 📜 License

MIT License - see [LICENSE](./LICENSE) for details.

## 🙏 Acknowledgments

- [MITRE ATT&CK](https://attack.mitre.org/) - Threat framework
- [MITRE CAR](https://car.mitre.org/) - Detection analytics inspiration
- [OCSF](https://github.com/ocsf/ocsf-schema) - Schema framework
- [Palantir ADS](https://github.com/palantir/alerting-detection-strategy-framework) - Documentation framework
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) - LLM security taxonomy

## 📊 Analytics Count

![Analytics Count](https://img.shields.io/badge/analytics-4-blue)
![OCSF](https://img.shields.io/badge/schema-OCSF%201.x-green)
![SQL](https://img.shields.io/badge/language-SQL-orange)

**Traditional**: 3 analytic  
**Cloud-Native**: 0 analytics  
**LLM Security**: 1 analytics

*Last updated: February 2026*

---

**Author**: [@analogsloth](https://github.com/analogsloth)  
**Status**: Active Development
