# Contributing to Hunting Analytics

Thank you for considering contributing! This repository aims to be a comprehensive resource for SQL-based threat hunting analytics.

## How to Contribute

### 1. Reporting Issues
- Use GitHub Issues for bugs, questions, or suggestions
- Search existing issues before creating new ones
- Include relevant details (OCSF version, SQL platform, etc.)

### 2. Contributing Analytics

**We welcome new analytics! Each submission should include:**

1. **README.md** following the Palantir ADS framework
2. **query.sql** with working SQL detection logic
3. **test-data.sql** for validation

**Analytic Requirements:**
- Uses OCSF schema (document any extensions)
- ANSI SQL where possible (note platform-specific features)
- MITRE ATT&CK mapping
- Clear documentation of assumptions and blind spots
- Test data that generates true positives

### 3. Analytic Naming Convention

**Format**: `HTA-[CATEGORY]-[NUMBER]`

**Categories:**
- `LM` - Lateral Movement
- `CA` - Credential Access  
- `PER` - Persistence
- `DE` - Defense Evasion
- `AI` - LLM/AI Security
- `K8S` - Kubernetes
- `AWS` - AWS-specific

### 4. Submission Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/HTA-XX-XXX-description`
3. Follow the template in `templates/analytic-template.md`
4. Test your SQL on at least one platform
5. Commit with clear messages
6. Push and open a Pull Request

## Questions?

Open an issue or reach out to [@analogsloth](https://github.com/analogsloth)

Thank you for contributing! 🎯
