# Enterprise SOC Implementation Blueprint

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org/)
[![Splunk](https://img.shields.io/badge/Splunk-Compatible-orange)](https://www.splunk.com/)

A comprehensive, production-ready Security Operations Center (SOC) implementation blueprint featuring Splunk SIEM, SOAR automation, and enterprise-grade security monitoring capabilities.

## 🎯 Success Criteria & Guardrails

- **MTTD ≤ 10 minutes** - Mean Time to Detection
- **MTTR ≤ 60 minutes** - Mean Time to Response for high-severity incidents
- **95%+ coverage** of top MITRE ATT&CK TTPs
- **False-positive rate < 5%** on tuned detection rules
- **Change control** with Git-backed configurations and CI/CD validation

## 🏗️ Architecture Overview

### Data Plane
- **Collectors**: Splunk Universal Forwarders, Syslog-NG, Fluent Bit
- **Network Monitoring**: Zeek NSM, NetFlow/IPFIX
- **Cloud Integration**: AWS CloudTrail/GuardDuty, Azure Sentinel, GCP Security
- **Identity Systems**: Okta, Azure AD, Active Directory

### Processing & Storage
- **Splunk Cluster**: Heavy Forwarders → Kafka → Indexer Cluster → Cold Storage
- **Search Head Cluster** with CIM compliance and modular apps
- **Data Models**: Accelerated searches for common security use cases

### Control Plane
- **SOAR Platform**: Splunk SOAR/Phantom with automated playbooks
- **Case Management**: TheHive or ServiceNow SecOps integration
- **Threat Intelligence**: MISP/OpenCTI with automated IOC ingestion
- **Observability**: Prometheus + Grafana monitoring stack

## 📁 Project Structure

```
enterprise-soc-blueprint/
├── docs/                          # Documentation and guides
│   ├── architecture/              # Architecture diagrams and designs
│   ├── deployment-guides/         # Step-by-step deployment instructions
│   ├── playbooks/                # Incident response playbooks
│   └── detection-library/        # Detection rule documentation
├── infrastructure/               # Infrastructure as Code
│   ├── terraform/               # Terraform modules and configurations
│   ├── ansible/                # Ansible playbooks and roles
│   └── kubernetes/             # Kubernetes manifests (optional)
├── splunk/                     # Splunk configurations and apps
│   ├── apps/                  # Custom Splunk applications
│   ├── configs/              # Core Splunk configurations
│   └── detections/          # Detection rules and searches
├── soar/                   # SOAR automation
│   ├── playbooks/         # Automated response playbooks
│   └── custom-apps/      # Custom SOAR applications
├── scripts/              # Deployment and utility scripts
│   ├── deployment/      # Automated deployment scripts
│   └── validation/     # Testing and validation scripts
└── examples/          # Example configurations for different scales
    ├── small-enterprise/    # < 1000 endpoints
    ├── medium-enterprise/   # 1000-5000 endpoints
    └── large-enterprise/    # > 5000 endpoints
```

## 🚀 Quick Start

### Prerequisites
- Terraform >= 1.0
- Ansible >= 2.9
- Docker (for containerized components)
- Cloud provider account (AWS/Azure/GCP)

### Deployment Options

#### Option 1: Automated Deployment
```bash
# Clone the repository
git clone https://github.com/your-org/enterprise-soc-blueprint.git
cd enterprise-soc-blueprint

# Configure your environment
cp examples/medium-enterprise/terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your specific values

# Deploy infrastructure
cd infrastructure/terraform
terraform init
terraform plan
terraform apply

# Configure and deploy applications
cd ../../scripts/deployment
./deploy-soc.sh
```

#### Option 2: Manual Step-by-Step
Follow the detailed guides in `docs/deployment-guides/`:
1. [Infrastructure Setup](docs/deployment-guides/01-infrastructure-setup.md)
2. [Splunk Cluster Deployment](docs/deployment-guides/02-splunk-deployment.md)
3. [SOAR Configuration](docs/deployment-guides/03-soar-setup.md)
4. [Detection Rules Implementation](docs/deployment-guides/04-detection-rules.md)
5. [Validation and Testing](docs/deployment-guides/05-validation.md)

## 🎯 Detection Coverage

Our detection library covers the following MITRE ATT&CK tactics:

| Tactic | Techniques Covered | Detection Rules |
|--------|-------------------|-----------------|
| Initial Access | T1078, T1190, T1566 | 12 rules |
| Execution | T1059, T1053, T1204 | 15 rules |
| Persistence | T1543, T1547, T1136 | 18 rules |
| Privilege Escalation | T1548, T1134, T1055 | 14 rules |
| Defense Evasion | T1070, T1027, T1112 | 20 rules |
| Credential Access | T1003, T1110, T1558 | 16 rules |
| Discovery | T1083, T1057, T1018 | 13 rules |
| Lateral Movement | T1021, T1077, T1076 | 11 rules |
| Collection | T1005, T1039, T1113 | 8 rules |
| Exfiltration | T1041, T1048, T1567 | 7 rules |

## 🔧 Configuration Examples

### Splunk Indexer Configuration
```conf
# indexes.conf
[winevent]
homePath = $SPLUNK_DB/winevent/db
coldPath = $SPLUNK_DB/winevent/colddb
thawedPath = $SPLUNK_DB/winevent/thaweddb
maxDataSize = auto_high_volume
maxHotBuckets = 10
maxWarmDBCount = 300
```

### SOAR Playbook Example
```python
# High-Risk Login Response
def on_start(container, summary):
    phantom.debug('Starting High-Risk Login Response')
    
    # Get artifact data
    artifact = container.get('artifacts')[0]
    risk_score = artifact.get('cef', {}).get('risk_score', 0)
    
    if risk_score >= 80:
        # Trigger containment actions
        disable_user_account(container)
        isolate_host(container)
        create_ticket(container)
        notify_team(container)
```

## 📊 Monitoring and KPIs

### Executive Dashboard Metrics
- Mean Time to Detection (MTTD)
- Mean Time to Response (MTTR)
- Incident volume by severity
- Top MITRE ATT&CK techniques observed
- False positive rates

### Operational Metrics
- Data ingestion rates
- Search performance
- System health and capacity
- Automation success rates

## 🧪 Testing and Validation

### Purple Team Exercises
We include Atomic Red Team test scenarios for:
- PowerShell abuse detection
- LSASS credential dumping
- Lateral movement via RDP/SMB
- OAuth token abuse
- MFA fatigue attacks

### Continuous Testing
```bash
# Run detection validation
./scripts/validation/test-detections.sh

# Execute purple team scenarios
./scripts/validation/atomic-red-team-tests.sh

# Validate SOAR playbooks
./scripts/validation/test-playbooks.sh
```

## 📈 Scaling Considerations

| Environment Size | Daily Ingest | Indexers | Search Heads | Storage |
|------------------|-------------|----------|--------------|---------|
| Small (< 1K endpoints) | 50-100 GB | 1-2 | 1 | 2TB hot, 10TB cold |
| Medium (1K-5K endpoints) | 200-500 GB | 3-5 | 2-3 | 5TB hot, 50TB cold |
| Large (> 5K endpoints) | 1TB+ | 6+ | 3+ | 10TB+ hot, 100TB+ cold |

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Areas for Contribution
- Additional detection rules
- New SOAR playbooks
- Cloud provider integrations
- Documentation improvements
- Testing scenarios

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- MITRE ATT&CK Framework
- Splunk Community
- Open Source Security Community
- Detection Engineering Community

## 📞 Support

- 📖 [Documentation](docs/)
- 🐛 [Issues](https://github.com/bunnyhp/enterprise-soc-blueprint/issues)
- 💬 [Discussions](https://github.com/your-org/enterprise-soc-blueprint/discussions)

---

**⚠️ Security Notice**: This blueprint includes security configurations and detection rules. Please review and customize all configurations for your specific environment before production deployment.
