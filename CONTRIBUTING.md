# Contributing to Enterprise SOC Implementation

Thank you for your interest in contributing to the Enterprise SOC Implementation project! This guide will help you get started with contributing code, documentation, detection rules, and other improvements.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Guidelines](#development-guidelines)
- [Submitting Changes](#submitting-changes)
- [Community](#community)

## Code of Conduct

This project adheres to a code of conduct that we expect all contributors to follow. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

## Getting Started

### Prerequisites

Before contributing, ensure you have:

- **Git** installed and configured
- **Terraform** >= 1.0
- **Ansible** >= 2.9
- **Docker** (for testing)
- **Python** >= 3.8
- **AWS CLI** configured (for testing infrastructure changes)
- **Splunk** knowledge (for detection rule contributions)

### Setting up the Development Environment

1. **Fork the repository**
   ```bash
   # Fork on GitHub, then clone your fork
   git clone https://github.com/YOUR_USERNAME/enterprise-soc-blueprint.git
   cd enterprise-soc-blueprint
   ```

2. **Set up upstream remote**
   ```bash
   git remote add upstream https://github.com/original-org/enterprise-soc-blueprint.git
   ```

3. **Install development dependencies**
   ```bash
   # Install pre-commit hooks
   pip install pre-commit
   pre-commit install
   
   # Install Terraform validation tools
   brew install tflint terraform-docs
   
   # Install Ansible lint
   pip install ansible-lint
   ```

4. **Validate your setup**
   ```bash
   # Test Terraform
   cd infrastructure/terraform
   terraform init -backend=false
   terraform validate
   
   # Test Ansible
   cd ../ansible
   ansible-playbook --syntax-check playbooks/site.yml
   ```

## How to Contribute

### Types of Contributions

We welcome several types of contributions:

#### 1. **Detection Rules**
- New MITRE ATT&CK technique coverage
- Improved detection logic
- Reduced false positives
- Performance optimizations

#### 2. **Infrastructure Code**
- Terraform modules and configurations
- Ansible playbooks and roles
- Cloud provider integrations
- Security improvements

#### 3. **SOAR Playbooks**
- Incident response automation
- Threat intelligence integration
- Third-party tool integrations
- Workflow optimizations

#### 4. **Documentation**
- Deployment guides
- Troubleshooting documentation
- Architecture diagrams
- User guides

#### 5. **Testing and Validation**
- Unit tests
- Integration tests
- Security tests
- Performance benchmarks

### Finding Issues to Work On

- Check the [Issues](https://github.com/your-org/enterprise-soc-blueprint/issues) page
- Look for issues labeled `good first issue` for newcomers
- Issues labeled `help wanted` are actively seeking contributors
- Check the [Project Board](https://github.com/your-org/enterprise-soc-blueprint/projects) for planned work

## Development Guidelines

### General Principles

1. **Security First**: All contributions must maintain or improve security posture
2. **Documentation**: Code changes must include appropriate documentation
3. **Testing**: New features require corresponding tests
4. **Backward Compatibility**: Avoid breaking changes when possible
5. **Performance**: Consider performance impact of changes
6. **Maintainability**: Write clear, readable, and maintainable code

### Coding Standards

#### Terraform
- Use consistent naming conventions: `resource_name`
- Include variable descriptions and types
- Use locals for complex expressions
- Tag all resources appropriately
- Follow HashiCorp's style guide

```hcl
# Good example
resource "aws_security_group" "splunk_indexer" {
  name        = "${var.project_name}-splunk-indexer"
  description = "Security group for Splunk indexers"
  vpc_id      = aws_vpc.soc_vpc.id

  tags = {
    Name        = "${var.project_name}-splunk-indexer-sg"
    Component   = "splunk"
    Role        = "indexer"
    Environment = var.environment
  }
}

variable "project_name" {
  description = "Name of the project used for resource naming"
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.project_name))
    error_message = "Project name must contain only lowercase letters, numbers, and hyphens."
  }
}
```

#### Ansible
- Use YAML best practices (2-space indentation)
- Include task names and descriptions
- Use handlers for service restarts
- Implement idempotency
- Use variables for configuration

```yaml
# Good example
- name: Install Splunk package
  unarchive:
    src: "{{ splunk_download_url }}/{{ splunk_package }}"
    dest: /opt
    remote_src: yes
    owner: "{{ splunk_user }}"
    group: "{{ splunk_group }}"
    creates: "{{ splunk_home }}/bin/splunk"
  become: yes
  notify: restart splunk
```

#### Python (SOAR Playbooks)
- Follow PEP 8 style guide
- Use type hints where appropriate
- Include docstrings for functions and classes
- Handle exceptions gracefully
- Use logging instead of print statements

```python
def enrich_ip_reputation(container: dict, ip_address: str, callback=None) -> bool:
    """
    Enrich IP address with threat intelligence data.
    
    Args:
        container: Phantom container object
        ip_address: IP address to enrich
        callback: Optional callback function
        
    Returns:
        bool: True if enrichment successful, False otherwise
    """
    phantom.debug(f'Enriching IP reputation for {ip_address}')
    
    try:
        phantom.act('ip reputation', 
                   parameters={'ip': ip_address}, 
                   assets=['virustotal'], 
                   callback=callback)
        return True
    except Exception as e:
        phantom.error(f'IP enrichment failed: {str(e)}')
        return False
```

#### Splunk SPL (Detection Rules)
- Use consistent field naming (CIM compliance)
- Include comments explaining complex logic
- Optimize for performance
- Use macros for reusable components
- Include MITRE ATT&CK technique mapping

```spl
# Good example - T1059.001 PowerShell Detection
index=winevent sourcetype=WinEventLog:Security EventCode=4688 
| where match(CommandLine, "(?i)powershell.*(-encodedcommand|-enc|-e|bypass|-nop|hidden|downloadstring|iex)")
| stats count min(_time) as first_seen max(_time) as last_seen by host, user, NewProcessName, CommandLine 
| where count >= 1
| eval risk_score = 60, 
       risk_object = host, 
       risk_rule = "T1059.001 - Suspicious PowerShell Execution",
       mitre_technique = "T1059.001"
| fields host, user, CommandLine, risk_score, risk_object, risk_rule, mitre_technique, first_seen, last_seen
```

### Testing Requirements

#### Infrastructure Testing
```bash
# Terraform validation
terraform fmt -check
terraform validate
tflint

# Test deployment (in isolated environment)
terraform plan
terraform apply -auto-approve
terraform destroy -auto-approve
```

#### Ansible Testing
```bash
# Syntax validation
ansible-playbook --syntax-check playbooks/site.yml

# Lint checking
ansible-lint playbooks/site.yml

# Molecule testing (if configured)
molecule test
```

#### Detection Rule Testing
```bash
# SPL syntax validation
./scripts/validation/validate-spl.sh

# Test detection logic
./scripts/validation/test-detections.sh --rule "SOC - Suspicious PowerShell"

# Performance testing
./scripts/validation/test-performance.sh
```

### Documentation Standards

#### Markdown
- Use consistent heading levels
- Include code examples where appropriate
- Link to related documentation
- Use tables for structured data
- Include diagrams for complex concepts

#### Code Documentation
- Include README.md in each major directory
- Document configuration variables
- Provide usage examples
- Explain architectural decisions
- Include troubleshooting sections

## Submitting Changes

### Pull Request Process

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Follow the coding standards above
   - Include appropriate tests
   - Update documentation
   - Ensure all tests pass

3. **Commit your changes**
   ```bash
   # Use conventional commit format
   git commit -m "feat(detection): add T1055 process injection detection
   
   - Implement detection for process injection techniques
   - Add test cases for validation
   - Update documentation with new rule details
   
   Closes #123"
   ```

4. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Create Pull Request**
   - Use the PR template
   - Include detailed description
   - Reference related issues
   - Add appropriate labels

### Commit Message Format

We use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or modifying tests
- `chore`: Maintenance tasks

**Scopes:**
- `terraform`: Infrastructure changes
- `ansible`: Configuration management
- `splunk`: Splunk-related changes
- `soar`: SOAR playbook changes
- `detection`: Detection rule changes
- `docs`: Documentation changes

### Pull Request Template

When creating a PR, please include:

```markdown
## Description
Brief description of changes made.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing
- [ ] Tests pass locally
- [ ] Added tests for new functionality
- [ ] Updated documentation

## Security Impact
- [ ] No security impact
- [ ] Security improvement
- [ ] Potential security concern (explain below)

## Checklist
- [ ] My code follows the style guidelines
- [ ] I have performed a self-review
- [ ] I have commented my code where necessary
- [ ] I have updated documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally

## Related Issues
Closes #(issue number)
```

### Review Process

1. **Automated Checks**: All PRs must pass automated tests
2. **Code Review**: At least one maintainer review required
3. **Security Review**: Security-sensitive changes require additional review
4. **Documentation Review**: Documentation changes reviewed for accuracy
5. **Testing**: Changes tested in isolated environment when possible

### Review Criteria

Reviewers will check for:
- **Functionality**: Does the code work as intended?
- **Security**: Are there any security implications?
- **Performance**: Will this impact system performance?
- **Maintainability**: Is the code readable and maintainable?
- **Testing**: Are there adequate tests?
- **Documentation**: Is documentation updated appropriately?

## Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **Security Issues**: Email security@company.com for security vulnerabilities

### Getting Help

- Check existing [Issues](https://github.com/your-org/enterprise-soc-blueprint/issues)
- Review [Documentation](docs/)
- Ask questions in [Discussions](https://github.com/your-org/enterprise-soc-blueprint/discussions)
- Join community calls (schedule TBD)

### Recognition

Contributors are recognized through:
- GitHub contributor statistics
- Release notes acknowledgments
- Community showcase (with permission)
- Maintainer invitation for significant contributors

## Specific Contribution Areas

### Detection Rules

When contributing detection rules:

1. **Research the technique** using MITRE ATT&CK framework
2. **Write the detection logic** with appropriate filters
3. **Test with sample data** to validate detection
4. **Optimize for performance** to minimize search time
5. **Document the rule** with clear descriptions
6. **Include test cases** for validation

Example detection rule contribution:
```spl
# Detection Rule: T1003.001 - LSASS Memory Dump
index=winevent sourcetype=WinEventLog:Security EventCode=4656 
    ObjectName="*lsass.exe*" AccessMask=0x1010
| stats count min(_time) as first_seen max(_time) as last_seen by host, user, ProcessName
| where count >= 1
| eval risk_score = 80,
       risk_object = host,
       risk_rule = "T1003.001 - LSASS Memory Access",
       mitre_technique = "T1003.001",
       mitre_tactic = "Credential Access"
```

### Infrastructure Improvements

When contributing infrastructure code:

1. **Test in isolated environment** before submitting
2. **Follow least privilege principles** for security
3. **Include monitoring and alerting** for new components
4. **Document configuration options** thoroughly
5. **Consider cost implications** of changes

### SOAR Playbooks

When contributing SOAR playbooks:

1. **Follow the playbook template** for consistency
2. **Include error handling** for robustness
3. **Add logging statements** for troubleshooting
4. **Test with sample data** to validate workflow
5. **Document integration requirements** clearly

## Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Schedule

- **Major releases**: Quarterly
- **Minor releases**: Monthly
- **Patch releases**: As needed for critical fixes

### Release Notes

Each release includes:
- New features and improvements
- Bug fixes
- Breaking changes (if any)
- Migration guides (if needed)
- Contributor acknowledgments

## Questions?

If you have questions about contributing, please:
1. Check the [FAQ](docs/faq.md)
2. Search existing [Issues](https://github.com/your-org/enterprise-soc-blueprint/issues)
3. Create a new [Discussion](https://github.com/your-org/enterprise-soc-blueprint/discussions)
4. Contact the maintainers directly

Thank you for contributing to the Enterprise SOC Implementation project!
