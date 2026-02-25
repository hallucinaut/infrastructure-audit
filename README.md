# 🔍 Infrastructure Audit - IaC Security & Compliance Auditor

> **Comprehensive security and compliance auditing for Infrastructure as Code (Terraform, CloudFormation, Kubernetes, ARM Templates)**

---

## 🎯 Problem Solved

Infrastructure as Code (IaC) is powerful, but **security misconfigurations** are common:
- **Public S3 buckets** exposing sensitive data
- **Security groups open to 0.0.0.0/0** allowing unrestricted access
- **Hardcoded credentials** in Terraform files
- **Privileged containers** running in Kubernetes
- **Unencrypted database instances**

**Infrastructure Audit solves this by automatically detecting these issues before deployment.**

---

## ✨ Features

### 🔒 Security Checks

#### AWS Security
- Public S3 bucket detection
- Security group open to 0.0.0.0/0
- EC2 without IAM instance profiles
- RDS publicly accessible
- RDS encryption disabled

#### Kubernetes Security
- Privileged containers
- Host network enabled
- Host path volumes
- Missing resource limits
- Running as root user

#### Terraform Security
- Hardcoded AWS credentials
- State backend encryption disabled
- State backend versioning disabled

#### Compliance Frameworks
- **SOC2** - Security controls
- **HIPAA** - Healthcare data protection
- **PCI-DSS** - Payment card industry
- **GDPR** - Data privacy
- **CIS Benchmarks** - Industry standards

### 🚀 Key Capabilities
- **Multi-Format Support** - AWS CloudFormation, Terraform, Kubernetes, ARM Templates
- **Real-Time Detection** - Identify security issues before deployment
- **Automated Reporting** - Generate detailed security reports
- **Remediation Scripts** - Create fix scripts for detected issues
- **CI/CD Integration** - Fail builds on critical findings
- **Severity Classification** - Prioritize issues by severity

---

## 🛠️ Installation

### Build from Source

```bash
cd infrastructure-audit
go mod download
go build -o infrastructure-audit cmd/infrastructure-audit/main.go
```

### Install Globally

```bash
go install -o /usr/local/bin/infrastructure-audit ./cmd/infrastructure-audit
```

---

## 🚀 Usage

### Basic Usage

```bash
# Audit current directory
./infrastructure-audit --dir=.

# Audit specific directory
./infrastructure-audit --dir=/path/to/infrastructure

# Fail on critical issues only
./infrastructure-audit --dir=. --fail-critical=true --fail-high=false --fail-medium=false
```

### Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `--dir` | Directory containing IaC files | `.` |
| `--fail-critical` | Fail if critical issues found | `true` |
| `--fail-high` | Fail if high issues found | `true` |
| `--fail-medium` | Fail if medium issues found | `false` |
| `--generate-remediation` | Generate remediation script | `false` |
| `--help` | Show help message | `false` |

### Examples

#### Audit Terraform Files

```bash
# Scan all .tf files
./infrastructure-audit --dir=./terraform --fail-critical=true
```

#### Audit Kubernetes Manifests

```bash
# Scan all K8s YAML files
./infrastructure-audit --dir=./k8s --fail-critical=true --fail-high=true
```

#### Audit AWS CloudFormation

```bash
# Scan CloudFormation templates
./infrastructure-audit --dir=./cloudformation --fail-critical=true
```

#### Generate Remediation Script

```bash
# Audit and generate fix script
./infrastructure-audit --dir=. --generate-remediation > remediation.sh
chmod +x remediation.sh
```

---

## 📊 Audit Report Example

```
================================================================================
📊 INFRASTRUCTURE SECURITY AUDIT REPORT
================================================================================
✅ Total files audited:     5
✅ Total checks performed:  25
⚠️  Critical issues:         2
❌ High issues:             3
⚠️  Medium issues:           4
🟢 Low issues:              1
ℹ️  Info issues:             0

================================================================================

🔍 DETAILED FINDINGS:

🔴 [CRITICAL] Public S3 Bucket
    File: terraform/s3-bucket.tf
    ID: AWS-001
    Description: S3 bucket should not be publicly accessible
    Remediation: Follow best practices for Public S3 Bucket
    Categories: AWS, S3, Data Protection
    ------------------------------------------------------------

🔴 [CRITICAL] RDS Publicly Accessible
    File: terraform/rds-instance.tf
    ID: AWS-004
    Description: RDS instances should not be publicly accessible
    Remediation: Follow best practices for RDS Publicly Accessible
    Categories: AWS, RDS, Database
    ------------------------------------------------------------

🟠 [HIGH] Security Group Open to 0.0.0.0/0
    File: terraform/security-group.tf
    ID: AWS-002
    Description: Security groups should not allow ingress from 0.0.0.0/0
    Remediation: Follow best practices for Security Group Open to 0.0.0.0/0
    Categories: AWS, EC2, Network Security
    ------------------------------------------------------------

================================================================================

✅ Audit FAILED: 2 critical issues found
```

---

## 🎨 Supported File Types

| Format | Extensions | Examples |
|--------|------------|----------|
| **Terraform** | `.tf` | `main.tf`, `variables.tf` |
| **AWS CloudFormation** | `.json`, `.yaml`, `.yml` | `template.json`, `cfn.yaml` |
| **Kubernetes** | `.yaml`, `.yml` | `deployment.yaml`, `service.yml` |
| **Azure ARM** | `.json` | `azuredeploy.json` |

---

## 🔧 CI/CD Integration

### GitHub Actions

```yaml
name: IaC Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Install infrastructure-audit
        run: |
          go build -o infrastructure-audit ./cmd/infrastructure-audit
      
      - name: Run audit
        run: |
          ./infrastructure-audit --dir=./infrastructure --fail-critical=true
```

### GitLab CI

```yaml
iac-audit:
  stage: security
  image: golang:1.21
  script:
    - go build -o infrastructure-audit ./cmd/infrastructure-audit
    - ./infrastructure-audit --dir=./infrastructure --fail-critical=true
```

### Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('IaC Audit') {
            steps {
                sh '''
                    go build -o infrastructure-audit ./cmd/infrastructure-audit
                    ./infrastructure-audit --dir=./infrastructure --fail-critical=true
                '''
            }
        }
    }
}
```

---

## 📝 Compliance Reporting

The tool generates compliance reports for:

### SOC2
- Access controls
- Encryption
- Audit logging
- Network security

### HIPAA
- PHI protection
- Access controls
- Audit controls
- Integrity controls

### PCI-DSS
- Network security
- Access control
- Encryption
- Monitoring

### GDPR
- Data protection
- Privacy by design
- Data minimization

### CIS Benchmarks
- Industry-standard security configurations
- Best practices enforcement

---

## 🧪 Testing

### Run Tests

```bash
go test ./...
```

### Test with Sample Files

```bash
# Create test infrastructure
mkdir -p test-infrastructure
cp sample-terraform.tf test-infrastructure/

# Run audit
./infrastructure-audit --dir=./test-infrastructure
```

---

## 📚 Sample Infrastructure Files

### Terraform Example

```hcl
resource "aws_s3_bucket" "example" {
  bucket = "my-secure-bucket"
  
  # ❌ This would be flagged if policy allows public access
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = "*"
      Action = "s3:GetObject"
      Resource = "arn:aws:s3:::my-secure-bucket/*"
    }]
  })
}
```

### Kubernetes Example

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: insecure-pod
spec:
  # ❌ This would be flagged
  hostNetwork: true
  containers:
  - name: app
    image: app:latest
    securityContext:
      privileged: true  # ❌ Critical issue
```

---

## 🚧 Roadmap

- [ ] Custom rule engine (RegO/OPA support)
- [ ] Multi-cloud support (GCP, Azure)
- [ ] Real-time monitoring integration
- [ ] Policy-as-code templates
- [ ] Dashboard and visualization
- [ ] Automated remediation execution
- [ ] Integration with SIEM systems

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch
3. Add new compliance rules
4. Submit a pull request

---

## 📄 License

MIT License - Free for commercial and personal use

---

## 🙏 Acknowledgments

Built with GPU for secure infrastructure deployments.

---

**Version:** 1.0.0  
**Author:** @hallucinaut  
**Last Updated:** February 25, 2026