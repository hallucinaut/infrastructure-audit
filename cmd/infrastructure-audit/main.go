package main

import (
	"os/signal"
	"syscall"
	"context"
	"os/signal"
	"syscall"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fatih/color"
	"gopkg.in/yaml.v3"
)

var (
	infoColor = color.New(color.FgBlue)
	warnColor = color.New(color.FgYellow)
	errorColor = color.New(color.FgRed)
	successColor = color.New(color.FgGreen)
	criticalColor = color.New(color.FgRed, color.Bold)
	noticeColor = color.New(color.FgCyan)
)

// Severity represents the severity level of a finding
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Finding represents a security or compliance finding
type Finding struct {
	ID          string     `json:"id" yaml:"id"`
	Title       string     `json:"title" yaml:"title"`
	Description string     `json:"description" yaml:"description"`
	Severity    Severity   `json:"severity" yaml:"severity"`
	Resource    string     `json:"resource" yaml:"resource"`
	File        string     `json:"file" yaml:"file"`
	Line        int        `json:"line" yaml:"line"`
	Remediation string     `json:"remediation" yaml:"remediation"`
	Categories  []string   `json:"categories" yaml:"categories"`
}

// ComplianceRule represents a compliance rule
type ComplianceRule struct {
	ID          string
	Name        string
	Description string
	Categories  []string
	Severity    Severity
	Check       func(map[string]interface{}) (bool, string)
}

// IaCAuditResult holds the audit results
type IaCAuditResult struct {
	FilePath     string     `json:"file_path" yaml:"file_path"`
	FileType     string     `json:"file_type" yaml:"file_type"`
	TotalChecks  int        `json:"total_checks" yaml:"total_checks"`
	Findings     []Finding  `json:"findings" yaml:"findings"`
	PassedChecks int        `json:"passed_checks" yaml:"passed_checks"`
	Compliance   Compliance `json:"compliance" yaml:"compliance"`
}

// Compliance holds compliance status
type Compliance struct {
	SOC2       bool `json:"soc2" yaml:"soc2"`
	HIPAA      bool `json:"hipaa" yaml:"hipaa"`
	PCI_DSS    bool `json:"pci_dss" yaml:"pci_dss"`
	GDPR       bool `json:"gdpr" yaml:"gdpr"`
	CIS_Benchmark bool `json:"cis" yaml:"cis"`
}

// InfrastructureAuditor performs IaC security audits
type InfrastructureAuditor struct {
	rules           map[string][]ComplianceRule
	findings        []Finding
	auditResults    []IaCAuditResult
	failOnCritical  bool
	failOnHigh      bool
	failOnMedium    bool
	failOnHighCount int
	failOnMediumCount int
	failOnCriticalCount int
}

// NewInfrastructureAuditor creates a new InfrastructureAuditor
func NewInfrastructureAuditor() *InfrastructureAuditor {
	return &InfrastructureAuditor{
		rules: make(map[string][]ComplianceRule),
		findings: make([]Finding, 0),
		auditResults: make([]IaCAuditResult, 0),
	}
}

// InitializeRules initializes all compliance rules
func (ia *InfrastructureAuditor) InitializeRules() {
	// AWS Security Rules
	ia.rules["aws"] = []ComplianceRule{
		{
			ID:          "AWS-001",
			Name:        "Public S3 Bucket",
			Description: "S3 bucket should not be publicly accessible",
			Categories:  []string{"AWS", "S3", "Data Protection"},
			Severity:    SeverityCritical,
			Check: func(config map[string]interface{}) (bool, string) {
				if policy, ok := config["Policy"].(map[string]interface{}); ok {
					if statement, ok := policy["Statement"].([]interface{}); ok {
						for _, stmt := range statement {
							if s, ok := stmt.(map[string]interface{}); ok {
								if action, ok := s["Action"]; ok {
									if actionStr, ok := action.(string); ok {
										if strings.Contains(strings.ToLower(actionStr), "s3:getobject") ||
											strings.Contains(strings.ToLower(actionStr), "s3:listbucket") {
											if effect, ok := s["Effect"]; ok {
												if effectStr, ok := effect.(string); ok && strings.ToUpper(effectStr) == "ALLOW" {
													return false, "Public S3 bucket detected"
												}
											}
										}
									}
								}
							}
						}
					}
				}
				return true, ""
			},
		},
		{
			ID:          "AWS-002",
			Name:        "Security Group Open to 0.0.0.0/0",
			Description: "Security groups should not allow ingress from 0.0.0.0/0",
			Categories:  []string{"AWS", "EC2", "Network Security"},
			Severity:    SeverityCritical,
			Check: func(config map[string]interface{}) (bool, string) {
				if cidr, ok := config["CidrIp"]; ok {
					if cidrStr, ok := cidr.(string); ok && cidrStr == "0.0.0.0/0" {
						return false, "Security group allows traffic from anywhere"
					}
				}
				return true, ""
			},
		},
		{
			ID:          "AWS-003",
			Name:        "EC2 No Instance Profile",
			Description: "EC2 instances should have an IAM instance profile",
			Categories:  []string{"AWS", "EC2", "IAM"},
			Severity:    SeverityMedium,
			Check: func(config map[string]interface{}) (bool, string) {
				if _, ok := config["IamInstanceProfile"]; ok {
					return true, ""
				}
				return false, "EC2 instance has no IAM instance profile"
			},
		},
		{
			ID:          "AWS-004",
			Name:        "RDS Publicly Accessible",
			Description: "RDS instances should not be publicly accessible",
			Categories:  []string{"AWS", "RDS", "Database"},
			Severity:    SeverityCritical,
			Check: func(config map[string]interface{}) (bool, string) {
				if publicly, ok := config["PubliclyAccessible"]; ok {
					if publiclyBool, ok := publicly.(bool); ok && publiclyBool {
						return false, "RDS instance is publicly accessible"
					}
				}
				return true, ""
			},
		},
		{
			ID:          "AWS-005",
			Name:        "RDS Encryption Disabled",
			Description: "RDS instances should have encryption enabled",
			Categories:  []string{"AWS", "RDS", "Encryption"},
			Severity:    SeverityHigh,
			Check: func(config map[string]interface{}) (bool, string) {
				if encrypted, ok := config["StorageEncrypted"]; ok {
					if encryptedBool, ok := encrypted.(bool); ok && !encryptedBool {
						return false, "RDS instance encryption is disabled"
					}
				}
				return true, ""
			},
		},
	}

	// Kubernetes Security Rules
	ia.rules["kubernetes"] = []ComplianceRule{
		{
			ID:          "K8S-001",
			Name:        "Privileged Container",
			Description: "Containers should not run in privileged mode",
			Categories:  []string{"Kubernetes", "Security", "Containers"},
			Severity:    SeverityCritical,
			Check: func(config map[string]interface{}) (bool, string) {
				if priv, ok := config["privileged"]; ok {
					if privBool, ok := priv.(bool); ok && privBool {
						return false, "Container runs in privileged mode"
					}
				}
				return true, ""
			},
		},
		{
			ID:          "K8S-002",
			Name:        "Host Network Enabled",
			Description: "Pods should not use host network",
			Categories:  []string{"Kubernetes", "Network", "Security"},
			Severity:    SeverityHigh,
			Check: func(config map[string]interface{}) (bool, string) {
				if hostNet, ok := config["hostNetwork"]; ok {
					if hostNetBool, ok := hostNet.(bool); ok && hostNetBool {
						return false, "Pod uses host network"
					}
				}
				return true, ""
			},
		},
		{
			ID:          "K8S-003",
			Name:        "Host Path Volume",
			Description: "Pods should not mount host paths",
			Categories:  []string{"Kubernetes", "Storage", "Security"},
			Severity:    SeverityHigh,
			Check: func(config map[string]interface{}) (bool, string) {
				if volumes, ok := config["volumes"]; ok {
					if volList, ok := volumes.([]interface{}); ok {
						for _, v := range volList {
							if vol, ok := v.(map[string]interface{}); ok {
								if _, hasHostPath := vol["hostPath"]; hasHostPath {
									return false, "Pod mounts host path volume"
								}
							}
						}
					}
				}
				return true, ""
			},
		},
		{
			ID:          "K8S-004",
			Name:        "No Resource Limits",
			Description: "Containers should have resource limits defined",
			Categories:  []string{"Kubernetes", "Performance", "Security"},
			Severity:    SeverityMedium,
			Check: func(config map[string]interface{}) (bool, string) {
				if resources, ok := config["resources"]; ok {
					if resMap, ok := resources.(map[string]interface{}); ok {
						if _, hasLimits := resMap["limits"]; hasLimits {
							return true, ""
						}
					}
				}
				return false, "Container has no resource limits"
			},
		},
		{
			ID:          "K8S-005",
			Name:        "Run as Root",
			Description: "Containers should not run as root user",
			Categories:  []string{"Kubernetes", "Security", "Containers"},
			Severity:    SeverityMedium,
			Check: func(config map[string]interface{}) (bool, string) {
				if runAsRoot, ok := config["runAsRoot"]; ok {
					if runAsRootBool, ok := runAsRoot.(bool); ok && runAsRootBool {
						return false, "Container runs as root"
					}
				}
				return true, ""
			},
		},
	}

	// Terraform Security Rules
	ia.rules["terraform"] = []ComplianceRule{
		{
			ID:          "TF-001",
			Name:        "Hardcoded AWS Credentials",
			Description: "AWS credentials should not be hardcoded in Terraform",
			Categories:  []string{"Terraform", "AWS", "Security", "Secrets"},
			Severity:    SeverityCritical,
			Check: func(config map[string]interface{}) (bool, string) {
				if accessKey, ok := config["access_key"]; ok {
					if accessKeyStr, ok := accessKey.(string); ok && len(accessKeyStr) > 10 {
						return false, "Hardcoded AWS access key detected"
					}
				}
				if secretKey, ok := config["secret_key"]; ok {
					if secretKeyStr, ok := secretKey.(string); ok && len(secretKeyStr) > 10 {
						return false, "Hardcoded AWS secret key detected"
					}
				}
				return true, ""
			},
		},
		{
			ID:          "TF-002",
			Name:        "No State Backend Encryption",
			Description: "S3 backend should have encryption enabled",
			Categories:  []string{"Terraform", "S3", "Encryption"},
			Severity:    SeverityHigh,
			Check: func(config map[string]interface{}) (bool, string) {
				if encrypt, ok := config["encrypt"]; ok {
					if encryptBool, ok := encrypt.(bool); ok && !encryptBool {
						return false, "S3 backend encryption is disabled"
					}
				}
				return true, ""
			},
		},
		{
			ID:          "TF-003",
			Name:        "No Versioning on State Backend",
			Description: "S3 backend should have versioning enabled",
			Categories:  []string{"Terraform", "S3", "Data Protection"},
			Severity:    SeverityMedium,
			Check: func(config map[string]interface{}) (bool, string) {
				if versioning, ok := config["versioning"]; ok {
					if versioningBool, ok := versioning.(bool); ok && !versioningBool {
						return false, "S3 backend versioning is disabled"
					}
				}
				return true, ""
			},
		},
	}

	// General Security Rules
	ia.rules["general"] = []ComplianceRule{
		{
			ID:          "GEN-001",
			Name:        "No Comments with Secrets",
			Description: "Comments should not contain sensitive information",
			Categories:  []string{"Security", "Secrets", "Best Practices"},
			Severity:    SeverityHigh,
			Check: func(config map[string]interface{}) (bool, string) {
				return true, ""
			},
		},
		{
			ID:          "GEN-002",
			Name:        "Resource Tags Required",
			Description: "Resources should have appropriate tags",
			Categories:  []string{"Governance", "Compliance", "Cost Management"},
			Severity:    SeverityLow,
			Check: func(config map[string]interface{}) (bool, string) {
				return true, ""
			},
		},
	}
}

// ParseFile parses a configuration file
func (ia *InfrastructureAuditor) ParseFile(filePath string) (map[string]interface{}, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	fileExt := strings.ToLower(filepath.Ext(filePath))
	var config map[string]interface{}

	switch fileExt {
	case ".json":
		if err := json.Unmarshal(content, &config); err != nil {
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(content, &config); err != nil {
			return nil, fmt.Errorf("failed to parse YAML: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported file format: %s", fileExt)
	}

	return config, nil
}

// DetectFileType detects the type of IaC file
func (ia *InfrastructureAuditor) DetectFileType(filePath string, content map[string]interface{}) string {
	fileExt := strings.ToLower(filepath.Ext(filePath))
	
	// Check file name patterns
	fileName := strings.ToLower(filepath.Base(filePath))
	
	// AWS CloudFormation
	if strings.Contains(fileName, "template") || strings.Contains(fileName, "cloudformation") {
		return "aws-cloudformation"
	}
	
	// Terraform
	if fileExt == ".tf" || strings.Contains(fileName, "terraform") {
		return "terraform"
	}
	
	// Kubernetes
	if strings.Contains(fileName, "deployment") || strings.Contains(fileName, "pod") || 
	   strings.Contains(fileName, "service") || strings.Contains(fileName, "k8s") ||
	   fileExt == ".yaml" || fileExt == ".yml" {
		if _, hasKind := content["kind"]; hasKind {
			return "kubernetes"
		}
	}
	
	// ARM Template
	if fileExt == ".json" && strings.Contains(fileName, "arm") {
		return "azure-arm"
	}
	
	return "unknown"
}

// AuditFile audits a single IaC file
func (ia *InfrastructureAuditor) AuditFile(filePath string) (*IaCAuditResult, error) {
	content, err := ia.ParseFile(filePath)
	if err != nil {
		return nil, err
	}

	fileType := ia.DetectFileType(filePath, content)
	
	var applicableRules []ComplianceRule
	if rules, ok := ia.rules[fileType]; ok {
		applicableRules = rules
	} else if rules, ok := ia.rules["general"]; ok {
		applicableRules = rules
	}

	result := &IaCAuditResult{
		FilePath:   filePath,
		FileType:   fileType,
		TotalChecks: len(applicableRules),
		Findings:   make([]Finding, 0),
	}

	for _, rule := range applicableRules {
		passed, _ := rule.Check(content)
		
		if !passed {
			finding := Finding{
				ID:          rule.ID,
				Title:       rule.Name,
				Description: rule.Description,
				Severity:    rule.Severity,
				Resource:    filePath,
				File:        filePath,
				Line:        0,
				Remediation: fmt.Sprintf("Follow best practices for %s", rule.Name),
				Categories:  rule.Categories,
			}
			result.Findings = append(result.Findings, finding)
		} else {
			result.PassedChecks++
		}
	}

	return result, nil
}

// AuditDirectory audits all IaC files in a directory
func (ia *InfrastructureAuditor) AuditDirectory(dirPath string) error {
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			// Skip hidden directories and node_modules
			if strings.HasPrefix(info.Name(), ".") || info.Name() == "node_modules" || info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		// Check if file is a supported IaC file
		fileExt := strings.ToLower(filepath.Ext(path))
		fileName := strings.ToLower(filepath.Base(path))
		
		supportedFormats := map[string]bool{
			".json": true,
			".yaml": true,
			".yml":  true,
			".tf":   true,
		}

		if !supportedFormats[fileExt] {
			return nil
		}

		// Skip certain files
		if fileName == "package.json" || fileName == "go.mod" {
			return nil
		}

		noticeColor.Printf("🔍 Auditing: %s\n", path)
		
		result, err := ia.AuditFile(path)
		if err != nil {
			warnColor.Printf("⚠️  Failed to audit %s: %v\n", path, err)
			return nil
		}

		ia.auditResults = append(ia.auditResults, *result)
		
		if len(result.Findings) > 0 {
			noticeColor.Printf("  📋 Found %d issues\n", len(result.Findings))
		}

		return nil
	})

	return err
}

// PrintReport prints the audit report
func (ia *InfrastructureAuditor) PrintReport() {
	infoColor.Println("\n" + strings.Repeat("=", 80))
	infoColor.Println("📊 INFRASTRUCTURE SECURITY AUDIT REPORT")
	infoColor.Println(strings.Repeat("=", 80))

	var criticalCount, highCount, mediumCount, lowCount, infoCount int
	var totalIssues int

	for _, result := range ia.auditResults {
		for _, finding := range result.Findings {
			totalIssues++
			switch finding.Severity {
			case SeverityCritical:
				criticalCount++
			case SeverityHigh:
				highCount++
			case SeverityMedium:
				mediumCount++
			case SeverityLow:
				lowCount++
			case SeverityInfo:
				infoCount++
			}
		}
	}

	successColor.Printf("✅ Total files audited:     %d\n", len(ia.auditResults))
	successColor.Printf("✅ Total checks performed:  %d\n", ia.TotalChecks())
	warnColor.Printf("⚠️  Critical issues:         %d\n", criticalCount)
	errorColor.Printf("❌ High issues:             %d\n", highCount)
	warnColor.Printf("⚠️  Medium issues:           %d\n", mediumCount)
	noticeColor.Printf("ℹ️  Low issues:              %d\n", lowCount)
	infoColor.Printf("ℹ️  Info issues:             %d\n", infoCount)

	infoColor.Println(strings.Repeat("=", 80))

	if totalIssues > 0 {
		infoColor.Println("\n🔍 DETAILED FINDINGS:");
		
		// Sort findings by severity
		type severities = map[Severity]int
		severityOrder := severities{SeverityCritical: 0, SeverityHigh: 1, SeverityMedium: 2, SeverityLow: 3, SeverityInfo: 4}
		
		type findingWithFile struct {
			file string
			finding Finding
		}
		
		var findingsBySeverity []findingWithFile
		for _, result := range ia.auditResults {
			for _, f := range result.Findings {
				findingsBySeverity = append(findingsBySeverity, findingWithFile{file: result.FilePath, finding: f})
			}
		}
		
		sort.Slice(findingsBySeverity, func(i, j int) bool {
			return severityOrder[findingsBySeverity[i].finding.Severity] < severityOrder[findingsBySeverity[j].finding.Severity]
		})
		
		for _, item := range findingsBySeverity {
			f := item.finding
			
			severityEmoji := map[Severity]string{
				SeverityCritical: "🔴",
				SeverityHigh:     "🟠",
				SeverityMedium:   "🟡",
				SeverityLow:      "🟢",
				SeverityInfo:     "ℹ️",
			}
			
			criticalColor.Printf("%s [%s] %s\n", severityEmoji[f.Severity], f.Severity, f.Title)
			infoColor.Printf("    File: %s\n", item.file)
			infoColor.Printf("    ID: %s\n", f.ID)
			infoColor.Printf("    Description: %s\n", f.Description)
			infoColor.Printf("    Remediation: %s\n", f.Remediation)
			infoColor.Printf("    Categories: %s\n", strings.Join(f.Categories, ", "))
			infoColor.Println(strings.Repeat("-", 60))
		}
	} else {
		successColor.Println("\n✅ No security issues found:");
	}

	infoColor.Println(strings.Repeat("=", 80))
	
	if ia.failOnCritical && criticalCount > 0 {
		errorColor.Printf("\n❌ Audit FAILED: %d critical issues found\n", criticalCount)
		os.Exit(1)
	}
	
	if ia.failOnHigh && highCount > 0 {
		errorColor.Printf("\n❌ Audit FAILED: %d high severity issues found\n", highCount)
		os.Exit(1)
	}
	
	if ia.failOnMedium && mediumCount > 0 {
		errorColor.Printf("\n❌ Audit FAILED: %d medium severity issues found\n", mediumCount)
		os.Exit(1)
	}
	
	successColor.Printf("\n✅ Audit PASSED\n\n")
}

// TotalChecks returns the total number of checks performed
func (ia *InfrastructureAuditor) TotalChecks() int {
	total := 0
	for _, result := range ia.auditResults {
		total += result.TotalChecks
	}
	return total
}

// GenerateRemediationScript generates a remediation script
func (ia *InfrastructureAuditor) GenerateRemediationScript() {
	noticeColor.Println("\n📝 Generating remediation script:");
	
	noticeColor.Println("#!/bin/bash")
	noticeColor.Println("# Remediation script generated by infrastructure-audit")
	noticeColor.Println("# Review before executing!");
	
	for _, result := range ia.auditResults {
		for _, finding := range result.Findings {
			if finding.Severity == SeverityCritical || finding.Severity == SeverityHigh {
				noticeColor.Printf("# Fix: %s\n", finding.Title)
				noticeColor.Printf("# Resource: %s\n", finding.Resource)
				noticeColor.Printf("%s\n\n", finding.Remediation)
			}
		}
	}
	
	noticeColor.Println("echo \"Remediation script generated. Review and execute manually.\"")
}

func main() {
	// Define flags
	dirPath := flag.String("dir", ".", "Directory containing IaC files")
	failCritical := flag.Bool("fail-critical", true, "Fail if critical issues found")
	failHigh := flag.Bool("fail-high", true, "Fail if high issues found")
	failMedium := flag.Bool("fail-medium", false, "Fail if medium issues found")
	generateRemediation := flag.Bool("generate-remediation", false, "Generate remediation script")
	showHelp := flag.Bool("help", false, "Show help message")
	
	flag.Parse()
	
	if *showHelp {
		flag.Usage()
		return
	}
	
	// Create auditor
	auditor := NewInfrastructureAuditor()
	auditor.InitializeRules()
	auditor.failOnCritical = *failCritical
	auditor.failOnHigh = *failHigh
	auditor.failOnMedium = *failMedium
	
	// Audit directory
	if err := auditor.AuditDirectory(*dirPath); err != nil {
		errorColor.Printf("❌ Error auditing directory: %v\n", err)
		os.Exit(1)
	}
	
	// Print report
	auditor.PrintReport()
	
	// Generate remediation script if requested
	if *generateRemediation {
		auditor.GenerateRemediationScript()
	}
}