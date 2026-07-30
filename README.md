# 🛡️ AWS Cloud Security Scanner

An automated, multi-tool security assessment framework designed to evaluate, audit, and report security posture across AWS cloud infrastructures.

The scanner audits core AWS services—including **S3 Buckets**, **IAM Accounts & Access Policies**, **CloudTrail Logs**, **Prowler Compliance**, and **ScoutSuite Scans**—and consolidates all findings into executive-grade **HTML**, **JSON**, and **PDF** reports.

---

## 📋 Table of Contents
- <a href="#key-features">Key Features</a>
- <a href="#architecture-diagram">Architecture Diagram</a>
- <a href="#repository-structure">Repository Structure</a>
- <a href="#quick-start-installation">Quick Start & Installation</a>
- <a href="#usage-instructions">Usage Instructions</a>
- <a href="#viewing-generated-reports">Viewing Generated Reports</a>
- <a href="#resources">Resources</a>

---

<h2><a class="anchor" id="key-features"></a> 🌟 Key Features</h2>

- **📦 S3 Bucket Security Scanner:**
  - Identifies public bucket policies and ACLs.
  - Verifies Server-Side Encryption (KMS / AES-256).
  - Checks bucket versioning and access logging.

- **👥 IAM Identity & Privilege Audit:**
  - Enumerates users, roles, and attached policies.
  - Highlights IAM accounts lacking **Multi-Factor Authentication (MFA)**.
  - Flags accounts with high-risk `AdministratorAccess` policies.

- **📊 CloudTrail & Threat Event Analysis:**
  - Verifies multi-region trail configuration and log file validation.
  - Checks KMS encryption status for CloudTrail logs.
  - Audits recent administrative security events (`CreateAccessKey`, `CreateUser`, `AttachUserPolicy`, etc.).

- **📝 Executive PDF & HTML Reporting:**
  - Calculates an overall **Security Health Score (0–100)**.
  - Categorizes findings by severity: **Critical**, **High**, **Medium**, and **Low**.
  - Generates actionable remediation roadmaps with visual status badges.

- **🔒 Built-in Privacy & Security:**
  - Credentials are never hardcoded or saved to disk.
  - Raw scan outputs (`outputs/`) are automatically untracked via `.gitignore` to prevent accidental credential or metadata exposure on Git.

---

<h2><a class="anchor" id="architecture-diagram"></a> 🏗️ Architecture Diagram</h2>

![image alt](https://github.com/Akanksha-cloudsec/aws-security-scanner/blob/0713b84c2163444f7f0802df4ad5020aa7f01b18/Architecture%20Diagram/Architecture%20Diagram.png)

---

<h2><a class="anchor" id="repository-structure"></a> 📁 Repository Structure</h2>

```text

 aws_security_scanner/
 ├── core/
 │   ├── aws_auth.py           # AWS session & credential authentication
 │   ├── logger.py             # Logging setup
 │   └── report_generator.py   # Consolidated HTML, JSON & PDF report engine
 │
 ├── scanners/
 │   ├── s3_scanner.py          # S3 storage audit module
 │   ├── iam_enum.py           # IAM enumeration & MFA audit module
 │   ├── cloudtrail_analyzer.py# CloudTrail audit & threat event analyzer
 │   ├── prowler_wrapper.py    # Prowler integration wrapper
 │   └── scoutsuite_wrapper.py # ScoutSuite integration wrapper
 │
 ├── templates/
 │   └── report_template.html  # Executive PDF/HTML Jinja2 report template
 │
 ├── outputs/                  # Raw outputs, reports, & logs (ignored in Git)
 │   ├── raw/                  # JSON scan outputs
 │   ├── reports/              # HTML & PDF security reports
 │   └── logs/                 # Scanner log files
 │
 ├── config.yaml               # Global scanner configuration file
 ├── main.py                   # Main CLI entry point
 ├── requirements.txt          # Python dependencies
 ├── .gitignore                    # Prevents output & credential tracking
 └── README.md                     # Project documentation

```

---

<h2><a class="anchor" id="quick-start-installation"></a> 🚀 Quick Start & Installation</h2>

### 1. Prerequisites
- **Python 3.8+**
- Active **AWS Credentials** (`AWS_ACCESS_KEY_ID` & `AWS_SECRET_ACCESS_KEY`) with read-only audit permissions (`SecurityAudit` or `ReadOnlyAccess`).

### 2. Install Dependencies
Navigate to the scanner directory and install required Python packages:

```bash
git clone https://github.com/Akanksha-cloudsec/aws-security-scanner.git
pip install -r requirements.txt
```

---

<h2><a class="anchor" id="usage-instructions"></a> 💻 Usage Instructions</h2>

### Basic Run (Default Region: `us-east-1`)
Run the scanner entry point. If credentials are not found in environment variables, you will be prompted securely:

```bash
python main.py
```

### Specify a Custom AWS Region
To target a specific region (e.g., `ap-south-1` for Mumbai, `us-west-2` for Oregon, `eu-west-1` for Ireland):

```bash
python main.py --region ap-south-1
```

### Pass Credentials via Command Line Flags
```bash
python main.py --access-key YOUR_ACCESS_KEY_ID --secret-key YOUR_SECRET_ACCESS_KEY --region ap-south-1
```

---

<h2><a class="anchor" id="viewing-generated-reports"></a> 📊 Viewing Generated Reports</h2>

Once a scan completes, consolidated reports are saved in `outputs/reports/`:

1. **PDF Executive Report:** `outputs/reports/security_report.pdf`
2. **HTML Web Report:** `outputs/reports/security_report.html`
3. **JSON Raw Data:** `outputs/reports/security_report.json`
  
Open `security_report.pdf` or `security_report.html` in any web browser or PDF viewer to review the assessment.
   - Sample
     
     ![image alt](https://github.com/Akanksha-cloudsec/aws-security-scanner/blob/43933536eef9201ddcc92eb401f1e58d39de6a4a/Images/Report.jpg)

---

<h2><a class="anchor" id="resources"></a> 📚 Resources</h2>

  [Amazon S3](https://aws.amazon.com/s3/)

  [Amazon IAM](https://aws.amazon.com/iam/)






