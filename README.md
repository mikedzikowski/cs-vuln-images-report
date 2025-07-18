
```markdown
# 🛡️ CrowdStrike CVE Image Vulnerability Report


![CrowdStrike](https://img.shields.io/badge/CrowdStrike-API-red)
![Python](https://img.shields.io/badge/Python-3.6%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

A powerful Python script that generates comprehensive reports of CVEs and their impacted container images using the CrowdStrike API.


## 📋 Table of Contents
- [Features](#-features)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Output Formats](#-output-formats)
- [Error Handling](#-error-handling)
- [Contributing](#-contributing)
- [Support](#-support)

## ✨ Features

### Core Functionality
- 🔍 Fetches all vulnerabilities from CrowdStrike API
- 🐳 Lists all impacted container images for each CVE
- 📊 Generates both JSON and CSV reports
- ⏱️ Real-time progress tracking
- 🔄 Automatic rate limiting and error handling

### Vulnerability Information
- CVE ID and severity
- CVSS score
- Detailed description
- Publication date

### Image Details
- Registry information
- Repository name
- Image tag

## 🔧 Prerequisites

- Python 3.6 or higher
- CrowdStrike API credentials:
  - Client ID
  - Client Secret
- Required Python package:
  ```bash
  pip install requests
  ```

## 📥 Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/cs-cve-image-vuln-report.git
cd cs-cve-image-vuln-report
```

2. Install the required package:
```bash
pip install requests
```

## ⚙️ Configuration

Update the credentials in the script:

```python
CLIENT_ID = "your_client_id_here"
CLIENT_SECRET = "your_client_secret_here"
```

## 🚀 Usage

Run the script:
```bash
python cs-cve-image-vuln-report.py
```

## 📄 Output Formats

### JSON Output
```json
[
  {
    "cve_id": "CVE-2023-XXXXX",
    "severity": "Critical",
    "cvss_score": 9.8,
    "description": "Vulnerability description...",
    "published_date": "2023-07-18T00:00:00Z",
    "impacted_images": [
      {
        "registry": "registry-1.docker.io",
        "repository": "library/ubuntu",
        "tag": "20.04"
      }
    ]
  }
]
```

### CSV Output
```csv
cve_id,severity,cvss_score,published_date,registry,repository,tag
CVE-2023-1234,Critical,9.8,2023-06-15T00:00:00Z,registry-1.docker.io,library/ubuntu,20.04
CVE-2023-5678,High,8.5,2023-06-20T00:00:00Z,quay.io,company/app,latest
```

### Output Files
- JSON: `vulnerability_analysis_TIMESTAMP.json`
- CSV: `vulnerability_analysis_TIMESTAMP.csv`

## 🛠️ Error Handling

Built-in handling for:
- 🔑 API authentication issues
- 🕒 Rate limiting
- 🌐 Network connectivity
- 📝 Data processing
- 📄 File operations

## 📊 Progress Tracking

Real-time information on:
- Total vulnerabilities found
- Current processing status
- Percentage completion
- Number of impacted images per CVE
- Execution time

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This is not an official CrowdStrike tool. Use at your own risk.

## 👨‍💻 Author

**Mike Dzikowski**

## 📈 Version History

- **1.0.0** (2023-07-18)
  - Initial release
  - JSON and CSV output support
  - Basic CVE and image reporting functionality

---

<div align="center">

Made with ❤️ for the CrowdStrike community

</div>
