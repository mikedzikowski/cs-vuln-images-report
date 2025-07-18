Here's the README.md for the script:

```markdown
# CrowdStrike CVE Image Vulnerability Report

A Python script that generates a detailed report of CVEs (Common Vulnerabilities and Exposures) and their impacted container images using the CrowdStrike API. For each CVE, it provides vulnerability details and lists all affected container images.

## Features

- Fetches all vulnerabilities from CrowdStrike API
- Lists all impacted container images for each CVE
- Provides detailed vulnerability information:
  - CVE ID
  - Severity
  - CVSS score
  - Description
  - Publication date
- For each impacted image, includes:
  - Registry
  - Repository
  - Tag

## Prerequisites

- Python 3.6 or higher
- CrowdStrike API credentials:
  - Client ID
  - Client Secret
- Required Python package:
  ```bash
  pip install requests
  ```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/cs-cve-image-vuln-report.git
cd cs-cve-image-vuln-report
```

2. Install the required package:
```bash
pip install requests
```

## Configuration

Update the following variables in the script with your CrowdStrike API credentials:

```python
CLIENT_ID = "your_client_id_here"
CLIENT_SECRET = "your_client_secret_here"
```

## Usage

Run the script:
```bash
python cs-cve-image-vuln-report.py
```

## Output

The script generates a timestamped JSON file with the following structure:

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

## Progress Tracking

The script provides real-time progress information:
- Total vulnerabilities found
- Current processing status
- Percentage completion
- Number of impacted images per CVE

## Error Handling

Built-in error handling for:
- API authentication
- Rate limiting
- Network connectivity
- Data processing
- Pagination

## Output File

Results are saved to a JSON file:
- Filename format: `vulnerability_analysis_YYYYMMDD_HHMMSS.json`
- Contains full vulnerability and image details
- Human-readable JSON format (pretty-printed)

## Summary Statistics

After completion, displays:
- Total number of CVEs processed
- Total number of impacted images
- Processing status

## Rate Limiting

Includes built-in rate limiting:
- 0.1-second delay between API calls
- Automatic retry on failures
- Maximum retry attempts for error cases

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This is not an official CrowdStrike tool. Use at your own risk.

## Support

For issues or feature requests, please open an issue in the GitHub repository.

## Author

Mike Dzikowski

## Version

1.0.0 (2023-07-18)
```

Would you like me to add or modify any sections in the README?
