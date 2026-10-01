# Host & Network Log Triage Sandbox

## Overview
An automated security triage sandbox designed to parse, detect, and report unauthorized access attempts across multi-platform audit logs. The tool automates incident triage by extracting targeted accounts, timestamps, event IDs, and source IPs, outputting structured reports for security compliance and SOC review.

## Key Features
- **Multi-Platform Ingestion:** Normalizes both Linux SSH authentication logs (`sshd`) and Windows Security Audit logs (Event ID `4625`).
- **Incident Extraction:** Identifies brute-force patterns and unauthorized logon failures.
- **Automated Reporting:** Generates structured CSV compliance reports for audit remediation.

## How to Run
```bash
python triage_parser.py