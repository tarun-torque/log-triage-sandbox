import csv
import re
from datetime import datetime

LOG_FILE = "auth_audit.log"
REPORT_CSV = "unauthorized_access_report.csv"

print("[*] Starting Log Triage and Incident Extraction...")

incidents = []

with open(LOG_FILE, "r") as f:
    for line in f:
        # Detect Linux SSH Brute-Force Attempts
        if "Failed password" in line:
            parts = line.strip().split()
            timestamp = f"{parts[0]} {parts[1]} {parts[2]}"
            user = parts[8] if "invalid user" not in line else parts[10]
            ip = parts[-4]
            incidents.append({
                "Timestamp": timestamp,
                "Platform": "Linux / SSH",
                "Target_Account": user,
                "Source_IP": ip,
                "Event_Type": "Failed Authentication (Brute-Force)"
            })
        
        # Detect Windows / RACF Unauthorized Logons (Event 4625)
        elif "EventID=4625" in line:
            timestamp = line[:15]
            user_match = re.search(r"User=(\w+)", line)
            ip_match = re.search(r"IP=([\d\.]+)", line)
            user = user_match.group(1) if user_match else "UNKNOWN"
            ip = ip_match.group(1) if ip_match else "UNKNOWN"
            incidents.append({
                "Timestamp": timestamp,
                "Platform": "Windows / Security Audit",
                "Target_Account": user,
                "Source_IP": ip,
                "Event_Type": "Failed Logon (EventID 4625)"
            })

# Export to CSV report
if incidents:
    keys = incidents[0].keys()
    with open(REPORT_CSV, "w", newline="") as output_file:
        dict_writer = csv.DictWriter(output_file, fieldnames=keys)
        dict_writer.writeheader()
        dict_writer.writerows(incidents)
    print(f"[+] Triage complete! Found {len(incidents)} unauthorized attempts.")
    print(f"[+] Output report saved to: {REPORT_CSV}")
else:
    print("[-] No unauthorized events detected.")
