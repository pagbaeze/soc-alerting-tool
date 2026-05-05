# SOC Alerting Tool (Python)

This project simulates a Security Operations Center (SOC) alerting system.

## Features
- Detects brute force login attempts
- Identifies impossible travel scenarios
- Flags suspicious login activity
- Risk-based scoring and alert severity classification
- MITRE ATT&CK mapping
- IOC (Indicators of Compromise) extraction

## Sample Output
- High-risk alerts for suspicious logins
- Structured report with recommended analyst actions

## Technologies Used
- Python
- CSV log analysis

## Purpose
Built to demonstrate hands-on cybersecurity skills for SOC Analyst roles.

## Files
- mini_soc_alert.py – Main detection script
- security_events.csv – Sample log data
- run_soc.bat – Windows launcher
- sample_output/soc_alert_report.txt – Example output

## How to Run
### Prerequisites
- Python 3.x installed  
- Windows OS (for .bat launcher)  
- No external libraries required  
---
### Option 1: Run with Batch File (Windows)
1. Download or clone the repository  
2. Open the project folder  
3. Double click: run_soc.bat
   
This will:
- Execute the script  
- Generate soc_alert_report.txt  
- Automatically open the report  

---

### Option 2: Run via Command Line

1. Open PowerShell  
2. Navigate to the project folder:
   cd path\to\soc-alerting-tool  

3. Run the script:
   py mini_soc_alert.py  

4. Open the generated file:
   soc_alert_report.txt  

---

### Input Data

The script uses:
security_events.csv  

You can modify this file to simulate:
- Failed logins  
- Suspicious locations  
- Privileged account activity  

---

### Output

The script generates:
soc_alert_report.txt  

This report includes:
- Alert severity (Low / Medium / High)  
- Risk score  
- Detection reasons  
- MITRE ATT&CK mapping  
- Indicators of Compromise (IOCs)  
- Analyst response actions  



