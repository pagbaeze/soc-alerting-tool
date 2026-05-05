import csv
import uuid
from collections import defaultdict
from datetime import datetime

INPUT_FILE = "security_events.csv"
OUTPUT_FILE = "soc_alert_report.txt"

FAILED_LOGIN_THRESHOLD = 5
LOCKOUT_THRESHOLD = 10

RISKY_COUNTRIES = {"Russia", "China", "North Korea", "Iran"}
PRIVILEGED_ROLES = {"Admin", "Domain Admin", "Security Admin"}

AFTER_HOURS_START = 20
AFTER_HOURS_END = 6

failed_logins = defaultdict(int)
known_ips = defaultdict(set)
user_countries = defaultdict(set)
last_successful_login_country = {}

alerts = []

def get_severity(score):
    if score >= 80:
        return "High"
    elif score >= 50:
        return "Medium"
    else:
        return "Low"

def get_category(event_type, reasons):
    reason_text = " ".join(reasons).lower()

    if "mfa disabled" in reason_text:
        return "Identity Security Risk"
    elif "failed login" in reason_text or "lockout" in reason_text:
        return "Brute Force / Account Lockout"
    elif "impossible travel" in reason_text or "risky country" in reason_text:
        return "Suspicious Login"
    elif "privileged account" in reason_text:
        return "Privileged Account Activity"
    elif event_type == "password_change":
        return "Account Change"
    else:
        return "General Security Alert"

def get_mitre_mapping(event_type, reasons):
    mappings = []
    reason_text = " ".join(reasons).lower()

    if "failed login" in reason_text or "successful login after multiple failed attempts" in reason_text:
        mappings.append("T1110 - Brute Force")

    if "risky country" in reason_text or "impossible travel" in reason_text or "multiple login countries" in reason_text:
        mappings.append("T1078 - Valid Accounts")

    if "mfa disabled" in reason_text:
        mappings.append("T1556 - Modify Authentication Process")

    if "privileged account" in reason_text:
        mappings.append("T1078.002 - Domain Accounts")

    if event_type == "password_change":
        mappings.append("T1098 - Account Manipulation")

    if event_type == "account_locked":
        mappings.append("T1110 - Brute Force")

    return mappings

def extract_iocs(user, source_ip, country):
    iocs = []

    if user:
        iocs.append(f"User Account: {user}")

    if source_ip:
        iocs.append(f"Source IP: {source_ip}")

    if country:
        iocs.append(f"Country: {country}")

    return iocs

with open(INPUT_FILE, "r", encoding="utf-8-sig") as file:
    reader = csv.DictReader(file)

    for row in reader:
        timestamp = row["timestamp"]
        user = row["user"]
        role = row["role"]
        event_type = row["event_type"]
        source_ip = row["source_ip"]
        country = row["country"]

        risk_score = 0
        reasons = []

        if source_ip not in known_ips[user]:
            risk_score += 20
            reasons.append(f"New IP detected for user: {source_ip}")

        known_ips[user].add(source_ip)

        user_countries[user].add(country)

        if len(user_countries[user]) >= 3:
            risk_score += 35
            reasons.append("Multiple login countries detected for user")

        if role in PRIVILEGED_ROLES:
            risk_score += 30
            reasons.append(f"Privileged account activity: {role}")

        if country in RISKY_COUNTRIES:
            risk_score += 40
            reasons.append(f"Login activity from risky country: {country}")

        try:
            event_time = datetime.strptime(timestamp, "%Y-%m-%d %H:%M")
            hour = event_time.hour

            if hour >= AFTER_HOURS_START or hour < AFTER_HOURS_END:
                risk_score += 25
                reasons.append("Activity occurred after business hours")
        except ValueError:
            reasons.append("Timestamp format could not be checked")

        if event_type == "failed_login":
            failed_logins[user] += 1

            if failed_logins[user] >= FAILED_LOGIN_THRESHOLD:
                risk_score += 50
                reasons.append(f"{failed_logins[user]} failed login attempts")

            if failed_logins[user] >= LOCKOUT_THRESHOLD:
                risk_score += 40
                reasons.append("Account lockout threshold reached")

        elif event_type == "successful_login":
            if failed_logins[user] >= FAILED_LOGIN_THRESHOLD:
                risk_score += 45
                reasons.append("Successful login after multiple failed attempts")

            if user in last_successful_login_country:
                previous_country = last_successful_login_country[user]

                if previous_country != country:
                    risk_score += 50
                    reasons.append(f"Impossible travel: {previous_country} to {country}")

            last_successful_login_country[user] = country
            failed_logins[user] = 0

        elif event_type == "mfa_disabled":
            risk_score += 70
            reasons.append("MFA disabled")

        elif event_type == "password_change":
            risk_score += 25
            reasons.append("Password changed")

        elif event_type == "account_locked":
            risk_score += 60
            reasons.append("Account locked")

        risk_score = min(risk_score, 100)

        if risk_score > 0:
            alerts.append({
                "alert_id": str(uuid.uuid4()),
                "severity": get_severity(risk_score),
                "category": get_category(event_type, reasons),
                "risk_score": risk_score,
                "timestamp": timestamp,
                "user": user,
                "role": role,
                "event_type": event_type,
                "source_ip": source_ip,
                "country": country,
                "reasons": reasons,
                "mitre_mapping": get_mitre_mapping(event_type, reasons),
                "iocs": extract_iocs(user, source_ip, country)
            })

with open(OUTPUT_FILE, "w", encoding="utf-8") as report:
    report.write("===== Mini SOC Alert Report =====\n")
    report.write(f"Generated: {datetime.now()}\n\n")

    if not alerts:
        report.write("No suspicious activity detected.\n")
    else:
        for alert in alerts:
            report.write(f"Alert ID: {alert['alert_id']}\n")
            report.write(f"Severity: {alert['severity']}\n")
            report.write(f"Category: {alert['category']}\n")
            report.write(f"Risk Score: {alert['risk_score']}/100\n")
            report.write(f"Time: {alert['timestamp']}\n")
            report.write(f"User: {alert['user']}\n")
            report.write(f"Role: {alert['role']}\n")
            report.write(f"Event Type: {alert['event_type']}\n")
            report.write(f"Source IP: {alert['source_ip']}\n")
            report.write(f"Country: {alert['country']}\n")

            report.write("Reasons:\n")
            for reason in alert["reasons"]:
                report.write(f"- {reason}\n")

            report.write("MITRE ATT&CK Mapping:\n")
            for technique in alert["mitre_mapping"]:
                report.write(f"- {technique}\n")

            report.write("Indicators of Compromise (IOCs):\n")
            for ioc in alert["iocs"]:
                report.write(f"- {ioc}\n")

            report.write("Analyst Response Actions:\n")

            if alert["severity"] == "High":
                report.write("- Contain affected account, system, or session if active.\n")
                report.write("- Investigate authentication logs, endpoint logs, and related security alerts.\n")
                report.write("- Identify scope of impact and search for related indicators across the environment.\n")
                report.write("- Validate whether the activity was legitimate or unauthorized.\n")
                report.write("- Initiate incident response procedures if malicious activity or compromise is confirmed.\n")

            elif alert["severity"] == "Medium":
                report.write("- Investigate activity and validate whether it is legitimate.\n")
                report.write("- Correlate with other logs or alerts for additional context.\n")
                report.write("- Monitor for repeated or escalating behavior.\n")

            else:
                report.write("- Log activity and continue monitoring for anomalies.\n")

            report.write("-" * 50 + "\n")

print(f"SOC alert report created: {OUTPUT_FILE}")