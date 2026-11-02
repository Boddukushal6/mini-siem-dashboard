
import sqlite3
import sys
from collections import Counter
from datetime import datetime, timedelta

# Accept multiple log files
log_files = sys.argv[1:] or [
    "logs/sample_auth.log",
    "logs/ssh.log",
    "logs/system.log"
]

login_failures = Counter()
ssh_failures = Counter()
service_failures = Counter()

success_count = 0
failed_count = 0

# Read all selected logs
for log_file in log_files:
    print("\nReading:", log_file)

    with open(log_file, "r") as file:
        for line in file:

            if "LOGIN_SUCCESS" in line:
                success_count += 1

            elif "LOGIN_FAILED" in line:
                failed_count += 1

                for item in line.split():
                    if item.startswith("ip="):
                        login_failures[item.split("=", 1)[1]] += 1

            elif "SSH_LOGIN_FAILED" in line:
                failed_count += 1

                for item in line.split():
                    if item.startswith("ip="):
                        ssh_failures[item.split("=", 1)[1]] += 1

            elif "SERVICE_FAILED" in line:
                for item in line.split():
                    if item.startswith("service="):
                        service_failures[item.split("=", 1)[1]] += 1

print("\n=== MINI SIEM ANALYZER ===")
print("Successful Logins:", success_count)
print("Failed Logins:", failed_count)

# Build detected events
events = []

for ip, count in login_failures.items():
    if count >= 3:
        severity = (
            "High" if count >= 8
            else "Medium" if count >= 5
            else "Low"
        )
        events.append((
            "Possible Brute-Force Attack",
            ip,
            count,
            severity
        ))

for ip, count in ssh_failures.items():
    if count >= 3:
        severity = (
            "High" if count >= 8
            else "Medium" if count >= 5
            else "Low"
        )
        events.append((
            "Possible SSH Brute-Force Attack",
            ip,
            count,
            severity
        ))

for service, count in service_failures.items():
    if count >= 3:
        events.append((
            "Repeated Service Failures: " + service,
            "LOCAL-SYSTEM",
            count,
            "Medium"
        ))

# Save events in SQLite
connection = sqlite3.connect("siem.db")
cursor = connection.cursor()

now = datetime.now()
detected_at = now.strftime("%Y-%m-%d %H:%M:%S")
cutoff = (now - timedelta(minutes=5)).strftime(
    "%Y-%m-%d %H:%M:%S"
)

print("\n=== DETECTED SECURITY EVENTS ===")

for alert_type, source_ip, count, severity in events:

    cursor.execute("""
        SELECT id, severity
        FROM alerts
        WHERE alert_type = ?
        AND source_ip = ?
        AND detected_at >= ?
        ORDER BY id DESC
        LIMIT 1
    """, (alert_type, source_ip, cutoff))

    existing = cursor.fetchone()

    if existing:
        alert_id, old_severity = existing

        if old_severity != severity:
            cursor.execute("""
                UPDATE alerts
                SET severity = ?,
                    failed_attempts = ?,
                    detected_at = ?
                WHERE id = ?
            """, (severity, count, detected_at, alert_id))

            print("Updated:", alert_type, source_ip, severity)
        else:
            print("Duplicate skipped:", alert_type, source_ip)

    else:
        cursor.execute("""
            INSERT INTO alerts
            (alert_type, source_ip, failed_attempts,
             severity, detected_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            alert_type,
            source_ip,
            count,
            severity,
            detected_at
        ))

        print("ALERT:", alert_type)
        print("Source:", source_ip)
        print("Attempts:", count)
        print("Severity:", severity)
        print("-------------------------")

connection.commit()
connection.close()

print("\nAnalysis completed!")
