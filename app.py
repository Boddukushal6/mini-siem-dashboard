
from flask import Flask, render_template, request
import sqlite3
from collections import Counter
from datetime import datetime

app = Flask(__name__)

def get_dashboard_data():

    success_count = 0
    failed_count = 0
    failed_ips = Counter()

    with open("logs/sample_auth.log", "r") as file:
        for line in file:
            if "LOGIN_SUCCESS" in line:
                success_count += 1
            elif "LOGIN_FAILED" in line:
                failed_count += 1
                for item in line.split():
                    if item.startswith("ip="):
                        ip = item.split("=")[1]
                        failed_ips[ip] += 1

    search_ip = request.args.get("ip", "").strip()
    selected_severity = request.args.get("severity", "").strip()

    connection = sqlite3.connect("siem.db")
    connection.row_factory = sqlite3.Row

    query = "SELECT * FROM alerts WHERE 1=1"
    params = []

    if search_ip:
        query += " AND source_ip LIKE ?"
        params.append(f"%{search_ip}%")

    if selected_severity:
        query += " AND severity = ?"
        params.append(selected_severity)

    query += " ORDER BY id DESC"

    alerts = connection.execute(query, params).fetchall()

    severity_data = connection.execute("""
        SELECT COALESCE(severity, 'Medium'), COUNT(*)
        FROM alerts
        GROUP BY COALESCE(severity, 'Medium')
    """).fetchall()

    total_alerts = connection.execute(
        "SELECT COUNT(*) FROM alerts"
    ).fetchone()[0]

    severity_counts = {
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for row in severity_data:
        severity_counts[row[0]] = row[1]

    connection.close()

    return {
        "success_count": success_count,
        "failed_count": failed_count,
        "total_alerts": total_alerts,
        "suspicious_ips": sum(
            1 for count in failed_ips.values() if count >= 5
        ),
        "alerts": alerts,
        "severity_labels": [row[0] for row in severity_data],
        "severity_counts": [row[1] for row in severity_data],
        "high_count": severity_counts["High"],
        "medium_count": severity_counts["Medium"],
        "low_count": severity_counts["Low"],
        "search_ip": search_ip,
        "selected_severity": selected_severity,
        "last_updated": datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    }


@app.route("/")
def dashboard():
    data = get_dashboard_data()
    return render_template("index.html", **data)


if __name__ == "__main__":
    app.run(debug=True)
