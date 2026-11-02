import sqlite3

connection = sqlite3.connect("siem.db")

cursor = connection.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT,
    source_ip TEXT,
    failed_attempts INTEGER
)
""")

connection.commit()
connection.close()

print("SIEM database created successfully!")
