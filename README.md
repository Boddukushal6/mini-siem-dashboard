# Mini SIEM Dashboard

## About
A beginner-friendly Security Information and Event Management (SIEM)
project built using Python, Flask and SQLite.

## Features
- Login success and failure analysis
- Brute-force attack detection
- SSH login failure detection
- Service failure detection
- Low, Medium and High severity alerts
- SQLite alert storage
- Web dashboard with charts
- IP search and severity filtering

## Technologies
- Python
- Flask
- SQLite
- HTML
- CSS
- JavaScript
- Chart.js
- Kali Linux

## How to Run

Activate virtual environment:

source venv/bin/activate

Install dependencies:

pip install -r requirements.txt

Initialize database:

python database.py

Analyze logs:

python analyzer.py logs/sample_auth.log logs/ssh.log logs/system.log

Start dashboard:

python app.py

Open in browser:

http://127.0.0.1:5000

## Disclaimer
This project is developed for educational purposes only.
