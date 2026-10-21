Python Log Monitor
A Python-based security log monitoring and analytics tool.

Features
Error detection
Warning detection
Critical event detection
Authentication failure detection
Brute-force attack detection
Top offending IP ranking
Threat scoring
Health scoring
Incident recommendations
JSON export
CSV export
Example Output
Threat Level: HIGH

Recommended Actions:

Investigate repeated authentication failures
Review critical system events immediately
Escalate incident to security team
Technologies
Python
argparse
pathlib
regex
datetime
JSON
CSV
Usage
python log_monitor.py --file test_log.log --output report.json --csv incidents.csv --verbose
