import argparse
import json
import re
import csv
from pathlib import Path
from datetime import datetime

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"


def parse_timestamp(ts):
    return datetime.strptime(ts, "%b %d %H:%M:%S")


def generate_html_report(report, output_file):

    error_total = len(report['errors'])
    warning_total = len(report['warnings'])
    critical_total = len(report['criticals'])
    auth_total = len(report['auth_failures'])

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Python Log Monitor</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

        <style>
            body {{
                font-family: sans-serif;
                background-color: #f4f4f4;
                margin: 20px;
            }}

            .container {{
                max-width: 1000px;
                margin: auto;
            }}

            .card {{
                background-color: white;
                padding: 20px;
                margin-bottom: 20px;
                border-radius: 10px;
                box-shadow: 0px 2px 5px rgba(0, 0, 0, 0.1);
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
            }}

            th, td {{
                border: 1px solid #ddd;
                padding: 10px;
                text-align: left;
            }}

            th {{
                background-color: #333;
                color: white;
            }}
        </style>
    </head>

    <body>
    <div class="container">

        <div class="card">
            <h1>Python Log Monitor</h1>

            <p><strong>Total Lines:</strong> {report['total_lines']}</p>
            <p><strong>Errors:</strong> {len(report['errors'])}</p>
            <p><strong>Warnings:</strong> {len(report['warnings'])}</p>
            <p><strong>Critical Events:</strong> {len(report['criticals'])}</p>
            <p><strong>Bruteforce Alerts:</strong> {len(report['bruteforce_alerts'])}</p></div>

            <div class="card">
                <h2>Security Assessment</h2>

                <p>
                    <strong>Health Score:</strong>
                    {report["statistics"]["health_score"]}/100
                </p>

                <p>
                    <strong>Threat Score:</strong>
                    {report["risk_assessment"]["risk_score"]}
                </p>

                <p>
                    <strong>Threat Level:</strong>
                    {report["risk_assessment"]["risk_level"]}
                </p>
            </div>

            <div class="card">
                <h2>Top IP Addresses:</h2>

                <table>
                    <tr>
                        <th>IP Address</th>
                        <th>Events</th>
                    </tr>

                    {''.join(
        f'<tr><td>{ip["ip"]}</td><td>{ip["count"]}</td></tr>'
        for ip in report["top_ips"]
    )}
                </table>
            </div>
            

            <div class="card">
                <h2>Recommended Actions</h2>

                <ul>
                    {''.join(
        f'<li>{item}</li>'
        for item in report["recommendations"]
    )}
                </ul>
            </div>

    </div>
    
    </body>
    </html>
    """

    with open(output_file, "w") as f:
        f.write(html)

    print(f"HTML report saved to {output_file}")


def main():
    parser = argparse.ArgumentParser(description='Log monitor tool')

    parser.add_argument("--file", required=True, help="Path to log file")
    parser.add_argument("--output", required=True, help="Path to JSON report")
    parser.add_argument("--limit", type=int, default=None, help="Only scan last N lines")
    parser.add_argument("--verbose", action="store_true", help="Print matches as found")
    parser.add_argument(
        "--csv",
        help="Optional CSV incident report output",
    )

    parser.add_argument(
        "--html",
        help="Optional HTML incident report output",
    )

    args = parser.parse_args()
    log_path = Path(args.file)

    if not log_path.exists():
        print(f"ERROR: Log file {log_path} does not exist")
        return

    if not log_path.is_file():
        print(f"ERROR: Log file {log_path} is not a file")
        return

    print("Arguments loaded:", args)

    try:
        with log_path.open("r") as f:
            lines = f.readlines()
    except PermissionError:
        print(f"ERROR: No permission to read log file: {log_path}")
        return

    if args.limit is not None:
        lines = lines[-args.limit:]

    error_pattern = re.compile(r"ERROR")
    warning_pattern = re.compile(r"WARNING")
    critical_pattern = re.compile(r"CRITICAL")
    ip_pattern = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    auth_fail_pattern = re.compile(
        r"(authentication\s+failure|authentication\s+failed|failed\s+login|auth\s+failure|failed\s+password|invalid\s+user)",
        re.IGNORECASE
        )
    timestamp_pattern = re.compile(r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")

    report = {
        "total_lines": len(lines),
        "errors": [],
        "warnings": [],
        "criticals": [],
        "ip_addresses": [],
        "auth_failures": [],
        "ip_frequency": {},
        "bruteforce_alerts": [],
        "statistics": {},
        "top_ips": [],
        "risk_assessment": {},
        "recommendations": []
    }
    incidents = []

    ip_counts = {}
    auth_events = {}

    for line in lines:

        ip = None

        ts_match = timestamp_pattern.search(line)
        timestamp = parse_timestamp(ts_match.group()) if ts_match else None

        if error_pattern.search(line):
            report["errors"].append(line.strip())

            incidents.append({
                "type": "ERROR",
                "timestamp": timestamp.strftime("%H:%M:%S") if timestamp else "",
                "details": line.strip()
            })
            if args.verbose:
                print(f"{RED}{BOLD}ERROR:{RESET} {line.strip()}")

        if warning_pattern.search(line):
            report["warnings"].append(line.strip())

            incidents.append({
                "type": "WARNING",
                "timestamp": timestamp.strftime("%H:%M:%S") if timestamp else "",
                "details": line.strip()
            })

            if args.verbose:
                print(f"{YELLOW}{BOLD}WARNING:{RESET} {line.strip()}")

        if critical_pattern.search(line):
            report["criticals"].append(line.strip())

            incidents.append({
                "type": "CRITICAL",
                "timestamp": timestamp.strftime("%H:%M:%S") if timestamp else "",
                "details": line.strip()
            })
            if args.verbose:
                print(f"{RED}{BOLD}CRITICAL:{RESET} {line.strip()}")

        ip_match = ip_pattern.search(line)
        if ip_match:
            ip = ip_match.group()
            report["ip_addresses"].append(line.strip())
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

            if args.verbose:
                print(f"{BLUE}IP:{RESET} {line.strip()}")

        if auth_fail_pattern.search(line):
            report["auth_failures"].append(line.strip())

            incidents.append({
                "type": "AUTH_FAILURE",
                "timestamp": timestamp.strftime("%H:%M:%S") if timestamp else "",
                "details": line.strip()
            })

            if ip_match and timestamp:
                auth_events.setdefault(ip, []).append(timestamp)

            if args.verbose:
                print(f"{RED}AUTH FAILURE:{RESET} {line.strip()}")

    report["ip_frequency"] = ip_counts

    top_ips = sorted(
        ip_counts.items(),
        key=lambda item: item[1],
        reverse=True
    )

    report["top_ips"] = [
        {
            "ip": ip,
            "count": count
        }
        for ip, count in top_ips[:5]
    ]

    for ip, times in auth_events.items():
        times.sort()
        for i in range(len(times)):
            window = [t for t in times if 0 <= (t - times[i]).total_seconds() <= 60]
            if len(window) >= 5:
                report["bruteforce_alerts"].append({
                    "ip": ip,
                    "failures": len(window),
                    "window_start": window[0].strftime("%H:%M:%S"),
                    "window_end": window[-1].strftime("%H:%M:%S"),
                })
                break

    error_count = len(report["errors"])
    warning_count = len(report["warnings"])
    critical_count = len(report["criticals"])

    if report["total_lines"] > 0:

        error_pct = round((error_count / report["total_lines"]) * 100, 2)
        warning_pct = round((warning_count / report["total_lines"]) * 100, 2)
        critical_pct = round((critical_count / report["total_lines"]) * 100, 2)

    else:

        error_pct = 0
        warning_pct = 0
        critical_pct = 0
    health_score = max(
        0,
        100 - (critical_count * 20) - (error_count * 10),
    )

    report["statistics"] = {

        "error_percentage": error_pct,
        "warning_percentage": warning_pct,
        "critical_percentage": critical_pct,
        "health_score": health_score,

    }

    risk_score = 0

    risk_score += error_count * 5
    risk_score += critical_count * 20
    risk_score += len(report["auth_failures"]) * 2
    risk_score += len(report["bruteforce_alerts"]) * 25

    risk_score = min(risk_score, 100)
    if risk_score >= 80:
        risk_level = "CRITICAL"

    elif risk_score >= 50:
        risk_level = "HIGH"

    elif risk_score >= 20:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    report["risk_assessment"] = {
        "risk_score": risk_score,
        "risk_level": risk_level,
    }

    recommendations = []

    if report["bruteforce_alerts"]:
        recommendations.append(
            "Investigate repeated authentication failures"
        )

    if critical_count > 0:
        recommendations.append(
            "Review critical system events immediately"
        )

    if error_count > 5:
        recommendations.append(
            "High error volume detected. Check application logs"
        )
    elif error_count > 0:
        recommendations.append(
            "Review detected application errors"
        )

    if report["top_ips"]:
        recommendations.append(
            f"Review activity from IP: "
            f"{report['top_ips'][0]['ip']}"
        )

    if risk_level in ["HIGH", "CRITICAL"]:
        recommendations.append(
            "Escalate incident to security team"
        )
    report["recommendations"] = recommendations

    print("\n" + BOLD + BLUE + "===== SUMMARY =====" + RESET)
    print(f"{RED}Errors:{RESET} {error_count}")
    print(f"{YELLOW}Warnings:{RESET} {warning_count}")
    print(f"{RED}Criticals:{RESET} {critical_count}")
    print(f"{RED}Auth Failures:{RESET} {len(report['auth_failures'])}")
    print(f"{BLUE}Unique IPs:{RESET} {len(report['ip_frequency'])}")
    if report["top_ips"]:
        print("\nTop IPs:")

        for rank, ip_data in enumerate(report["top_ips"], start=1):
            print(
                f"{BLUE}{rank}.{RESET} "
                f"{ip_data['ip']} "
                f"({ip_data['count']} events)"
            )

    print(f"{RED}Bruteforce Alerts:{RESET} {len(report['bruteforce_alerts'])}")
    print(f"{GREEN}Health Score:{RESET} {health_score}/100")
    print(f"{RED}Threat Score:{RESET} {risk_score}")
    print(f"{RED}Threat Level:{RESET} {risk_level}")
    print("\nRecommended Actions:")

    for recommendation in recommendations:
        print(f"- {recommendation}")

    print(BOLD + BLUE + "===================" + RESET)

    output_path = Path(args.output)

    try:

        with output_path.open("w") as f:
            json.dump(report, f, indent=4)

        print(f"Report saved to {output_path}")

        if args.csv:
            try:
                with open(args.csv, "w", newline="") as csvfile:
                    writer = csv.DictWriter(csvfile,
                                            fieldnames=["type", "timestamp", "details"]
                                            )
                    writer.writeheader()

                    for incident in incidents:
                        writer.writerow(incident)
                print(f"CSV report saved to {args.csv}")

            except Exception as e:
                print(f"ERROR writing CSV report {e}")
    except PermissionError:
        print(f"ERROR: No permission to write to output file: {output_path}")
    except Exception as e:
        print(f"ERROR: Could not write report: {e}")

    if args.html:
        try:
            generate_html_report(
                report,
                args.html
            )
        except Exception as e:
            print(f"ERROR writing HTML report: {e}")


if __name__ == "__main__":
    main()

