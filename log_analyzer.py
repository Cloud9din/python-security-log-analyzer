from collections import Counter
from pathlib import Path


# --------------------------------------------------
# FILE LOCATIONS
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

LOG_FILE = BASE_DIR / "sample_logs" / "security.log"
REPORT_DIR = BASE_DIR / "reports"
REPORT_FILE = REPORT_DIR / "security_report.txt"


# --------------------------------------------------
# SETTINGS
# --------------------------------------------------

FAILED_LOGIN_THRESHOLD = 3


# --------------------------------------------------
# READ LOG FILE
# --------------------------------------------------

def read_log_file(file_path):
    """Read the security log file."""

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return file.readlines()

    except FileNotFoundError:
        print(f"\n[ERROR] Log file not found: {file_path}")
        return []


# --------------------------------------------------
# PARSE ONE LOG LINE
# --------------------------------------------------

def parse_log_line(line):
    """
    Convert one log line into structured data.

    Example:
    2026-10-03 08:14:02 WARNING LOGIN_FAILED
    user=admin ip=203.0.113.25
    """

    line = line.strip()

    if not line:
        return None

    parts = line.split()

    if len(parts) < 4:
        return None

    date = parts[0]
    time = parts[1]
    severity = parts[2]
    event = parts[3]

    extra_data = {}

    for item in parts[4:]:

        if "=" in item:
            key, value = item.split("=", 1)
            extra_data[key] = value

    return {
        "timestamp": f"{date} {time}",
        "severity": severity,
        "event": event,
        "data": extra_data
    }


# --------------------------------------------------
# ANALYSE LOGS
# --------------------------------------------------

def analyse_logs(lines):

    severity_counter = Counter()
    event_counter = Counter()
    ip_counter = Counter()

    failed_login_counter = Counter()
    access_denied_counter = Counter()

    malware_alerts = []
    port_scans = []

    parsed_logs = []


    for line in lines:

        log = parse_log_line(line)

        if not log:
            continue

        parsed_logs.append(log)

        severity = log["severity"]
        event = log["event"]

        ip_address = log["data"].get("ip")


        # Count severity types

        severity_counter[severity] += 1


        # Count event types

        event_counter[event] += 1


        # Count IP activity

        if ip_address:
            ip_counter[ip_address] += 1


        # Failed logins

        if event == "LOGIN_FAILED" and ip_address:

            failed_login_counter[ip_address] += 1


        # Access denied events

        if event == "ACCESS_DENIED" and ip_address:

            access_denied_counter[ip_address] += 1


        # Malware alerts

        if event == "MALWARE_ALERT":

            malware_alerts.append(log)


        # Port scan alerts

        if event == "PORT_SCAN":

            port_scans.append(log)


    return {
        "logs": parsed_logs,
        "severity": severity_counter,
        "events": event_counter,
        "ips": ip_counter,
        "failed_logins": failed_login_counter,
        "access_denied": access_denied_counter,
        "malware": malware_alerts,
        "port_scans": port_scans
    }


# --------------------------------------------------
# DETECT SECURITY THREATS
# --------------------------------------------------

def detect_threats(results):

    threats = []


    # Repeated failed logins

    for ip_address, count in results["failed_logins"].items():

        if count >= FAILED_LOGIN_THRESHOLD:

            threats.append({
                "severity": "HIGH",
                "type": "Repeated Failed Logins",
                "ip": ip_address,
                "details": f"{count} failed login attempts detected"
            })


    # Repeated access denied

    for ip_address, count in results["access_denied"].items():

        if count >= 3:

            threats.append({
                "severity": "MEDIUM",
                "type": "Repeated Access Denied",
                "ip": ip_address,
                "details": f"{count} access denied events detected"
            })


    # Malware

    for alert in results["malware"]:

        threats.append({
            "severity": "CRITICAL",
            "type": "Malware Alert",
            "ip": alert["data"].get("ip", "Unknown"),
            "details": (
                f"Suspicious file: "
                f"{alert['data'].get('file', 'Unknown')}"
            )
        })


    # Port scans

    for scan in results["port_scans"]:

        threats.append({
            "severity": "HIGH",
            "type": "Port Scan",
            "ip": scan["data"].get("ip", "Unknown"),
            "details": (
                f"Ports scanned: "
                f"{scan['data'].get('ports', 'Unknown')}"
            )
        })


    return threats


# --------------------------------------------------
# DISPLAY RESULTS
# --------------------------------------------------

def display_results(results, threats):

    print("\n" + "=" * 60)

    print("        PYTHON SECURITY LOG ANALYZER")

    print("=" * 60)


    print("\nSECURITY SUMMARY")
    print("-" * 60)

    print(
        f"Total log entries: "
        f"{len(results['logs'])}"
    )

    print(
        f"Successful logins: "
        f"{results['events'].get('LOGIN_SUCCESS', 0)}"
    )

    print(
        f"Failed logins: "
        f"{results['events'].get('LOGIN_FAILED', 0)}"
    )

    print(
        f"Access denied: "
        f"{results['events'].get('ACCESS_DENIED', 0)}"
    )

    print(
        f"Warnings: "
        f"{results['severity'].get('WARNING', 0)}"
    )

    print(
        f"Errors: "
        f"{results['severity'].get('ERROR', 0)}"
    )


    # Most active IPs

    print("\nMOST ACTIVE IP ADDRESSES")
    print("-" * 60)

    for ip_address, count in results["ips"].most_common(5):

        print(
            f"{ip_address:<18} "
            f"{count} events"
        )


    # Threats

    print("\nSECURITY ALERTS")
    print("-" * 60)


    if not threats:

        print("No suspicious activity detected.")

    else:

        for threat in threats:

            print(
                f"[{threat['severity']}] "
                f"{threat['type']}"
            )

            print(
                f"IP: {threat['ip']}"
            )

            print(
                f"Details: "
                f"{threat['details']}"
            )

            print("-" * 60)


# --------------------------------------------------
# CREATE REPORT
# --------------------------------------------------

def create_report(results, threats):

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    with open(
        REPORT_FILE,
        "w",
        encoding="utf-8"
    ) as report:


        report.write(
            "PYTHON SECURITY LOG ANALYZER REPORT\n"
        )

        report.write(
            "=" * 60 + "\n\n"
        )


        report.write(
            "SECURITY SUMMARY\n"
        )

        report.write(
            "-" * 60 + "\n"
        )


        report.write(
            f"Total log entries: "
            f"{len(results['logs'])}\n"
        )

        report.write(
            f"Successful logins: "
            f"{results['events'].get('LOGIN_SUCCESS', 0)}\n"
        )

        report.write(
            f"Failed logins: "
            f"{results['events'].get('LOGIN_FAILED', 0)}\n"
        )

        report.write(
            f"Access denied: "
            f"{results['events'].get('ACCESS_DENIED', 0)}\n"
        )

        report.write(
            f"Warnings: "
            f"{results['severity'].get('WARNING', 0)}\n"
        )

        report.write(
            f"Errors: "
            f"{results['severity'].get('ERROR', 0)}\n"
        )


        report.write(
            "\nMOST ACTIVE IP ADDRESSES\n"
        )

        report.write(
            "-" * 60 + "\n"
        )


        for ip_address, count in results["ips"].most_common(5):

            report.write(
                f"{ip_address}: "
                f"{count} events\n"
            )


        report.write(
            "\nSECURITY ALERTS\n"
        )

        report.write(
            "-" * 60 + "\n"
        )


        if not threats:

            report.write(
                "No suspicious activity detected.\n"
            )

        else:

            for threat in threats:

                report.write(
                    f"\nSeverity: "
                    f"{threat['severity']}\n"
                )

                report.write(
                    f"Alert: "
                    f"{threat['type']}\n"
                )

                report.write(
                    f"IP Address: "
                    f"{threat['ip']}\n"
                )

                report.write(
                    f"Details: "
                    f"{threat['details']}\n"
                )


    print(
        f"\nReport created:"
        f"\n{REPORT_FILE}"
    )


# --------------------------------------------------
# MAIN PROGRAM
# --------------------------------------------------

def main():

    print(
        "\nLoading security logs..."
    )


    lines = read_log_file(
        LOG_FILE
    )


    if not lines:
        return


    results = analyse_logs(
        lines
    )


    threats = detect_threats(
        results
    )


    display_results(
        results,
        threats
    )


    create_report(
        results,
        threats
    )


# --------------------------------------------------
# START PROGRAM
# --------------------------------------------------

if __name__ == "__main__":
    main()
