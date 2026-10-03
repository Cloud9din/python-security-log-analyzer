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
ACCESS_DENIED_THRESHOLD = 3


# --------------------------------------------------
# READ LOG FILE
# --------------------------------------------------

def read_log_file(file_path):
    """Read the simulated security log file."""

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return file.readlines()

    except FileNotFoundError:
        print(f"\n[ERROR] Log file not found: {file_path}")
        return []

    except OSError as error:
        print(f"\n[ERROR] Unable to read log file: {error}")
        return []


# --------------------------------------------------
# PARSE ONE LOG LINE
# --------------------------------------------------

def parse_log_line(line):
    """
    Convert one log line into structured data.

    Example:
    2026-10-03 08:14:02 WARNING LOGIN_FAILED
    user=admin ip=EXTERNAL-A
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
# GET NETWORK SOURCE
# --------------------------------------------------

def get_network_source(log):
    """
    Return the masked network source from a log entry.

    The sample log currently uses the key 'ip',
    but all values are masked labels such as
    EXTERNAL-A or INTERNAL-B.
    """

    return (
        log["data"].get("source")
        or log["data"].get("ip")
        or "Unknown"
    )


# --------------------------------------------------
# ANALYSE LOGS
# --------------------------------------------------

def analyse_logs(lines):

    severity_counter = Counter()
    event_counter = Counter()
    source_counter = Counter()

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
        network_source = get_network_source(log)


        # Count severity types

        severity_counter[severity] += 1


        # Count event types

        event_counter[event] += 1


        # Count network source activity

        if network_source != "Unknown":
            source_counter[network_source] += 1


        # Failed login activity

        if (
            event == "LOGIN_FAILED"
            and network_source != "Unknown"
        ):

            failed_login_counter[network_source] += 1


        # Access denied activity

        if (
            event == "ACCESS_DENIED"
            and network_source != "Unknown"
        ):

            access_denied_counter[network_source] += 1


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
        "sources": source_counter,
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

    for network_source, count in results["failed_logins"].items():

        if count >= FAILED_LOGIN_THRESHOLD:

            threats.append({
                "severity": "HIGH",
                "type": "Repeated Failed Logins",
                "source": network_source,
                "details": (
                    f"{count} failed login attempts detected"
                )
            })


    # Repeated access denied activity

    for network_source, count in results["access_denied"].items():

        if count >= ACCESS_DENIED_THRESHOLD:

            threats.append({
                "severity": "MEDIUM",
                "type": "Repeated Access Denied",
                "source": network_source,
                "details": (
                    f"{count} access denied events detected"
                )
            })


    # Malware alerts

    for alert in results["malware"]:

        threats.append({
            "severity": "CRITICAL",
            "type": "Malware Alert",
            "source": get_network_source(alert),
            "details": (
                f"Suspicious file: "
                f"{alert['data'].get('file', 'Unknown')}"
            )
        })


    # Port scan alerts

    for scan in results["port_scans"]:

        threats.append({
            "severity": "HIGH",
            "type": "Port Scan",
            "source": get_network_source(scan),
            "details": (
                f"Ports scanned: "
                f"{scan['data'].get('ports', 'Unknown')}"
            )
        })


    return threats


# --------------------------------------------------
# DISPLAY SECURITY SUMMARY
# --------------------------------------------------

def display_summary(results):

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


# --------------------------------------------------
# DISPLAY MOST ACTIVE SOURCES
# --------------------------------------------------

def display_active_sources(results):

    print("\nMOST ACTIVE NETWORK SOURCES")
    print("-" * 60)


    if not results["sources"]:

        print("No network source activity found.")
        return


    for network_source, count in results["sources"].most_common(5):

        print(
            f"{network_source:<18} "
            f"{count} events"
        )


# --------------------------------------------------
# DISPLAY SECURITY ALERTS
# --------------------------------------------------

def display_alerts(threats):

    print("\nSECURITY ALERTS")
    print("-" * 60)


    if not threats:

        print("No suspicious activity detected.")
        return


    for threat in threats:

        print(
            f"[{threat['severity']}] "
            f"{threat['type']}"
        )

        print(
            f"Network Source: "
            f"{threat['source']}"
        )

        print(
            f"Details: "
            f"{threat['details']}"
        )

        print("-" * 60)


# --------------------------------------------------
# DISPLAY RESULTS
# --------------------------------------------------

def display_results(results, threats):

    display_summary(results)

    display_active_sources(results)

    display_alerts(threats)


# --------------------------------------------------
# CREATE SECURITY REPORT
# --------------------------------------------------

def create_report(results, threats):

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    try:

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


            # Security summary

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


            # Active sources

            report.write(
                "\nMOST ACTIVE NETWORK SOURCES\n"
            )

            report.write(
                "-" * 60 + "\n"
            )


            if not results["sources"]:

                report.write(
                    "No network source activity found.\n"
                )

            else:

                for (
                    network_source,
                    count
                ) in results["sources"].most_common(5):

                    report.write(
                        f"{network_source}: "
                        f"{count} events\n"
                    )


            # Security alerts

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
                        f"Network Source: "
                        f"{threat['source']}\n"
                    )

                    report.write(
                        f"Details: "
                        f"{threat['details']}\n"
                    )


        print(
            f"\nReport created:"
            f"\n{REPORT_FILE}"
        )


    except OSError as error:

        print(
            f"\n[ERROR] "
            f"Unable to create report: {error}"
        )


# --------------------------------------------------
# MAIN PROGRAM
# --------------------------------------------------

def main():

    print(
        "\nLoading simulated security logs..."
    )


    lines = read_log_file(
        LOG_FILE
    )


    if not lines:

        print(
            "\nNo log entries available for analysis."
        )

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
