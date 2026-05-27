# ============================================
# SIMPLE CYBERSECURITY LOG ANALYZER
# ============================================
# Example Educational Script
# Purpose:
#   Analyze authentication logs for suspicious activity.
# ============================================

# Import Python libraries
import re
from collections import defaultdict


# ============================================
# FUNCTION 1: LOAD LOG FILE
# ============================================
# This function opens and reads the log file.
# It returns all lines from the file.
# ============================================

def load_log_file(filename):
    """
    Opens a log file and returns all lines.

    Parameters:
        filename (str): Name of the log file

    Returns:
        list: All lines from the log file
    """

    try:
        with open(filename, 'r') as file:
            return file.readlines()

    except FileNotFoundError:
        print(f"[ERROR] File '{filename}' not found.")
        return []


# ============================================
# FUNCTION 2: EXTRACT IP ADDRESS
# ============================================
# This function uses REGEX (regular expressions)
# to find an IP address inside a log line.
# ============================================

def extract_ip(log_line):
    """
    Extracts an IP address from a log entry.

    Parameters:
        log_line (str): One line from the log file

    Returns:
        str or None: IP address if found
    """

    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    match = re.search(ip_pattern, log_line)

    if match:
        return match.group()

    return None


# ============================================
# FUNCTION 3: DETECT FAILED LOGINS
# ============================================
# This function counts failed login attempts.
# If an IP has too many failed attempts,
# it creates an alert.
# ============================================

def detect_failed_logins(log_lines, threshold=3):
    """
    Detects repeated failed logins.

    Parameters:
        log_lines (list): All log entries
        threshold (int): Number of failures before alert

    Returns:
        dict: Suspicious IPs and failure counts
    """

    failed_attempts = defaultdict(int)

    for line in log_lines:

        # Look for the phrase "FAILED LOGIN"
        if "FAILED LOGIN" in line:

            ip = extract_ip(line)

            if ip:
                failed_attempts[ip] += 1

    suspicious_ips = {}

    for ip, count in failed_attempts.items():

        if count >= threshold:
            suspicious_ips[ip] = count

    return suspicious_ips


# ============================================
# FUNCTION 4: CHECK BLACKLISTED IPS
# ============================================
# Some IP addresses may already be known
# malicious addresses.
# This function compares logs against
# a blacklist.
# ============================================

def check_blacklisted_ips(log_lines, blacklist):
    """
    Checks if any IP addresses are blacklisted.

    Parameters:
        log_lines (list): Log entries
        blacklist (set): Known malicious IPs

    Returns:
        set: Detected blacklisted IPs
    """

    detected_ips = set()

    for line in log_lines:

        ip = extract_ip(line)

        if ip in blacklist:
            detected_ips.add(ip)

    return detected_ips


# ============================================
# FUNCTION 5: GENERATE SECURITY REPORT
# ============================================
# This function prints the results.
# SOC analysts often summarize findings
# like this for incident response.
# ============================================

def generate_report(failed_logins, blacklisted_hits):
    """
    Displays the final security report.
    """

    print("\n========== SECURITY REPORT ==========")

    # Failed login section
    print("\n[Repeated Failed Logins]")

    if failed_logins:

        for ip, count in failed_logins.items():
            print(f"ALERT: {ip} had {count} failed login attempts")

    else:
        print("No suspicious failed logins detected.")


    # Blacklisted IP section
    print("\n[Blacklisted IP Activity]")

    if blacklisted_hits:

        for ip in blacklisted_hits:
            print(f"WARNING: Blacklisted IP detected -> {ip}")

    else:
        print("No blacklisted IPs detected.")


# ============================================
# MAIN PROGRAM
# ============================================
# This is where the script starts running.
# ============================================

def main():

    # Example blacklist
    blacklist = {
        "185.220.101.1",
        "45.33.32.156",
        "192.168.1.200"
    }


    # Load the log file
    log_lines = load_log_file("sample_logs.txt")


    # Detect suspicious login attempts
    failed_logins = detect_failed_logins(log_lines)


    # Detect blacklisted IPs
    blacklisted_hits = check_blacklisted_ips(log_lines, blacklist)


    # Display report
    generate_report(failed_logins, blacklisted_hits)


# Run the script
if __name__ == "__main__":
    main()