# ============================================
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