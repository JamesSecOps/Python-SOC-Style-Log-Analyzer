# Python-SOC-Style-Log-Analyzer
This project is a beginner-friendly cybersecurity script written in Python. It simulates the type of work a SOC (Security Operations Center) analyst might do when reviewing login activity.
The script:
- Reads a log file
- Looks for suspicious activity
- Detects repeated failed logins
- Detects suspicious IP addresses
- Generates alerts


# Example Log File
Create a file named:
sample_logs.txt
Paste this into it:
2026-05-26 10:15:22 SUCCESSFUL LOGIN user=admin ip=192.168.1.5
2026-05-26 10:17:11 FAILED LOGIN user=admin ip=45.33.32.156
2026-05-26 10:17:45 FAILED LOGIN user=admin ip=45.33.32.156
2026-05-26 10:18:02 FAILED LOGIN user=admin ip=45.33.32.156
2026-05-26 10:19:30 FAILED LOGIN user=root ip=185.220.101.1
2026-05-26 10:20:01 SUCCESSFUL LOGIN user=james ip=192.168.1.50


# Expected Output
### ========== SECURITY REPORT ==========

[Repeated Failed Logins]
ALERT: 45.33.32.156 had 3 failed login attempts

[Blacklisted IP Activity]
WARNING: Blacklisted IP detected -> 45.33.32.156
WARNING: Blacklisted IP detected -> 185.220.101.1

# Important Cybersecurity Concepts Used

### ===Log Analysis===
SOC analysts constantly review logs to identify threats.
Examples:
- Failed logins
- Malware alerts
- Suspicious connections
- Unauthorized access attempts

### ===Regular Expressions (Regex)===
Regex is used heavily in cybersecurity.
This script uses regex to locate IP addresses: 
r'\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b'
This pattern searches for:
- Numbers
- Dots
- Standard IPv4 format

### ===Threat Detection===
Repeated failed logins may indicate:
- Brute-force attacks
- Password spraying
- Unauthorized access attempts

### ===Blacklisting===
Organizations often maintain lists of:
- Known malicious IPs
- Botnets
- TOR exit nodes
- Malware servers

# How To Run The Script

Step 1
Install Python.
You can get it from:
python.org

Step 2
Save the script as:
log_analyzer.py

Step 3
Save the example logs as:
sample_logs.txt

Step 4
Run the script:
python log_analyzer.py
