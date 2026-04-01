#!/usr/bin/env python3
"""
Multi-Vendor Network Security Audit Tool
Version: 7.0 - Excel Reporting & Human-in-the-Loop
"""
import sys
import re
import os
import argparse
import pandas as pd
from datetime import datetime

# --- Color Codes ---
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

# --- Base Audit Engine ---
class AuditEngine:
    def __init__(self, file_path):
        self.file_path = file_path
        self.config_content = ""
        self.results_data = [] # For Excel/Pandas
        self.score = {"PASS": 0, "FAIL": 0, "WARN": 0}
        
        base = os.path.splitext(os.path.basename(file_path))[0]
        self.report_name_txt = f"{base}_audited.txt"
        self.report_name_xlsx = f"{base}_audited.xlsx"

    def load_config(self):
        if not os.path.exists(self.file_path):
            print(f"{Colors.RED}[ERROR]{Colors.RESET} File not found: {self.file_path}")
            return False
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                self.config_content = f.read()
            return True
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Failed to read file: {e}")
            return False

    def log(self, cis_id, status, message):
        self.score[status] += 1
        color = Colors.GREEN if status == "PASS" else Colors.RED if status == "FAIL" else Colors.YELLOW
        print(f"{color}[{status}]{Colors.RESET} {Colors.BOLD}ID {cis_id}:{Colors.RESET} {message}")
        
        # Store for Excel
        self.results_data.append({
            "CIS ID": cis_id,
            "Status": status,
            "Finding": message,
            "Audit Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

    def check(self, cis_id, pattern, pass_msg, fail_msg, warning=False, inverse=False):
        match = re.search(pattern, self.config_content, re.MULTILINE | re.DOTALL | re.IGNORECASE)
        if inverse:
            if match: self.log(cis_id, "FAIL", fail_msg)
            else: self.log(cis_id, "PASS", pass_msg)
        else:
            if match: self.log(cis_id, "PASS", pass_msg)
            else: self.log(cis_id, "WARN" if warning else "FAIL", fail_msg)

    def export_reports(self, vendor_name):
        # 1. Export Excel (Audit Ready)
        df = pd.DataFrame(self.results_data)
        try:
            df.to_excel(self.report_name_xlsx, index=False, sheet_name="Audit Results")
            print(f"{Colors.GREEN}[✓] Excel Report exported: {self.report_name_xlsx}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Failed to export Excel: {e}")

        # 2. Export Text Log
        with open(self.report_name_txt, "w") as f:
            f.write(f"SECURITY AUDIT REPORT - {vendor_name}\nTarget: {self.file_path}\n\n")
            for res in self.results_data:
                f.write(f"[{res['Status']}] {res['CIS ID']}: {res['Finding']}\n")
            f.write(f"\nSUMMARY: PASS: {self.score['PASS']} | FAIL: {self.score['FAIL']} | WARN: {self.score['WARN']}")
        print(f"{Colors.GREEN}[✓] Text Log exported: {self.report_name_txt}{Colors.RESET}")

# --- Vendor Modules (Restored Full 10 Controls) ---

class FortinetAudit(AuditEngine):
    def run(self):
        print(f"\n{Colors.PURPLE}==> Auditing Fortinet (FortiOS)...{Colors.RESET}")
        self.check("1.1", r'set allowaccess.*telnet', "Telnet disabled.", "Telnet enabled!", inverse=True)
        self.check("1.2", r'set allowaccess.*(?<!s)http\b', "HTTP disabled.", "HTTP management enabled.", inverse=True)
        self.check("2.1", r'set admin-https-ssl-versions tlsv1-[23]', "Strong TLS enforced.", "Legacy TLS allowed.", warning=True)
        self.check("2.2", r'set admin-sport (443|80)', "Admin port obfuscated.", "Default Admin port (443/80) in use.", inverse=True, warning=True)
        self.check("3.1", r'set admintimeout', "Admin idle timeout set.", "No idle timeout configured.", warning=True)
        self.check("3.2", r'set pre-login-banner enable', "Pre-login banner enabled.", "Banner disabled.", warning=True)
        self.check("4.1", r'config system admin.*?edit "admin"', "Default admin renamed.", "Default admin account exists.", inverse=True)
        self.check("5.1", r'config log (fortianalyzer|syslogd) setting', "Remote logging set.", "No remote logging detected.")
        self.check("6.1", r'set ntpserver', "NTP configured.", "NTP not configured.")
        self.check("7.1", r'set snmp community (public|private)', "Default SNMP strings removed.", "Default SNMP found!", inverse=True)

class JuniperAudit(AuditEngine):
    def run(self):
        print(f"\n{Colors.PURPLE}==> Auditing Juniper (Junos) per CIS v2.1.0...{Colors.RESET}")
        
        # 6.10.6 Ensure Telnet is Not Set (Automated) [cite: 409, 348]
        # Hierarchy: [edit system services] [cite: 353, 354]
        self.check("6.10.6", r'set system services telnet', 
                   "Telnet is disabled (Standard).", "Telnet service is enabled!", inverse=True)

        # 6.10.1.1 Ensure SSH Service is Configured (Manual/Scorable) [cite: 406, 201]
        # SSH is the secure alternative to Telnet[cite: 202, 245].
        self.check("6.10.1.1", r'set system services ssh', 
                   "SSH service is enabled.", "SSH service is missing.")

        # 6.10.1.5 Ensure Remote Root-Login is denied via SSH (Automated) [cite: 406, 241]
        # Hierarchy: [edit system services ssh] [cite: 241]
        # Must NOT contain 'root-login allow'[cite: 406, 241].
        self.check("6.10.1.5", r'root-login allow', 
                   "Remote root login is restricted.", "Root login allowed via SSH!", inverse=True)

        # 6.10.1.2 Ensure SSH is Restricted to Version 2 (Automated) [cite: 406, 234]
        # Junos uses SSH v2 by default but versioning should be explicit[cite: 234].
        self.check("6.10.1.2", r'protocol-version v2', 
                   "SSH v2 is explicitly enforced.", "SSH versioning not strictly set to v2.", warning=True)

        # 6.6.3 Ensure Idle Timeout is set for all Login Classes (Automated) [cite: 403, 257]
        # Hierarchy: [edit system login class <name>] [cite: 86, 257]
        self.check("6.6.3", r'idle-timeout \d+', 
                   "Login idle timeout is configured.", "No idle-timeout found in login classes.", warning=True)

        # 6.6.8 Ensure login message is set (Automated) [cite: 403, 271]
        # Hierarchy: [edit system login] [cite: 271]
        self.check("6.6.8", r'set system login announcement|set system login message', 
                   "Login banner/message is configured.", "Legal login message is missing.", warning=True)

        # 6.14 Ensure Configuration File Encryption is Set (Automated) [cite: 411, 467]
        # Prevents plain-text recovery of secrets from the config[cite: 467].
        self.check("6.14", r'set system configuration-database encryption', 
                   "Config file encryption is active.", "Config file encryption is NOT set!")

        # 6.12.1 Ensure External SYSLOG Host is Set (Automated) [cite: 411, 449]
        # Requires 'any informational' or better[cite: 449].
        self.check("6.12.1", r'set system syslog host \S+ any informational', 
                   "Remote Syslog host is correctly configured.", "Remote Syslog missing or level too low.")

        # 5.1 Ensure Common SNMP Community Strings are NOT used (Automated) [cite: 399, 185]
        # Targets 'public' and 'private' strings[cite: 185].
        self.check("5.1", r'set snmp community (public|private)', 
                   "Common SNMP strings removed.", "Default SNMP community strings detected!", inverse=True)

        # 3.10 Ensure inbound firewall filter is set for Loopback interface (Automated) [cite: 395, 98]
        # Protecting the Routing Engine (RE) via lo0[cite: 35, 98].
        self.check("3.10", r'set interfaces lo0 unit 0 family inet filter input', 
                   "Loopback interface filter is applied.", "No inbound filter on lo0 (Critical RE risk)!")

class CiscoAudit(AuditEngine):
    def run(self):
        print(f"\n{Colors.PURPLE}==> Auditing Cisco (IOS)...{Colors.RESET}")
        self.check("1.1", r'no service password-encryption', "Password encryption ON.", "Password encryption is OFF.", inverse=True)
        self.check("1.2", r'banner motd', "MOTD banner set.", "No MOTD banner.", warning=True)
        self.check("2.1", r'transport input telnet', "Telnet disabled.", "Telnet allowed on VTY!", inverse=True)
        self.check("2.2", r'transport input ssh', "SSH enabled on VTY.", "SSH not enabled on VTY.")
        self.check("3.1", r'exec-timeout [1-9]', "VTY timeout set.", "No VTY timeout set.")
        self.check("3.2", r'ip ssh version 2', "SSH v2 enforced.", "SSH v2 not enforced.")
        self.check("4.1", r'snmp-server community (public|private)', "Default SNMP removed.", "Default SNMP found!", inverse=True)
        self.check("5.1", r'logging host', "Remote logging set.", "No remote syslog host.")
        self.check("6.1", r'ntp server', "NTP configured.", "NTP not configured.")
        self.check("7.1", r'no ip http server', "HTTP Server disabled.", "HTTP server is ENABLED.", inverse=True)

# --- Human-in-the-Loop Controller ---

def main():
    print(f"{Colors.BOLD}{Colors.CYAN}=== SECURITY AUDIT TOOL v7.0 ==={Colors.RESET}")
    print("                              by cybereagle2001                          ")
    current_file = sys.argv[1] if len(sys.argv) > 1 else None

    while True:
        if not current_file:
            current_file = input(f"\n{Colors.BOLD}Enter path to config file: {Colors.RESET}").strip()
            if not current_file: break

        print(f"\n{Colors.BOLD}Select Audit Target for: {Colors.CYAN}{current_file}{Colors.RESET}")
        print("1. Fortinet (FortiOS)")
        print("2. Juniper (Junos)")
        print("3. Cisco (IOS)")
        print("4. Exit Tool")
        
        choice = input(f"\n{Colors.BOLD}Selection [1-4]: {Colors.RESET}")
        
        if choice == '1': auditor, v_name = FortinetAudit(current_file), "Fortinet"
        elif choice == '2': auditor, v_name = JuniperAudit(current_file), "Juniper"
        elif choice == '3': auditor, v_name = CiscoAudit(current_file), "Cisco"
        elif choice == '4': break
        else: continue

        if auditor.load_config():
            auditor.run()
            auditor.export_reports(v_name)
        
        print(f"\n{Colors.BLUE}{'-'*40}{Colors.RESET}")
        if input(f"{Colors.BOLD}Audit another file? (y/n): {Colors.RESET}").lower() != 'y':
            break
        current_file = None

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
