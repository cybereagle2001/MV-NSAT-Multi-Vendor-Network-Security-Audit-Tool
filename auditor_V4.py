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
        print(f"\n{Colors.PURPLE}==> Auditing Juniper (Junos)...{Colors.RESET}")
        self.check("1.1", r'set system services telnet', "Telnet disabled.", "Telnet enabled.", inverse=True)
        self.check("1.2", r'set system services ssh', "SSH enabled.", "SSH not enabled.")
        self.check("2.1", r'root-login allow', "Root SSH restricted.", "Root SSH allowed!", inverse=True)
        self.check("2.2", r'protocol-version v1', "SSH v1 disabled.", "SSH v1 detected!", inverse=True)
        self.check("3.1", r'set system login idle-timeout', "Idle timeout set.", "No idle timeout set.", warning=True)
        self.check("3.2", r'set system login banner', "Banner configured.", "No banner configured.", warning=True)
        self.check("4.1", r'plain-text-password', "No plain-text passwords.", "Plain-text passwords detected!", inverse=True)
        self.check("5.1", r'set system syslog host', "Remote Syslog set.", "Remote Syslog missing.")
        self.check("6.1", r'set snmp community (public|private)', "Default SNMP removed.", "Default SNMP detected!", inverse=True)
        self.check("7.1", r'set interfaces lo0.*filter (input|input-list)', "lo0 filter applied.", "No lo0 filter!")

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
