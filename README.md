# 🛡️ MV-NSAT: Multi-Vendor Network Security Audit Tool

**MV-NSAT** is a lightweight, extensible auditing framework built for security consultants and systems engineers to validate network hardening against official **CIS (Center for Internet Security) Benchmarks**. 

In modern infrastructure, **"Layer 8"** (the human element) is the most critical vector, but misconfigured network devices provide the technical "open doors." MV-NSAT closes those doors by providing rapid, repeatable, and reportable security baselining.

## 🚀 Key Features
* **Multi-Vendor Support:** Native audit modules for **Fortinet (FortiOS)**, **Juniper (Junos)**, and **Cisco (IOS)**.
* **Official CIS Mapping:** Audit logic is strictly mapped to:
    * *CIS Fortinet FortiGate 7.x Benchmark v1.0.1/v1.4.0*
    * *CIS Juniper OS Benchmark v2.1.0*
    * *CIS Cisco IOS Benchmark v4.0.0*
* **Human-in-the-Loop:** Designed for real-world consultancy. Audit multiple configurations in a single session with a dynamic file-selection workflow.
* **Audit-Ready Reporting:** * **Excel (.xlsx):** Professional tabular format with timestamps and CIS IDs for formal compliance registries.
    * **Text (.txt):** Rapid-fire logs for immediate technical remediation.
* **Modular Architecture:** Easily extend the `AuditEngine` to support custom organizational policies or new vendors.

## 🛠️ Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/cybereagle2001/MV-NSAT-Multi-Vendor-Network-Security-Audit-Tool.git
    cd MV-NSAT
    ```

2.  **Install dependencies:**
    ```bash
    pip install pandas openpyxl
    ```

## 📖 Usage

Run the script and provide the initial path to your configuration backup file:

```bash
python auditor.py path/to/config.conf
```

### The Workflow
1.  **Target Selection:** Choose the vendor module (Fortinet, Juniper, or Cisco).
2.  **Automated Analysis:** The engine performs deep regex pattern matching against the CIS Level 1 profile.
3.  **Real-time Review:** Color-coded console output identifies **PASS**, **FAIL**, and **WARN** (Level 2/Manual) items.
4.  **Auto-Export:** Reports are generated as `{filename}_audited.xlsx` and `{filename}_audited.txt`.
5.  **Interactive Cycle:** The "Human-in-the-Loop" prompt allows you to immediately load a new configuration file or exit.

## 📊 Benchmark Mapping (Sample Controls)

| CIS ID | Category | Description | Platform |
|:---|:---|:---|:---|
| **2.1.1** | Management | Disable Telnet Service | FortiOS |
| **6.10.6** | Management | Ensure Telnet is Not Set | Junos |
| **3.10** | RE Protection | Inbound Firewall Filter for lo0 | Junos |
| **1.1** | Encryption | Service Password-Encryption | Cisco IOS |
| **7.2.1** | Logging | Centralized Logging & Reporting | Multi-Vendor |

## 🤝 Contribution
This tool is part of a broader mission to simplify system hardening and is developed alongside the **MalqartFramework**. If you have custom regex patterns for specific hardening standards, feel free to submit a PR.
---
**Author :** Oussama Ben Hadj Dahman  (cybereagle2001)
