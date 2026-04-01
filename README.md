# 🛡️ MV-NSAT: Multi-Vendor Network Security Audit Tool

**MV-NSAT** is a lightweight, extensible auditing framework built for security consultants and systems engineers who need to validate network hardening against **CIS (Center for Internet Security) Benchmarks**. 

In modern infrastructure, "Layer 8" (the human element) is often the weakest link, but misconfigured "Layer 3" devices provide the open doors. MV-NSAT closes those doors by providing rapid, repeatable, and reportable security baselining.

## 🚀 Features
* **Multi-Vendor Support:** Native audit modules for **Fortinet**, **Juniper**, and **Cisco**.
* **Deep Inspection:** Scans 10+ critical CIS controls per vendor (Management services, SSH hardening, AAA, Logging, SNMP, etc.).
* **Human-in-the-Loop:** Designed for batch processing; audit multiple configurations in a single session without restarting the script.
* **Audit-Ready Reporting:** * **Excel (.xlsx):** Structured tabular data for formal compliance registries.
    * **Text (.txt):** Rapid-fire logs for immediate technical remediation.
* **Modular Architecture:** Easily extend the `AuditEngine` to support new vendors or custom organizational policies.

## 🛠️ Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/YourUsername/MV-NSAT.git
   cd MV-NSAT
   ```

2. **Install dependencies:**
   ```bash
   pip install pandas openpyxl
   ```

## 📖 Usage

Run the script and provide the path to your configuration backup file:

```bash
python auditor.py path/to/config.conf
```

### Workflow
1.  **Select Vendor:** Choose the appropriate module (Fortinet, Juniper, or Cisco).
2.  **Analyze:** The engine performs regex-based pattern matching against CIS hardening standards.
3.  **Review:** Real-time color-coded console output (PASS/FAIL/WARN).
4.  **Export:** Reports are automatically generated using the naming convention: `{original_filename}_audited`.
5.  **Repeat:** Choose to load a new file or exit.

## 📊 Covered Benchmarks (Samples)
| ID | Control Category | Description |
|:---|:---|:---|
| 1.1 | Management Access | Ensures insecure protocols (Telnet/HTTP) are disabled. |
| 2.1 | SSH Hardening | Enforces TLS 1.2+, SSH v2, and restricts Root login. |
| 3.1 | Session Security | Validates idle timeouts and legal login banners. |
| 5.1 | Observability | Checks for remote Syslog/FortiAnalyzer integration. |

## 🤝 Contribution
This tool is part of a broader mission to simplify system hardening. If you'd like to add new regex patterns or vendor modules, feel free to submit a PR.

---
**Author:** Oussama Ben Hadj Dahman (cybereagle2001)
