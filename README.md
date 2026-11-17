# 🛡️ Project 3: Advanced Endpoint Detection & Tuning Lab

**Author:** Jamal  
**Role Target:** SOC Analyst Tier 1 / Detection Engineer  
**Tech Stack:** Wazuh v4.x, Sysmon (Olaf Hartong Modular), Windows Server, MITRE ATT&CK  

## 📖 Executive Summary
This project demonstrates a complete defensive engineering lifecycle on a Windows endpoint. Unlike standard tutorials that stop at alert generation, this lab focuses on operational realities: distinguishing signal from noise, validating detections against compliance frameworks, and implementing secure tuning rules that reduce fatigue without creating security blind spots.

Key achievements include simulating DNS Hijacking and Registry Persistence, hunting across noisy datasets using absolute time ranges, and deploying conditional suppression rules verified via engine testing (`wazuh-analysisd -t`).

---

## 🏗️ Architecture & Hardening Strategy

### Dual-Sensor Deployment
The environment uses two independent sensors to ensure coverage redundancy:

1.  **Wazuh Agent (FIM):** Monitors file system state changes and registry keys in realtime. Configured with strict whitelisting for high-value binaries (`reg.exe`, `powershell.exe`, `cmd.exe`) and critical paths (`System32\drivers\etc`).
2.  **Sysmon (Behavioral):** Uses the Olaf Hartong Modular configuration to provide granular process creation, image loading, and registry event logging mapped directly to MITRE ATT&CK techniques.

> 💡 **Design Decision:** Relying solely on FIM misses transient attacks; relying solely on Sysmon generates excessive noise. Combining both allows for high-fidelity correlation where FIM confirms *state change* and Sysmon provides *contextual behavior*.

### Compliance Mapping
All custom rules and monitoring configurations are mapped to industry standards to demonstrate business alignment:

-   **NIST 800-53:** SI.7 (Software, Firmware, and Information Integrity)
-   **PCI DSS:** Requirement 11.5 (File Integrity Monitoring)
-   **TSC:** CC6.1, CC7.2 (Logical Access & System Operations)

---

## 🚦 Attack Scenarios & Detection Evidence

### Scenario 1: DNS Hijacking via Hosts File Modification

-   **Technique:** T1565.001 (Stored Data Manipulation)
-   **Action:** Injected malicious IP-domain mapping into `%WINDIR%\System32\drivers\etc\hosts`.
-   **Detection:** Wazuh FIM triggered a realtime alert showing the exact diff of the injected line. Post-remediation verification confirmed successful cleanup via negative diff analysis.
-   **Evidence:**
    - [Hosts File Modified Diff](08_FIM_Hosts_Hijack_DIFF.png)
    - [Cleanup Verification](09_FIM_Hosts_Clean_DIFF.png)

### Scenario 2: Registry Persistence (Autostart Backdoor)

-   **Technique:** T1547.001 (Boot/Logon Autostart Execution: Registry Run Keys)
-   **Action:** Added `WindowsUpdateService` value pointing to a fake updater binary under `HKLM\...\CurrentVersion\Run`.
-   **Dual-Sensor Validation:**
    -   **FIM:** Detected registry key addition during scheduled scan cycle with full path attribution.
    -   **Sysmon EID 13: Captured the registry write operation in realtime (Command-line context requires correlation with EID 1). (`reg.exe add ...`).
    -   **Custom Rule:** Elevated detection severity to Level 10 and enriched with MITRE ID T1547.001.
-   **Evidence:**
    - [Registry Injection Command](11_FIM_Registry_Injection.png)
    - [Sysmon EID13 Detection](13_Reg_Persistence_MITRE.png)

---

## 🔍 Threat Hunting Methodology

Instead of passive waiting, active hunting was performed over a 24-hour window to identify persistence mechanisms buried in noise:

1.  **Broad Sweep:** Queried `rule.mitre.tactic: Persistence` → Returned **393 hits** (High Noise Baseline).
2.  **Refinement:** Filtered to specific technique `rule.mitre.id: T1547.001` → Reduced to **3 targeted hits**.
3.  **IOC Extraction:** Identified malicious binary path (`C:\Windows\Temp\updater.exe`) and user context (`jamal\jamal`).
4.  **Negative Verification:** After remediation, queried `eventType: SetValue` within an isolated absolute time range → Confirmed **0 hits**, validating remediation.

> ⚠️ **Critical Lesson:** Relative time filters ("Last 5 minutes") can contaminate results if applied before service restart propagation completes. Absolute ranges anchored to precise remediation timestamps are mandatory for valid negative testing.

---

## 🧪 Secure Tuning & Engineering Discipline

A common anti-pattern is suppressing entire rule IDs to silence noise. This creates security gaps. In this project, we implemented **Conditional Suppression**:

-   **Problem:** Rule 92154 (Sysmon Image Load) generated 393 alerts/day for benign `taskschd.dll` loads.
-   **Solution:** Created child rule `100103` (`level=0`) that ONLY triggers when ALL benign indicators are present simultaneously:
    -   `imageLoaded` ends with `taskschd.dll`
    -   `signed` equals `true`
    -   `signatureStatus` equals `Valid`
-   **Validation:** Verified syntax via `wazuh-analysisd -t` before deployment. Confirmed post-tuning that unsigned variants still trigger alerts while signed ones are suppressed.
-   **Integrity Check:** Verified that general Sysmon EID7 detection remained active (47 hits) proving the engine was not disabled, only surgically tuned.

**Code Snippet (Rule 100103):**

```xml
<rule id="100103" level="0">
  <if_sid>92154</if_sid>
  <field name="data.win.eventdata.signed">^true$</field>
  <field name="data.win.eventdata.signatureStatus">^Valid$</field>
  <field name="data.win.eventdata.imageLoaded">taskschd\.dll$</field>
  <description>Tuning: suppress benign Microsoft-signed taskschd.dll loads</description>
</rule>
```

**Evidence:**
- [Tuning Code & Test](18_Tuning_Rule_Write_a.png)
- [Suppression Success](19a_Tuning_Noise_Gone.png)
- [System Integrity Check](19b_Tuning_Still_Detecting.png)

---

## 📸 Evidence Gallery

| Phase | Image | Description |
| :--- | :--- | :--- |
| **Setup** | [03_Services_Status](03_Services_Status.png) | Dual-sensor readiness verified |
| **Hardening** | [01_FIM_Agent_Config](01_FIM_Agent_Config.png) | Restricted monitoring for high-value binaries |
| **Attack** | [11_Reg_Injection](11_FIM_Registry_Injection.png) | Malicious registry value creation |
| **Detection** | [12_FIM_Reg_Alert](12_FIM_Registry_Alert.png) | FIM alert with full path attribution |
| **Hunting** | [17_Noise_Baseline](17_Tuning_Identify_Baseline_a.png) | Initial broad sweep showing alert fatigue |
| **Hunting** | [15_Refined_Hunt](15_Hunting_Persistence_Refined.png) | Narrowed search isolating true positive |
| **Tuning** | [19a_Suppression_OK](19a_Tuning_Noise_Gone.png) | Zero hits for benign signed loads |
| **Quality** | [18b_Analysisd_Test](18_Tuning_Rule_Write_b.png) | Engine validation before production deploy |

---

## 🗣️ Key Takeaways for Interviews

✅ **"I validate tuning scientifically."**  
*(Reference the absolute-range methodology and analysisd testing)*

✅ **"My tuning decisions prioritize security posture over convenience."**  
*(Contrast rejected 'blind ignore' vs adopted 'conditional suppression')*

✅ **"I think like an attacker but verify like an auditor."**  
*(Demonstrate how simulated attacks were paired with negative-space proofs of elimination)*

✅ **"I treat every anomaly as data until proven otherwise."**  
*(Highlight preservation of archived/raw logs even when alerting suppressed)*

---

*Built with integrity. Validated through adversity. Operationally validated..*
