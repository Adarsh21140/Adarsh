
# Incident Investigation & Remediation Report: Potentially Unwanted Application (PUA) Analysis

## 1. Incident Overview
- **Incident ID:** `INC-2026-090924`
- **Classification:** Potentially Unwanted Application (PUA) / Unwanted Software Bundle
- **Affected Endpoints:** `HOST-WIN-01`, `HOST-WIN-02`
- **Initial Trigger:** Multiple automated EDR detections indicating process memory injection and anomalous network enumeration.

During routine alert triage, endpoint telemetry revealed suspicious execution patterns involving `shift.exe`. Correlated event analysis uncovered payload decompression routines, outbound network traffic to external infrastructure, and up to 20 secondary masqueraded executable files dropped across user-level directories. Because identical behaviors were identified concurrently across multiple enterprise systems, the incident was handled as a distributed software compromise requiring immediate host isolation and full containment.

---

## 2. Investigation & Technical Findings

### 2.1 Process Injection & Network Enumeration
- **MITRE ATT&CK Technique:** [T1055 (Process Injection)](https://attack.mitre.org/techniques/T1055/)
- **Detection Trigger:** `shift.exe possibly injected code into shift.exe using VirtualAlloc API`

Both endpoints triggered high-fidelity alerts indicating that `shift.exe` allocated dynamic virtual memory using Windows `VirtualAlloc` API calls. This technique is commonly associated with shellcode injection, memory unpacking, or evasion of disk-level heuristic detection. Concurrently, internal network enumeration activities were observed, pointing toward unauthorized system or local network discovery attempts.

### 2.2 Unwanted Software Bundle & Execution
- **Detection Name:** `PUA:Win32/ShiftBrowser`
- **Reputation / Detection Ratio:** 20/71 engines on VirusTotal
- **Observed Command Line:**
  ```cmd
  shift.exe --type=utility --utility-sub-type=unzip.mojom.Unzipper --lang=en-US --service-sandbox-type=service.../prefetch:14
Execution logs demonstrated shift.exe spawning utility processes to invoke an internal decompression routine (unzip.mojom.Unzipper). In isolation, decompression utilities are standard browser components; however, in this context, they functioned as an unpacker mechanism to deliver secondary binary artifacts into staging folders.

2.3 Command-and-Control (C2) / Fallback Channel Egress
MITRE ATT&CK Technique: T1008 (Fallback Channels)

Observed Destinations:

107.178.240.159:443

3.150.53.81:443

162.159.61.3:443

109.61.91.198:443

104.20.24.60:443

173.194.45.113:80

192.178.155.138:80

192.178.155.139:443

172.253.62.188:5228

9.9.9.9:53 (DNS query)

The application initiated outbound sessions across diverse IP ranges and ports (HTTP, HTTPS, non-standard port 5228, and external DNS). This multi-destination pattern is consistent with fallback channel mechanisms designed to maintain beaconing resilience against firewall or proxy filtering.

2.4 Artifact Enumeration
Telemetry identified up to 20 dropped, renamed, or masqueraded executable binaries residing in temporary and user application folders. The scale of file modifications confirmed that the threat was an active multi-component application suite rather than an isolated standalone binary.

3. Investigation Methodology
Alert Correlation: Cross-referenced process start times, parent-child relationships, and command-line arguments between HOST-WIN-01 and HOST-WIN-02.

Process Lineage Analysis: Traced parent process execution down through worker threads and utility helper processes.

Network Telemetry Mapping: Categorized external IPs by ASN, geolocation, reputation, and application layer protocols.

Endpoint File Scans: Identified file locations, digital signatures, and hash values across all generated artifacts.

4. Threat & Risk Assessment
Severity Level: Medium – High

Primary Risks:

Secondary malware retrieval via external fallback channels.

Credential caching risks from unverified browser/bundle utilities.

Potential lateral movement following local network enumeration.

Scope: Restricted to two host endpoints; no signs of active lateral movement outside the initial hosts.

5. Remediation & Incident Response Plan
Phase 1: Containment
Host Isolation: Immediately applied EDR network isolation to HOST-WIN-01 and HOST-WIN-02.

Process Termination: Killed active execution trees of shift.exe and associated child tasks.

Perimeter Blocks: Sinkholed suspicious external IPs and hostnames at the perimeter firewall.

Phase 2: Eradication
Ran automated deep scans and manual file purges for all 20 identified executable artifacts.

Inspected persistence hooks:

Startup registry keys (Run, RunOnce)

Windows Task Scheduler entries

Services and browser helper objects / extensions

Removed associated unzipper/staging temporary directories.

Phase 3: Validation & Credential Hardening
Executed follow-up EDR scans; confirmed zero recurrence of VirtualAlloc injection alerts or outbound beaconing.

Revoked active user sessions and required a full domain credential reset for the affected local user accounts.

Enforced multi-factor authentication (MFA) verification on all external corporate logins.

Phase 4: Recovery & Monitoring
Restored network connectivity to both machines.

Configured custom EDR detection rules targeting unusual browser-based decompression switches (--utility-sub-type=unzip%) for a 14-day watch period.

6. Conclusion & Key Takeaways
Prompt correlation of process injection detections and multi-channel outbound activity enabled fast containment of this unwanted software bundle before further data exfiltration or persistence could be established. Restricting software execution permissions in user directories and tuning EDR behavioral blocks against known PUA signatures will mitigate similar bundle infections in the future.
