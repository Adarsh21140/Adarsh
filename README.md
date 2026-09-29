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
