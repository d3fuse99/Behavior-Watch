# BEHAVIOR-WATCH 🛡️

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)]()
[![EDR Engine](https://img.shields.io/badge/EDR-Heuristic%20Engine-red.svg)]()

**BEHAVIOR-WATCH** is a lightweight, modular Endpoint Detection and Response (EDR) telemetry and active mitigation engine. Instead of relying solely on static signatures, it monitors live process telemetry in real-time, correlates multi-vector heuristic indicators, computes dynamic threat scores with decay mechanics, and executes automated process tree isolation and encrypted quarantine.

---

## 📸 Preview

![Dashboard Preview](preview.png)

---

## ⚡ Key Features & Detection Vectors

- **🛡️ Process Tree Freeze & Kill:** Instantly suspends the target process upon reaching the threat threshold (`NtSuspendProcess`), traverses child processes, and safely terminates the entire execution tree.
- **🔒 XOR-Encrypted Quarantine:** Neutralizes extracted payloads on disk with `XOR 0x5A` encryption and `.vir` formatting to prevent accidental execution.
- **🧬 Deep Memory Heuristics:** Scans committed read/write/execute memory pages via Windows `VirtualQueryEx` and `ReadProcessMemory` for injection markers and in-memory payloads.
- **⚡ In-Memory Hash Caching:** Real-time SHA-256 fingerprinting optimized with `(path, mtime)` caching to avoid excessive disk I/O.
- **🏹 Ransomware Defense:** Detects system recovery tampering (`vssadmin delete shadows`, `bcdedit /set recoveryenabled no`, `wbadmin`, `wmic shadowcopy`).
- **🪓 LOLBins & Evasion Detection:** Flags malicious use of system binaries (`certutil`, `bitsadmin`, `mshta`, `regsvr32`) downloading payloads over HTTP/FTP, double extensions (`.pdf.exe`), and suspicious execution directories.
- **⏱️ Dynamic Scoring & Decay:** Implements a time-to-decay score model. Benign temporary spikes decay naturally, while persistent attack chains escalate to mitigation.
- **📜 Structured Audit Logging:** Streams atomic security events to `behavior_audit.jsonl` (NDJSON format) for SIEM ingestion.

---

## 📊 Detection Matrix

| Heuristic Indicator | Description | Default Weight |
| :--- | :--- | :--- |
| `RANSOMWARE_INHIBIT_SYSTEM_RECOVERY` | Shadow copy / backup deletion attempts | +100 pts |
| `KNOWN_MALICIOUS_HASH` | File SHA-256 matches threat database | +100 pts |
| `MALICIOUS_MEMORY_SIGNATURE` | Payload artifact found in process memory | +90 pts |
| `SUSPICIOUS_PARENT_CHILD` | Browser/Office spawning shell (`cmd`, `powershell`, etc.) | +50 pts |
| `REGISTRY_PERSISTENCE` | Untrusted binary registered in `Run`/`RunOnce` | +40 pts |
| `TEMP_DIR_EXEC_PATH` | Execution from `Temp` / `AppData\Local\Temp` | +40 pts |
| `EVASION_PATH_PATTERN` | Double extensions (`.pdf.exe`), Recycle Bin paths | +35 pts |
| `EXTERNAL_TCP_ESTABLISHED` | Unexpected outbound internet connectivity | +25 pts |
| `SUSTAINED_CPU_SPIKE` | Sustained CPU saturation (>80% over 3 cycles) | +20 pts |

---

## 🚀 Quick Start

### 1. Requirements
* Python 3.8 or higher
* Administrative privileges (required for process memory inspection and termination)

### 2. Install Dependencies
```bash
pip install psutil
