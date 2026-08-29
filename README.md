# BEHAVIOR-WATCH 🛡️

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)]()
[![EDR Engine](https://img.shields.io/badge/EDR-Heuristic%20Engine-red.svg)]()

**BEHAVIOR-WATCH** is a lightweight, modular Endpoint Detection and Response (EDR) telemetry and active mitigation engine. Instead of relying solely on static signatures, it monitors live process telemetry in real-time, correlates multi-vector heuristic indicators, computes dynamic threat scores with decay mechanics, and executes automated process tree isolation and encrypted quarantine.

---

## 📸 Preview

<img width="710" height="380" alt="изображение" src="https://github.com/user-attachments/assets/64d9e023-7834-4a3e-8052-60f02728e3a0" />

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
```

### 3. Run Engine

**Windows (Administrator PowerShell / CMD):**
```powershell
python behavior_watch.py
```

**Linux (Root):**
```bash
sudo python3 behavior_watch.py
```

---

## ⚙️ Configuration (`config.json`)

All weights, polling intervals, safelists, and malicious hash lists can be customized without restarting the core script:

```json
{
    "threat_threshold": 100,
    "decay_rate": 5,
    "loop_interval": 1.5,
    "points_temp_dir": 40,
    "points_suspicious_path": 35,
    "points_established_net": 25,
    "points_sustained_cpu": 20,
    "points_suspicious_parent": 50,
    "points_known_bad_hash": 100,
    "points_registry_persistence": 40,
    "points_ransomware_behavior": 100,
    "points_memory_signature": 90
}
```

---

## 📁 Quarantine & Forensics

When a threat threshold is breached (Score ≥ 100):
1. Target process and its children are immediately **suspended**.
2. Executable binary is duplicated into `./EDR_Quarantine/<filename>_<timestamp>.vir` using XOR encryption.
3. Original executable is removed from disk and registry persistence keys are cleaned up.
4. Process tree is **terminated**.
5. Structured event is appended to `behavior_audit.jsonl`:

```json
{
  "timestamp": "2026-08-29T12:00:00.123456",
  "pid": 4776,
  "name": "document.pdf.exe",
  "path": "C:\\Users\\User\\AppData\\Local\\Temp\\document.pdf.exe",
  "threat_score": 100,
  "triggered_heuristics": ["TEMP_DIR_EXEC_PATH", "EVASION_PATH_PATTERN", "EXTERNAL_TCP_ESTABLISHED"],
  "quarantine_path": "EDR_Quarantine\\document.pdf_1780231648.vir",
  "action_taken": "TERMINATED_AND_QUARANTINED"
}
```

---

## ⚠️ Disclaimer
This software is developed strictly for security research, defense simulation, and educational purposes. Ensure you run this tool in a test environment or virtual machine when simulating malicious binaries.

---

## 📝 License
Distributed under the [MIT License](LICENSE
