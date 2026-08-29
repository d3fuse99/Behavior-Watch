import os
import time
import json
import sys
from datetime import datetime
from pathlib import Path
import psutil
from config import COLOR_RED, COLOR_RESET

def enforce_quarantine_quota():
    try:
        quarantine_dir = Path("./EDR_Quarantine")
        if not quarantine_dir.exists():
            return
        files = sorted(list(quarantine_dir.glob("*.vir")), key=lambda x: x.stat().st_mtime)
        total_size = sum(f.stat().st_size for f in files)
        max_quota = 104857600
        while total_size > max_quota and files:
            removed_file = files.pop(0)
            total_size -= removed_file.stat().st_size
            removed_file.unlink()
    except Exception:
        pass

def xor_encrypt_file(src_path, dest_path, key=0x5A):
    with open(src_path, "rb") as fin:
        data = bytearray(fin.read())
    for i in range(len(data)):
        data[i] ^= key
    with open(dest_path, "wb") as fout:
        fout.write(data)

def quarantine_file(file_path):
    try:
        if not file_path or not os.path.isfile(file_path):
            return None
        enforce_quarantine_quota()
        quarantine_dir = Path("./EDR_Quarantine")
        quarantine_dir.mkdir(exist_ok=True)
        src = Path(file_path)
        dest_name = f"{src.stem}_{int(time.time())}.vir"
        dest = quarantine_dir / dest_name
        xor_encrypt_file(src, dest)
        return str(dest)
    except Exception:
        return None

def cleanup_autorun_registry(exe_path, autorun_paths):
    if sys.platform != "win32" or not exe_path:
        return
    try:
        import winreg
        exe_lower = exe_path.lower()
        for path_entry, (hive, subkey, val_name) in autorun_paths.items():
            if exe_lower in path_entry:
                try:
                    with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as key:
                        winreg.DeleteValue(key, val_name)
                except Exception:
                    continue
    except Exception:
        pass

def log_security_event(pid, name, path, score, triggered, quarantine_path):
    event = {
        "timestamp": datetime.now().isoformat(),
        "pid": pid,
        "name": name,
        "path": path,
        "threat_score": score,
        "triggered_heuristics": triggered,
        "quarantine_path": quarantine_path,
        "action_taken": "TERMINATED_AND_QUARANTINED"
    }
    try:
        with open("behavior_audit.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
    except Exception as e:
        print(f"{COLOR_RED}[!] Failed to write to audit log: {e}{COLOR_RESET}")

def terminate_process_tree(proc, score, triggered, autorun_paths=None):
    try:
        pid = proc.pid
        name = proc.name()
        exe = ""
        try:
            exe = proc.exe()
        except Exception:
            pass

        try:
            proc.suspend()
        except Exception:
            pass

        processes_to_kill = []
        try:
            processes_to_kill = proc.children(recursive=True)
        except Exception:
            pass
        processes_to_kill.append(proc)

        for p in processes_to_kill:
            try:
                p.suspend()
            except Exception:
                pass

        quarantine_path = quarantine_file(exe) if exe else None

        for p in processes_to_kill:
            try:
                p.kill()
            except Exception:
                pass

        if exe and os.path.isfile(exe):
            try:
                os.remove(exe)
            except Exception:
                pass

        if autorun_paths and exe:
            cleanup_autorun_registry(exe, autorun_paths)

        log_security_event(pid, name, exe, score, triggered, quarantine_path)
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False