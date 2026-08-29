import os
import sys
import time
from datetime import datetime
import psutil
from config import CONFIG, COLOR_YELLOW, COLOR_RESET
from mitigation import terminate_process_tree
from heuristics import (
    get_registry_autorun_paths,
    analyze_path_heuristics,
    analyze_network_heuristics,
    analyze_cpu_heuristics,
    analyze_parent_heuristics,
    analyze_hash_heuristics,
    analyze_registry_heuristics,
    analyze_ransomware_heuristics,
    analyze_lolbin_heuristics,
    analyze_memory_heuristics
)
from dashboard import draw_dashboard, show_startup_screen

process_state = {}

def is_safelisted(proc):
    try:
        pid = proc.pid
        name = proc.name().lower()
        my_pid = os.getpid()
        parent_pid = os.getppid()
        if pid in {0, 1, 4, my_pid, parent_pid}:
            return True
        if name in CONFIG["safelist_names"]:
            try:
                exe = proc.exe().lower()
                if sys.platform == "win32":
                    win_dir = os.environ.get("SystemRoot", "c:\\windows").lower()
                    if exe.startswith(win_dir) or name in ["python.exe", "python"]:
                        return True
                else:
                    valid_prefixes = ["/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/"]
                    if any(exe.startswith(p) for p in valid_prefixes) or name in ["python", "python3"]:
                        return True
            except Exception:
                return False
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False
    return False

def apply_scoring_decay():
    stale_pids = []
    for pid, data in process_state.items():
        if not data["updated"]:
            stale_pids.append(pid)
            continue
        if data["score"] > 0:
            data["score"] = max(0, data["score"] - CONFIG["decay_rate"])
        if data["score"] == 0:
            data["heuristics"].clear()
        data["updated"] = False
    for pid in stale_pids:
        del process_state[pid]

def main():
    terminated_log = []
    is_admin = False
    try:
        if sys.platform == "win32":
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            is_admin = os.getuid() == 0
    except Exception:
        pass
    show_startup_screen(is_admin)
    try:
        while True:
            autorun_paths = get_registry_autorun_paths()
            for proc in psutil.process_iter(attrs=["pid", "name", "exe"]):
                try:
                    pid = proc.info["pid"]
                    name = proc.info["name"] or "Unknown"
                    exe = proc.info["exe"] or ""
                    if is_safelisted(proc):
                        continue
                    if pid not in process_state:
                        process_state[pid] = {
                            "pid": pid,
                            "name": name,
                            "exe": exe,
                            "score": 0,
                            "cpu_history": [],
                            "heuristics": set(),
                            "updated": True
                        }
                    else:
                        process_state[pid]["updated"] = True
                    current_record = process_state[pid]
                    score = current_record["score"]
                    heuristics = current_record["heuristics"]
                    if exe:
                        score = analyze_path_heuristics(exe, score, heuristics)
                        score = analyze_hash_heuristics(exe, score, heuristics)
                    score = analyze_network_heuristics(proc, score, heuristics)
                    score = analyze_cpu_heuristics(proc, pid, score, heuristics, process_state)
                    score = analyze_parent_heuristics(proc, score, heuristics)
                    score = analyze_registry_heuristics(proc, score, heuristics, autorun_paths)
                    score = analyze_ransomware_heuristics(proc, score, heuristics)
                    score = analyze_lolbin_heuristics(proc, score, heuristics)
                    score = analyze_memory_heuristics(proc, score, heuristics)
                    process_state[pid]["score"] = score
                    process_state[pid]["heuristics"] = heuristics
                    if score >= CONFIG["threat_threshold"]:
                        triggered_list = list(heuristics)
                        success = terminate_process_tree(proc, score, triggered_list, autorun_paths)
                        if success:
                            terminated_log.append({
                                "time": datetime.now().strftime("%H:%M:%S"),
                                "pid": pid,
                                "name": name,
                                "score": score
                            })
                            if pid in process_state:
                                del process_state[pid]
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            apply_scoring_decay()
            draw_dashboard(process_state, terminated_log)
            if not is_admin:
                print(f"{COLOR_YELLOW}[!] Warning: Not running as Administrator/Root. Telemetry may be limited.{COLOR_RESET}")
            time.sleep(CONFIG["loop_interval"])
    except KeyboardInterrupt:
        print(f"\n{COLOR_YELLOW}[*] Shutting down BEHAVIOR-WATCH cleanly...{COLOR_RESET}")
        sys.exit(0)

if __name__ == "__main__":
    main()