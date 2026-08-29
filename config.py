import os
import sys
import json

CONFIG_FILE = "config.json"
DEFAULT_CONFIG = {
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
    "points_memory_signature": 90,
    "safelist_names": [
        "idle", "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
        "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
        "spoolsv.exe", "taskhostw.exe", "conhost.exe", "python.exe", "python",
        "init", "systemd", "dockerd", "bash", "zsh", "ssh", "sshd", "kernel"
    ],
    "known_bad_hashes": [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ]
}

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return {**DEFAULT_CONFIG, **data}
        except Exception:
            return DEFAULT_CONFIG
    else:
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(DEFAULT_CONFIG, f, indent=4)
        except Exception:
            pass
        return DEFAULT_CONFIG

CONFIG = load_config()

COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_RED = "\033[91m"
COLOR_CYAN = "\033[96m"
COLOR_GRAY = "\033[90m"
COLOR_BG_RED = "\033[41m\033[37m"

if sys.platform == "win32":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        h_stdout = kernel32.GetStdHandle(-11)
        mode = ctypes.c_ulong()
        kernel32.GetConsoleMode(h_stdout, ctypes.byref(mode))
        kernel32.SetConsoleMode(h_stdout, mode.value | 0x0004)
    except Exception:
        pass