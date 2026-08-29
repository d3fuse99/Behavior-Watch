import os
import re
import sys
import hashlib
import psutil
from config import CONFIG

_HASH_CACHE = {}

KNOWN_NETWORK_APPS = {
    "firefox.exe", "chrome.exe", "msedge.exe", "opera.exe", "brave.exe",
    "steam.exe", "steamwebhelper.exe", "discord.exe", "telegram.exe", "spotify.exe",
    "code.exe", "msedgewebview2.exe", "searchhost.exe", "startmenuexperiencehost.exe",
    "microsoftstartfeed.exe", "widgets.exe", "onedrive.exe", "devenv.exe"
}

def is_trusted_directory(exe_path):
    if not exe_path:
        return False
    path_lower = exe_path.lower()
    win_dir = os.environ.get("SystemRoot", "c:\\windows").lower()
    if path_lower.startswith(win_dir):
        return True
    trusted_keywords = [
        ":\\program files\\",
        ":\\program files (x86)\\",
        "\\steam\\",
        "\\steamlibrary\\",
        "\\steamapps\\",
        "\\programs\\microsoft vs code\\",
        "/usr/",
        "/bin/",
        "/sbin/"
    ]
    return any(keyword in path_lower for keyword in trusted_keywords)

def get_registry_autorun_paths():
    paths = {}
    if sys.platform != "win32":
        return paths
    try:
        import winreg
        targets = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce")
        ]
        for hive, subkey in targets:
            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                    count = winreg.QueryInfoKey(key)[1]
                    for i in range(count):
                        name, value, _ = winreg.EnumValue(key, i)
                        val_str = str(value).strip('\"').lower()
                        paths[val_str] = (hive, subkey, name)
            except Exception:
                continue
    except Exception:
        pass
    return paths

def get_file_hash_cached(file_path):
    try:
        if not file_path or not os.path.isfile(file_path):
            return None
        st = os.stat(file_path)
        if st.st_size > 26214400:
            return None
        cache_key = (file_path, st.st_mtime)
        if cache_key in _HASH_CACHE:
            return _HASH_CACHE[cache_key]
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        digest = sha256.hexdigest()
        _HASH_CACHE[cache_key] = digest
        return digest
    except Exception:
        return None

def analyze_path_heuristics(exe_path, score, triggered_set):
    if not exe_path:
        return score
    path_lower = exe_path.lower()
    temp_indicators = ["\\temp\\", "/tmp/", "\\appdata\\local\\temp\\", "\\appdata\\roaming\\"]
    if any(indicator in path_lower for indicator in temp_indicators):
        if "TEMP_DIR_EXEC_PATH" not in triggered_set:
            score += CONFIG["points_temp_dir"]
            triggered_set.add("TEMP_DIR_EXEC_PATH")
    suspicious_patterns = [
        r"\.exe\.exe$", r"\.pdf\.exe$", r"\.xlsx\.exe$", r"\.txt\.exe$",
        r"\\recycler\\", r"\\\$recycle\.bin\\",
        r"\\users\\public\\", r"/users/public/"
    ]
    if any(re.search(pattern, path_lower) for pattern in suspicious_patterns):
        if "EVASION_PATH_PATTERN" not in triggered_set:
            score += CONFIG["points_suspicious_path"]
            triggered_set.add("EVASION_PATH_PATTERN")
    return score

def analyze_network_heuristics(proc, score, triggered_set):
    try:
        name = proc.name().lower()
        if name in KNOWN_NETWORK_APPS:
            return score
        try:
            exe_path = proc.exe().lower()
            if is_trusted_directory(exe_path):
                return score
        except Exception:
            pass
        if hasattr(proc, "net_connections"):
            connections = proc.net_connections(kind="inet")
        else:
            connections = proc.connections(kind="inet")
        for conn in connections:
            if conn.status == "ESTABLISHED":
                raddr = conn.raddr
                if raddr and raddr.ip not in ("127.0.0.1", "::1", "0.0.0.0"):
                    if "EXTERNAL_TCP_ESTABLISHED" not in triggered_set:
                        score += CONFIG["points_established_net"]
                        triggered_set.add("EXTERNAL_TCP_ESTABLISHED")
                        break
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass
    return score

def analyze_cpu_heuristics(proc, pid, score, triggered_set, process_state):
    try:
        current_cpu = proc.cpu_percent()
        cpu_history = process_state.get(pid, {}).get("cpu_history", [])
        cpu_history.append(current_cpu)
        if len(cpu_history) > 3:
            cpu_history.pop(0)
        if pid in process_state:
            process_state[pid]["cpu_history"] = cpu_history
        if len(cpu_history) == 3 and all(usage > 80.0 for usage in cpu_history):
            if "SUSTAINED_CPU_SPIKE" not in triggered_set:
                score += CONFIG["points_sustained_cpu"]
                triggered_set.add("SUSTAINED_CPU_SPIKE")
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass
    return score

def analyze_parent_heuristics(proc, score, triggered_set):
    try:
        parent = proc.parent()
        if parent:
            p_name = parent.name().lower()
            c_name = proc.name().lower()
            suspicious_parents = ["chrome.exe", "msword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "discord.exe", "teams.exe", "firefox.exe", "msedge.exe"]
            suspicious_children = ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "curl.exe", "certutil.exe", "bitsadmin.exe", "schtasks.exe", "mshta.exe"]
            if p_name in suspicious_parents and c_name in suspicious_children:
                if "SUSPICIOUS_PARENT_CHILD" not in triggered_set:
                    score += CONFIG["points_suspicious_parent"]
                    triggered_set.add("SUSPICIOUS_PARENT_CHILD")
    except Exception:
        pass
    return score

def analyze_hash_heuristics(exe_path, score, triggered_set):
    if not exe_path:
        return score
    file_hash = get_file_hash_cached(exe_path)
    if file_hash and file_hash in CONFIG["known_bad_hashes"]:
        if "KNOWN_MALICIOUS_HASH" not in triggered_set:
            score += CONFIG["points_known_bad_hash"]
            triggered_set.add("KNOWN_MALICIOUS_HASH")
    return score

def analyze_registry_heuristics(proc, score, triggered_set, autorun_paths):
    try:
        exe_path = proc.exe().lower()
        if not exe_path:
            return score
        if is_trusted_directory(exe_path):
            return score
        for path_entry in autorun_paths:
            if exe_path in path_entry:
                if "REGISTRY_PERSISTENCE" not in triggered_set:
                    score += CONFIG["points_registry_persistence"]
                    triggered_set.add("REGISTRY_PERSISTENCE")
                    break
    except Exception:
        pass
    return score

def analyze_ransomware_heuristics(proc, score, triggered_set):
    try:
        cmd = [arg.lower() for arg in proc.cmdline()]
        if cmd:
            cmd_str = " ".join(cmd)
            vss_attack = "vssadmin" in cmd_str and "delete" in cmd_str and "shadows" in cmd_str
            bcd_attack = "bcdedit" in cmd_str and "recoveryenabled" in cmd_str and "no" in cmd_str
            wb_attack = "wbadmin" in cmd_str and "delete" in cmd_str and "catalog" in cmd_str
            wmic_attack = "wmic" in cmd_str and "shadowcopy" in cmd_str and "delete" in cmd_str
            if vss_attack or bcd_attack or wb_attack or wmic_attack:
                if "RANSOMWARE_INHIBIT_SYSTEM_RECOVERY" not in triggered_set:
                    score += CONFIG["points_ransomware_behavior"]
                    triggered_set.add("RANSOMWARE_INHIBIT_SYSTEM_RECOVERY")
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass
    return score

def analyze_lolbin_heuristics(proc, score, triggered_set):
    try:
        cmd = [arg.lower() for arg in proc.cmdline()]
        if not cmd:
            return score
        cmd_str = " ".join(cmd)
        lolbins = ["certutil.exe", "bitsadmin.exe", "regsvr32.exe", "mshta.exe", "rundll32.exe"]
        proc_name = proc.name().lower()
        if proc_name in lolbins:
            if "http://" in cmd_str or "https://" in cmd_str or "ftp://" in cmd_str:
                if "SUSPICIOUS_LOLBIN_EXECUTION" not in triggered_set:
                    score += CONFIG["points_suspicious_parent"]
                    triggered_set.add("SUSPICIOUS_LOLBIN_EXECUTION")
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass
    return score

def analyze_memory_heuristics(proc, score, triggered_set):
    if score < 40 or sys.platform != "win32":
        return score
    try:
        import ctypes
        from ctypes import wintypes

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", wintypes.LPVOID),
                ("AllocationBase", wintypes.LPVOID),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD)
            ]

        PROCESS_VM_READ = 0x0010
        PROCESS_QUERY_INFORMATION = 0x0400
        MEM_COMMIT = 0x1000
        PAGE_EXECUTE_READWRITE = 0x40
        PAGE_READWRITE = 0x04

        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, proc.pid)
        if not handle:
            return score

        signatures = [b"mimikatz", b"beacon.dll", b"metasploit", b"powersploit", b"lsass dump"]
        mbi = MEMORY_BASIC_INFORMATION()
        address = 0
        max_address = 0x7FFFFFFF

        while address < max_address:
            res = ctypes.windll.kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not res:
                break
            if mbi.State == MEM_COMMIT and mbi.Protect in (PAGE_EXECUTE_READWRITE, PAGE_READWRITE):
                scan_size = min(mbi.RegionSize, 65536)
                buf = ctypes.create_string_buffer(scan_size)
                bytes_read = ctypes.c_size_t()
                if ctypes.windll.kernel32.ReadProcessMemory(handle, ctypes.c_void_p(address), buf, scan_size, ctypes.byref(bytes_read)):
                    mem_data = buf.raw[:bytes_read.value].lower()
                    for sig in signatures:
                        if sig in mem_data:
                            if "MALICIOUS_MEMORY_SIGNATURE" not in triggered_set:
                                score += CONFIG["points_memory_signature"]
                                triggered_set.add("MALICIOUS_MEMORY_SIGNATURE")
                                ctypes.windll.kernel32.CloseHandle(handle)
                                return score
            address += mbi.RegionSize
        ctypes.windll.kernel32.CloseHandle(handle)
    except Exception:
        pass
    return score