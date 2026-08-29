import time
from pathlib import Path
from config import CONFIG, COLOR_RESET, COLOR_BOLD, COLOR_GREEN, COLOR_YELLOW, COLOR_RED, COLOR_CYAN, COLOR_GRAY, COLOR_BG_RED

def get_quarantine_count():
    try:
        q_dir = Path("./EDR_Quarantine")
        if q_dir.exists():
            return len(list(q_dir.glob("*.vir")))
    except Exception:
        pass
    return 0

def show_startup_screen(is_admin):
    print("\033[H\033[2J", end="", flush=True)
    print(f"{COLOR_CYAN}================================================================================{COLOR_RESET}")
    print(f"{COLOR_BOLD}{COLOR_RED}")
    print("  ____  ______ _    _           _    _ _____ _    _")
    print(" |  _ \\|  ____| |  | |         | |  | |_   _| |  | |")
    print(" | |_) | |__  | |__| |  _____  | |  | | | | | |__| |")
    print(" |  _ <|  __| |  __  | |_____| | |/\\| | | | |  __  |")
    print(" | |_) | |____| |  | |         \\  /\\  /_| |_| |  | |")
    print(" |____/|______|_|  |_|          \\/  \\/|_____|_|  |_|")
    print(f"{COLOR_RESET}")
    print(f"{COLOR_BOLD}                 -- SECURITY TELEMETRY ENGINE INITIALIZING --{COLOR_RESET}")
    print(f"{COLOR_CYAN}================================================================================{COLOR_RESET}")
    print(f"{COLOR_GREEN}[+]{COLOR_RESET} Loading Configuration (config.json)... OK")
    print(f"{COLOR_GREEN}[+]{COLOR_RESET} Loading Detection Pipelines & Caching Engine... OK")
    admin_status = "SUCCESS" if is_admin else "LIMITED"
    admin_color = COLOR_GREEN if is_admin else COLOR_YELLOW
    print(f"{COLOR_GREEN}[+]{COLOR_RESET} Verifying Admin Privileges... {admin_color}{admin_status}{COLOR_RESET}")
    print(f"{COLOR_GREEN}[+]{COLOR_RESET} Ready. Launching Console Interface...")
    print(f"{COLOR_CYAN}================================================================================{COLOR_RESET}")
    time.sleep(0.5)

def draw_dashboard(process_state, terminated_log):
    print("\033[H\033[2J", end="", flush=True)
    print(f"{COLOR_BOLD}{COLOR_CYAN}================================================================================{COLOR_RESET}")
    print(f"{COLOR_BOLD}{COLOR_BG_RED}  BEHAVIOR-WATCH // ADVANCED HEURISTIC DETECTION & QUARANTINE ENGINE ACTIVE  {COLOR_RESET}")
    print(f"{COLOR_BOLD}{COLOR_CYAN}================================================================================{COLOR_RESET}")
    print(f"{COLOR_BOLD}System Status:{COLOR_RESET} {COLOR_GREEN}ONLINE{COLOR_RESET} | "
          f"{COLOR_BOLD}Scan Interval:{COLOR_RESET} {CONFIG['loop_interval']}s | "
          f"{COLOR_BOLD}Quarantined:{COLOR_RESET} {get_quarantine_count()} | "
          f"{COLOR_BOLD}Monitored PIDs:{COLOR_RESET} {len(process_state)}")
    print(f"{COLOR_GRAY}Press Ctrl+C to terminate the monitoring engine.{COLOR_RESET}")
    print(f"{COLOR_CYAN}--------------------------------------------------------------------------------{COLOR_RESET}")
    active_threats = [data for pid, data in process_state.items() if data["score"] > 0]
    active_threats = sorted(active_threats, key=lambda x: x["score"], reverse=True)
    print(f"{COLOR_BOLD}{'PID':<8} {'PROCESS NAME':<18} {'SCORE':<7} {'RISK LEVEL':<10} {'TRIGGERED EVENTS'}{COLOR_RESET}")
    print(f"{COLOR_GRAY}{'-'*80}{COLOR_RESET}")
    if not active_threats:
        print(f"\n{COLOR_GREEN}  [OK] All active processes behave within safety standards. No threats detected.{COLOR_RESET}\n")
    else:
        for item in active_threats[:10]:
            score = item["score"]
            if score >= 75:
                risk_color = COLOR_RED
                risk_lbl = "CRITICAL"
            elif score >= 40:
                risk_color = COLOR_YELLOW
                risk_lbl = "WARNING"
            else:
                risk_color = COLOR_GREEN
                risk_lbl = "SAFE"
            heuristics_str = ", ".join(item["heuristics"]) if item["heuristics"] else "None (Decaying)"
            truncated_name = item["name"][:18]
            print(f"{item['pid']:<8} {truncated_name:<18} {risk_color}{score:<7} {risk_lbl:<10}{COLOR_RESET} {COLOR_GRAY}{heuristics_str}{COLOR_RESET}")
    print(f"{COLOR_CYAN}--------------------------------------------------------------------------------{COLOR_RESET}")
    print(f"{COLOR_BOLD}Recent Mitigations:{COLOR_RESET}")
    if not terminated_log:
        print(f" {COLOR_GRAY}No processes mitigated during this session.{COLOR_RESET}")
    else:
        for item in terminated_log[-4:]:
            print(f" {COLOR_RED}[MITIGATED]{COLOR_RESET} {item['time']} - PID {item['pid']} ({item['name']}) "
                  f"quarantined & terminated. ({item['score']} pts).")
    print(f"{COLOR_CYAN}================================================================================{COLOR_RESET}")