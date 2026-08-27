"""
=============================================================
  MODULES:
    [1] Network Reconnaissance   — Discover live hosts
    [2] Port Scanner (C++)       — Find open TCP ports
    [3] Malware Scanner          — File threat detection
    [4] Vulnerability Tracker    — CVE & patch checking
    [5] Secure Access Tester     — Password strength audit
    [6] Full Lab Run             — Run all modules
    [7] View Reports             — List saved reports
    [0] Exit
=============================================================

  ⚠  ETHICAL USE NOTICE:
  This tool is for EDUCATIONAL & DEFENSIVE use ONLY.
  Only scan/test systems you own or have permission to test.
  Unauthorized scanning is illegal and unethical.
=============================================================
"""

import os
import sys
import subprocess
import datetime

# Add project root to Python path so imports work
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# Import our modules
from modules.recon        import run_recon
from modules.malware_scan import run_malware_scan, create_test_file
from modules.vuln_tracker import run_vuln_tracker, list_all_cves
from modules.access_tester import run_access_tester

# Path to the compiled C++ port scanner
CPP_SCANNER = os.path.join(BASE_DIR, "cpp", "port_scanner.exe")
REPORT_DIR  = os.path.join(BASE_DIR, "reports")


# -----------------------------------------------
# COLOURS for terminal output
# -----------------------------------------------
class C:
    CYAN    = '\033[96m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    RED     = '\033[91m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    RESET   = '\033[0m'
    LINE    = "─" * 55


def cprint(text, colour=C.RESET):
    """Print with colour."""
    print(f"{colour}{text}{C.RESET}")


# -----------------------------------------------
# BANNER — printed at startup
# -----------------------------------------------
def print_banner():
    os.system("clear" if os.name != "nt" else "cls")
    cprint("""
 
[1]  Network Reconnaissance  (Ping Sweep)           
[2]  Port Scanner            (C++ — fast)           
[3]  Malware Scanner         (File hash check)     
[4]  Vulnerability Tracker   (CVE lookup)           
[5]  Secure Access Tester    (Password audit)       
[6]  Full Lab Run            (All modules)          
[7]  View Reports            (Saved outputs)        
[0]  Exit                                           
  
""", C.CYAN)
    cprint(f"  ⏱  {datetime.datetime.now().strftime('%A, %d %B %Y  —  %H:%M:%S')}\n", C.DIM)


# -----------------------------------------------
# MODULE 1: Network Reconnaissance
# -----------------------------------------------
def menu_recon():
    cprint("\n  ── MODULE 1: Network Reconnaissance ──", C.CYAN)
    print("  Discovers live hosts by sending ICMP ping requests.")
    print("  ⚠  Only scan your OWN network.\n")

    print("  [1] Quick test (localhost only — safe demo)")
    print("  [2] Custom IP range")
    choice = input("\n  Choose: ").strip()

    if choice == "1":
        print("\n  [*] Scanning localhost (127.0.0.1)...")
        run_recon("127.0.0.1", "127.0.0.1")

    elif choice == "2":
        start = input("  Start IP (e.g. 192.168.1.1): ").strip()
        end   = input("  End   IP (e.g. 192.168.1.20): ").strip()
        if start and end:
            run_recon(start, end)
        else:
            cprint("  [!] Invalid input.", C.RED)
    else:
        cprint("  [!] Invalid choice.", C.RED)


# -----------------------------------------------
# MODULE 2: Port Scanner (C++)
# -----------------------------------------------
def menu_port_scanner():
    cprint("\n  ── MODULE 2: Port Scanner (C++) ──", C.CYAN)
    print("  Scans a target IP for open TCP ports.")
    print("  C++ is used for speed — scans with multiple threads.\n")

    # Check if the binary is compiled
    if not os.path.isfile(CPP_SCANNER):
        cprint("  [!] C++ port scanner not compiled yet!", C.RED)
        cprint("  Run this first:\n", C.YELLOW)
        print("      cd cpp/")
        print("      make")
        print("      cd ..\n")
        build_now = input("  Try to build it now? (y/n): ").strip().lower()
        if build_now == "y":
            _build_cpp_scanner()
            if not os.path.isfile(CPP_SCANNER):
                cprint("  [!] Build failed. Please check g++ is installed.", C.RED)
                return
        else:
            return

    print("  [1] Scan localhost — top 1024 ports (safe demo)")
    print("  [2] Custom target and port range")
    choice = input("\n  Choose: ").strip()

    if choice == "1":
        target = "127.0.0.1"
        start  = "1"
        end    = "1024"
    elif choice == "2":
        target = input("  Target IP : ").strip()
        start  = input("  Start port (e.g. 1)    : ").strip()
        end    = input("  End   port (e.g. 1024) : ").strip()
        if not target or not start or not end:
            cprint("  [!] Invalid input.", C.RED)
            return
    else:
        cprint("  [!] Invalid choice.", C.RED)
        return

    print(f"\n  [*] Launching C++ port scanner...")
    print(f"  [*] Target: {target}  Ports: {start}–{end}\n")

    try:
        # Call the compiled C++ binary from Python
        result = subprocess.run(
            [CPP_SCANNER, target, start, end],
            cwd=BASE_DIR
        )
    except FileNotFoundError:
        cprint("  [!] C++ scanner binary not found. Please compile it.", C.RED)
    except KeyboardInterrupt:
        print("\n  [!] Scan interrupted by user.")


def _build_cpp_scanner():
    """Attempt to compile the C++ port scanner."""
    cprint("  [*] Compiling C++ port scanner...", C.YELLOW)
    cpp_dir = os.path.join(BASE_DIR, "cpp")
    try:
        result = subprocess.run(
            ["make"],
            cwd=cpp_dir,
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            cprint("  [✓] Compiled successfully!", C.GREEN)
        else:
            cprint(f"  [!] Build error:\n{result.stderr}", C.RED)
    except FileNotFoundError:
        cprint("  [!] 'make' or 'g++' not found. Install build-essential.", C.RED)


# -----------------------------------------------
# MODULE 3: Malware Scanner
# -----------------------------------------------
def menu_malware_scan():
    cprint("\n  ── MODULE 3: Malware Scanner ──", C.CYAN)
    print("  Scans files for known malware using SHA-256 signatures.")
    print("  Works like a mini antivirus engine.\n")

    print("  [1] Demo scan (scan the data/ folder with a test threat)")
    print("  [2] Scan a custom directory")
    print("  [3] View signature database info")
    choice = input("\n  Choose: ").strip()

    if choice == "1":
        data_dir = os.path.join(BASE_DIR, "data")
        cprint("\n  [*] Creating a harmless test threat file first...", C.YELLOW)
        create_test_file()
        print(f"\n  [*] Scanning: {data_dir}")
        run_malware_scan(data_dir)

    elif choice == "2":
        target = input("  Enter directory path to scan: ").strip()
        if os.path.isdir(target):
            run_malware_scan(target)
        else:
            cprint(f"  [!] Directory not found: {target}", C.RED)

    elif choice == "3":
        import json
        sig_file = os.path.join(BASE_DIR, "data", "malware_signatures.json")
        with open(sig_file) as f:
            data = json.load(f)
        sigs = data.get("signatures", [])
        print(f"\n  Loaded {len(sigs)} signatures:\n")
        print(f"  {'Name':<30} {'Type':<15} {'Severity'}")
        print("  " + "-"*60)
        for s in sigs:
            print(f"  {s['name']:<30} {s['type']:<15} {s['severity']}")
    else:
        cprint("  [!] Invalid choice.", C.RED)


# -----------------------------------------------
# MODULE 4: Vulnerability Tracker
# -----------------------------------------------
def menu_vuln_tracker():
    cprint("\n  ── MODULE 4: Vulnerability Tracker ──", C.CYAN)
    print("  Checks software versions against known CVEs.")
    print("  Tells you what needs to be patched and why.\n")

    print("  [1] Run demo scan (common vulnerable software)")
    print("  [2] Check specific software")
    print("  [3] Browse CVE database")
    choice = input("\n  Choose: ").strip()

    if choice == "1":
        run_vuln_tracker()  # Uses built-in demo list

    elif choice == "2":
        software_list = []
        print("\n  Enter software to check (type 'done' when finished):\n")
        while True:
            name = input("  Software name (or 'done'): ").strip()
            if name.lower() == "done":
                break
            version = input(f"  Version of {name}: ").strip()
            if name and version:
                software_list.append({"name": name, "version": version})

        if software_list:
            run_vuln_tracker(software_list)
        else:
            cprint("  [!] No software entered.", C.YELLOW)

    elif choice == "3":
        print("\n  All CVEs in database:\n")
        list_all_cves()
    else:
        cprint("  [!] Invalid choice.", C.RED)


# -----------------------------------------------
# MODULE 5: Secure Access Tester
# -----------------------------------------------
def menu_access_tester():
    cprint("\n  ── MODULE 5: Secure Access Tester ──", C.CYAN)
    print("  Analyses password strength using OWASP guidelines")
    print("  and entropy calculations. Nothing is stored.\n")
    run_access_tester()


# -----------------------------------------------
# MODULE 6: Full Lab Run
# -----------------------------------------------
def full_lab_run():
    cprint("\n" + "="*58, C.CYAN)
    cprint("  🛡  CYBERSHIELD LAB — FULL RUN", C.BOLD)
    cprint("  Running all 5 modules in sequence...", C.DIM)
    cprint("="*58 + "\n", C.CYAN)

    results_summary = {}
    start_time = datetime.datetime.now()

    # ── 1. Recon ──
    cprint("\n  ▶ MODULE 1: Reconnaissance", C.GREEN)
    hosts = run_recon("127.0.0.1", "127.0.0.1")
    results_summary["recon"] = f"{len(hosts)} live host(s) found"

    # ── 2. Port Scan ──
    cprint("\n  ▶ MODULE 2: Port Scanning (C++)", C.GREEN)
    if os.path.isfile(CPP_SCANNER):
        subprocess.run([CPP_SCANNER, "127.0.0.1", "1", "1024"], cwd=BASE_DIR)
        results_summary["ports"] = "Port scan complete (see report)"
    else:
        cprint("  [!] C++ scanner not compiled. Skipping. (Run: cd cpp && make)", C.YELLOW)
        results_summary["ports"] = "Skipped — not compiled"

    # ── 3. Malware Scan ──
    cprint("\n  ▶ MODULE 3: Malware Scanner", C.GREEN)
    create_test_file()
    scan_result = run_malware_scan(os.path.join(BASE_DIR, "data"))
    results_summary["malware"] = f"{scan_result.get('threats', 0)} threat(s) detected"

    # ── 4. Vulnerability Tracker ──
    cprint("\n  ▶ MODULE 4: Vulnerability Tracker", C.GREEN)
    vulns = run_vuln_tracker()
    results_summary["vulns"] = f"{len(vulns)} CVE(s) matched"

    # ── 5. Access Test ──
    cprint("\n  ▶ MODULE 5: Secure Access Tester", C.GREEN)
    print("  [*] Running automated sample password tests...")
    from modules.access_tester import analyse_password, display_result
    samples = ["admin", "Babcock@2026!IT", "X#9mK!2vL@pQ3n"]
    for pwd in samples:
        r = analyse_password(pwd)
        print(f"  {r['strength_icon']}  {'*'*8} ({len(pwd)} chars) — "
              f"{r['strength']} — Score: {r['score']}/100 — "
              f"Entropy: {r['entropy_bits']} bits")
    results_summary["access"] = f"{len(samples)} passwords tested"

    # ── Final Report ──
    elapsed = (datetime.datetime.now() - start_time).seconds

    cprint(f"\n{'='*58}", C.CYAN)
    cprint(f"  🛡  FULL LAB RUN COMPLETE", C.BOLD)
    cprint(f"  Duration: {elapsed} seconds", C.DIM)
    cprint(f"{'='*58}", C.CYAN)
    print()
    for module, result in results_summary.items():
        cprint(f"  ✅ {module.upper():<12} : {result}", C.GREEN)
    print()
    cprint(f"  All reports saved to: {REPORT_DIR}/", C.DIM)


# -----------------------------------------------
# MODULE 7: View Reports
# -----------------------------------------------
def view_reports():
    cprint("\n  ── Saved Reports ──", C.CYAN)
    os.makedirs(REPORT_DIR, exist_ok=True)
    files = sorted(os.listdir(REPORT_DIR))

    if not files:
        cprint("  [*] No reports yet. Run a module to generate one.", C.YELLOW)
        return

    print(f"\n  Found {len(files)} report(s) in {REPORT_DIR}:\n")
    for i, fname in enumerate(files, 1):
        fpath   = os.path.join(REPORT_DIR, fname)
        fsize   = os.path.getsize(fpath)
        fmod    = datetime.datetime.fromtimestamp(os.path.getmtime(fpath))
        print(f"  [{i:>2}] {fname:<45} {fsize:>6} bytes  {fmod.strftime('%d %b %Y %H:%M')}")

    choice = input("\n  Enter report number to view (or Enter to skip): ").strip()
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(files):
            fpath = os.path.join(REPORT_DIR, files[idx])
            print(f"\n{'='*58}")
            with open(fpath, "r") as f:
                print(f.read())
            print(f"{'='*58}")
        else:
            cprint("  [!] Invalid selection.", C.RED)


# -----------------------------------------------
# MAIN LOOP
# -----------------------------------------------
def main():
    while True:
        print_banner()
        choice = input("  Select module [0–7]: ").strip()

        if choice == "1":
            menu_recon()
        elif choice == "2":
            menu_port_scanner()
        elif choice == "3":
            menu_malware_scan()
        elif choice == "4":
            menu_vuln_tracker()
        elif choice == "5":
            menu_access_tester()
        elif choice == "6":
            full_lab_run()
        elif choice == "7":
            view_reports()
        elif choice == "0":
            cprint("\n  [*] Exiting CyberShield Lab. Stay secure! 🛡\n", C.GREEN)
            sys.exit(0)
        else:
            cprint("  [!] Invalid option. Choose 0–7.", C.RED)

        input("\n  Press Enter to return to menu...")


# -----------------------------------------------
# ENTRY POINT
# -----------------------------------------------
if __name__ == "__main__":
    main()
