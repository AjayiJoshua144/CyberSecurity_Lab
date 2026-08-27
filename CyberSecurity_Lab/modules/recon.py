"""
=============================================================
CyberShield Lab — Module 1: Network Reconnaissance
=============================================================
File    : modules/recon.py
Author  : Ajayi Joshua Abayomi | Babcock University 300L IT

PURPOSE:
  Network reconnaissance is the very FIRST step an attacker
  (or defender) takes. Before doing anything else, you need
  to know which machines are alive on the network.

  This module performs a "ping sweep" — it sends ICMP echo
  requests (pings) to a range of IP addresses and reports
  back which ones responded (are ALIVE/ONLINE).

HOW IT WORKS:
  1. User provides a network range (e.g. 192.168.1.1 to .50)
  2. We send one ping to each IP address
  3. If the machine responds → it's LIVE
  4. We collect and display all live hosts

REAL-WORLD USE:
  Defenders use this to audit what devices are on their
  network. Unknown devices could be rogue machines or
  intruders. This is Step 1 of any penetration test too.

ETHICAL NOTICE: Only scan networks you own or are authorised
to test. Default target is localhost (127.0.0.1).
=============================================================
"""

import subprocess   # To run system ping commands
import ipaddress    # To handle IP address ranges cleanly
import socket       # To resolve hostnames from IPs
import platform     # To detect OS (ping syntax differs)
import datetime     # For timestamps in reports
import os           # File paths
from concurrent.futures import ThreadPoolExecutor, as_completed
# ThreadPoolExecutor lets us scan multiple IPs at the same time
# instead of one-by-one (much faster!)


# -----------------------------------------------
# HELPER: Ping a single IP address
# Returns True if alive, False if no response
# -----------------------------------------------
def ping_host(ip: str) -> bool:
    """
    Send one ICMP ping to an IP address.

    On Linux/macOS: ping -c 1 -W 1 <ip>
    On Windows:     ping -n 1 -w 1000 <ip>

    -c 1 / -n 1 = send only ONE packet
    -W 1 / -w 1000 = wait max 1 second for reply
    """
    # Detect operating system — ping syntax is different
    os_name = platform.system().lower()

    if os_name == "windows":
        cmd = ["ping", "-n", "1", "-w", "1000", str(ip)]
    else:
        # Linux and macOS
        cmd = ["ping", "-c", "1", "-W", "1", str(ip)]

    try:
        # Run the ping command
        # stdout=subprocess.DEVNULL hides the raw ping output
        # stderr=subprocess.DEVNULL hides error messages
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3  # Kill it if it hangs beyond 3 seconds
        )
        # Return code 0 = success = host replied
        return result.returncode == 0

    except subprocess.TimeoutExpired:
        return False   # Host didn't respond in time
    except Exception:
        return False   # Something else went wrong


# -----------------------------------------------
# HELPER: Reverse DNS lookup
# Tries to find the hostname of an IP address
# (e.g. 192.168.1.1 → "router.local")
# -----------------------------------------------
def get_hostname(ip: str) -> str:
    """Try to resolve an IP to a hostname."""
    try:
        hostname = socket.gethostbyaddr(str(ip))[0]
        return hostname
    except socket.herror:
        return "Unknown"  # No DNS record found


# -----------------------------------------------
# MAIN FUNCTION: Scan a range of IP addresses
# -----------------------------------------------
def run_recon(start_ip: str = "127.0.0.1",
              end_ip: str   = "127.0.0.1",
              max_workers:  int = 20) -> list:
    """
    Perform a ping sweep from start_ip to end_ip.

    Parameters:
        start_ip    : First IP to scan (e.g. "192.168.1.1")
        end_ip      : Last IP to scan  (e.g. "192.168.1.50")
        max_workers : How many IPs to scan simultaneously

    Returns:
        List of dicts with info about live hosts
    """

    print("\n" + "="*55)
    print("  MODULE 1: NETWORK RECONNAISSANCE (Ping Sweep)")
    print("="*55)
    print(f"  Range    : {start_ip}  →  {end_ip}")
    print(f"  Workers  : {max_workers} concurrent threads")
    print(f"  Started  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-"*55)

    # Build the list of all IPs in the range
    try:
        start = ipaddress.ip_address(start_ip)
        end   = ipaddress.ip_address(end_ip)
    except ValueError as e:
        print(f"  [ERROR] Invalid IP address: {e}")
        return []

    # Collect all IPs into a list
    ip_list = []
    current = int(start)
    while current <= int(end):
        ip_list.append(str(ipaddress.ip_address(current)))
        current += 1

    print(f"  Total IPs to probe: {len(ip_list)}\n")

    live_hosts = []    # Will store results
    scanned    = 0     # Progress counter

    # Use ThreadPoolExecutor to scan multiple IPs in parallel
    # This is MUCH faster than a simple for loop
    with ThreadPoolExecutor(max_workers=max_workers) as executor:

        # Submit all ping tasks at once
        future_to_ip = {
            executor.submit(ping_host, ip): ip
            for ip in ip_list
        }

        # Process results as they come in
        for future in as_completed(future_to_ip):
            ip      = future_to_ip[future]
            is_live = future.result()
            scanned += 1

            # Show progress every 10 hosts or on last host
            if scanned % 10 == 0 or scanned == len(ip_list):
                pct = (scanned / len(ip_list)) * 100
                print(f"  [*] Progress: {scanned}/{len(ip_list)} ({pct:.0f}%)", end="\r")

            if is_live:
                hostname = get_hostname(ip)
                host_info = {
                    "ip":       ip,
                    "hostname": hostname,
                    "status":   "LIVE",
                    "time":     datetime.datetime.now().strftime("%H:%M:%S")
                }
                live_hosts.append(host_info)
                print(f"\n  [LIVE] {ip:<18} Hostname: {hostname}")

    print(f"\n\n{'='*55}")
    print(f"  Recon Complete!")
    print(f"  Total scanned : {len(ip_list)}")
    print(f"  Live hosts    : {len(live_hosts)}")
    print(f"  Dead/Silent   : {len(ip_list) - len(live_hosts)}")
    print("="*55)

    # Save report
    _save_recon_report(live_hosts, start_ip, end_ip)

    return live_hosts


# -----------------------------------------------
# REPORT: Save results to a text file
# -----------------------------------------------
def _save_recon_report(hosts: list, start: str, end: str):
    """Write reconnaissance results to a report file."""

    timestamp  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = os.path.join(os.path.dirname(__file__), "..", "reports")
    os.makedirs(report_dir, exist_ok=True)
    filepath   = os.path.join(report_dir, f"recon_{timestamp}.txt")

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("="*55 + "\n")
        f.write(" CyberShield Lab — Reconnaissance Report\n")
        f.write(" Author: Ajayi Joshua Abayomi\n")
        f.write(" Babcock University, 300L IT\n")
        f.write("="*55 + "\n\n")
        f.write(f"Scan Range   : {start} -> {end}\n")
        f.write(f"Timestamp    : {datetime.datetime.now()}\n")
        f.write(f"Live Hosts   : {len(hosts)}\n\n")
        f.write("-"*55 + "\n")
        f.write(f"{'IP Address':<20} {'Hostname':<25} Status\n")
        f.write("-"*55 + "\n")

        if not hosts:
            f.write("  No live hosts found.\n")
        else:
            for h in hosts:
                f.write(f"  {h['ip']:<18} {h['hostname']:<25} {h['status']}\n")

        f.write("\n" + "="*55 + "\n")

    print(f"\n  [+] Recon report saved: {filepath}")
