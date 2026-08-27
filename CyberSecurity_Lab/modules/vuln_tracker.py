"""
=============================================================
CyberShield Lab — Module 3: Vulnerability Tracker
=============================================================
File    : modules/vuln_tracker.py
Author  : Ajayi Joshua Abayomi | Babcock University 300L IT

PURPOSE:
  A vulnerability tracker helps an analyst know WHAT
  software is running on a system and WHETHER that software
  has any KNOWN SECURITY HOLES (called CVEs).

  CVE = Common Vulnerabilities and Exposures
  Every publicly known vulnerability gets a unique ID like:
  CVE-2021-44228 (that's Log4Shell — one of the worst ever).

HOW IT WORKS:
  1. Load our local CVE database (in a real tool this would
     come from nvd.nist.gov via API)
  2. Ask the user what software and versions they're running
  3. Compare against the CVE database
  4. Report any matches with CVSS severity scores

CVSS SCORE:
  CVSS (Common Vulnerability Scoring System) gives each
  vulnerability a score from 0.0 to 10.0:
    9.0 – 10.0 → CRITICAL  (patch IMMEDIATELY)
    7.0 –  8.9 → HIGH      (patch urgently)
    4.0 –  6.9 → MEDIUM    (schedule patch)
    0.1 –  3.9 → LOW       (monitor)

REAL-WORLD USE:
  Security teams run vulnerability scanners like Nessus,
  Qualys, or OpenVAS regularly to catch these before
  attackers do. This module is a simplified version.
=============================================================
"""

import json        # Reading CVE database
import os          # File paths
import datetime    # Timestamps


# -----------------------------------------------
# CONSTANTS
# -----------------------------------------------
BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
DATA_DIR  = os.path.join(BASE_DIR, "..", "data")
REPORT_DIR= os.path.join(BASE_DIR, "..", "reports")
CVE_FILE  = os.path.join(DATA_DIR, "cve_database.json")


# -----------------------------------------------
# LOAD CVE DATABASE
# -----------------------------------------------
def load_cve_database() -> list:
    """
    Load vulnerability entries from our local JSON database.
    Returns a list of CVE dicts.
    """
    try:
        with open(CVE_FILE, "r") as f:
            data = json.load(f)
        vulns = data.get("vulnerabilities", [])
        print(f"  [*] Loaded {len(vulns)} CVE entries from database.")
        return vulns
    except FileNotFoundError:
        print(f"  [ERROR] CVE database not found: {CVE_FILE}")
        return []
    except json.JSONDecodeError:
        print("  [ERROR] CVE database is corrupted/invalid JSON.")
        return []


# -----------------------------------------------
# SEVERITY DISPLAY HELPER
# -----------------------------------------------
def severity_icon(score: float) -> str:
    """Return a visual indicator for CVSS score severity."""
    if score >= 9.0:
        return "🔴 CRITICAL"
    elif score >= 7.0:
        return "🟠 HIGH"
    elif score >= 4.0:
        return "🟡 MEDIUM"
    else:
        return "🟢 LOW"


# -----------------------------------------------
# CORE: Check if a software version is vulnerable
# -----------------------------------------------
def is_version_vulnerable(user_version: str,
                           vulnerable_versions: list) -> bool:
    """
    Check if the user's version is in the vulnerable list.

    This is a simple string-match check.
    Real scanners use semantic versioning comparison
    (e.g. "2.14.0" < "2.15.0") but string matching
    is easier to understand for a student project.

    Parameters:
        user_version         : e.g. "2.14.1"
        vulnerable_versions  : e.g. ["2.0", "2.1", ..., "2.14.1"]

    Returns True if vulnerable, False if safe.
    """
    user_version = user_version.strip().lower()
    for v in vulnerable_versions:
        if user_version == v.strip().lower():
            return True
    return False


# -----------------------------------------------
# SEARCH: Find CVEs for a specific software name
# -----------------------------------------------
def search_software(software_name: str, cve_db: list) -> list:
    """
    Find all CVEs that affect a given software.

    We do a case-insensitive partial match on the
    affected_software field.
    """
    name_lower = software_name.lower()
    matches = []
    for cve in cve_db:
        if name_lower in cve["affected_software"].lower():
            matches.append(cve)
    return matches


# -----------------------------------------------
# MAIN FUNCTION: Run vulnerability check
# -----------------------------------------------
def run_vuln_tracker(software_list: list = None) -> list:
    """
    Check a list of software packages for known CVEs.

    Parameters:
        software_list : List of dicts like:
                        [{"name": "Apache Log4j", "version": "2.14.1"},
                         {"name": "Linux Kernel",  "version": "5.10"}]
                        If None, uses a demo list.

    Returns:
        List of vulnerability findings
    """
    print("\n" + "="*58)
    print("  MODULE 3: CVE VULNERABILITY TRACKER")
    print("="*58)
    print(f"  Started  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-"*58)

    # Load CVE database
    cve_db = load_cve_database()
    if not cve_db:
        return []

    # Use demo list if none provided
    if software_list is None:
        software_list = [
            {"name": "Apache Log4j",         "version": "2.14.1"},
            {"name": "Linux Kernel",          "version": "5.10"},
            {"name": "Windows Print Spooler", "version": "Windows 10 pre-July 2021"},
            {"name": "Microsoft Outlook",     "version": "Outlook 2019"},
        ]
        print("\n  [*] Using demo software list (no input provided):\n")
        for s in software_list:
            print(f"      • {s['name']:<35} v{s['version']}")

    print(f"\n  [*] Checking {len(software_list)} software packages...\n")
    print("-"*58)

    findings = []

    for software in software_list:
        name    = software.get("name", "Unknown")
        version = software.get("version", "Unknown")

        print(f"\n  Checking: {name} (version: {version})")

        # Search for matching CVEs
        related_cves = search_software(name, cve_db)

        if not related_cves:
            print(f"  [✓] No CVEs found for '{name}' in our database.")
            print(f"      Note: Our DB is small. Check nvd.nist.gov for full coverage.")
            continue

        # Check each related CVE
        for cve in related_cves:
            vulnerable = is_version_vulnerable(version, cve["affected_versions"])

            if vulnerable:
                finding = {
                    "software":    name,
                    "version":     version,
                    "cve_id":      cve["cve_id"],
                    "cve_name":    cve["name"],
                    "cvss_score":  cve["cvss_score"],
                    "severity":    cve["severity"],
                    "description": cve["description"],
                    "remediation": cve["remediation"],
                    "fixed_in":    cve["fixed_version"]
                }
                findings.append(finding)

                # Display the finding
                print(f"\n  ┌─────────────────────────────────────────────┐")
                print(f"  │  ⚠  VULNERABILITY FOUND                      │")
                print(f"  ├─────────────────────────────────────────────┤")
                print(f"  │  CVE ID   : {cve['cve_id']:<35}│")
                print(f"  │  Name     : {cve['name']:<35}│")
                print(f"  │  CVSS     : {cve['cvss_score']:<5} {severity_icon(cve['cvss_score']):<28}│")
                print(f"  │  Fixed In : {cve['fixed_version']:<35}│")
                print(f"  ├─────────────────────────────────────────────┤")
                print(f"  │  Info: {cve['description'][:45]:<44}│")
                print(f"  │  Fix : {cve['remediation'][:45]:<44}│")
                print(f"  └─────────────────────────────────────────────┘")
            else:
                print(f"  [✓] {cve['cve_id']} — Version {version} is NOT affected.")

    # ---- Summary ----
    print(f"\n\n{'='*58}")
    print(f"  Vulnerability Scan Complete!")
    print(f"  Packages checked    : {len(software_list)}")
    print(f"  Vulnerabilities     : {len(findings)}")

    if findings:
        critical = sum(1 for f in findings if f["cvss_score"] >= 9.0)
        high     = sum(1 for f in findings if 7.0 <= f["cvss_score"] < 9.0)
        medium   = sum(1 for f in findings if 4.0 <= f["cvss_score"] < 7.0)

        print(f"\n  Breakdown:")
        print(f"  🔴 Critical : {critical}")
        print(f"  🟠 High     : {high}")
        print(f"  🟡 Medium   : {medium}")

        print(f"\n  PRIORITY ACTION:")
        # Sort findings by CVSS score (highest first)
        findings_sorted = sorted(findings, key=lambda x: x["cvss_score"], reverse=True)
        for f in findings_sorted:
            print(f"  [{severity_icon(f['cvss_score'])}] {f['cve_id']} — {f['software']}")
            print(f"       → Fix: {f['remediation'][:60]}")
    else:
        print(f"  [✓] No known vulnerabilities found in checked versions.")

    print("="*58)

    # Save report
    _save_vuln_report(findings, software_list)

    return findings


# -----------------------------------------------
# DISPLAY ALL CVEs IN DATABASE
# -----------------------------------------------
def list_all_cves():
    """Show all CVE entries currently in the database."""
    cve_db = load_cve_database()

    print(f"\n  {'CVE ID':<20} {'Name':<25} {'Software':<25} {'CVSS':<6} Severity")
    print("  " + "-"*90)

    for cve in sorted(cve_db, key=lambda x: x["cvss_score"], reverse=True):
        print(f"  {cve['cve_id']:<20} {cve['name']:<25} "
              f"{cve['affected_software']:<25} {cve['cvss_score']:<6} "
              f"{severity_icon(cve['cvss_score'])}")


# -----------------------------------------------
# REPORT WRITER
# -----------------------------------------------
def _save_vuln_report(findings: list, software: list):
    """Write vulnerability findings to a report file."""

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(REPORT_DIR, exist_ok=True)
    filepath  = os.path.join(REPORT_DIR, f"vuln_report_{timestamp}.txt")

    with open(filepath, "w") as f:
        f.write("="*58 + "\n")
        f.write(" CyberShield Lab — Vulnerability Report\n")
        f.write(" Author: Ajayi Joshua Abayomi\n")
        f.write(" Babcock University, 300L IT\n")
        f.write("="*58 + "\n\n")
        f.write(f"Timestamp   : {datetime.datetime.now()}\n")
        f.write(f"Packages    : {len(software)}\n")
        f.write(f"Findings    : {len(findings)}\n\n")

        if findings:
            f.write("-"*58 + "\n")
            f.write("VULNERABILITIES:\n")
            f.write("-"*58 + "\n")
            for find in sorted(findings, key=lambda x: x["cvss_score"], reverse=True):
                f.write(f"\n  Software   : {find['software']} v{find['version']}\n")
                f.write(f"  CVE ID     : {find['cve_id']}\n")
                f.write(f"  Name       : {find['cve_name']}\n")
                f.write(f"  CVSS Score : {find['cvss_score']} ({find['severity']})\n")
                f.write(f"  Fix        : {find['remediation']}\n")
        else:
            f.write("No vulnerabilities found.\n")

        f.write("\n" + "="*58 + "\n")

    print(f"\n  [+] Vulnerability report saved: {filepath}")
