"""
=============================================================
CyberShield Lab — Module 4: Secure Access Tester
=============================================================
File    : modules/access_tester.py
Author  : Ajayi Joshua Abayomi | Babcock University 300L IT

PURPOSE:
  Weak passwords and poor credential management are the
  #1 cause of data breaches worldwide. This module tests:

  1. PASSWORD STRENGTH ANALYSIS
     → How hard is a password to crack?
     → Does it follow NIST/OWASP password guidelines?

  2. COMMON PASSWORD CHECK
     → Is the password in the top 50 most-used passwords?
     → Attackers try these FIRST in any attack.

  3. PASSWORD ENTROPY CALCULATION
     → Entropy measures unpredictability in bits.
     → Higher entropy = harder to brute force.
     → Formula: E = L × log2(R)
       where L = password length, R = character set size

  4. BRUTE FORCE TIME ESTIMATE
     → How long would it take a modern attacker to crack
       this password by trying all combinations?

REAL-WORLD USE:
  Security auditors use tools like Hashcat, John the Ripper,
  and Hydra to test passwords. This module simulates the
  ANALYTICAL side of that process — showing you WHY a
  password is weak without actually cracking anything.

KEY CONCEPT — OWASP Password Policy:
  OWASP recommends passwords should:
  ✓ Be at least 12 characters long
  ✓ Contain uppercase + lowercase letters
  ✓ Contain numbers
  ✓ Contain special characters
  ✓ NOT be a common/dictionary word
  ✓ NOT contain the username
=============================================================
"""

import os         # File paths
import math       # log2() for entropy calculation
import string     # Character sets
import re         # Regular expressions for pattern checking
import datetime   # Timestamps
import hashlib    # For simulating hash checking


# -----------------------------------------------
# CONSTANTS
# -----------------------------------------------
BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
DATA_DIR  = os.path.join(BASE_DIR, "..", "data")
REPORT_DIR= os.path.join(BASE_DIR, "..", "reports")
PWLIST    = os.path.join(DATA_DIR, "common_passwords.txt")

# Attacker assumptions (modern GPU cracking speed)
# A mid-range GPU can try ~1 billion hashes per second
# bcrypt (a good password hash) reduces this to ~20,000/sec
HASH_RATE_FAST = 1_000_000_000  # MD5/SHA (weak hashing) — per second
HASH_RATE_SLOW = 20_000         # bcrypt (strong hashing) — per second


# -----------------------------------------------
# LOAD COMMON PASSWORDS LIST
# -----------------------------------------------
def load_common_passwords() -> set:
    """
    Load the list of commonly used weak passwords.
    Returns a set (for O(1) lookup speed).
    """
    try:
        with open(PWLIST, "r") as f:
            passwords = set(line.strip().lower() for line in f if line.strip())
        return passwords
    except FileNotFoundError:
        # Fallback to a tiny built-in list
        return {"password", "123456", "admin", "qwerty", "letmein"}


# -----------------------------------------------
# CALCULATE CHARACTER SET SIZE
# Used in entropy formula
# -----------------------------------------------
def get_charset_size(password: str) -> int:
    """
    Determine the size of the character pool used.

    Larger pool = more possible combinations = stronger.
    Lower case only (a-z)         → 26
    + Upper case (A-Z)            → +26 = 52
    + Digits (0-9)                → +10 = 62
    + Special (!@#$ etc.)         → +32 = 94
    """
    size = 0
    if re.search(r'[a-z]', password): size += 26
    if re.search(r'[A-Z]', password): size += 26
    if re.search(r'\d', password):    size += 10
    if re.search(r'[^a-zA-Z0-9]', password): size += 32
    return max(size, 1)  # Avoid log(0)


# -----------------------------------------------
# CALCULATE ENTROPY
# -----------------------------------------------
def calculate_entropy(password: str) -> float:
    """
    Calculate the entropy of a password in bits.

    Formula: E = len(password) × log2(charset_size)

    Entropy guide:
      < 28 bits  → Very Weak  (cracked in seconds)
      28-35 bits → Weak       (cracked in minutes)
      36-59 bits → Moderate   (cracked in hours/days)
      60-127 bits→ Strong     (cracked in years)
      128+ bits  → Very Strong (practically uncrackable)
    """
    charset_size = get_charset_size(password)
    entropy      = len(password) * math.log2(charset_size)
    return round(entropy, 2)


# -----------------------------------------------
# ESTIMATE BRUTE FORCE TIME
# -----------------------------------------------
def estimate_crack_time(entropy_bits: float) -> dict:
    """
    Estimate how long a brute-force attack would take.

    Total possible combinations = 2^entropy_bits
    Time = combinations / attempts_per_second

    We calculate for BOTH weak hashing (MD5) and
    strong hashing (bcrypt) to show why the HASH TYPE
    matters as much as the password itself.
    """
    combinations = 2 ** entropy_bits

    # Time in seconds
    time_fast = combinations / HASH_RATE_FAST  # Weak hash
    time_slow = combinations / HASH_RATE_SLOW  # Strong hash (bcrypt)

    def format_time(seconds: float) -> str:
        """Convert seconds into a human-readable string."""
        if seconds < 1:
            return "< 1 second"
        elif seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        elif seconds < 3153600000:
            return f"{seconds/31536000:.1f} years"
        else:
            return "Billions of years (uncrackable)"

    return {
        "combinations": int(combinations),
        "with_md5":     format_time(time_fast),
        "with_bcrypt":  format_time(time_slow),
    }


# -----------------------------------------------
# MAIN STRENGTH ANALYSER
# -----------------------------------------------
def analyse_password(password: str, username: str = "") -> dict:
    """
    Full OWASP-compliant password strength analysis.

    Parameters:
        password : The password to analyse
        username : Optional — check if password contains username

    Returns:
        Dict with score, issues, suggestions, and entropy
    """
    common_passwords = load_common_passwords()

    issues      = []   # List of problems found
    suggestions = []   # What to do to fix them
    score       = 0    # Out of 100

    # ---- CHECK 1: Length ----
    # NIST recommends at least 12 characters
    if len(password) >= 16:
        score += 25
    elif len(password) >= 12:
        score += 18
    elif len(password) >= 8:
        score += 10
        issues.append("Password is shorter than 12 characters.")
        suggestions.append("Use at least 12 characters (16+ is better).")
    else:
        score += 0
        issues.append("Password is dangerously short (< 8 characters).")
        suggestions.append("Use at least 12 characters.")

    # ---- CHECK 2: Uppercase letters ----
    if re.search(r'[A-Z]', password):
        score += 15
    else:
        issues.append("No uppercase letters.")
        suggestions.append("Add at least one uppercase letter (A-Z).")

    # ---- CHECK 3: Lowercase letters ----
    if re.search(r'[a-z]', password):
        score += 15
    else:
        issues.append("No lowercase letters.")
        suggestions.append("Add at least one lowercase letter (a-z).")

    # ---- CHECK 4: Numbers ----
    if re.search(r'\d', password):
        score += 15
    else:
        issues.append("No numbers.")
        suggestions.append("Include at least one number (0-9).")

    # ---- CHECK 5: Special characters ----
    if re.search(r'[^a-zA-Z0-9]', password):
        score += 15
    else:
        issues.append("No special characters.")
        suggestions.append("Add symbols like !@#$%^&*.")

    # ---- CHECK 6: Common passwords list ----
    if password.lower() in common_passwords:
        score -= 40
        issues.append("Password is in the TOP COMMON PASSWORDS list!")
        suggestions.append("Never use dictionary words or well-known passwords.")

    # ---- CHECK 7: Repeating characters ----
    if re.search(r'(.)\1{2,}', password):
        score -= 10
        issues.append("Password has repeating characters (e.g. 'aaa' or '111').")
        suggestions.append("Avoid sequences of the same character.")

    # ---- CHECK 8: Sequential patterns ----
    if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|qwe|wer)', password.lower()):
        score -= 10
        issues.append("Password contains predictable sequences (123, abc, qwe).")
        suggestions.append("Avoid keyboard patterns and number sequences.")

    # ---- CHECK 9: Username in password ----
    if username and username.lower() in password.lower():
        score -= 15
        issues.append("Password contains your username — easily guessable.")
        suggestions.append("Never include your name or username in your password.")

    # Clamp score between 0 and 100
    score = max(0, min(100, score))

    # ---- ENTROPY ----
    entropy = calculate_entropy(password)
    crack   = estimate_crack_time(entropy)

    # ---- STRENGTH LABEL ----
    if score >= 80:
        strength = "VERY STRONG"
        strength_icon = "🟢"
    elif score >= 60:
        strength = "STRONG"
        strength_icon = "🟡"
    elif score >= 40:
        strength = "MODERATE"
        strength_icon = "🟠"
    else:
        strength = "WEAK"
        strength_icon = "🔴"

    return {
        "password":       password,
        "score":          score,
        "strength":       strength,
        "strength_icon":  strength_icon,
        "entropy_bits":   entropy,
        "charset_size":   get_charset_size(password),
        "length":         len(password),
        "issues":         issues,
        "suggestions":    suggestions,
        "crack_time":     crack,
        "is_common":      password.lower() in common_passwords
    }


# -----------------------------------------------
# DISPLAY RESULTS — nicely formatted
# -----------------------------------------------
def display_result(result: dict):
    """Pretty-print a password analysis result."""
    print(f"\n  {'='*55}")
    print(f"  PASSWORD ANALYSIS RESULT")
    print(f"  {'='*55}")
    print(f"  Password   : {'*' * min(len(result['password']), 8)}  (masked)")
    print(f"  Length     : {result['length']} characters")
    print(f"  Charset    : {result['charset_size']} possible characters")
    print(f"  Entropy    : {result['entropy_bits']} bits")
    print(f"  Score      : {result['score']}/100")
    print(f"  Strength   : {result['strength_icon']}  {result['strength']}")

    print(f"\n  ── Estimated Crack Time ──────────────────────")
    print(f"  With MD5 (weak hash)  : {result['crack_time']['with_md5']}")
    print(f"  With bcrypt (strong)  : {result['crack_time']['with_bcrypt']}")
    print(f"  [!] This shows why how you STORE passwords matters!")

    if result["issues"]:
        print(f"\n  ── Issues Found ({len(result['issues'])}) ─────────────────────")
        for i, issue in enumerate(result["issues"], 1):
            print(f"  {i}. ❌ {issue}")

    if result["suggestions"]:
        print(f"\n  ── How to Improve ──────────────────────────")
        for s in result["suggestions"]:
            print(f"     ✅ {s}")

    if not result["issues"]:
        print(f"\n  ── ✅ No issues found! This is a strong password.")

    print(f"  {'='*55}")


# -----------------------------------------------
# MAIN FUNCTION: Interactive access tester
# -----------------------------------------------
def run_access_tester():
    """
    Main entry point for the access tester module.
    Lets user test multiple passwords interactively.
    """
    print("\n" + "="*55)
    print("  MODULE 4: SECURE ACCESS TESTER")
    print("="*55)
    print("  This module analyses password strength using")
    print("  OWASP security guidelines and entropy math.\n")
    print("  [!] Passwords are NOT stored or transmitted.")
    print("  [!] They are analysed locally and discarded.\n")
    print("-"*55)

    results    = []
    test_count = 0

    while True:
        print(f"\n  Options:")
        print(f"  [1] Test a password")
        print(f"  [2] Test multiple passwords from a list")
        print(f"  [3] View best practices")
        print(f"  [4] Return to main menu")

        choice = input("\n  Your choice: ").strip()

        if choice == "1":
            # Mask input — don't echo to screen
            try:
                import getpass
                pwd = getpass.getpass("  Enter password to test (hidden): ")
            except Exception:
                pwd = input("  Enter password to test: ")

            username = input("  Enter username (optional, press Enter to skip): ").strip()
            result   = analyse_password(pwd, username)
            display_result(result)
            results.append(result)
            test_count += 1

        elif choice == "2":
            # Test a pre-defined sample list (demo mode)
            sample_passwords = [
                "password",
                "Joshua1990",
                "MyD0g$N@meIsMax!",
                "X#9mK!2vL@pQ3n",
                "qwerty123",
                "Babcock@2026!IT"
            ]
            print(f"\n  [*] Testing {len(sample_passwords)} sample passwords...\n")
            for pwd in sample_passwords:
                result = analyse_password(pwd)
                print(f"  {result['strength_icon']} {result['strength']:<12} "
                      f"Score: {result['score']:>3}/100  "
                      f"Entropy: {result['entropy_bits']:>6} bits  "
                      f"→  {'*'*8} ({len(pwd)} chars)")
                results.append(result)

            print(f"\n  [*] Run option [1] to see full analysis for any password.")

        elif choice == "3":
            _show_best_practices()

        elif choice == "4":
            break

        else:
            print("  [!] Invalid choice. Try again.")

    # Save report if any tests were done
    if results:
        _save_access_report(results)

    return results


# -----------------------------------------------
# BEST PRACTICES
# -----------------------------------------------
def _show_best_practices():
    """Display OWASP/NIST password best practices."""
    print(f"\n  {'='*55}")
    print(f"  OWASP/NIST PASSWORD BEST PRACTICES")
    print(f"  {'='*55}")
    practices = [
        ("✅", "Use at least 12 characters (16+ strongly recommended)"),
        ("✅", "Mix uppercase, lowercase, numbers, and symbols"),
        ("✅", "Use a passphrase: 'BlueHorse$Runs@Night' is strong"),
        ("✅", "Use a password manager (Bitwarden, KeePass, 1Password)"),
        ("✅", "Enable Two-Factor Authentication (2FA) everywhere"),
        ("✅", "Use a UNIQUE password for every account"),
        ("❌", "Never use: your name, birthday, or username"),
        ("❌", "Never use: 'password', '123456', 'qwerty'"),
        ("❌", "Never reuse passwords across multiple sites"),
        ("❌", "Never share passwords via WhatsApp, email, or SMS"),
        ("❌", "Never save passwords in plain text files"),
    ]
    for icon, tip in practices:
        print(f"  {icon}  {tip}")
    print(f"  {'='*55}\n")


# -----------------------------------------------
# REPORT WRITER
# -----------------------------------------------
def _save_access_report(results: list):
    """Save access testing results to a file."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(REPORT_DIR, exist_ok=True)
    filepath  = os.path.join(REPORT_DIR, f"access_test_{timestamp}.txt")

    with open(filepath, "w") as f:
        f.write("="*55 + "\n")
        f.write(" CyberShield Lab — Access Test Report\n")
        f.write(" Author: Ajayi Joshua Abayomi\n")
        f.write(" Babcock University, 300L IT\n")
        f.write("="*55 + "\n\n")
        f.write(f"Timestamp      : {datetime.datetime.now()}\n")
        f.write(f"Passwords Tested: {len(results)}\n\n")
        f.write("-"*55 + "\n")

        for i, r in enumerate(results, 1):
            f.write(f"\n  Test #{i}\n")
            f.write(f"  Strength : {r['strength']} ({r['score']}/100)\n")
            f.write(f"  Length   : {r['length']}\n")
            f.write(f"  Entropy  : {r['entropy_bits']} bits\n")
            f.write(f"  Issues   : {len(r['issues'])}\n")
            if r['issues']:
                for iss in r['issues']:
                    f.write(f"    - {iss}\n")

        f.write("\n" + "="*55 + "\n")

    print(f"\n  [+] Access test report saved: {filepath}")
