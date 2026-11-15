"""Password Strength Checker - a beginner cybersecurity project.

Run:  python checker.py
"""
import getpass
import math
import re
import string
import sys
import warnings
from pathlib import Path

# ---------- SETTINGS (easy things to change) ----------
MIN_LENGTH = 12                      # recommended minimum length
COMMON_FILE = Path(__file__).with_name("common_passwords.txt")
SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
LEET = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t"})
# ------------------------------------------------------


def load_common(path=COMMON_FILE):
    """Load common passwords from a text file (one per line)."""
    try:
        return {line.strip().lower() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}
    except FileNotFoundError:
        return set()


COMMON = load_common()


def charset_size(pw):
    """Size of the character pool the password draws from."""
    size = 0
    if any(c in string.ascii_lowercase for c in pw):
        size += 26
    if any(c in string.ascii_uppercase for c in pw):
        size += 26
    if any(c in string.digits for c in pw):
        size += 10
    if any(c in string.punctuation or c == " " for c in pw):
        size += 33
    return size


def entropy_bits(pw):
    """Estimated entropy: length * log2(pool size). Higher = harder to guess."""
    size = charset_size(pw)
    return len(pw) * math.log2(size) if size else 0.0


def has_sequence(pw, run=3):
    """Detect runs like 'abc', '123', 'qwe' (forwards or backwards)."""
    low = pw.lower()
    for seq in SEQUENCES:
        for s in (seq, seq[::-1]):
            for i in range(len(s) - run + 1):
                if s[i:i + run] in low:
                    return True
    return False


def has_repeats(pw, run=3):
    """Detect the same character repeated, like 'aaa'."""
    return re.search(r"(.)\1{%d,}" % (run - 1), pw) is not None


def is_common(pw):
    low = pw.lower()
    return low in COMMON or low.translate(LEET) in COMMON


def crack_time(bits):
    """Rough time to brute-force at 10 billion guesses/second."""
    seconds = (2 ** bits) / 2 / 1e10
    for unit, size in [("years", 31_536_000), ("days", 86_400), ("hours", 3600), ("minutes", 60)]:
        if seconds >= size:
            value = seconds / size
            return f"{value:,.0f} {unit}" if value < 1e12 else "longer than the age of the universe"
    return "instantly" if seconds < 1 else f"{seconds:.0f} seconds"


def check_password(pw):
    """Return (score 0-100, label, feedback list, entropy bits)."""
    feedback = []
    if not pw:
        return 0, "Empty", ["Enter a password."], 0.0

    bits = entropy_bits(pw)
    score = min(100, int(bits / 80 * 100))  # ~80 bits counts as full marks

    if len(pw) < MIN_LENGTH:
        feedback.append(f"Use at least {MIN_LENGTH} characters (yours: {len(pw)}).")
    if not (re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw)):
        feedback.append("Mix uppercase and lowercase letters.")
    if not re.search(r"\d", pw):
        feedback.append("Add at least one number.")
    if not re.search(r"[^A-Za-z0-9]", pw):
        feedback.append("Add a symbol (like ! @ # $).")

    if has_sequence(pw):
        score -= 15
        feedback.append("Avoid sequences like 'abc', '123' or 'qwe'.")
    if has_repeats(pw):
        score -= 15
        feedback.append("Avoid repeated characters like 'aaa'.")
    if is_common(pw):
        score = min(score, 5)
        feedback.append("This is a very common password (even with symbol swaps).")

    score = max(0, min(100, score))
    for limit, label in [(20, "Very weak"), (40, "Weak"), (60, "Fair"), (80, "Strong")]:
        if score < limit:
            return score, label, feedback, bits
    return score, "Very strong", feedback, bits


def read_password(show):
    """Read a password. Hidden by default; falls back to visible input if the
    terminal can't hide it (some VS Code run modes)."""
    if show:
        return input("Enter a password (blank to quit): ")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return getpass.getpass("Enter a password (blank to quit, typing is hidden): ")
    except (getpass.GetPassWarning, EOFError, OSError):
        print("(Hidden input is not supported here, so typing will be visible.)")
        return input("Enter a password (blank to quit): ")


def main():
    show = "--show" in sys.argv
    print("=== Password Strength Checker ===")
    print("Tip: test with made-up passwords, never your real ones.")
    print("Typing is hidden by default. Run with --show to see what you type.\n")
    while True:
        pw = read_password(show)
        if not pw:
            break
        score, label, tips, bits = check_password(pw)
        print(f"\nScore:   {score}/100 ({label})")
        print(f"Entropy: {bits:.1f} bits")
        print(f"Crack time (estimate): {crack_time(bits)}")
        for t in tips:
            print(f" - {t}")
        print()


if __name__ == "__main__":
    main()
