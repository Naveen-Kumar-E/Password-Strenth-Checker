"""
Password Strength Analyzer & Cracker Simulator
Core analysis engine — hashing, entropy, brute-force simulation
"""

import hashlib
import math
import time
import re
from dataclasses import dataclass, field
from typing import Optional


# ──────────────────────────────────────────────
# Common password wordlist (top 50 for demo)
# ──────────────────────────────────────────────
COMMON_PASSWORDS = {
    "password", "123456", "password1", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon", "baseball",
    "iloveyou", "master", "sunshine", "ashley", "bailey", "passw0rd",
    "shadow", "123123", "654321", "superman", "qazwsx", "michael",
    "football", "batman", "iloveyou", "welcome", "login", "admin",
    "princess", "solo", "qwerty123", "password123", "starwars",
    "hello", "charlie", "donald", "password2", "qwertyuiop",
    "summer", "winter", "spring", "autumn", "flower", "pass",
    "test", "root", "123", "user"
}


# ──────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────
@dataclass
class CharacterAnalysis:
    length: int
    has_lowercase: bool
    has_uppercase: bool
    has_digits: bool
    has_symbols: bool
    pool_size: int
    unique_chars: int


@dataclass
class PatternFlags:
    is_common: bool
    has_repeated_chars: bool      # e.g. "aaabbb"
    has_sequential: bool          # e.g. "abc", "123"
    has_keyboard_walk: bool       # e.g. "qwerty", "asdf"
    has_leet_speak: bool          # e.g. "p@ssw0rd"
    has_date_pattern: bool        # e.g. "2024", "19xx"


@dataclass
class HashResult:
    md5: str
    sha1: str
    sha256: str
    sha512: str
    bcrypt_note: str = "bcrypt is slow by design — ideal for password storage"


@dataclass
class CrackEstimate:
    attack_type: str
    seconds: float               # estimated seconds to crack (avg case)
    human_readable: str
    guesses_per_second: int
    total_combinations: float
    description: str


@dataclass
class StrengthResult:
    password: str
    score: int                   # 0–100
    level: str                   # very weak / weak / fair / strong / very strong
    entropy_bits: float
    char_analysis: CharacterAnalysis
    patterns: PatternFlags
    hashes: HashResult
    crack_estimates: list[CrackEstimate]
    suggestions: list[str]
    time_taken_ms: float


# ──────────────────────────────────────────────
# Core functions
# ──────────────────────────────────────────────

def compute_hashes(password: str) -> HashResult:
    """Compute MD5, SHA-1, SHA-256, SHA-512 hashes."""
    enc = password.encode("utf-8")
    return HashResult(
        md5=hashlib.md5(enc).hexdigest(),
        sha1=hashlib.sha1(enc).hexdigest(),
        sha256=hashlib.sha256(enc).hexdigest(),
        sha512=hashlib.sha512(enc).hexdigest(),
    )


def analyze_characters(password: str) -> CharacterAnalysis:
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_sym   = bool(re.search(r"[^a-zA-Z0-9]", password))

    pool = 0
    if has_lower: pool += 26
    if has_upper: pool += 26
    if has_digit: pool += 10
    if has_sym:   pool += 32

    return CharacterAnalysis(
        length=len(password),
        has_lowercase=has_lower,
        has_uppercase=has_upper,
        has_digits=has_digit,
        has_symbols=has_sym,
        pool_size=pool,
        unique_chars=len(set(password)),
    )


def calculate_entropy(char_analysis: CharacterAnalysis) -> float:
    """Shannon entropy = length × log2(pool_size)."""
    if char_analysis.pool_size == 0 or char_analysis.length == 0:
        return 0.0
    return char_analysis.length * math.log2(char_analysis.pool_size)


def detect_patterns(password: str) -> PatternFlags:
    pw_lower = password.lower()

    sequential_patterns = (
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
        "qwertyuiop", "asdfghjkl", "zxcvbnm",
        "qwerty", "asdf", "zxcv",
    )

    keyboard_walks = ["qwerty", "asdf", "zxcv", "qazwsx", "wsxedc"]

    has_seq = any(pat in pw_lower for pat in sequential_patterns)
    has_kb  = any(walk in pw_lower for walk in keyboard_walks)
    has_leet = bool(re.search(r"[0-9@$!]", password)) and bool(re.search(r"[a-zA-Z]", password))
    has_date = bool(re.search(r"(19|20)\d{2}|[0-3]\d[0-1]\d\d{2}", password))
    has_rep  = bool(re.search(r"(.)\1{2,}", password))

    return PatternFlags(
        is_common=pw_lower in COMMON_PASSWORDS,
        has_repeated_chars=has_rep,
        has_sequential=has_seq,
        has_keyboard_walk=has_kb,
        has_leet_speak=has_leet,
        has_date_pattern=has_date,
    )


def format_time(seconds: float) -> str:
    """Convert seconds to human-readable crack time."""
    if seconds < 0.001:
        return "instant (< 1ms)"
    if seconds < 1:
        return f"{seconds * 1000:.1f} milliseconds"
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    if seconds < 86400 * 365:
        return f"{seconds / 86400:.1f} days"
    years = seconds / (86400 * 365)
    if years < 1_000:
        return f"{years:.1f} years"
    if years < 1_000_000:
        return f"{years / 1_000:.1f} thousand years"
    if years < 1_000_000_000:
        return f"{years / 1_000_000:.1f} million years"
    if years < 1_000_000_000_000:
        return f"{years / 1_000_000_000:.1f} billion years"
    return "longer than the age of the universe"


def simulate_brute_force(char_analysis: CharacterAnalysis) -> CrackEstimate:
    """Simulate GPU-accelerated brute-force (10B guesses/sec)."""
    SPEED = 10_000_000_000  # 10 billion/sec (modern GPU cluster)
    pool = char_analysis.pool_size or 1
    length = char_analysis.length or 1

    total = pool ** length
    seconds = total / SPEED / 2  # average case = half of total

    return CrackEstimate(
        attack_type="Brute-Force",
        seconds=seconds,
        human_readable=format_time(seconds),
        guesses_per_second=SPEED,
        total_combinations=total,
        description=f"Trying all {pool}^{length} = {total:.2e} combinations at 10B/sec (GPU cluster)"
    )


def simulate_dictionary_attack(password: str, patterns: PatternFlags) -> CrackEstimate:
    """Simulate dictionary + mutation attack (Hashcat rules)."""
    SPEED = 10_000_000_000
    WORDLIST_SIZE = 10_000_000  # 10M common words

    if patterns.is_common:
        seconds = 1 / SPEED  # found immediately
        desc = "Password found directly in top-10M wordlist — cracked immediately"
    else:
        # mutations: l33t, append numbers, capitalise, symbols
        mutations = 1
        if patterns.has_leet_speak: mutations *= 100
        mutations *= (10 ** min(len(password) - 6, 6))  # appended digits
        mutations = max(mutations, 1)
        total = WORDLIST_SIZE * mutations
        seconds = total / SPEED / 2
        desc = f"Wordlist ({WORDLIST_SIZE:,} words) × {mutations:,} mutation rules (Hashcat)"

    return CrackEstimate(
        attack_type="Dictionary + Rules",
        seconds=seconds,
        human_readable=format_time(seconds),
        guesses_per_second=SPEED,
        total_combinations=WORDLIST_SIZE,
        description=desc
    )


def simulate_rainbow_table(entropy: float) -> CrackEstimate:
    """Simulate rainbow table lookup (precomputed hashes)."""
    # Tables typically cover up to ~40-bit entropy (unsalted)
    if entropy <= 36:
        seconds = 0.000001  # microsecond lookup
        desc = "Hash likely in precomputed table — instant lookup. Use bcrypt+salt!"
    elif entropy <= 50:
        seconds = 60  # table exists but large
        desc = "Possible with very large rainbow tables. Salting defeats this."
    else:
        seconds = float("inf")
        desc = "Entropy too high for rainbow tables. Salting makes this impossible."

    return CrackEstimate(
        attack_type="Rainbow Table",
        seconds=seconds,
        human_readable="not feasible" if seconds == float("inf") else format_time(seconds),
        guesses_per_second=0,
        total_combinations=0,
        description=desc
    )


def generate_suggestions(password: str, char_analysis: CharacterAnalysis,
                          patterns: PatternFlags, entropy: float) -> list[str]:
    tips = []
    if char_analysis.length < 8:
        tips.append("Use at least 8 characters — 16+ is recommended.")
    if char_analysis.length < 16:
        tips.append("Longer passwords are exponentially harder to crack. Aim for 16+.")
    if not char_analysis.has_uppercase:
        tips.append("Add uppercase letters to expand the character pool.")
    if not char_analysis.has_symbols:
        tips.append("Special characters (!@#$%) multiply the search space by 32×.")
    if patterns.is_common:
        tips.append("This is a commonly used password — avoid it entirely.")
    if patterns.has_keyboard_walk:
        tips.append("Keyboard walks (qwerty, asdf) are in every attacker's wordlist.")
    if patterns.has_repeated_chars:
        tips.append("Repeated characters reduce effective entropy significantly.")
    if patterns.has_date_pattern:
        tips.append("Date patterns are easily guessed with targeted attacks.")
    if entropy >= 64 and not tips:
        tips.append("Excellent password! Store it in a password manager.")
    return tips


def calculate_score(entropy: float, patterns: PatternFlags, length: int) -> tuple[int, str]:
    score = min(int(entropy * 1.2), 100)

    # penalise bad patterns
    if patterns.is_common:        score = min(score, 10)
    if patterns.has_keyboard_walk: score = max(score - 20, 5)
    if patterns.has_repeated_chars: score = max(score - 10, 5)
    if patterns.has_sequential:    score = max(score - 10, 5)
    if length < 6:                 score = min(score, 15)

    if score < 20:   level = "very weak"
    elif score < 40: level = "weak"
    elif score < 60: level = "fair"
    elif score < 80: level = "strong"
    else:            level = "very strong"

    return score, level


# ──────────────────────────────────────────────
# Main entry point
# ──────────────────────────────────────────────

def analyze_password(password: str) -> StrengthResult:
    """Full analysis pipeline. Returns a StrengthResult."""
    t0 = time.perf_counter()

    char_analysis = analyze_characters(password)
    entropy       = calculate_entropy(char_analysis)
    patterns      = detect_patterns(password)
    hashes        = compute_hashes(password)
    score, level  = calculate_score(entropy, patterns, len(password))
    suggestions   = generate_suggestions(password, char_analysis, patterns, entropy)

    crack_estimates = [
        simulate_brute_force(char_analysis),
        simulate_dictionary_attack(password, patterns),
        simulate_rainbow_table(entropy),
    ]

    elapsed_ms = (time.perf_counter() - t0) * 1000

    return StrengthResult(
        password=password,
        score=score,
        level=level,
        entropy_bits=round(entropy, 2),
        char_analysis=char_analysis,
        patterns=patterns,
        hashes=hashes,
        crack_estimates=crack_estimates,
        suggestions=suggestions,
        time_taken_ms=round(elapsed_ms, 3),
    )


# ──────────────────────────────────────────────
# CLI demo
# ──────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    test_passwords = [
        "password", "P@ssw0rd!", "correct-horse-battery-staple",
        "Tr0ub4dor&3", "X9#mK2$pL7@qR4!v"
    ]

    pw_list = sys.argv[1:] if len(sys.argv) > 1 else test_passwords

    for pw in pw_list:
        r = analyze_password(pw)
        print(f"\n{'='*60}")
        print(f"Password : {'*' * len(pw)}  (length {r.char_analysis.length})")
        print(f"Entropy  : {r.entropy_bits} bits")
        print(f"Score    : {r.score}/100 — {r.level.upper()}")
        print(f"Pool     : {r.char_analysis.pool_size} chars")
        print(f"\nHashes:")
        print(f"  MD5    : {r.hashes.md5}")
        print(f"  SHA-256: {r.hashes.sha256[:48]}...")
        print(f"\nCrack estimates:")
        for est in r.crack_estimates:
            print(f"  [{est.attack_type:20}] {est.human_readable}")
        print(f"\nSuggestions:")
        for s in r.suggestions:
            print(f"  • {s}")
        print(f"\nAnalysis time: {r.time_taken_ms}ms")
