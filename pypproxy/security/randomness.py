from __future__ import annotations

import base64
import math
import re
from collections import Counter
from dataclasses import dataclass


@dataclass
class RandomnessResult:
    test_name: str
    passed: bool
    score: float
    detail: str

    def to_dict(self) -> dict:
        return {
            "test_name": self.test_name,
            "passed": self.passed,
            "score": round(self.score, 4),
            "detail": self.detail,
        }


def analyse_token(token: str) -> list[RandomnessResult]:
    """Run statistical randomness tests on a token string."""
    # Try to decode base64/base64url tokens
    bits = _token_to_bits(token)
    if not bits:
        return [RandomnessResult("parse", False, 0.0, "Could not extract bits from token")]

    results: list[RandomnessResult] = []
    results.append(_frequency_test(bits))
    results.append(_runs_test(bits))
    results.append(_longest_run_test(bits))
    results.append(_entropy_test(token))
    results.append(_serial_test(bits))
    return results


def _token_to_bits(token: str) -> list[int]:
    # strip JWT signature part
    if token.count(".") == 2:
        token = token.split(".")[1]  # use payload

    # try base64url decode
    for attempt in (token, token + "=" * (-len(token) % 4)):
        try:
            raw = base64.urlsafe_b64decode(attempt)
            return [int(b) for byte in raw for b in format(byte, "08b")]
        except Exception:
            pass

    # treat as hex
    try:
        clean = re.sub(r"[^0-9a-fA-F]", "", token)
        if len(clean) >= 16:
            raw = bytes.fromhex(clean)
            return [int(b) for byte in raw for b in format(byte, "08b")]
    except Exception:
        pass

    # use raw bytes
    raw = token.encode()
    return [int(b) for byte in raw for b in format(byte, "08b")]


def _frequency_test(bits: list[int]) -> RandomnessResult:
    """NIST SP800-22 frequency (monobit) test."""
    n = len(bits)
    s = sum(1 if b else -1 for b in bits)
    s_obs = abs(s) / math.sqrt(n)
    p_value = math.erfc(s_obs / math.sqrt(2))
    passed = p_value >= 0.01
    ratio = sum(bits) / n
    return RandomnessResult(
        "Frequency (monobit)",
        passed,
        p_value,
        f"Ones ratio={ratio:.3f} (ideal=0.5), p={p_value:.4f}",
    )


def _runs_test(bits: list[int]) -> RandomnessResult:
    """NIST runs test."""
    n = len(bits)
    ones = sum(bits)
    pi = ones / n

    if abs(pi - 0.5) >= 2 / math.sqrt(n):
        return RandomnessResult(
            "Runs",
            False,
            0.0,
            f"Pre-condition failed: ones ratio={pi:.3f} too far from 0.5",
        )

    v_obs = 1 + sum(1 for i in range(n - 1) if bits[i] != bits[i + 1])
    num = abs(v_obs - 2 * n * pi * (1 - pi))
    den = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    p_value = math.erfc(num / den)
    passed = p_value >= 0.01
    return RandomnessResult("Runs", passed, p_value, f"runs={v_obs}, p={p_value:.4f}")


def _longest_run_test(bits: list[int]) -> RandomnessResult:
    """Longest run of ones test (simplified)."""
    longest = 0
    current = 0
    for b in bits:
        if b == 1:
            current += 1
            longest = max(longest, current)
        else:
            current = 0

    n = len(bits)
    expected = math.log2(n) if n > 0 else 0
    ratio = longest / expected if expected > 0 else float("inf")
    passed = ratio < 3.0
    return RandomnessResult(
        "Longest run",
        passed,
        1.0 / ratio if ratio > 0 else 0.0,
        f"longest_run={longest}, expected~{expected:.1f}, ratio={ratio:.2f}",
    )


def _entropy_test(token: str) -> RandomnessResult:
    """Shannon entropy of the token characters."""

    counts = Counter(token)
    n = len(token)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts.values() if c > 0)
    max_entropy = math.log2(len(counts)) if len(counts) > 1 else 0
    ratio = entropy / max_entropy if max_entropy > 0 else 0
    passed = ratio >= 0.7
    return RandomnessResult(
        "Shannon entropy",
        passed,
        ratio,
        f"entropy={entropy:.2f} bits, max={max_entropy:.2f}, ratio={ratio:.2f}",
    )


def _serial_test(bits: list[int]) -> RandomnessResult:
    """Serial (digram frequency) test."""

    n = len(bits)
    if n < 4:
        return RandomnessResult("Serial", False, 0.0, "Too few bits")

    digrams = Counter(zip(bits, bits[1:], strict=False))
    expected = (n - 1) / 4
    chi2 = sum((c - expected) ** 2 / expected for c in digrams.values())
    # 3 degrees of freedom, rough threshold
    passed = chi2 < 16.27  # chi2 p=0.001, df=3
    return RandomnessResult(
        "Serial (digram)",
        passed,
        1.0 / (1 + chi2 / 10),
        f"chi2={chi2:.2f} (threshold<16.27)",
    )
