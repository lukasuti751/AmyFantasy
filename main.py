"""
AmyFantasy — single-file fantasy prompt studio (safe / non-explicit)

Purpose
  - Generate fantasy-art prompts (non-explicit) with consistent variants
  - Maintain a local library (JSON) with tags, attribution, and seeds
  - Produce keccak256 hashes for AliXepaXXX onchain storage
  - Assist with commit/reveal prep (commit hash, salt, saltHint)
    - Optional chain interaction when web3.py is installed

Design choices
  - Single file by request
  - No hardcoded API keys
  - No explicit sexual content generation (safety gate)
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import datetime as _dt
import getpass
import hashlib
import json
import os
import random
import re
import secrets
import sys
import textwrap
import time
import typing as t
from dataclasses import dataclass, field


# -----------------------------
# Utilities: console + formatting
# -----------------------------


def _now_iso() -> str:
    return _dt.datetime.utcnow().replace(tzinfo=_dt.timezone.utc).isoformat()


def _clamp(x: int, lo: int, hi: int) -> int:
    if lo > hi:
        lo, hi = hi, lo
    return lo if x < lo else hi if x > hi else x


def _wrap(s: str, width: int = 92) -> str:
    return "\n".join(textwrap.wrap(s, width=width, replace_whitespace=False, drop_whitespace=False))


def _eprint(*a: t.Any) -> None:
    print(*a, file=sys.stderr)


class Console:
    def __init__(self, color: bool | None = None) -> None:
        if color is None:
            color = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
        self.color = bool(color)

    def _c(self, code: str, s: str) -> str:
        if not self.color:
            return s
        return f"\x1b[{code}m{s}\x1b[0m"

    def h(self, s: str) -> str:
        return self._c("1;36", s)

    def ok(self, s: str) -> str:
        return self._c("1;32", s)

    def warn(self, s: str) -> str:
        return self._c("1;33", s)

    def bad(self, s: str) -> str:
        return self._c("1;31", s)


CON = Console()


# -----------------------------
# Safety gate (non-explicit)
# -----------------------------


class SafetyError(ValueError):
    pass


class Safety:
    """
    Enforces a conservative rule set:
      - blocks explicit sexual content and anything involving minors
      - blocks a small set of illegal/abusive categories

    This is not an exhaustive classifier; it is a practical filter for a prompt generator.
    """

    # Strong blocks: minors
    _MINOR_PAT = re.compile(
        r"\b("
        r"child|children|kid|kids|minor|minors|underage|teen|teenager|schoolgirl|schoolboy|loli|shota"
        r")\b",
        re.IGNORECASE,
    )

    # Strong blocks: explicit sex terms (kept minimal; goal is to avoid porn generation)
    _EXPLICIT_PAT = re.compile(
        r"\b("
        r"porn|porno|nsfw|explicit|sex|sexual|nude|naked|genital|genitals|nipples|areola|penetration|"
        r"blowjob|handjob|oral|anal|vagina|penis|cum|ejaculate|orgasm|masturbat"
        r")\b",
        re.IGNORECASE,
    )

    # Illegal / abusive content (limited set)
    _ILLEGAL_PAT = re.compile(
        r"\b("
        r"bestiality|rape|non[- ]?consensual|incest"
        r")\b",
        re.IGNORECASE,
    )

    @classmethod
    def check_text(cls, text: str) -> None:
        if not text:
            return
        if cls._MINOR_PAT.search(text):
            raise SafetyError("Blocked: content involving minors.")
        if cls._ILLEGAL_PAT.search(text):
            raise SafetyError("Blocked: illegal/abusive content.")
        if cls._EXPLICIT_PAT.search(text):
            raise SafetyError("Blocked: explicit sexual content.")

    @classmethod
    def safe_flags_for_contract(cls, text: str) -> int:
        """
        The contract supports flags bits 9 (minors) and 10 (explicit sexual).
        We always return 0 for safe prompts, or raise SafetyError.
        """
        cls.check_text(text)
        return 0


# -----------------------------
# Deterministic random / entropy
# -----------------------------


def _seed_from_bytes(b: bytes) -> int:
    return int.from_bytes(hashlib.sha256(b).digest(), "big")


class Rng:
    """
    A deterministic RNG for reproducible prompt variants.
    Uses Python's Mersenne Twister seeded from SHA-256 for stable behavior across runs.
    """

    def __init__(self, seed: bytes) -> None:
        self._r = random.Random(_seed_from_bytes(seed))

    def choice(self, seq: t.Sequence[t.Any]) -> t.Any:
        return seq[self._r.randrange(0, len(seq))]

    def randrange(self, a: int, b: int | None = None) -> int:
        if b is None:
            return self._r.randrange(0, a)
        return self._r.randrange(a, b)

    def shuffle(self, xs: list[t.Any]) -> None:
        self._r.shuffle(xs)

    def randbytes(self, n: int) -> bytes:
        # Deterministic, not cryptographic.
        out = bytearray()
        while len(out) < n:
            out.extend(self._r.getrandbits(32).to_bytes(4, "big"))
        return bytes(out[:n])

    def uniform(self, a: float, b: float) -> float:
        return self._r.uniform(a, b)


def random_hex32() -> str:
    return "0x" + secrets.token_hex(32)


def random_hex20() -> str:
    return "0x" + secrets.token_hex(20)


def random_b32() -> bytes:
    return secrets.token_bytes(32)


def b32_to_hex(b: bytes) -> str:
    return "0x" + b.hex()


def _keccak_256(data: bytes) -> bytes:
    """
    Prefer real keccak when available; fallback is sha3_256 (not the same as keccak).
    We include both paths and clearly label the fallback to avoid silent mistakes.
    """
    try:
        # pycryptodome style
        from Crypto.Hash import keccak  # type: ignore

        k = keccak.new(digest_bits=256)
        k.update(data)
        return k.digest()
    except Exception:
        try:
            import sha3  # type: ignore

            k = sha3.keccak_256()
            k.update(data)
            return k.digest()
        except Exception:
            # Fallback (NOT keccak): NIST SHA3-256
            return hashlib.sha3_256(data).digest()


def keccak_hex(data: bytes) -> str:
    return "0x" + _keccak_256(data).hex()


def solidity_packed(*items: tuple[str, t.Any]) -> bytes:
    """
    Minimal subset of abi.encodePacked for the exact tuples we use here.
    Supported types: address, bytes32, uint256, uint64
    """
    out = bytearray()
    for typ, val in items:
        if typ == "address":
            if isinstance(val, str):
                v = val.lower()
                if v.startswith("0x"):
                    v = v[2:]
                b = bytes.fromhex(v.rjust(40, "0"))
            elif isinstance(val, bytes):
                b = val.rjust(20, b"\x00")
            else:
                raise TypeError("address must be hex string or bytes")
            if len(b) != 20:
                raise ValueError("address must be 20 bytes")
            out.extend(b)
        elif typ == "bytes32":
            if isinstance(val, str):
                v = val[2:] if val.startswith("0x") else val
                b = bytes.fromhex(v.rjust(64, "0"))
            elif isinstance(val, bytes):
                b = val.rjust(32, b"\x00")
            else:
                raise TypeError("bytes32 must be hex string or bytes")
            if len(b) != 32:
                raise ValueError("bytes32 must be 32 bytes")
            out.extend(b)
        elif typ == "uint256":
            if not isinstance(val, int):
                raise TypeError("uint256 must be int")
            out.extend(int(val).to_bytes(32, "big"))
        elif typ == "uint64":
            if not isinstance(val, int):
                raise TypeError("uint64 must be int")
            out.extend(int(val).to_bytes(8, "big"))
        else:
            raise ValueError(f"unsupported type {typ}")
    return bytes(out)


# -----------------------------
# Prompt building blocks
# -----------------------------


@dataclass(frozen=True)
class PromptSpec:
    theme: str
    subject: str
    setting: str
    lighting: str
    palette: str
    medium: str
    lens: str
    mood: str
    details: tuple[str, ...]
    negatives: tuple[str, ...]

    def render(self) -> str:
        parts: list[str] = []
        parts.append(f"{self.theme}")
        parts.append(f"Subject: {self.subject}")
        parts.append(f"Setting: {self.setting}")
        parts.append(f"Lighting: {self.lighting}")
        parts.append(f"Palette: {self.palette}")
        parts.append(f"Medium: {self.medium}")
        parts.append(f"Lens/Framing: {self.lens}")
        parts.append(f"Mood: {self.mood}")
        if self.details:
            parts.append("Details: " + ", ".join(self.details))
        if self.negatives:
            parts.append("Negative: " + ", ".join(self.negatives))
        return " | ".join(parts)


class Lexicon:
    THEMES = [
        "High fantasy illustration",
        "Arcane cathedral realism",
        "Mythic ink + watercolor",
        "Crystalline dreamscape",
        "Eldritch botanical fantasy",
        "Celestial clockwork fable",
        "Rune-etched storybook art",
        "Ancient tapestry scene",
        "Neo-baroque fantasy portrait",
        "Luminous cave-myth vignette",
        "Stormbound hero chronicle",
        "Glacier-sigil folklore",
        "Sunken-library myth",
        "Astral sea voyage",
        "Moonlit ruins tableau",
    ]

    SUBJECTS = [
        "a masked archivist weaving starlight threads into a map",
        "a gentle dragon curled around an observatory, reading constellations",
        "a wandering knight carrying a lantern filled with fireflies",
        "a sorcerer carving runes into falling snow",
        "an oracle holding a glass prism that refracts memories",
        "a clockmaker witch balancing gears and petals",
        "a river spirit made of mist and reeds",
        "a fox familiar delivering a sealed prophecy",
        "a bard with a stringed instrument of meteor iron",
        "a librarian golem sorting floating books by scent",
        "a guardian statue awakening at dusk",
        "an alchemist painting potions into existence",
        "a sky-sailor steering through auroras",
        "a phoenix perched on a frost-crowned throne",
        "a merfolk cartographer sketching currents in bioluminescent ink",
    ]

    SETTINGS = [
        "inside a forgotten observatory with rotating brass ceilings",
        "in a mossy amphitheater where statues hum softly",
        "on a cliffside city of lanterns and wind-chimes",
        "within a sunken library whose shelves breathe bubbles",
