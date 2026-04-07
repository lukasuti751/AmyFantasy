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
