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
        "beneath a colossal tree with roots shaped like staircases",
        "in a mirror desert where dunes reflect another sky",
        "at the edge of a floating archipelago of ruins",
        "on a glacier-lake under a halo of moons",
        "in a corridor of stained glass that projects living myths",
        "among tidal caves lit by blue algae constellations",
        "inside a train made of carved jade running through clouds",
        "at a night market that sells bottled dawn",
        "in a cathedral grown from coral and bone-white stone",
        "on an astral ship docked to a comet",
        "in a vineyard of silver leaves and ember grapes",
    ]

    LIGHTING = [
        "soft volumetric godrays",
        "moonlight with prismatic bloom",
        "candlelit chiaroscuro",
        "bioluminescent rim light",
        "stormlight flashes and afterglow",
        "golden hour haze",
        "starlit mist with bokeh",
        "eclipse backlight",
        "lantern glow with drifting embers",
        "aurora spill lighting",
        "underwater caustics",
        "dusty sunbeams in ruins",
        "neon rune-glow",
        "twilight gradient wash",
        "dawn fog illumination",
    ]

    PALETTES = [
        "opal + midnight blue + silver",
        "emerald + brass + parchment",
        "amethyst + charcoal + pearl",
        "saffron + ultramarine + rose",
        "jade + obsidian + gold leaf",
        "copper + teal + ash white",
        "lavender + indigo + ice cyan",
        "vermillion + sepia + cream",
        "cobalt + ivory + scarlet accents",
        "forest green + fog gray + amber",
        "sea-glass cyan + slate + coral",
        "sunset orange + plum + ink",
        "straw gold + moss + stone",
        "iridescent pastel + shadow black",
        "winter blue + iron + candle gold",
    ]

    MEDIA = [
        "ultra-detailed digital painting",
        "oil on canvas texture",
        "gouache illustration",
        "ink engraving style",
        "soft 3D cinematic render",
        "matte painting",
        "watercolor wash",
        "charcoal + pastel sketch",
        "mixed media collage",
        "anime-inspired cinematic frame",
        "photoreal fantasy composite",
        "linocut print aesthetic",
        "isometric diorama",
        "tilt-shift miniature look",
        "storybook pen and ink",
    ]

    LENSES = [
        "35mm wide shot, leading lines",
        "50mm portrait, shallow depth of field",
        "85mm close-up, creamy bokeh",
        "top-down composition, symmetrical",
        "low angle heroic framing",
        "high angle establishing shot",
        "macro detail inset + wide background",
        "cinemascope, dramatic negative space",
        "center framing with ornate border",
        "over-the-shoulder narrative view",
        "silhouette framing through arches",
        "reflection composition using water/mirrors",
        "rule-of-thirds, dynamic diagonals",
        "spiral composition, painterly movement",
        "long exposure glow trails",
    ]

    MOODS = [
        "quiet wonder",
        "melancholic serenity",
        "mysterious awe",
        "hopeful resolve",
        "sacred hush",
        "electric anticipation",
        "mythic grandeur",
        "dreamlike calm",
        "whimsical curiosity",
        "somber nostalgia",
        "radiant triumph",
        "haunting beauty",
        "gentle humor",
        "tense stillness",
        "ethereal reverence",
    ]

    DETAIL_POOL = [
        "intricate rune filigree",
        "floating dust motes",
        "soft fog layers",
        "ancient inscriptions",
        "ornate embroidery",
        "glowing sigils",
        "shimmering particles",
        "weathered stone texture",
        "delicate feathers",
        "subsurface scattering",
        "micro-scratches on metal",
        "hand-painted brush strokes",
        "cracked porcelain highlights",
        "moss and lichen",
        "tiny constellations in shadows",
        "steam curls and condensation",
        "wet cobblestone reflections",
        "paper fibers and ink bleed",
        "lens flare sparingly",
        "soft atmospheric perspective",
        "high-frequency detail pass",
        "cinematic color grading",
        "dynamic cloth folds",
        "calligraphic motifs",
        "sparkling frost crystals",
        "salt spray mist",
        "polished gemstone caustics",
        "glow-in-the-dark fungi",
        "crystal refractions",
        "wind-swept hair strands",
        "tiny lanterns in distance",
        "misty mountains silhouette",
        "subtle chromatic aberration",
        "embossed gold leaf accents",
        "torn parchment edges",
        "stained-glass reflections",
        "spiraling smoke trails",
        "ethereal halos",
        "shadow puppet shapes",
        "spiral staircase background",
    ]

    NEGATIVE_POOL = [
        "low quality",
        "blurry",
        "overexposed",
        "underexposed",
        "jpeg artifacts",
        "extra limbs",
        "bad anatomy",
        "text",
        "watermark",
        "logo",
        "signature",
        "cropped",
        "deformed hands",
        "oversaturated",
        "muddy colors",
        "duplicate faces",
        "misaligned eyes",
        "flat lighting",
        "harsh shadows",
        "noise",
        "grainy",
        "plastic skin",
        "uncanny",
        "out of frame",
        "bad perspective",
    ]


def build_prompt(seed: bytes, richness: int = 11) -> PromptSpec:
    """
    richness influences number of detail tokens and negatives.
    """
    r = Rng(seed)
    richness = _clamp(richness, 3, 23)

    theme = r.choice(Lexicon.THEMES)
    subject = r.choice(Lexicon.SUBJECTS)
    setting = r.choice(Lexicon.SETTINGS)
    lighting = r.choice(Lexicon.LIGHTING)
    palette = r.choice(Lexicon.PALETTES)
    medium = r.choice(Lexicon.MEDIA)
    lens = r.choice(Lexicon.LENSES)
    mood = r.choice(Lexicon.MOODS)

    # Details: randomized counts in a range, not always minimal.
    dmin = 6 + (richness // 4)
    dmax = 14 + (richness // 2)
    details_n = r.randrange(dmin, dmax + 1)
    pool = list(Lexicon.DETAIL_POOL)
    r.shuffle(pool)
    details = tuple(pool[:details_n])

    # Negatives: variable count with a cap.
    nmin = 5
    nmax = 13 + (richness // 3)
    neg_n = r.randrange(nmin, min(nmax, len(Lexicon.NEGATIVE_POOL)) + 1)
    npool = list(Lexicon.NEGATIVE_POOL)
    r.shuffle(npool)
    negatives = tuple(npool[:neg_n])

    spec = PromptSpec(
        theme=theme,
        subject=subject,
        setting=setting,
        lighting=lighting,
        palette=palette,
        medium=medium,
        lens=lens,
        mood=mood,
        details=details,
        negatives=negatives,
    )

    Safety.check_text(spec.render())
    return spec


# -----------------------------
# Local library storage
# -----------------------------


@dataclass
class LibraryItem:
    id: str
    created_at: str
    seed_b64: str
    richness: int
    prompt: str
    prompt_hash: str
    tags: list[str] = field(default_factory=list)
    attribution: str = ""
    notes: str = ""

    def seed_bytes(self) -> bytes:
        return base64.b64decode(self.seed_b64.encode("ascii"))


class Library:
    def __init__(self, path: str) -> None:
        self.path = path
        self.items: dict[str, LibraryItem] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.path):
            self.items = {}
            return
        with open(self.path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        items: dict[str, LibraryItem] = {}
        for it in raw.get("items", []):
            li = LibraryItem(**it)
            items[li.id] = li
        self.items = items

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        payload = {
            "version": 1,
            "saved_at": _now_iso(),
            "items": [dataclasses.asdict(v) for v in self.items.values()],
        }
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=False)
        os.replace(tmp, self.path)

    def add(self, item: LibraryItem) -> None:
        if item.id in self.items:
            raise ValueError("id already exists")
        self.items[item.id] = item
        self.save()

    def get(self, item_id: str) -> LibraryItem:
        if item_id not in self.items:
            raise KeyError(item_id)
