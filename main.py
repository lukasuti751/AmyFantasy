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
        return self.items[item_id]

    def list_ids(self) -> list[str]:
        return sorted(self.items.keys())

    def search(self, q: str) -> list[LibraryItem]:
        ql = q.lower().strip()
        out: list[LibraryItem] = []
        for it in self.items.values():
            hay = " ".join([it.prompt, it.attribution, it.notes, " ".join(it.tags)]).lower()
            if ql in hay:
                out.append(it)
        out.sort(key=lambda x: x.created_at, reverse=True)
        return out

    def tag(self, item_id: str, tags: list[str]) -> None:
        it = self.get(item_id)
        seen = set(it.tags)
        for t0 in tags:
            t1 = normalize_tag(t0)
            if not t1:
                continue
            if t1 not in seen:
                it.tags.append(t1)
                seen.add(t1)
        self.save()

    def set_attribution(self, item_id: str, attribution: str) -> None:
        it = self.get(item_id)
        it.attribution = attribution.strip()
        self.save()

    def set_notes(self, item_id: str, notes: str) -> None:
        it = self.get(item_id)
        it.notes = notes
        self.save()


def default_library_path() -> str:
    base = os.path.expanduser("~")
    return os.path.join(base, ".amyfantasy", "library.json")


def normalize_tag(tag: str) -> str:
    tag = tag.strip().lower()
    tag = re.sub(r"\s+", "-", tag)
    tag = re.sub(r"[^a-z0-9\-_\.]+", "", tag)
    return tag[:48]


def hash_prompt_text(prompt: str) -> str:
    Safety.check_text(prompt)
    return keccak_hex(prompt.encode("utf-8"))


def make_item_id(seed: bytes) -> str:
    # Short stable ID.
    h = hashlib.blake2b(seed, digest_size=9).digest()
    return base64.urlsafe_b64encode(h).decode("ascii").rstrip("=")


# -----------------------------
# Commit / reveal helpers for AliXepaXXX
# -----------------------------


@dataclass(frozen=True)
class CommitBundle:
    author: str
    prompt_hash: str
    salt: str
    salt_hint: str
    commit_hash: str


def _require_hex(s: str, nbytes: int | None = None) -> str:
    s = s.strip()
    if not s.startswith("0x"):
        raise ValueError("expected 0x-prefixed hex string")
    hx = s[2:]
    if not re.fullmatch(r"[0-9a-fA-F]*", hx):
        raise ValueError("invalid hex")
    if nbytes is not None and len(hx) != nbytes * 2:
        raise ValueError(f"expected {nbytes} bytes hex")
    return "0x" + hx.lower()


def commit_bundle(author: str, prompt_hash: str, salt: str | None = None, salt_hint: str | None = None) -> CommitBundle:
    """
    Matches contract: commit = keccak256(abi.encodePacked(author, promptHash, salt, saltHint))
    """
    author = _require_hex(author, 20)
    prompt_hash = _require_hex(prompt_hash, 32)
    if salt is None:
        salt = b32_to_hex(random_b32())
    if salt_hint is None:
        salt_hint = b32_to_hex(random_b32())
    salt = _require_hex(salt, 32)
    salt_hint = _require_hex(salt_hint, 32)

    data = solidity_packed(
        ("address", author),
        ("bytes32", prompt_hash),
        ("bytes32", salt),
        ("bytes32", salt_hint),
    )
    ch = keccak_hex(data)
    return CommitBundle(author=author, prompt_hash=prompt_hash, salt=salt, salt_hint=salt_hint, commit_hash=ch)


# -----------------------------
# Optional chain interaction
# -----------------------------


class ChainError(RuntimeError):
    pass


class Chain:
    def __init__(self, rpc_url: str, private_key: str | None = None) -> None:
        self.rpc_url = rpc_url
        self.private_key = private_key
        self.web3 = None
        self.account = None
        self._init_web3()

    def _init_web3(self) -> None:
        try:
            from web3 import Web3  # type: ignore
        except Exception as e:
            raise ChainError(
                "web3.py not installed. Install with: pip install web3\n"
                "You can still use AmyFantasy offline for prompt+hash+commit/reveal."
            ) from e

        w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        if not w3.is_connected():
            raise ChainError("RPC not reachable.")
        self.web3 = w3

        if self.private_key:
            acct = w3.eth.account.from_key(self.private_key)
            self.account = acct

    def checksum(self, addr: str) -> str:
        assert self.web3 is not None
        return self.web3.to_checksum_address(addr)

    def chain_id(self) -> int:
        assert self.web3 is not None
        return int(self.web3.eth.chain_id)

    def address(self) -> str:
        if not self.account:
            raise ChainError("No private key loaded.")
        return str(self.account.address)

    def _build_contract(self, address: str, abi: list[dict[str, t.Any]]):
        assert self.web3 is not None
        return self.web3.eth.contract(address=self.checksum(address), abi=abi)

    @staticmethod
    def alixepaxxx_abi_min() -> list[dict[str, t.Any]]:
        # Minimal ABI for commit/reveal/forge/tag/preview/storySeed and basic reads.
        return [
            {
                "type": "function",
                "name": "commit",
                "stateMutability": "nonpayable",
                "inputs": [
                    {"name": "commitHash", "type": "bytes32"},
                    {"name": "saltHint", "type": "bytes32"},
                    {"name": "minDelayBlocks", "type": "uint256"},
                    {"name": "maxDelayBlocks", "type": "uint256"},
                ],
                "outputs": [],
            },
            {
                "type": "function",
                "name": "reveal",
                "stateMutability": "nonpayable",
                "inputs": [
                    {"name": "commitHash", "type": "bytes32"},
                    {"name": "promptHash", "type": "bytes32"},
                    {"name": "salt", "type": "bytes32"},
                ],
                "outputs": [{"name": "entropy", "type": "bytes32"}],
            },
            {
                "type": "function",
                "name": "forge",
                "stateMutability": "payable",
                "inputs": [
                    {"name": "promptHash", "type": "bytes32"},
                    {"name": "flags", "type": "uint64"},
                    {"name": "revealEntropy", "type": "bytes32"},
                ],
                "outputs": [{"name": "id", "type": "uint256"}],
            },
            {
                "type": "function",
                "name": "tag",
                "stateMutability": "payable",
                "inputs": [
                    {"name": "id", "type": "uint256"},
                    {"name": "tagHash", "type": "bytes32"},
                ],
                "outputs": [],
            },
            {
                "type": "function",
                "name": "baseFeeWei",
                "stateMutability": "view",
                "inputs": [],
                "outputs": [{"name": "", "type": "uint256"}],
            },
            {
                "type": "function",
                "name": "tagFeeWei",
                "stateMutability": "view",
                "inputs": [],
                "outputs": [{"name": "", "type": "uint256"}],
            },
            {
                "type": "function",
                "name": "preview",
                "stateMutability": "pure",
                "inputs": [
                    {"name": "promptHash", "type": "bytes32"},
                    {"name": "entropy", "type": "bytes32"},
                    {"name": "words", "type": "uint256"},
                ],
                "outputs": [{"name": "", "type": "string"}],
            },
            {
                "type": "function",
                "name": "storySeed",
                "stateMutability": "view",
                "inputs": [
                    {"name": "id", "type": "uint256"},
                    {"name": "userSalt", "type": "bytes32"},
                ],
                "outputs": [{"name": "", "type": "bytes32"}],
            },
        ]

    def send_tx(self, tx) -> str:
        assert self.web3 is not None
        if not self.account:
            raise ChainError("No private key loaded.")
        signed = self.account.sign_transaction(tx)
        h = self.web3.eth.send_raw_transaction(signed.rawTransaction)
        return h.hex()

    def build_and_send(self, contract_addr: str, fn: str, args: list[t.Any], value_wei: int = 0) -> str:
        assert self.web3 is not None
        if not self.account:
            raise ChainError("No private key loaded.")

        c = self._build_contract(contract_addr, self.alixepaxxx_abi_min())
        nonce = self.web3.eth.get_transaction_count(self.account.address)
        gas_price = self.web3.eth.gas_price
        tx = getattr(c.functions, fn)(*args).build_transaction(
            {
                "from": self.account.address,
                "nonce": nonce,
                "value": int(value_wei),
                "gasPrice": int(gas_price),
            }
        )

        # Estimate gas with a safety buffer.
        try:
            est = self.web3.eth.estimate_gas(tx)
            tx["gas"] = int(est * 12 // 10) + 25000
        except Exception:
            tx["gas"] = 450000
        return self.send_tx(tx)

    def call(self, contract_addr: str, fn: str, args: list[t.Any]) -> t.Any:
        c = self._build_contract(contract_addr, self.alixepaxxx_abi_min())
        return getattr(c.functions, fn)(*args).call()


# -----------------------------
# Command implementations
# -----------------------------


def cmd_generate(args: argparse.Namespace) -> int:
    lib = Library(args.library)
    richness = int(args.richness)

    seed = secrets.token_bytes(32) if args.seed is None else base64.b64decode(args.seed.encode("ascii"))
    if len(seed) < 16:
        seed = seed.ljust(16, b"\x00")

    spec = build_prompt(seed=seed, richness=richness)
    prompt = spec.render()

    Safety.check_text(prompt)
    ph = hash_prompt_text(prompt)
    item_id = make_item_id(seed)

    it = LibraryItem(
        id=item_id,
        created_at=_now_iso(),
        seed_b64=base64.b64encode(seed).decode("ascii"),
        richness=richness,
        prompt=prompt,
        prompt_hash=ph,
        tags=[normalize_tag(t0) for t0 in (args.tags or []) if normalize_tag(t0)],
        attribution=args.attribution or "",
        notes=args.notes or "",
    )
    lib.add(it)

    print(CON.ok("Saved"))
    print(f"- id: {it.id}")
    print(f"- prompt_hash (bytes32): {it.prompt_hash}")
    print(f"- richness: {it.richness}")
    if it.tags:
        print(f"- tags: {', '.join(it.tags)}")
    if it.attribution:
        print(f"- attribution: {it.attribution}")
    print()
    print(_wrap(it.prompt))
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    lib = Library(args.library)
    ids = lib.list_ids()
    if not ids:
        print(CON.warn("Library empty. Use `generate` first."))
        return 0
    for i in ids:
        it = lib.get(i)
        print(f"{it.id}  {it.created_at}  {it.prompt_hash}")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    lib = Library(args.library)
    it = lib.get(args.id)
    print(CON.h(f"AmyFantasy item {it.id}"))
    print(f"- created_at: {it.created_at}")
    print(f"- prompt_hash: {it.prompt_hash}")
    print(f"- richness: {it.richness}")
    print(f"- tags: {', '.join(it.tags) if it.tags else '(none)'}")
    print(f"- attribution: {it.attribution if it.attribution else '(none)'}")
    if it.notes:
        print(f"- notes: {it.notes}")
    print()
    print(_wrap(it.prompt))
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    lib = Library(args.library)
    res = lib.search(args.query)
    if not res:
        print(CON.warn("No matches."))
        return 0
    for it in res:
        print(f"{it.id}  {it.created_at}  {it.prompt_hash}  tags={len(it.tags)}")
    return 0


def cmd_tag(args: argparse.Namespace) -> int:
    lib = Library(args.library)
    lib.tag(args.id, args.tags)
    print(CON.ok("Updated tags."))
    return 0


def cmd_attrib(args: argparse.Namespace) -> int:
    lib = Library(args.library)
    lib.set_attribution(args.id, args.attribution)
    print(CON.ok("Updated attribution."))
    return 0


def cmd_notes(args: argparse.Namespace) -> int:
    lib = Library(args.library)
    lib.set_notes(args.id, args.notes)
    print(CON.ok("Updated notes."))
    return 0


def cmd_commit(args: argparse.Namespace) -> int:
    lib = Library(args.library)
    it = lib.get(args.id)
    author = args.author
    if author is None:
        # Generate a random address if none provided (offline prep).
        author = random_hex20()

    bundle = commit_bundle(author=author, prompt_hash=it.prompt_hash)

    print(CON.h("Commit bundle"))
    print(f"- author: {bundle.author}")
    print(f"- prompt_hash: {bundle.prompt_hash}")
    print(f"- salt: {bundle.salt}")
    print(f"- salt_hint: {bundle.salt_hint}")
    print(f"- commit_hash: {bundle.commit_hash}")
    return 0


def cmd_preview(args: argparse.Namespace) -> int:
    # Local preview (matches contract "decorative preview" vibe, not identical).
    lib = Library(args.library)
    it = lib.get(args.id)
    seed = it.seed_bytes()
    r = Rng(seed + b"preview" + args.salt.encode("utf-8"))
    words = _clamp(int(args.words), 3, 33)
    chunks: list[str] = []
    for i in range(words):
        # pseudo-word
        b = r.randbytes(4)
        n = int.from_bytes(b, "big")
        chunks.append(f"0x{n:04x}-{(n * 97 + i) % 10000:04d}")
    print(" ".join(chunks))
    return 0


def _read_private_key_from_env_or_prompt(args: argparse.Namespace) -> str | None:
    if args.private_key:
        return args.private_key.strip()
    env = os.environ.get("AMYFANTASY_PRIVATE_KEY")
    if env:
        return env.strip()
    legacy = os.environ.get("ANNAFANTASY_PRIVATE_KEY")
    if legacy:
        return legacy.strip()
    if args.prompt_key:
        return getpass.getpass("Private key (0x...): ").strip()
    return None


def cmd_chain_info(args: argparse.Namespace) -> int:
    pk = _read_private_key_from_env_or_prompt(args)
    ch = Chain(args.rpc, private_key=pk)
    print(CON.h("Chain info"))
    print(f"- chain_id: {ch.chain_id()}")
    if pk:
        print(f"- address: {ch.address()}")
    return 0


def cmd_chain_forge(args: argparse.Namespace) -> int:
    lib = Library(args.library)
    it = lib.get(args.id)
    pk = _read_private_key_from_env_or_prompt(args)
    if not pk:
        raise ChainError("Need a private key (use --private-key or --prompt-key or env AMYFANTASY_PRIVATE_KEY).")

    flags = Safety.safe_flags_for_contract(it.prompt)
    # revealEntropy is optional; default 0x00..00
    reveal_entropy = _require_hex(args.reveal_entropy, 32) if args.reveal_entropy else "0x" + "00" * 32

    ch = Chain(args.rpc, private_key=pk)
    # read fee from chain
    fee = int(ch.call(args.contract, "baseFeeWei", []))

    txh = ch.build_and_send(
        contract_addr=args.contract,
        fn="forge",
        args=[it.prompt_hash, int(flags), reveal_entropy],
        value_wei=fee,
    )
    print(CON.ok("Sent"))
    print(f"- tx: 0x{txh}")
    print(f"- fee_wei: {fee}")
    return 0


def cmd_chain_tag(args: argparse.Namespace) -> int:
    pk = _read_private_key_from_env_or_prompt(args)
    if not pk:
        raise ChainError("Need a private key (use --private-key or --prompt-key or env AMYFANTASY_PRIVATE_KEY).")
    tag = normalize_tag(args.tag)
    if not tag:
        raise ValueError("empty tag after normalization")
    tag_hash = keccak_hex(tag.encode("utf-8"))

    ch = Chain(args.rpc, private_key=pk)
    fee = int(ch.call(args.contract, "tagFeeWei", []))
    txh = ch.build_and_send(
        contract_addr=args.contract,
        fn="tag",
        args=[int(args.prompt_id), tag_hash],
        value_wei=fee,
    )
    print(CON.ok("Sent"))
    print(f"- tx: 0x{txh}")
    print(f"- tag: {tag}")
    print(f"- tag_hash: {tag_hash}")
    print(f"- fee_wei: {fee}")
    return 0


def cmd_chain_commit(args: argparse.Namespace) -> int:
    lib = Library(args.library)
    it = lib.get(args.id)
    pk = _read_private_key_from_env_or_prompt(args)
    if not pk:
        raise ChainError("Need a private key (use --private-key or --prompt-key or env AMYFANTASY_PRIVATE_KEY).")
    ch = Chain(args.rpc, private_key=pk)
    author = ch.address()

    bundle = commit_bundle(author=author, prompt_hash=it.prompt_hash)
    min_delay = int(args.min_delay)
    max_delay = int(args.max_delay)

    txh = ch.build_and_send(
        contract_addr=args.contract,
        fn="commit",
        args=[bundle.commit_hash, bundle.salt_hint, min_delay, max_delay],
        value_wei=0,
    )
    print(CON.ok("Sent"))
    print(f"- tx: 0x{txh}")
    print(f"- commit_hash: {bundle.commit_hash}")
    print(f"- salt: {bundle.salt}")
    print(f"- salt_hint: {bundle.salt_hint}")
    return 0


def cmd_chain_reveal(args: argparse.Namespace) -> int:
    lib = Library(args.library)
    it = lib.get(args.id)
    pk = _read_private_key_from_env_or_prompt(args)
    if not pk:
        raise ChainError("Need a private key (use --private-key or --prompt-key or env AMYFANTASY_PRIVATE_KEY).")
    ch = Chain(args.rpc, private_key=pk)
    author = ch.address()

    # Use provided bundle values, else regenerate won't match; so we require inputs.
    commit_hash = _require_hex(args.commit_hash, 32)
    salt = _require_hex(args.salt, 32)

    # Confirm locally (best effort) that the commit matches, if salt_hint is provided.
    salt_hint = _require_hex(args.salt_hint, 32) if args.salt_hint else None
    if salt_hint:
        b = commit_bundle(author=author, prompt_hash=it.prompt_hash, salt=salt, salt_hint=salt_hint)
        if b.commit_hash != commit_hash:
            raise ValueError("Provided commit_hash does not match (author, prompt_hash, salt, salt_hint).")

    txh = ch.build_and_send(
        contract_addr=args.contract,
        fn="reveal",
        args=[commit_hash, it.prompt_hash, salt],
        value_wei=0,
    )
    print(CON.ok("Sent"))
    print(f"- tx: 0x{txh}")
    return 0


# -----------------------------
# CLI wiring
# -----------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="AmyFantasy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(
            """
            AmyFantasy — fantasy prompt studio (safe / non-explicit)

            Quickstart:
              python AmyFantasy.py generate
              python AmyFantasy.py list
              python AmyFantasy.py show <id>
              python AmyFantasy.py commit <id> --author 0xYourAddress

            Optional chain ops (requires: pip install web3 and a working RPC):
              python AmyFantasy.py chain-info --rpc https://...
              python AmyFantasy.py chain-commit <id> --rpc ... --contract 0x... --prompt-key
              python AmyFantasy.py chain-reveal <id> --rpc ... --contract 0x... --commit-hash 0x... --salt 0x... --prompt-key
              python AmyFantasy.py chain-forge <id> --rpc ... --contract 0x... --prompt-key
            """
        ).strip(),
    )
    p.add_argument("--library", default=default_library_path(), help="Path to library JSON.")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="Generate and save a new safe fantasy prompt.")
    g.add_argument("--richness", default=11, type=int, help="3..23; higher => more details.")
    g.add_argument("--seed", default=None, help="Base64 seed for reproducible output.")
    g.add_argument("--tags", nargs="*", default=[], help="Optional tags.")
    g.add_argument("--attribution", default="", help="Optional attribution string (offchain).")
    g.add_argument("--notes", default="", help="Optional notes (offchain).")
    g.set_defaults(fn=cmd_generate)

    ls = sub.add_parser("list", help="List library items.")
    ls.set_defaults(fn=cmd_list)

    sh = sub.add_parser("show", help="Show a library item.")
    sh.add_argument("id", help="Item id.")
    sh.set_defaults(fn=cmd_show)

    se = sub.add_parser("search", help="Search prompts/tags/notes.")
    se.add_argument("query", help="Search query.")
    se.set_defaults(fn=cmd_search)

    tg = sub.add_parser("tag", help="Add tags to an item.")
    tg.add_argument("id", help="Item id.")
    tg.add_argument("tags", nargs="+", help="Tags to add.")
    tg.set_defaults(fn=cmd_tag)

    at = sub.add_parser("attrib", help="Set attribution for an item.")
    at.add_argument("id", help="Item id.")
    at.add_argument("attribution", help="Attribution text.")
    at.set_defaults(fn=cmd_attrib)

    nt = sub.add_parser("notes", help="Set notes for an item.")
    nt.add_argument("id", help="Item id.")
    nt.add_argument("notes", help="Notes text.")
    nt.set_defaults(fn=cmd_notes)

    cm = sub.add_parser("commit", help="Create a commit/reveal bundle (offline).")
    cm.add_argument("id", help="Item id.")
    cm.add_argument("--author", default=None, help="0x address. If omitted, generates a random address.")
    cm.set_defaults(fn=cmd_commit)

    pv = sub.add_parser("preview", help="Local decorative preview (offline).")
    pv.add_argument("id", help="Item id.")
    pv.add_argument("--words", default=17, type=int, help="3..33 words.")
    pv.add_argument("--salt", default="glass-rose", help="Extra salt for local preview.")
    pv.set_defaults(fn=cmd_preview)

    ci = sub.add_parser("chain-info", help="Show chain id and (optional) wallet address.")
    ci.add_argument("--rpc", required=True, help="RPC URL.")
    ci.add_argument("--private-key", default=None, help="0x private key (avoid sharing; use env instead).")
    ci.add_argument("--prompt-key", action="store_true", help="Prompt for private key.")
    ci.set_defaults(fn=cmd_chain_info)

    cf = sub.add_parser("chain-forge", help="Forge prompt hash onchain (requires web3).")
    cf.add_argument("id", help="Item id.")
    cf.add_argument("--rpc", required=True, help="RPC URL.")
    cf.add_argument("--contract", required=True, help="AliXepaXXX contract address.")
    cf.add_argument("--private-key", default=None, help="0x private key (or env AMYFANTASY_PRIVATE_KEY).")
    cf.add_argument("--prompt-key", action="store_true", help="Prompt for private key.")
    cf.add_argument("--reveal-entropy", default=None, help="Optional bytes32 entropy (0x..).")
    cf.set_defaults(fn=cmd_chain_forge)

    ct = sub.add_parser("chain-tag", help="Tag a forged prompt onchain (requires web3).")
    ct.add_argument("--rpc", required=True, help="RPC URL.")
    ct.add_argument("--contract", required=True, help="AliXepaXXX contract address.")
    ct.add_argument("--prompt-id", required=True, type=int, help="Onchain prompt id.")
    ct.add_argument("--tag", required=True, help="Tag text (will be normalized & hashed).")
    ct.add_argument("--private-key", default=None, help="0x private key (or env AMYFANTASY_PRIVATE_KEY).")
    ct.add_argument("--prompt-key", action="store_true", help="Prompt for private key.")
    ct.set_defaults(fn=cmd_chain_tag)

    cc = sub.add_parser("chain-commit", help="Submit commit() onchain (requires web3).")
    cc.add_argument("id", help="Item id.")
    cc.add_argument("--rpc", required=True, help="RPC URL.")
    cc.add_argument("--contract", required=True, help="AliXepaXXX contract address.")
    cc.add_argument("--min-delay", default=9, type=int, help="Min reveal delay blocks.")
    cc.add_argument("--max-delay", default=333, type=int, help="Max reveal delay blocks.")
    cc.add_argument("--private-key", default=None, help="0x private key (or env AMYFANTASY_PRIVATE_KEY).")
    cc.add_argument("--prompt-key", action="store_true", help="Prompt for private key.")
    cc.set_defaults(fn=cmd_chain_commit)

    cr = sub.add_parser("chain-reveal", help="Submit reveal() onchain (requires web3).")
    cr.add_argument("id", help="Item id.")
    cr.add_argument("--rpc", required=True, help="RPC URL.")
    cr.add_argument("--contract", required=True, help="AliXepaXXX contract address.")
    cr.add_argument("--commit-hash", required=True, help="bytes32 0x.. commit hash.")
    cr.add_argument("--salt", required=True, help="bytes32 0x.. salt.")
    cr.add_argument("--salt-hint", default=None, help="Optional bytes32 saltHint for local verification.")
    cr.add_argument("--private-key", default=None, help="0x private key (or env AMYFANTASY_PRIVATE_KEY).")
    cr.add_argument("--prompt-key", action="store_true", help="Prompt for private key.")
    cr.set_defaults(fn=cmd_chain_reveal)

    return p


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    p = build_parser()
    args = p.parse_args(argv)
    try:
        return int(args.fn(args))
    except SafetyError as e:
        _eprint(CON.bad("Safety block:"), str(e))
        return 2
    except ChainError as e:
        _eprint(CON.bad("Chain error:"), str(e))
        return 3
    except FileNotFoundError as e:
        _eprint(CON.bad("File error:"), str(e))
        return 4
    except KeyError as e:
        _eprint(CON.bad("Not found:"), str(e))
        return 5
    except Exception as e:
        _eprint(CON.bad("Error:"), repr(e))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
