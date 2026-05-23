"""
DeepFuzz -- Typed Config Definitions for 5 Target Programs.

Each target has typed parameter definitions (bool, enum, int, string)
with values categorized as safe/hint/boundary.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple

# ---------------------------------------------------------------------------
# Option Types
# ---------------------------------------------------------------------------

@dataclass
class BoolOption:
    name: str
    default: bool = False
    negation: Optional[str] = None  # e.g. "no-" prefix

@dataclass
class EnumOption:
    name: str
    choices: List[str]
    connector: str = "="
    default: Optional[str] = None

@dataclass
class IntOption:
    name: str
    min_val: int
    max_val: int
    connector: str = "="
    safe_values: List[int] = field(default_factory=list)
    hint_values: List[int] = field(default_factory=list)
    boundary_values: List[int] = field(default_factory=list)
    default: Optional[int] = None

@dataclass
class StringOption:
    name: str
    connector: str = "="
    candidates: List[str] = field(default_factory=list)
    default: Optional[str] = None

@dataclass
class TargetConfig:
    name: str
    bool_opts: List[BoolOption] = field(default_factory=list)
    enum_opts: List[EnumOption] = field(default_factory=list)
    int_opts: List[IntOption] = field(default_factory=list)
    string_opts: List[StringOption] = field(default_factory=list)
    mutex_groups: List[List[str]] = field(default_factory=list)
    dependencies: Dict[str, List[str]] = field(default_factory=dict)
    fixed_prefix: str = ""

    def all_option_names(self) -> List[str]:
        names = []
        for o in self.bool_opts: names.append(o.name)
        for o in self.enum_opts: names.append(o.name)
        for o in self.int_opts: names.append(o.name)
        for o in self.string_opts: names.append(o.name)
        return names

# ---------------------------------------------------------------------------
# Target Definitions
# ---------------------------------------------------------------------------

TARGET_CONFIGS: Dict[str, TargetConfig] = {}

# --- xz ---
TARGET_CONFIGS["xz"] = TargetConfig(
    name="xz",
    bool_opts=[
        BoolOption(name="-k", default=False),
        BoolOption(name="-f", default=False),
        BoolOption(name="-c", default=False),
        BoolOption(name="--no-sparse", default=False),
    ],
    enum_opts=[
        EnumOption(name="-F", choices=["auto", "xz", "lzma", "raw"],
                   connector="=", default="auto"),
        EnumOption(name="-z", choices=[]),
        EnumOption(name="-d", choices=[]),
        EnumOption(name="-t", choices=[]),
        EnumOption(name="-l", choices=[]),
    ],
    int_opts=[
        IntOption(name="-0", min_val=0, max_val=0),  # alias
        IntOption(name="-1", min_val=0, max_val=0),
        IntOption(name="-2", min_val=0, max_val=0),
        IntOption(name="-3", min_val=0, max_val=0),
        IntOption(name="-4", min_val=0, max_val=0),
        IntOption(name="-5", min_val=0, max_val=0),
        IntOption(name="-6", min_val=0, max_val=0),
        IntOption(name="-7", min_val=0, max_val=0),
        IntOption(name="-8", min_val=0, max_val=0),
        IntOption(name="-9", min_val=0, max_val=0),
        IntOption(name="--memlimit-compress", min_val=1, max_val=4096,
                  connector="=", safe_values=[512], hint_values=[256, 1024],
                  boundary_values=[1, 4096]),
        IntOption(name="--block-size", min_val=1, max_val=4096,
                  connector="=", safe_values=[4096], hint_values=[512, 2048],
                  boundary_values=[1, 4096]),
        IntOption(name="--threads", min_val=1, max_val=64,
                  connector="=", safe_values=[1], hint_values=[2, 4],
                  boundary_values=[1, 64]),
    ],
    mutex_groups=[["-z", "-d", "-t", "-l"]],
)

# --- tiff2pdf ---
TARGET_CONFIGS["tiff2pdf"] = TargetConfig(
    name="tiff2pdf",
    bool_opts=[
        BoolOption(name="-z", default=False),
        BoolOption(name="-j", default=False),
        BoolOption(name="-n", default=False),
        BoolOption(name="-d", default=False),
    ],
    int_opts=[
        IntOption(name="-q", min_val=0, max_val=100,
                  connector="=", safe_values=[75], hint_values=[50, 90],
                  boundary_values=[0, 100]),
    ],
    enum_opts=[
        EnumOption(name="-p", choices=["letter", "legal", "a4", "a3", "a2"],
                   connector="="),
        EnumOption(name="-F", choices=["none", "fit", "fill"],
                   connector="="),
    ],
)

# --- objdump ---
TARGET_CONFIGS["objdump"] = TargetConfig(
    name="objdump",
    bool_opts=[
        BoolOption(name="-d"), BoolOption(name="-D"), BoolOption(name="-t"),
        BoolOption(name="-r"), BoolOption(name="-s"), BoolOption(name="-h"),
        BoolOption(name="-x"), BoolOption(name="-g"), BoolOption(name="-G"),
        BoolOption(name="-S"), BoolOption(name="-l"), BoolOption(name="-C"),
        BoolOption(name="-w"),
    ],
    enum_opts=[
        EnumOption(name="-M", choices=[],
                   connector="="),
    ],
    int_opts=[
        IntOption(name="--start-address", min_val=0, max_val=0xFFFFFFFF,
                  connector="=", safe_values=[0x400000],
                  hint_values=[0x1000, 0x800000],
                  boundary_values=[0, 0xFFFFFFFF]),
    ],
    mutex_groups=[["-d", "-D"]],
)

# --- readelf ---
TARGET_CONFIGS["readelf"] = TargetConfig(
    name="readelf",
    bool_opts=[
        BoolOption(name="-a"), BoolOption(name="-h"), BoolOption(name="-l"),
        BoolOption(name="-S"), BoolOption(name="-e"), BoolOption(name="-s"),
        BoolOption(name="-r"), BoolOption(name="-d"), BoolOption(name="-n"),
        BoolOption(name="-V"), BoolOption(name="-A"), BoolOption(name="-W"),
        BoolOption(name="--debug-dump"),
    ],
)

# --- nm ---
TARGET_CONFIGS["nm"] = TargetConfig(
    name="nm",
    bool_opts=[
        BoolOption(name="-A"), BoolOption(name="-a"), BoolOption(name="-D"),
        BoolOption(name="-g"), BoolOption(name="-u"), BoolOption(name="-l"),
        BoolOption(name="-p"), BoolOption(name="-S"), BoolOption(name="-n"),
    ],
    enum_opts=[
        EnumOption(name="--format", choices=["bsd", "sysv", "posix"],
                   connector="="),
    ],
)

# ---------------------------------------------------------------------------
# Value Sources
# ---------------------------------------------------------------------------

SOURCE_PROBS = {"safe": 0.45, "hint": 0.35, "boundary": 0.20}

def get_value_source(source_type: str) -> str:
    import random
    r = random.random()
    if r < SOURCE_PROBS["safe"]:
        return "safe"
    elif r < SOURCE_PROBS["safe"] + SOURCE_PROBS["hint"]:
        return "hint"
    else:
        return "boundary"

def get_int_value(opt: IntOption, source: str) -> int:
    import random
    if source == "safe" and opt.safe_values:
        return random.choice(opt.safe_values)
    elif source == "hint" and opt.hint_values:
        return random.choice(opt.hint_values)
    elif source == "boundary" and opt.boundary_values:
        return random.choice(opt.boundary_values)
    else:
        return random.randint(opt.min_val, opt.max_val)
