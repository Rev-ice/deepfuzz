"""
DeepFuzz -- Config Generator.

Generates and mutates command-line configurations using typed definitions.
5 mutation operations: add, drop, replace, toggle, merge.
Value source with 3 tiers: safe, hint, boundary.
"""

import random
import json
from typing import List, Dict, Optional
from deepfuzz_typed_config import (
    TargetConfig, BoolOption, EnumOption, IntOption, StringOption,
    get_value_source, get_int_value, TARGET_CONFIGS
)


class Config:
    """Represents a single command-line configuration."""

    def __init__(self, options_str: str = "", score: float = 0.0,
                 max_depth: float = 0.0):
        self.options_str = options_str
        self.score = score
        self.max_depth = max_depth

    def to_dict(self) -> dict:
        return {
            "options": self.options_str,
            "score": self.score,
            "max_depth": self.max_depth,
        }

    @staticmethod
    def from_dict(d: dict) -> "Config":
        return Config(
            options_str=d.get("options", ""),
            score=d.get("score", 0.0),
            max_depth=d.get("max_depth", 0.0),
        )


def parse_options(config_str: str) -> set:
    """Parse a config string into a set of option names."""
    tokens = config_str.strip().split()
    opts = set()
    for t in tokens:
        if t.startswith("--"):
            if "=" in t:
                opts.add(t.split("=")[0])
            else:
                opts.add(t)
        elif t.startswith("-") and len(t) == 2:
            opts.add(t)
    return opts


def config_str_to_options_dict(config_str: str) -> Dict[str, str]:
    """Parse config string to {option_name: value} dict."""
    result = {}
    tokens = config_str.strip().split()
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t.startswith("-"):
            if "=" in t:
                name, val = t.split("=", 1)
                result[name] = val
            else:
                # check if next token is a value (not starting with -)
                if i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                    result[t] = tokens[i + 1]
                    i += 1
                else:
                    result[t] = "1"  # bool flag present
        i += 1
    return result


def options_dict_to_config_str(opts: Dict[str, str],
                               target: "TargetConfig" = None) -> str:
    """Convert {option_name: value} dict back to config string.

    Uses target type definitions to decide output format:
    - bool:   present=key, absent=omit
    - others: always key=val or key val
    """
    # Build type lookup from target
    opt_type = {}
    if target:
        for bo in target.bool_opts:
            opt_type[bo.name] = "bool"
        for eo in target.enum_opts:
            opt_type[eo.name] = "enum"
        for io in target.int_opts:
            opt_type[io.name] = "intnum"
        for so in target.string_opts:
            opt_type[so.name] = "string"

    parts = []
    for name, val in opts.items():
        typ = opt_type.get(name, "bool")

        if typ == "bool":
            if val and val != "0":
                parts.append(name)
        else:
            # int, float, enum, string — always emit with value
            if "=" in name or name.endswith("="):
                parts.append(f"{name}{val}")
            else:
                parts.append(f"{name}={val}")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Mutation Operations
# ---------------------------------------------------------------------------

OPS = ["add", "drop", "replace", "toggle", "merge"]
OP_PROBS = {
    "add": 0.25,
    "drop": 0.15,
    "replace": 0.25,
    "toggle": 0.20,
    "merge": 0.15,
}


def _check_mutex(target: TargetConfig, current_opts: set,
                 new_opt: str) -> bool:
    """Check if new_opt conflicts with current_opts via mutex groups."""
    for group in target.mutex_groups:
        if new_opt in group:
            for other in group:
                if other != new_opt and other in current_opts:
                    return False
    return True


def _gen_option_value(target: TargetConfig, opt_name: str) -> Optional[str]:
    """Generate a value string for a given option name, respecting type."""
    # Check all option types
    for bo in target.bool_opts:
        if bo.name == opt_name:
            return "1"  # present

    for eo in target.enum_opts:
        if eo.name == opt_name:
            if eo.choices:
                return random.choice(eo.choices)
            return "1"

    for io in target.int_opts:
        if io.name == opt_name:
            source = get_value_source("int")
            return str(get_int_value(io, source))

    for so in target.string_opts:
        if so.name == opt_name:
            if so.candidates:
                return random.choice(so.candidates)
            return "default"

    return None


def mutate_add(target: TargetConfig, current: Dict[str, str]) -> Dict[str, str]:
    """Add a compatible new option."""
    current_names = set(current.keys())
    available = [
        n for n in target.all_option_names()
        if n not in current_names
        and _check_mutex(target, current_names, n)
    ]
    if not available:
        return current
    new_opt = random.choice(available)
    val = _gen_option_value(target, new_opt)
    if val is not None:
        current[new_opt] = val
    return current


def mutate_drop(target: TargetConfig, current: Dict[str, str]) -> Dict[str, str]:
    """Drop a random option."""
    if not current:
        return current
    key = random.choice(list(current.keys()))
    del current[key]
    return current


def mutate_replace(target: TargetConfig, current: Dict[str, str]) -> Dict[str, str]:
    """Replace a parameter value with a new one of the same type."""
    if not current:
        return current
    key = random.choice(list(current.keys()))
    val = _gen_option_value(target, key)
    if val is not None:
        current[key] = val
    return current


def mutate_toggle(target: TargetConfig, current: Dict[str, str]) -> Dict[str, str]:
    """Toggle a boolean option on/off."""
    bool_names = [bo.name for bo in target.bool_opts]
    available = [k for k in bool_names if k not in current or current[k] != "1"]
    absent = [k for k in bool_names if k not in current]

    if absent and random.random() < 0.5:
        key = random.choice(absent)
        current[key] = "1"
    elif available:
        key = random.choice([k for k in bool_names if k in current])
        del current[key]
    return current


def mutate_merge(target: TargetConfig, current: Dict[str, str],
                 other: Dict[str, str]) -> Dict[str, str]:
    """Merge two configs (50% from each)."""
    all_keys = set(list(current.keys()) + list(other.keys()))
    result = {}
    for k in all_keys:
        if random.random() < 0.5 and k in current:
            result[k] = current[k]
        elif k in other:
            result[k] = other[k]
        elif k in current:
            result[k] = current[k]
    return result


def mutate_config(target: TargetConfig, config: Config,
                  all_configs: List[Config] = None) -> Config:
    """Apply a random mutation operation to a config."""
    op = random.choices(OPS, weights=[OP_PROBS[o] for o in OPS], k=1)[0]
    current_dict = config_str_to_options_dict(config.options_str)

    if op == "add":
        new_dict = mutate_add(target, current_dict)
    elif op == "drop":
        new_dict = mutate_drop(target, current_dict)
    elif op == "replace":
        new_dict = mutate_replace(target, current_dict)
    elif op == "toggle":
        new_dict = mutate_toggle(target, current_dict)
    elif op == "merge":
        if all_configs and len(all_configs) > 1:
            other = random.choice(
                [c for c in all_configs if c.options_str != config.options_str])
            other_dict = config_str_to_options_dict(other.options_str)
            new_dict = mutate_merge(target, current_dict, other_dict)
        else:
            new_dict = current_dict
    else:
        new_dict = current_dict

    new_str = options_dict_to_config_str(new_dict, target)
    return Config(options_str=new_str, score=config.score,
                  max_depth=config.max_depth)


def generate_initial_configs(target_name: str, count: int = 50) -> List[Config]:
    """Generate an initial set of configurations for a target."""
    target = TARGET_CONFIGS.get(target_name)
    if not target:
        raise ValueError(f"Unknown target: {target_name}")

    configs = []
    for _ in range(count):
        # Start with random selection of options
        opts_dict = {}
        n_opts = random.randint(1, min(6, len(target.all_option_names())))
        chosen = random.sample(target.all_option_names(), n_opts)

        for name in chosen:
            # Check mutex
            ok = True
            for group in target.mutex_groups:
                if name in group:
                    for other in group:
                        if other != name and other in opts_dict:
                            ok = False
            if ok:
                val = _gen_option_value(target, name)
                if val is not None:
                    opts_dict[name] = val

        cfg_str = options_dict_to_config_str(opts_dict, target)
        if cfg_str.strip():
            configs.append(Config(options_str=cfg_str))

    return configs


def select_seed_config(configs: List[Config]) -> Config:
    """Select a seed config weighted by depth performance."""
    if not configs:
        return Config()

    weights = []
    for c in configs:
        w = 1.0 + c.max_depth + c.score
        weights.append(w)

    total = sum(weights)
    if total <= 0:
        return random.choice(configs)

    probs = [w / total for w in weights]
    return random.choices(configs, weights=probs, k=1)[0]


def write_config_pool(configs: List[Config], path: str):
    """Write config pool to config_set.json (one config string per line)."""
    with open(path, "w") as f:
        for c in configs:
            f.write(c.options_str + "\n")


def read_config_pool(path: str) -> List[Config]:
    """Read config pool from config_set.json."""
    configs = []
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    configs.append(Config(options_str=line))
    except FileNotFoundError:
        pass
    return configs
