"""
DeepFuzz -- Main Controller.

Modes:
  init   : Generate initial config pool and write config_set.json
  daemon : Periodic config refresh (reads affinity_log.jsonl, updates config_set.json)
  once   : One-shot config generation + scoring

Usage:
  python3 deepfuzz_main.py --target xz --afl-output /tmp/out --mode init
  python3 deepfuzz_main.py --target xz --afl-output /tmp/out --depth-model depth_model.json --mode daemon &
"""

import os
import sys
import time
import json
import argparse
from typing import List

from deepfuzz_typed_config import TARGET_CONFIGS, TargetConfig
from deepfuzz_generate_configs import (
    Config, generate_initial_configs, select_seed_config,
    mutate_config, write_config_pool, read_config_pool,
)
from deepfuzz_score_execution import score_and_rank
from deepfuzz_compress_config_queue import compress_configs_kmeans


# ---------------------------------------------------------------------------
# Config Management
# ---------------------------------------------------------------------------

CONFIG_COUNT_INIT = 50       # initial number of configs
CONFIG_COUNT_NEW = 20        # new configs generated per cycle
CONFIG_COUNT_MAX = 50        # max configs after compression
DAEMON_INTERVAL = 60         # seconds between daemon cycles


def init_config_pool(target_name: str, afl_output: str, count: int = None) -> List[Config]:
    """Generate initial config pool and write to config_set.json."""
    if count is None:
        count = CONFIG_COUNT_INIT

    target = TARGET_CONFIGS.get(target_name)
    if not target:
        raise ValueError(f"Unknown target: {target_name}")

    print(f"[*] Generating {count} initial configs for {target_name}...")
    configs = generate_initial_configs(target_name, count)

    config_path = os.path.join(afl_output, "config_set.json")
    write_config_pool(configs, config_path)
    print(f"[*] Wrote {len(configs)} configs to {config_path}")

    return configs


def daemon_cycle(target_name: str, afl_output: str, depth_model_path: str):
    """One cycle of the config daemon."""
    config_path = os.path.join(afl_output, "config_set.json")
    log_path = os.path.join(afl_output, "affinity_log.jsonl")

    # Load current configs
    configs = read_config_pool(config_path)
    print(f"[*] Daemon: loaded {len(configs)} existing configs")

    # Score based on affinity log
    if os.path.exists(log_path):
        configs, scores = score_and_rank(log_path, configs)
        print(f"[*] Scored {len(configs)} configs from affinity log")

    # Generate new configs via mutation
    target = TARGET_CONFIGS.get(target_name)
    if target and configs:
        new_configs = []
        for _ in range(CONFIG_COUNT_NEW):
            seed = select_seed_config(configs)
            mutated = mutate_config(target, seed, configs)
            if mutated.options_str.strip():
                new_configs.append(mutated)

        configs.extend(new_configs)
        print(f"[*] Generated {len(new_configs)} new configs via mutation")

    # Compress pool
    if len(configs) > CONFIG_COUNT_MAX:
        configs = compress_configs_kmeans(configs, max_configs=CONFIG_COUNT_MAX)
        print(f"[*] Compressed to {len(configs)} configs")

    # Write updated pool
    write_config_pool(configs, config_path)
    print(f"[*] Wrote {len(configs)} configs to {config_path}")


def run_daemon(target_name: str, afl_output: str, depth_model_path: str):
    """Run config daemon in a loop."""
    print(f"[*] DeepFuzz daemon starting for {target_name}")
    print(f"    Output dir: {afl_output}")
    print(f"    Interval: {DAEMON_INTERVAL}s")

    while True:
        try:
            daemon_cycle(target_name, afl_output, depth_model_path)
        except Exception as e:
            print(f"[!] Daemon error: {e}")
            import traceback
            traceback.print_exc()

        time.sleep(DAEMON_INTERVAL)


def run_once(target_name: str, afl_output: str, depth_model_path: str):
    """One-shot scoring and config refresh."""
    daemon_cycle(target_name, afl_output, depth_model_path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="DeepFuzz Main Controller")
    parser.add_argument("--target", required=True,
                       choices=list(TARGET_CONFIGS.keys()),
                       help="Target program name")
    parser.add_argument("--afl-output", required=True,
                       help="AFL++ output directory")
    parser.add_argument("--depth-model", default=None,
                       help="Path to depth_model.json")
    parser.add_argument("--mode", required=True,
                       choices=["init", "daemon", "once"],
                       help="Operation mode")
    parser.add_argument("--count", type=int, default=None,
                       help="Number of initial configs (init mode)")

    args = parser.parse_args()

    if args.mode == "init":
        init_config_pool(args.target, args.afl_output, args.count)

        # Run warmup calibration if depth model and seeds are available
        if args.depth_model and args.afl_output:
            try:
                from deepfuzz_warmup import run_warmup
                import os as _os
                seed_dir = _os.path.join(args.afl_output, "..", "seeds")
                if not _os.path.isdir(seed_dir):
                    seed_dir = _os.path.join(args.afl_output, "queue")
                config_path = _os.path.join(args.afl_output, "config_set.json")
                configs = []
                if _os.path.isfile(config_path):
                    with open(config_path) as f:
                        configs = [l.strip() for l in f if l.strip()][:3]
                run_warmup(
                    binary="",
                    depth_model_path=args.depth_model,
                    seed_dir=seed_dir,
                    configs=configs,
                    output_dir=args.afl_output,
                )
            except Exception:
                pass  # warmup is optional

    elif args.mode == "daemon":
        if not args.depth_model:
            print("[!] --depth-model required for daemon mode")
            sys.exit(1)
        run_daemon(args.target, args.afl_output, args.depth_model)

    elif args.mode == "once":
        run_once(args.target, args.afl_output, args.depth_model or "")


if __name__ == "__main__":
    main()
