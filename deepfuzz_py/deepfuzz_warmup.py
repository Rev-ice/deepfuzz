"""
DeepFuzz -- Dynamic Depth Warmup (hybrid calibration).

Runs initial seeds through the target binary to collect runtime
call-stack depth data, then fuses with the static angr model.

The hybrid strategy: combined_depth = max(static_depth, runtime_depth).
This eliminates both static analysis blind spots (indirect calls)
and dynamic exploration gaps (uncovered code).

Prerequisite: Target binary must be compiled with -finstrument-functions
and linked with the DeepFuzz-patched afl-compiler-rt.o (which includes
__cyg_profile_func_enter/exit).
"""

import json
import os
import sys
import time
import struct
import subprocess
import tempfile
from typing import Dict, List, Optional

try:
    import sysv_ipc
    HAS_SYSV_IPC = True
except ImportError:
    HAS_SYSV_IPC = False


# Must match depth_shm_data_t in deepfuzz-depth.h (8 bytes)
DEPTH_SHM_SIZE = 8

def _create_depth_shm():
    """Create a SysV shared memory segment matching C __deepfuzz_depth_init.
    Returns sysv_ipc.SharedMemory or None."""
    if not HAS_SYSV_IPC:
        return None
    try:
        shm = sysv_ipc.SharedMemory(None, sysv_ipc.IPC_CREAT, size=DEPTH_SHM_SIZE)
        os.environ["__DEEPFUZZ_DEPTH_SHM_ID"] = str(shm.id)
        shm.write(b'\x00' * DEPTH_SHM_SIZE)
        return shm
    except Exception:
        return None


def _read_depth_shm(shm) -> int:
    """Read max_call_depth from SysV SHM. Returns 0 on failure."""
    try:
        data = shm.read(DEPTH_SHM_SIZE)
        max_depth, cur_depth = struct.unpack("II", data)
        return max_depth
    except Exception:
        return 0


def _reset_depth_shm(shm):
    """Reset depth SHM to zero."""
    try:
        shm.write(b'\x00' * DEPTH_SHM_SIZE)
    except Exception:
        pass


def run_single(binary: str, input_data: bytes, config: str,
               shm, timeout: int = 10) -> int:
    """Run target binary once with given input and config, return max call depth.

    Args:
        binary: Path to target binary
        input_data: Input bytes (seed file content)
        config: Config string (e.g. "-d -k")
        shm: sysv_ipc.SharedMemory segment
        timeout: Timeout in seconds

    Returns:
        Max call depth observed (0 if not available)
    """
    _reset_depth_shm(shm)

    env = os.environ.copy()
    env["__DEEPFUZZ_DEPTH_SHM_ID"] = str(shm.id)

    seed_path = ""
    try:
        # Write input to temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".seed") as tf:
            tf.write(input_data)
            seed_path = tf.name

        cmd_parts = [binary] + config.split() + [seed_path]

        subprocess.run(
            cmd_parts,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
        )

        return _read_depth_shm(shm)

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return 0
    finally:
        if seed_path and os.path.exists(seed_path):
            os.unlink(seed_path)


def run_warmup(
    binary: str,
    depth_model_path: str,
    seed_dir: str,
    configs: list,
    output_dir: str,
    timeout: int = 60,
) -> str:
    """Run warmup: execute each seed with each config, collect runtime
    call depth from shared memory, and update the depth model.

    Returns path to the updated depth_model.json.
    """
    # Load static model
    with open(depth_model_path, "r") as f:
        model = json.load(f)

    if "edges" not in model:
        return depth_model_path

    # Collect seeds
    seeds = []
    if os.path.isdir(seed_dir):
        for fn in os.listdir(seed_dir):
            fpath = os.path.join(seed_dir, fn)
            if os.path.isfile(fpath) and os.path.getsize(fpath) < 1024 * 1024:
                with open(fpath, "rb") as sf:
                    seeds.append(sf.read())

    if not seeds:
        print("[*] Warmup: no seeds found, skipping")
        return depth_model_path

    # Limit to avoid excessive runtime
    max_runs = min(len(seeds), 5) * min(len(configs), 3)
    print(f"[*] Warmup: {len(seeds)} seeds x {len(configs)} configs "
          f"(limited to {max_runs} runs)")

    # Create depth SHM (SysV, matching C layer shmget/shmat)
    shm = _create_depth_shm()
    if shm is None:
        print("[*] Warmup: could not create depth SHM, using static model only")
        return depth_model_path

    # Collect dynamic observations per edge
    dynamic_observations: Dict[int, float] = {}
    runs_done = 0

    try:
        for si, seed in enumerate(seeds):
            if runs_done >= max_runs:
                break
            for ci, config in enumerate(configs[:3]):
                if runs_done >= max_runs:
                    break

                depth = run_single(binary, seed, config, shm,
                                   timeout=min(timeout, 10))

                if depth > 0:
                    for edge_id_str in model.get("edges", {}):
                        eid = int(edge_id_str)
                        if eid not in dynamic_observations or \
                           depth > dynamic_observations[eid]:
                            dynamic_observations[eid] = float(depth)

                runs_done += 1

    finally:
        try:
            shm.detach()
            shm.remove()
        except Exception:
            pass

    if dynamic_observations:
        model = fuse_static_dynamic(model, dynamic_observations)
        print(f"[*] Warmup: fused {len(dynamic_observations)} dynamic "
              f"observations (max depth={max(dynamic_observations.values()):.1f})")
    else:
        print("[*] Warmup: no dynamic depth data collected "
              "(target may not be instrumented with -finstrument-functions)")

    # Write calibrated model
    os.makedirs(output_dir, exist_ok=True)
    updated_path = os.path.join(output_dir, "depth_model_calibrated.json")

    with open(updated_path, "w") as f:
        json.dump(model, f, indent=2)

    print(f"[*] Warmup: calibrated model written to {updated_path}")
    return updated_path


def fuse_static_dynamic(
    static_model: dict,
    dynamic_observations: Dict[int, float],
) -> dict:
    """Fuse static and dynamic depth observations (max strategy)."""
    edges = static_model.get("edges", {})

    for edge_id_str, dyn_depth in dynamic_observations.items():
        if edge_id_str in edges:
            edge = edges[edge_id_str]
            static_combined = edge.get("combined", 0.0)

            if dyn_depth > static_combined:
                edge["combined"] = dyn_depth
                edge["inter"] = dyn_depth
                edge["intra"] = 0.0

    if edges:
        static_model["max_depth"] = max(
            e.get("combined", 0.0) for e in edges.values()
        )

    static_model["calibrated"] = bool(dynamic_observations)
    return static_model


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="DeepFuzz Warmup Calibration")
    parser.add_argument("--binary", required=True, help="Path to target binary")
    parser.add_argument("--depth-model", required=True,
                       help="Path to static depth_model.json")
    parser.add_argument("--seeds", required=True, help="Path to seed directory")
    parser.add_argument("--configs", default="", help="File with configs or comma-separated list")
    parser.add_argument("--output", required=True, help="Output directory")
    parser.add_argument("--timeout", type=int, default=10,
                       help="Timeout per run (seconds)")

    args = parser.parse_args()

    # Parse configs
    configs = []
    if args.configs:
        if os.path.isfile(args.configs):
            with open(args.configs) as f:
                configs = [l.strip() for l in f if l.strip()]
        else:
            configs = [c.strip() for c in args.configs.split(",") if c.strip()]
    if not configs:
        configs = [""]  # default: no config flags

    result = run_warmup(
        binary=args.binary,
        depth_model_path=args.depth_model,
        seed_dir=args.seeds,
        configs=configs,
        output_dir=args.output,
        timeout=args.timeout,
    )
    print(f"Calibrated model: {result}")
