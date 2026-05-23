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


# Must match depth_shm_data_t in deepfuzz-depth.h (8 bytes)
DEPTH_SHM_SIZE = 8

def _create_depth_shm() -> Optional[int]:
    """Create a POSIX shared memory segment for depth data. Returns shm fd."""
    try:
        import mmap
        name = f"/deepfuzz_warmup_{os.getpid()}_{int(time.time())}"
        fd = os.open(f"/tmp/deepfuzz_shm_{os.getpid()}", os.O_CREAT | os.O_RDWR)
        os.ftruncate(fd, DEPTH_SHM_SIZE)
        return fd
    except Exception:
        return None


def _read_depth_shm(fd: int) -> int:
    """Read max_call_depth from the SHM segment. Returns 0 on failure."""
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        data = os.read(fd, DEPTH_SHM_SIZE)
        if len(data) >= 8:
            max_depth, cur_depth = struct.unpack("II", data[:8])
            return max_depth
    except Exception:
        pass
    return 0


def _reset_depth_shm(fd: int):
    """Reset depth SHM to zero."""
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, b'\x00' * DEPTH_SHM_SIZE)
    except Exception:
        pass


def run_single(binary: str, input_data: bytes, config: str,
               shm_fd: int, timeout: int = 10) -> int:
    """Run target binary once with given input and config, return max call depth.

    Args:
        binary: Path to target binary
        input_data: Input bytes (seed file content)
        config: Config string (e.g. "-d -k")
        shm_fd: File descriptor for depth SHM
        timeout: Timeout in seconds

    Returns:
        Max call depth observed (0 if not available)
    """
    _reset_depth_shm(shm_fd)

    env = os.environ.copy()
    env["__DEEPFUZZ_DEPTH_SHM_ID"] = str(shm_fd)

    try:
        # Write input to temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".seed") as tf:
            tf.write(input_data)
            seed_path = tf.name

        # Build command
        cmd_parts = [binary] + config.split() + [seed_path]

        proc = subprocess.run(
            cmd_parts,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
        )

        depth = _read_depth_shm(shm_fd)

        os.unlink(seed_path)
        return depth

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        # Target not instrumented or failed to run
        if os.path.exists(seed_path):
            os.unlink(seed_path)
        return 0


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

    # Create depth SHM
    shm_fd = _create_depth_shm()
    if shm_fd is None:
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

                depth = run_single(binary, seed, config, shm_fd,
                                   timeout=min(timeout, 10))

                if depth > 0:
                    # Record the observed call depth — this is an
                    # inter-procedural signal. Map to all edges in the
                    # static model by raising the floor.
                    for edge_id_str in model.get("edges", {}):
                        eid = int(edge_id_str)
                        if eid not in dynamic_observations or \
                           depth > dynamic_observations[eid]:
                            dynamic_observations[eid] = float(depth)

                runs_done += 1

    finally:
        os.close(shm_fd)

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
