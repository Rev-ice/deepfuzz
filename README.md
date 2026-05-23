# DeepFuzz

Coverage-guided fuzzer with **library call depth** as a feedback dimension, built on AFL++ 4.40c.

Extends AFL++ with a hybrid two-level depth model (static angr call-graph analysis + dynamic runtime calibration) applied to energy scheduling, mutation strategy, and config selection.

## Architecture

```
Python outer layer (heavy logic)          C inner layer (performance-critical)
┌──────────────────────────┐          ┌──────────────────────────────┐
│ depth model builder (angr)│          │ config co-execution          │
│ typed config generator    │  JSON    │   (same seed × multi config) │
│ k-means config compression│◄────────►│ depth-boosted energy schedule│
│ affinity scoring          │  SHM     │ depth-aware mutation strategy│
│ daemon (periodic refresh) │          │ runtime depth instrumentation│
└──────────────────────────┘          └──────────────────────────────┘
```

## Prerequisites

- **macOS or Linux** (tested on macOS ARM64, Linux x86_64)
- **AFL++ 4.40c (exact version required)**
  - Download: https://github.com/AFLplusplus/AFLplusplus/releases/tag/v4.40c
  - ⚠️ Do NOT use AFL++ stable/dev branch — API may be incompatible with overlay patches
- **clang/LLVM 14+** (for `afl-clang-fast` instrumentation)
- **json-c** — `brew install json-c` (macOS) or `apt install libjson-c-dev` (Linux)
- **Python 3.9+** with `angr`, `networkx`, `scikit-learn`, `numpy`

### Target binary compilation

For runtime depth instrumentation, compile the target with:

```bash
CC=./afl-clang-fast CFLAGS="-finstrument-functions -fno-optimize-sibling-calls" ./configure
make
```

If `-finstrument-functions` is not used, DeepFuzz falls back to static-only depth model (no dynamic calibration).

## Quick Start

```bash
# 1. Clone and build AFL++ 4.40c
wget https://github.com/AFLplusplus/AFLplusplus/archive/refs/tags/v4.40c.tar.gz
tar xzf v4.40c.tar.gz
cd AFLplusplus-4.40c

# 2. Apply DeepFuzz files on top
cp -r /path/to/deepfuzz/src/* src/
cp -r /path/to/deepfuzz/include/* include/
cp /path/to/deepfuzz/src/afl-compiler-rt.o.c instrumentation/
cp /path/to/deepfuzz/src/GNUmakefile .
cp -r /path/to/deepfuzz/deepfuzz_py .
cp /path/to/deepfuzz/run_deepfuzz.sh .

# 3. Install Python dependencies
pip3 install -r deepfuzz_py/requirements.txt

# 4. Build
AFL_NO_X86=1 make -j$(nproc) afl-fuzz

# 5. Build depth model for your target
python3 deepfuzz_py/deepfuzz_build_depth_model.py \
    --binary ./target --output depth_model.json

# 6. Run
./run_deepfuzz.sh xz ./target ./seeds /tmp/out
```

Or manually:

```bash
# Init config pool
python3 deepfuzz_py/deepfuzz_main.py --target xz --afl-output /tmp/out --mode init

# Start daemon (background)
python3 deepfuzz_py/deepfuzz_main.py --target xz --afl-output /tmp/out \
    --depth-model depth_model.json --mode daemon &

# Launch fuzzer
./afl-fuzz -i seeds/ -o /tmp/out -J depth_model.json -r grammar/xz.json -- ./target @@
```

## File Layout

```
deepfuzz/
├── include/
│   ├── deepfuzz-depth.h       # depth model structures + API (NEW)
│   ├── afl-hashmap.h           # option hashmap (NEW, from VAFuzz)
│   ├── afl-variability.h       # config injection API (NEW)
│   └── afl-fuzz.h              # AFL++ header (MODIFIED: +DeepFuzz fields)
├── src/
│   ├── deepfuzz-depth.c        # depth model impl (NEW)
│   ├── afl-hashmap.c           # option hashmap impl (NEW, from VAFuzz)
│   ├── afl-variability.c       # config injection + argv havoc (NEW)
│   ├── afl-fuzz.c              # main fuzzer (MODIFIED: -J/-r, init, config switch)
│   ├── afl-fuzz-run.c          # execution runner (MODIFIED: config co-exec loop)
│   ├── afl-fuzz-one.c          # mutation engine (MODIFIED: depth-aware havoc)
│   ├── afl-fuzz-queue.c        # energy scheduling (MODIFIED: depth bonus)
│   ├── afl-compiler-rt.o.c     # runtime instrumentation (MODIFIED: depth SHM)
│   └── GNUmakefile             # build system (MODIFIED: +new .o, +json-c)
├── deepfuzz_py/
│   ├── deepfuzz_main.py        # main controller (init/daemon/once)
│   ├── deepfuzz_build_depth_model.py  # angr-based depth model builder
│   ├── deepfuzz_typed_config.py       # 5 target config definitions
│   ├── deepfuzz_generate_configs.py   # config mutation engine
│   ├── deepfuzz_compress_config_queue.py  # k-means compression
│   ├── deepfuzz_score_execution.py    # affinity scoring
│   └── deepfuzz_warmup.py      # dynamic depth calibration
├── grammar/                    # JSON grammar files for command-line options
├── run_deepfuzz.sh             # one-shot build & run
└── README.md
```

## New CLI Options

| Flag | Purpose |
|------|---------|
| `-J <file>` | Path to `depth_model.json` (hybrid two-level depth model) |
| `-r <file>` | Path to JSON grammar file (command-line option definitions) |

## 5 Pre-configured Targets

| Target | Grammar | Typed Config |
|--------|---------|-------------|
| xz | xz.json | `deepfuzz_typed_config.py` |
| objdump | objdump_all_bool.json | `deepfuzz_typed_config.py` |
| readelf | — | `deepfuzz_typed_config.py` |
| nm | nm_all_bool.json | `deepfuzz_typed_config.py` |
| tiff2pdf | — | `deepfuzz_typed_config.py` |

To add a new target, define its `TargetConfig` in `deepfuzz_typed_config.py` and create a JSON grammar file.

## Key Design Decisions

1. **AFL++ 4.40c base (not VAFuzz)**: Ported only the config co-execution framework (~700 lines) from VAFuzz. Removed Z3/PC/regression/GSL/embedded-Python (~3400 lines of VAFuzz dead code).
2. **File-based Python↔C communication**: No embedded CPython. `config_set.json` is plain text (one config string per line). `depth_model.json` is JSON. `affinity_log.jsonl` is JSONL. Plus POSIX shared memory for coverage bitmap and depth SHM.
3. **Hybrid two-level depth model**: `combined_depth = inter_depth + intra_depth/(max_intra+1)`, fused with runtime `__cyg_profile` observations via `max(static, dynamic)`.

## License

This project builds on AFL++ (Apache 2.0) and VAFuzz (MIT). DeepFuzz additions are MIT licensed.
