"""
DeepFuzz -- Static Depth Model Builder (angr-based).

Builds a hybrid two-level depth model:
  1. Inter-procedural: BFS on call graph from entry point
  2. Intra-procedural: BFS on CFG within each function (normalized)

Output: depth_model.json

Formula:
  combined_depth(edge) = inter_depth(func) + intra_depth(bb) / (max_intra(func) + 1)
"""

import json
import sys
import os
from collections import deque


def build_depth_model(
    binary_path: str,
    output_path: str = "depth_model.json",
    map_size: int = 65536,
    load_libs: bool = True,
):
    """
    Build the hybrid two-level depth model using angr.

    Args:
        binary_path: Path to the target binary
        output_path: Path for output JSON
        map_size: AFL++ bitmap size (default 65536)
        load_libs: Whether to load shared libraries in angr
    """
    try:
        import angr
        import networkx as nx
    except ImportError as e:
        print(f"[!] Missing dependency: {e}")
        print("[*] Install with: pip install angr networkx")
        sys.exit(1)

    print(f"[*] Loading binary: {binary_path}")
    proj = angr.Project(binary_path, auto_load_libs=load_libs)

    # Build CFG
    print("[*] Building CFG (this may take a while)...")
    cfg = proj.analyses.CFGFast(
        resolve_indirect_jumps=True,
        force_complete_scan=False,
    )

    # Build call graph
    print("[*] Building call graph...")
    call_graph = cfg.functions.callgraph
    entry_func = proj.entry

    # Find entry function object
    entry_node = None
    for func in cfg.functions.values():
        if func.addr == entry_func:
            entry_node = func
            break

    if entry_node is None:
        print("[!] Could not find entry function, using first function")
        entry_node = next(iter(cfg.functions.values()))

    # BFS on call graph to compute inter-procedural depths
    print("[*] Computing inter-procedural depths...")
    inter_depths = {}  # function_addr -> depth

    queue = deque()
    queue.append((entry_node.addr, 0))
    visited = set()

    while queue:
        func_addr, depth = queue.popleft()
        if func_addr in visited:
            continue
        visited.add(func_addr)
        inter_depths[func_addr] = depth

        # Follow call edges
        for succ in call_graph.successors(func_addr):
            if succ not in visited:
                queue.append((succ, depth + 1))

    print(f"[*] Computed inter-procedural depths for {len(inter_depths)} functions")

    # For each function, compute intra-procedural depths via BFS on CFG
    print("[*] Computing intra-procedural depths...")
    edge_entries = {}  # edge_id -> {"combined": ..., "inter": ..., "intra": ...}

    for func in cfg.functions.values():
        func_addr = func.addr
        inter_d = inter_depths.get(func_addr, 0.0)

        # Get function's CFG nodes
        try:
            func_cfg = cfg.functions[func_addr].transition_graph
        except (KeyError, AttributeError):
            continue

        if len(func_cfg) == 0:
            continue

        # BFS within the function to compute intra-depths
        intra_depths = {}

        # Find the function entry node
        try:
            entry_bb = cfg.functions[func_addr].get_node(func_addr)
        except Exception:
            continue

        if entry_bb is None:
            continue

        queue = deque()
        queue.append((entry_bb, 0))
        intra_visited = set()
        max_intra = 0

        while queue:
            node, depth = queue.popleft()
            bb_addr = node.addr
            if bb_addr in intra_visited:
                continue
            intra_visited.add(bb_addr)
            intra_depths[bb_addr] = depth
            if depth > max_intra:
                max_intra = depth

            for succ in func_cfg.successors(node):
                if succ.addr not in intra_visited:
                    queue.append((succ, depth + 1))

        # Compute combined depth for each edge in this function
        for bb_addr, intra_d in intra_depths.items():
            # Map to AFL++ edge ID (simplified: use lower 21 bits)
            edge_id = bb_addr & (map_size - 1)

            norm_intra = intra_d / (max_intra + 1) if max_intra > 0 else 0.0
            combined = inter_d + norm_intra

            # Keep max if edge appears in multiple functions
            if edge_id not in edge_entries or combined > edge_entries[edge_id].get("combined", 0.0):
                edge_entries[edge_id] = {
                    "combined": round(combined, 4),
                    "inter": round(float(inter_d), 4),
                    "intra": round(norm_intra, 4),
                    "function": func.name if hasattr(func, 'name') else f"0x{func_addr:x}",
                    "bb_addr": f"0x{bb_addr:x}",
                }

    # Compute max depth
    max_depth = max(
        (e["combined"] for e in edge_entries.values()),
        default=1.0
    )

    # Build output model
    model = {
        "map_size": map_size,
        "max_depth": round(max_depth, 4),
        "binary": binary_path,
        "num_functions": len(inter_depths),
        "num_edges": len(edge_entries),
        "edges": {},
    }

    # Use string keys for JSON compatibility
    for edge_id, entry in edge_entries.items():
        model["edges"][str(edge_id)] = entry

    # Write output
    with open(output_path, "w") as f:
        json.dump(model, f, indent=2)

    print(f"[*] Depth model written to {output_path}")
    print(f"    Functions: {len(inter_depths)}")
    print(f"    Edges with depth: {len(edge_entries)}")
    print(f"    Max combined depth: {max_depth:.2f}")

    return model


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="DeepFuzz Depth Model Builder")
    parser.add_argument("--binary", required=True, help="Path to target binary")
    parser.add_argument("--output", default="depth_model.json",
                       help="Output JSON path")
    parser.add_argument("--map-size", type=int, default=65536,
                       help="AFL++ bitmap size")
    parser.add_argument("--no-libs", action="store_true",
                       help="Don't auto-load shared libraries")

    args = parser.parse_args()
    build_depth_model(
        binary_path=args.binary,
        output_path=args.output,
        map_size=args.map_size,
        load_libs=not args.no_libs,
    )
