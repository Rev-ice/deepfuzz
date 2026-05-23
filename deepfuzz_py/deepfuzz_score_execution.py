"""
DeepFuzz -- Execution Feedback Scoring.

Reads affinity_log.jsonl to compute per-config scores and
seed-config affinity measures.
"""

import json
import os
from typing import List, Dict, Tuple
from collections import defaultdict
from deepfuzz_generate_configs import Config


def parse_affinity_log(log_path: str) -> List[dict]:
    """Parse affinity_log.jsonl into list of entries."""
    entries = []
    if not os.path.exists(log_path):
        return entries
    with open(log_path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return entries


def compute_config_scores(
    entries: List[dict],
    config_count: int,
) -> List[float]:
    """Compute a score for each config based on affinity data.

    Score = avg_depth * 0.5 + frac_deep_edges * 0.3 + new_cov_frac * 0.2
    """
    config_data = defaultdict(lambda: {
        "depths": [], "deep_edges": [], "new_cov": [], "count": 0
    })

    for e in entries:
        cid = e.get("config_idx", 0)
        config_data[cid]["depths"].append(e.get("max_depth", 0.0))
        config_data[cid]["deep_edges"].append(e.get("deep_edges", 0))
        config_data[cid]["count"] += 1

    scores = [0.0] * max(config_count, max(config_data.keys()) + 1 if config_data else 0)
    max_depth = max(
        (max(v["depths"]) for v in config_data.values() if v["depths"]),
        default=1.0
    )
    max_de = max(
        (max(v["deep_edges"]) for v in config_data.values() if v["deep_edges"]),
        default=1
    )

    for cid, data in config_data.items():
        if data["count"] == 0:
            continue
        avg_depth = sum(data["depths"]) / len(data["depths"])
        avg_de = sum(data["deep_edges"]) / len(data["deep_edges"])

        norm_depth = avg_depth / max_depth if max_depth > 0 else 0
        norm_de = avg_de / max_de if max_de > 0 else 0

        scores[cid] = norm_depth * 0.5 + norm_de * 0.5

    return scores


def update_config_scores(configs: List[Config], scores: List[float]):
    """Update config objects with new scores."""
    for i, c in enumerate(configs):
        if i < len(scores):
            c.score = scores[i]


def score_and_rank(
    log_path: str, configs: List[Config]
) -> Tuple[List[Config], List[float]]:
    """Full scoring pipeline: parse log, compute scores, update configs."""
    entries = parse_affinity_log(log_path)
    scores = compute_config_scores(entries, len(configs))
    update_config_scores(configs, scores)
    return configs, scores
