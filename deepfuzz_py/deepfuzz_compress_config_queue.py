"""
DeepFuzz -- K-means Config Queue Compression.

Compresses a large config pool into a representative subset using
k-means clustering. Each cluster's best representative (highest depth score)
is retained. Falls back gracefully to depth-sorted selection if sklearn
is not available.
"""

from typing import List
from deepfuzz_generate_configs import Config


def compress_configs_kmeans(
    configs: List[Config],
    max_configs: int = 50,
    features: List[List[float]] = None,
) -> List[Config]:
    """Compress config pool via k-means clustering.

    Args:
        configs: List of Config objects
        max_configs: Max number of configs to keep
        features: Feature vectors for each config (if None, uses score only)

    Returns:
        Compressed list of Config objects
    """
    if len(configs) <= max_configs:
        return configs

    # Try sklearn k-means
    try:
        from sklearn.cluster import KMeans
        import numpy as np

        if features is None:
            X = np.array([[c.score, c.max_depth] for c in configs])
        else:
            X = np.array(features)

        n_clusters = min(max_configs, len(configs))
        kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        labels = kmeans.fit_predict(X)

        # Select best representative per cluster (highest depth + score)
        clusters = {i: [] for i in range(n_clusters)}
        for idx, label in enumerate(labels):
            clusters[label].append((idx, configs[idx]))

        result = []
        for cluster_id, items in clusters.items():
            # Sort by combined score: depth * 0.6 + score * 0.4
            items.sort(key=lambda x: x[1].max_depth * 0.6 + x[1].score * 0.4,
                      reverse=True)
            result.append(items[0][1])

        return result

    except ImportError:
        # Graceful fallback: sort by depth+score and take top N
        return fallback_compress(configs, max_configs)


def fallback_compress(configs: List[Config], max_configs: int = 50) -> List[Config]:
    """Fallback compression: sort by (depth * 0.6 + score * 0.4) and take top N."""
    configs.sort(key=lambda c: c.max_depth * 0.6 + c.score * 0.4,
                 reverse=True)
    return configs[:max_configs]
