/*
   DeepFuzz -- depth model implementation
   ------------------------------------
   Hybrid two-level depth model:
   - Static: inter-procedural call depth (from angr) +
             intra-procedural CFG depth (normalized)
   - Dynamic: runtime call-stack depth (from __cyg_profile instrumentation)
   - Combined: max(static, dynamic) per edge
 */

#include "deepfuzz-depth.h"
#include "afl-fuzz.h"
#include "alloc-inl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/shm.h>

/* ---------- JSON depth model loader (uses json-c) ---------- */

#include <json-c/json.h>

void deepfuzz_load_depth_model(void *state, const char *json_path) {

  afl_state_t *afl = (afl_state_t *)state;

  if (!json_path) { return; }

  struct json_object *root = json_object_from_file(json_path);
  if (!root) {

    WARNF("Could not parse depth model file: %s", json_path);
    return;

  }

  /* parse map_size */
  struct json_object *j_map_size;
  u32 map_size = 65536;
  if (json_object_object_get_ex(root, "map_size", &j_map_size)) {

    map_size = (u32)json_object_get_int(j_map_size);

  }

  /* parse max_depth */
  struct json_object *j_max_depth;
  double max_depth = 1.0;
  if (json_object_object_get_ex(root, "max_depth", &j_max_depth)) {

    max_depth = json_object_get_double(j_max_depth);

  }

  /* allocate entries */
  depth_entry_t *entries = ck_alloc(sizeof(depth_entry_t) * map_size);

  /* parse edges */
  struct json_object *j_edges;
  if (json_object_object_get_ex(root, "edges", &j_edges)) {

    json_object_object_foreach(j_edges, key, val) {

      u32 edge_id = (u32)atoi(key);
      if (edge_id >= map_size) { continue; }

      struct json_object *j_combined, *j_inter, *j_intra;

      if (json_object_object_get_ex(val, "combined", &j_combined)) {

        entries[edge_id].combined_depth = json_object_get_double(j_combined);

      }

      if (json_object_object_get_ex(val, "inter", &j_inter)) {

        entries[edge_id].inter_depth = json_object_get_double(j_inter);

      }

      if (json_object_object_get_ex(val, "intra", &j_intra)) {

        entries[edge_id].intra_depth = json_object_get_double(j_intra);

      }

    }

  }

  json_object_put(root);

  /* store in afl_state */
  afl->depth_model.entries = entries;
  afl->depth_model.map_size = map_size;
  afl->depth_model.max_depth = max_depth;
  afl->depth_model.depth_threshold = max_depth * DEPTH_THRESHOLD_RATIO;
  afl->depth_model.loaded = 1;

  OKF("Depth model loaded: map_size=%u, max_depth=%.2f", map_size, max_depth);

}


/* ---------- Per-seed Depth Computation ---------- */

void deepfuzz_compute_seed_depth(void *state, struct queue_entry *q) {

  afl_state_t *afl = (afl_state_t *)state;

  if (!afl->depth_model.loaded || !q) { return; }

  depth_model_t  *dm = &afl->depth_model;
  depth_entry_t  *entries = dm->entries;
  u32             map_size = dm->map_size;
  u8             *trace_bits = afl->fsrv.trace_bits;

  double  max_combined = 0.0;
  u32     deep_edge_cnt = 0;
  double  threshold = dm->depth_threshold;

  /* Iterate over trace_bits to find max combined_depth among touched edges */
  for (u32 i = 0; i < map_size; i++) {

    if (trace_bits[i] != 0) {  /* edge was touched this execution */

      /* edge_id in the coverage map is the XOR of prev and cur location.
         We approximate: use the index directly since the depth model
         stores entries by edge_id = bb_addr & MAP_SIZE_MASK */
      u32 edge_id = i;

      double combined = entries[edge_id].combined_depth;

      /* Fuse with dynamic runtime depth (from SHM) */
      if (afl->depth_shm && afl->depth_shm->max_call_depth > 0) {

        double dynamic_d = (double)afl->depth_shm->max_call_depth;
        if (dynamic_d > combined) { combined = dynamic_d; }

      }

      if (combined > max_combined) { max_combined = combined; }

      if (combined >= threshold) { deep_edge_cnt++; }

    }

  }

  /* Update seed depth info */
  seed_depth_info_t *di = &q->depth_info;

  di->prev_best_depth = di->max_combined_depth;
  di->max_combined_depth = max_combined;
  di->depth_gradient = max_combined - di->prev_best_depth;
  di->deep_edge_count = deep_edge_cnt;

  /* Reset depth SHM for next execution */
  if (afl->depth_shm) {

    afl->depth_shm->max_call_depth = 0;
    afl->depth_shm->cur_call_depth = 0;

  }

}


/* ---------- Depth-based Energy Bonus ---------- */

double deepfuzz_depth_bonus(void *state, struct queue_entry *q) {

  afl_state_t *afl = (afl_state_t *)state;

  if (!afl->depth_model.loaded || !q) { return 0.0; }

  seed_depth_info_t *di = &q->depth_info;
  double model_max = afl->depth_model.max_depth;

  if (model_max <= 0.0 || di->max_combined_depth <= 0.0) { return 0.0; }

  double norm_depth = di->max_combined_depth / model_max;
  if (norm_depth > 1.0) { norm_depth = 1.0; }

  double bonus = DEPTH_BASE_WEIGHT * norm_depth;

  /* Extra gradient bonus for seeds that broke new depth ground */
  if (di->depth_gradient > 0.0) {

    double grad_norm = di->depth_gradient / model_max;
    if (grad_norm > 1.0) { grad_norm = 1.0; }
    bonus += DEPTH_GRADIENT_WEIGHT * grad_norm;

  }

  /* Bonus for number of deep edges touched (up to 0.3 extra) */
  if (di->deep_edge_count > 0) {

    double edge_bonus = 0.3 * (di->deep_edge_count / 100.0);
    if (edge_bonus > 0.3) { edge_bonus = 0.3; }
    bonus += edge_bonus;

  }

  return bonus;

}


/* ---------- Deep Seed Classification ---------- */

u8 deepfuzz_is_deep_seed(void *state, struct queue_entry *q) {

  afl_state_t *afl = (afl_state_t *)state;

  if (!afl->depth_model.loaded || !q) { return 0; }

  return (q->depth_info.max_combined_depth >=
          afl->depth_model.depth_threshold) ? 1 : 0;

}
