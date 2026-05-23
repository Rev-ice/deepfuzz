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

/* ---------- Simple JSON parser for depth_model.json ----------
 *
 * Expected format:
 * {
 *   "map_size": 65536,
 *   "max_depth": 12.67,
 *   "edges": {
 *     "1234": { "combined": 4.67, "inter": 4.0, "intra": 0.67 },
 *     ...
 *   }
 * }
 *
 * We use a bare-minimum parser to avoid depending on json-c for the depth model.
 */

static char *json_get_string_value(const char *json, const char *key) {

  char search[256];
  snprintf(search, sizeof(search), "\"%s\"", key);

  const char *pos = strstr(json, search);
  if (!pos) { return NULL; }

  pos = strchr(pos, ':');
  if (!pos) { return NULL; }
  pos++;

  /* skip whitespace */
  while (*pos == ' ' || *pos == '\t' || *pos == '\n') { pos++; }

  if (*pos != '"') { return NULL; }
  pos++;

  const char *end = strchr(pos, '"');
  if (!end) { return NULL; }

  size_t len = end - pos;
  char *val = ck_alloc(len + 1);
  memcpy(val, pos, len);
  val[len] = '\0';

  return val;

}

static double json_get_number_value(const char *json, const char *key) {

  char *str = json_get_string_value(json, key);
  if (str) {

    double v = atof(str);
    ck_free(str);
    return v;

  }

  /* try raw number (not quoted) */
  char search[256];
  snprintf(search, sizeof(search), "\"%s\"", key);

  const char *pos = strstr(json, search);
  if (!pos) { return 0.0; }

  pos = strchr(pos, ':');
  if (!pos) { return 0.0; }
  pos++;

  while (*pos == ' ' || *pos == '\t' || *pos == '\n') { pos++; }

  return atof(pos);

}

void deepfuzz_load_depth_model(void *state, const char *json_path) {

  afl_state_t *afl = (afl_state_t *)state;

  if (!json_path) { return; }

  FILE *f = fopen(json_path, "r");
  if (!f) {

    WARNF("Could not open depth model file: %s", json_path);
    return;

  }

  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fseek(f, 0, SEEK_SET);

  if (fsize <= 0 || fsize > 50 * 1024 * 1024) {  /* 50 MB max */

    WARNF("Depth model file too large or empty: %s", json_path);
    fclose(f);
    return;

  }

  char *json_buf = ck_alloc(fsize + 1);
  if (fread(json_buf, 1, fsize, f) != (size_t)fsize) {

    WARNF("Could not read depth model file: %s", json_path);
    ck_free(json_buf);
    fclose(f);
    return;

  }

  json_buf[fsize] = '\0';
  fclose(f);

  /* parse map_size */
  u32 map_size = (u32)json_get_number_value(json_buf, "map_size");
  if (map_size == 0) { map_size = 65536; }

  /* parse max_depth */
  double max_depth = json_get_number_value(json_buf, "max_depth");
  if (max_depth <= 0.0) { max_depth = 1.0; }

  /* allocate entries */
  depth_entry_t *entries = ck_alloc(sizeof(depth_entry_t) * map_size);

  /* parse edges */
  const char *edges_start = strstr(json_buf, "\"edges\"");
  if (edges_start) {

    const char *obj_start = strchr(edges_start, '{');
    if (obj_start) {

      /* iterate through edge_id keys */
      const char *p = obj_start + 1;

      while (*p) {

        /* skip whitespace */
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') { p++; }

        if (*p == '}' || *p == '\0') { break; }

        if (*p == '"') {

          p++;
          const char *key_end = strchr(p, '"');
          if (!key_end) { break; }

          /* parse edge_id */
          char key_buf[32];
          size_t key_len = key_end - p;
          if (key_len >= sizeof(key_buf)) { key_len = sizeof(key_buf) - 1; }
          memcpy(key_buf, p, key_len);
          key_buf[key_len] = '\0';
          u32 edge_id = (u32)atoi(key_buf);

          if (edge_id < map_size) {

            /* find value object */
            const char *val = strchr(key_end, '{');
            if (val) {

              const char *val_end = strchr(val, '}');
              if (val_end) {

                /* extract sub-JSON for this edge */
                size_t sub_len = val_end - val + 1;
                char *sub_json = ck_alloc(sub_len + 1);
                memcpy(sub_json, val, sub_len);
                sub_json[sub_len] = '\0';

                entries[edge_id].combined_depth =
                    json_get_number_value(sub_json, "combined");
                entries[edge_id].inter_depth =
                    json_get_number_value(sub_json, "inter");
                entries[edge_id].intra_depth =
                    json_get_number_value(sub_json, "intra");

                ck_free(sub_json);

              }

            }

          }

          p = key_end + 1;

        } else if (*p == ',') {

          p++;

        } else {

          p++;

        }

      }

    }

  }

  ck_free(json_buf);

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
