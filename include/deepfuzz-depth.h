/*
   DeepFuzz -- depth model header
   ------------------------------------
 */

#ifndef _DEEPFUZZ_DEPTH_H
#define _DEEPFUZZ_DEPTH_H

#include "config.h"
#include "types.h"

/* ---------- Constants ---------- */

#define DEEPFUZZ_MAX_EDGES        (1 << 21)   /* 2,097,152 */
#define DEPTH_BASE_WEIGHT         0.4
#define DEPTH_GRADIENT_WEIGHT     0.6
#define DEPTH_THRESHOLD_RATIO     0.5         /* deep if >= max_depth * 0.5  */
#define DEEPFUZZ_DEPTH_SHM_SIZE   8           /* 2 x u32 */

/* ---------- Depth Model (static, loaded from depth_model.json) ---------- */

typedef struct depth_entry {

  double combined_depth;    /* inter + intra/(max_intra+1) */
  double inter_depth;       /* function call depth         */
  double intra_depth;       /* intra-procedural depth      */

} depth_entry_t;

typedef struct depth_model {

  depth_entry_t *entries;   /* indexed by edge_id, size = map_size */
  double         max_depth;
  double         depth_threshold;  /* max_depth * DEPTH_THRESHOLD_RATIO */
  u32            map_size;
  u8             loaded;

} depth_model_t;

/* ---------- Per-seed Depth Statistics ---------- */

typedef struct seed_depth_info {

  double max_combined_depth;  /* max combined_depth among edges touched */
  double prev_best_depth;     /* previous best depth record             */
  double depth_gradient;      /* max_combined_depth - prev_best_depth   */
  u32    deep_edge_count;     /* # of edges whose depth >= threshold    */

} seed_depth_info_t;

/* ---------- Runtime Depth SHM (8 bytes, written by instrumentation) ---------- */

typedef struct depth_shm_data {

  u32 max_call_depth;       /* max concurrent call stack depth this exec */
  u32 cur_call_depth;       /* current call depth (live)                 */

} depth_shm_data_t;

/* forward declaration */
struct queue_entry;

/* ---------- API ---------- */

void  deepfuzz_load_depth_model(void *afl_state, const char *json_path);
void  deepfuzz_compute_seed_depth(void *afl_state, struct queue_entry *q);
double deepfuzz_depth_bonus(void *afl_state, struct queue_entry *q);
u8    deepfuzz_is_deep_seed(void *afl_state, struct queue_entry *q);

#endif /* _DEEPFUZZ_DEPTH_H */
