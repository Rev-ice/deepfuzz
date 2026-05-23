/*
   DeepFuzz -- variability / config injection header (trimmed from VAFuzz)
   ------------------------------------
   Retained: config injection, argv havoc, grammar parsing
   Removed:  Z3/PC/regression declarations, variability_driver
 */

#ifndef AFL_VARIABILITY_H
#define AFL_VARIABILITY_H

#include "config.h"
#include "types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/* forward declarations */
typedef struct afl_state afl_state_t;
struct option_entry;
struct option_setting;

/* --- Utilities --- */

void copy_option_entry(struct option_entry *dest, struct option_entry *src);
void copy_option_setting(struct option_setting *dest, struct option_setting *src);
void set_temp_config_file_path(afl_state_t *afl);
u8   compare_option_setting(struct option_setting *opt_set1,
                             struct option_setting *opt_set2);

u32  count_lines_in_file(u8 *path);
int  random_int(int min, int max);
double random_double(double min, double max);

/* --- Grammar / Config Management --- */

void read_grammar_file(afl_state_t *afl);
void generate_initial_configs(afl_state_t *afl);

/* --- Config Injection --- */

u8 inject_config_to_fsrv(afl_state_t *afl, struct option_setting **opt_setting_row);
u8 inject_config_str_to_fsrv(afl_state_t *afl, u8 *config);

/* --- Bitmap <-> Config Conversion --- */

u8 *bitmap_to_config(afl_state_t *afl, u8 *bitmap);
u8 *config_to_bitmap(afl_state_t *afl, u8 *config);

/* --- Config-level Havoc Mutation --- */

void argv_havoc(afl_state_t *afl, u8 *cur_bitmap);

/* --- DeepFuzz Config Pool I/O (file-exchange with Python layer) --- */

void deepfuzz_load_config_pool(afl_state_t *afl, const char *json_path);
void deepfuzz_write_affinity_log(afl_state_t *afl);

#endif /* AFL_VARIABILITY_H */
