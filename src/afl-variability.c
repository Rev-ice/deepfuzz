/*
   DeepFuzz -- variability / config injection (trimmed from VAFuzz)
   ------------------------------------
   Retained: config injection, argv havoc, grammar parsing
   Removed:  Z3/PC/regression logic, variability_driver
 */

#include "afl-variability.h"
#include <libgen.h>
#include <limits.h>
#include <time.h>
#include <json-c/json.h>
#include "afl-fuzz.h"

/* ---------- Utilities ---------- */

int random_int(int min, int max) {
  return min + rand() % (max - min + 1);
}

double random_double(double min, double max) {
  double scale = rand() / (double)RAND_MAX;
  return min + scale * (max - min);
}

/* ---------- Config File Path ---------- */

void set_temp_config_file_path(afl_state_t *afl) {

  char *target_path = strcpy(
      ck_alloc(strlen(afl->fsrv.target_path) + 1), afl->fsrv.target_path);
  char *target_dir = dirname((char *)target_path);
  char *temp_config_file_path = ck_alloc(strlen(target_dir) + 13);
  strcpy(temp_config_file_path, target_path);
  strcat(temp_config_file_path, "/config.seed");

  if (access(temp_config_file_path, F_OK) == -1) {
    FILE *f = fopen(temp_config_file_path, "w");
    if (f == NULL) { PFATAL("Unable to create config.seed file"); }
    fprintf(f, " \n");
    fclose(f);
  }

  afl->temp_config_file_path = ck_alloc(strlen(temp_config_file_path) + 1);
  strcpy(afl->temp_config_file_path, temp_config_file_path);
  ck_free(target_path);
  ck_free(temp_config_file_path);

}

/* ---------- Option Entry / Setting Copy Helpers ---------- */

static void deep_copy_array(u8 **src, u8 ***dest) {

  size_t num_strings = 0;
  while (src[num_strings] != NULL) { num_strings++; }

  u8 **temp_dest = (u8 **)malloc((num_strings + 1) * sizeof(u8 *));
  if (temp_dest == NULL) { return; }

  for (size_t i = 0; i < num_strings; i++) {
    size_t len = strlen((char *)src[i]);
    temp_dest[i] = (u8 *)malloc((len + 1) * sizeof(u8));
    if (temp_dest[i] == NULL) {
      for (size_t j = 0; j < i; j++) { free(temp_dest[j]); }
      free(temp_dest);
      return;
    }
    strcpy((char *)temp_dest[i], (char *)src[i]);
  }

  temp_dest[num_strings] = NULL;
  *dest = temp_dest;

}

void copy_option_entry(struct option_entry *dest, struct option_entry *src) {

  dest->opt = strdup(src->opt);
  dest->type = strdup(src->type);
  dest->id = src->id;
  if (src->isChoice) { deep_copy_array(src->choices, &dest->choices); }
  dest->intRangeMax = src->intRangeMax;
  dest->intRangeMin = src->intRangeMin;
  dest->realRangeMax = src->realRangeMax;
  dest->realRangeMin = src->realRangeMin;
  dest->strSize = src->strSize;

}

void copy_option_setting(struct option_setting *dest,
                          struct option_setting *src) {

  dest->opt = strdup(src->opt);
  dest->bool_val = src->bool_val;
  dest->int_val = src->int_val;
  dest->real_val = src->real_val;
  dest->type = strdup(src->type);
  if (src->str_val != NULL) { dest->str_val = strdup(src->str_val); }
  dest->is_static = src->is_static;
  dest->is_negated = src->is_negated;

}

u8 compare_option_setting(struct option_setting *opt_set1,
                           struct option_setting *opt_set2) {

  if (strcmp(opt_set1->opt, opt_set2->opt) != 0) { return 0; }
  if (strcmp(opt_set1->type, opt_set2->type) != 0) { return 0; }

  if (strcmp(opt_set1->type, "bool") == 0) {
    if (opt_set1->bool_val != opt_set2->bool_val) { return 0; }
  } else if (strcmp(opt_set1->type, "intnum") == 0) {
    if (opt_set1->int_val != opt_set2->int_val) { return 0; }
  } else if (strcmp(opt_set1->type, "realnum") == 0) {
    if (opt_set1->real_val != opt_set2->real_val) { return 0; }
  } else {
    if (strcmp(opt_set1->str_val, opt_set2->str_val) != 0) { return 0; }
  }

  if (opt_set1->is_negated != opt_set2->is_negated) { return 0; }
  return 1;

}

u32 count_lines_in_file(u8 *file_name) {

  char c;
  u32  counter = 0;

  FILE *file = fopen(file_name, "r");
  if (file == NULL) { PFATAL("Unable to open file: %s", file_name); }
  for (c = getc(file); c != EOF; c = getc(file)) {
    if (c == '\n') { counter += 1; }
  }
  fclose(file);
  return counter;

}

/* ---------- Grammar File Reader ---------- */

void read_grammar_file(afl_state_t *afl) {

  ACTF("Reading grammar file...");
  if (!afl->grammar_file) {
    fprintf(stderr, "Error: Grammar file not provided.\n");
    return;
  }

  FILE *fp = fopen(afl->grammar_file, "r");
  if (!fp) {
    fprintf(stderr, "Error: Unable to open grammar file.\n");
    return;
  }

  char  buffer[30000];
  size_t len = fread(buffer, 1, sizeof(buffer), fp);
  fclose(fp);

  if (len <= 0) {
    fprintf(stderr, "Error: Unable to read from file.\n");
    return;
  }

  struct json_tokener *tok = json_tokener_new();
  struct json_object  *json_obj = json_tokener_parse_ex(tok, buffer, len);
  if (!json_obj) {
    fprintf(stderr, "Error: Unable to parse JSON.\n");
    json_tokener_free(tok);
    return;
  }
  json_tokener_free(tok);

  struct json_object *options_arr =
      json_object_object_get(json_obj, "options");
  if (!options_arr || !json_object_is_type(options_arr, json_type_array)) {
    fprintf(stderr, "Error: Missing or invalid 'options' array.\n");
    json_object_put(json_obj);
    return;
  }

  u32 tot_options = json_object_array_length(options_arr);
  afl->options_count = tot_options;
  afl->options_holder = ck_alloc(sizeof(u8 *) * tot_options);
  afl->options_type = ck_alloc(sizeof(u8 *) * tot_options);
  afl->options_ranges = ck_alloc(sizeof(int *) * tot_options);
  for (u32 i = 0; i < tot_options; i++) {
    afl->options_ranges[i] = ck_alloc(sizeof(int) * 2);
  }
  afl->options_choices = ck_alloc(sizeof(u8 **) * tot_options);
  afl->options_connectors = ck_alloc(sizeof(u8 *) * tot_options);
  afl->options_choices_count = ck_alloc(sizeof(int) * tot_options);

  for (u32 i = 0; i < tot_options; i++) {

    struct json_object *option =
        json_object_array_get_idx(options_arr, i);
    struct json_object *opt_obj = json_object_object_get(option, "opt");
    struct json_object *type_obj = json_object_object_get(option, "type");
    struct json_object *connector_obj =
        json_object_object_get(option, "connector");

    if (!connector_obj) { connector_obj = json_object_new_string("="); }

    if (opt_obj && type_obj && connector_obj) {

      const char *opt_str = json_object_get_string(opt_obj);
      const char *type_str = json_object_get_string(type_obj);
      const char *connector_str = json_object_get_string(connector_obj);

      afl->options_holder[i] = ck_alloc(strlen(opt_str) + 1);
      afl->options_type[i] = ck_alloc(strlen(type_str) + 1);
      afl->options_connectors[i] = ck_alloc(strlen(connector_str) + 1);
      strcpy(afl->options_holder[i], opt_str);
      strcpy(afl->options_type[i], type_str);
      strcpy(afl->options_connectors[i], connector_str);

      if (strcmp(type_str, "realnum") == 0 ||
          strcmp(type_str, "intnum") == 0) {
        struct json_object *range_obj =
            json_object_object_get(option, "range");
        if (range_obj) {
          struct json_object *range_start =
              json_object_array_get_idx(range_obj, 0);
          struct json_object *range_end =
              json_object_array_get_idx(range_obj, 1);
          if (range_start && range_end) {
            afl->options_ranges[i][0] = json_object_get_int(range_start);
            afl->options_ranges[i][1] = json_object_get_int(range_end);
          }
        }
      } else if (strcmp(type_str, "choice") == 0) {
        struct json_object *choices_obj =
            json_object_object_get(option, "choices");
        if (choices_obj) {
          u32 num_choices = json_object_array_length(choices_obj);
          afl->options_choices_count[i] = num_choices;
          afl->options_choices[i] = ck_alloc(sizeof(u8 *) * num_choices);
          for (u32 j = 0; j < num_choices; j++) {
            struct json_object *choice =
                json_object_array_get_idx(choices_obj, j);
            const char *choice_str = json_object_get_string(choice);
            afl->options_choices[i][j] = ck_alloc(strlen(choice_str) + 1);
            strcpy(afl->options_choices[i][j], choice_str);
          }
        }
      }

    } else {
      fprintf(stderr, "Error: Missing required fields in option object.\n");
    }

  }

  json_object_put(json_obj);
  OKF("Grammar file read successfully");

}

/* ---------- Bitmap <-> Config Conversion ---------- */

u8 *bitmap_to_config(afl_state_t *afl, u8 *bitmap) {

  u8 *config = ck_alloc(sizeof(u8) * 5000);
  strcpy(config, "");
  u32 total_opts = (u32)afl->options_count;

  for (u32 idx = 0; idx < total_opts; idx++) {

    u32 byte_idx = idx / 8;
    u32 bit_idx = idx % 8;
    u8  bit = (bitmap[byte_idx] >> bit_idx) & 1;
    if (!bit) { continue; }

    u8 *opt = afl->options_holder[idx];
    u8 *type = afl->options_type[idx];
    u8 *connector = afl->options_connectors[idx];

    if (strcmp(type, "bool") == 0) {
      u8 *tmp = alloc_printf("%s %s ", config, opt);
      ck_free(config);
      config = tmp;
    } else if (strcmp(type, "intnum") == 0) {
      int val = random_int(afl->options_ranges[idx][0],
                            afl->options_ranges[idx][1]);
      u8 *tmp = alloc_printf("%s %s%s%d ", config, opt, connector, val);
      ck_free(config);
      config = tmp;
    } else if (strcmp(type, "realnum") == 0) {
      double val = random_double((double)afl->options_ranges[idx][0],
                                  (double)afl->options_ranges[idx][1]);
      u8 *tmp = alloc_printf("%s %s%s%f ", config, opt, connector, val);
      ck_free(config);
      config = tmp;
    } else if (strcmp(type, "choice") == 0) {
      if (afl->options_choices_count[idx] > 0) {
        u32 cid = random_int(0, afl->options_choices_count[idx] - 1);
        u8 *tmp = alloc_printf("%s %s %s ", config, opt,
                                afl->options_choices[idx][cid]);
        ck_free(config);
        config = tmp;
      } else {
        u8 *tmp = alloc_printf("%s %s ", config, opt);
        ck_free(config);
        config = tmp;
      }
    } else if (strcmp(type, "string") == 0) {
      u8 *tmp = alloc_printf("%s %s %s ", config, opt, "value");
      ck_free(config);
      config = tmp;
    }

  }

  return config;

}

u8 *config_to_bitmap(afl_state_t *afl, u8 *config) {

  u32 bitmap_len = (u32)ceil((double)afl->options_count / 8.0);
  u8  *bitmap = ck_alloc(bitmap_len);
  memset(bitmap, 0, bitmap_len);

  char *cfg_copy = strdup(config);
  char *token = strtok(cfg_copy, " ");

  while (token) {
    for (u32 i = 0; i < (u32)afl->options_count; i++) {
      if (strcmp(token, afl->options_holder[i]) == 0) {
        u32 byte_idx = i / 8;
        u32 bit_idx = i % 8;
        bitmap[byte_idx] |= (1 << bit_idx);
        break;
      }
    }
    token = strtok(NULL, " ");
  }

  ck_free(cfg_copy);
  return bitmap;

}

/* ---------- Argv Havoc (config-bitmap-level mutation) ---------- */

void argv_havoc(afl_state_t *afl, u8 *cur_bitmap) {

  u32 len = (u32)ceil((double)afl->options_count / 8.0);

  if (!cur_bitmap || !afl->options_holder) { return; }

  u8 *out_buf = ck_alloc(sizeof(u8) * len);
  u8 *temp_buf = ck_alloc(sizeof(u8) * afl->options_count);

  if (afl->stage_max < HAVOC_MIN) { afl->stage_max = HAVOC_MIN; }

  u32 stack_max = 1 << (1 + rand_below(afl, afl->havoc_stack_pow2));

  u8 **config_holder = ck_alloc(sizeof(u8 *) * afl->stage_max);
  afl->configs_to_inject_local_bitmap =
      ck_alloc(sizeof(u8 *) * afl->stage_max);
  int size_of_config_holder = afl->stage_max;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max;
       ++afl->stage_cur) {

    u32 use_stacking = 1 + rand_below(afl, stack_max);
    afl->stage_cur_val = use_stacking;

    memcpy(out_buf, cur_bitmap, len);
    u32 temp_len = len;

    for (u32 i = 0; i < use_stacking; ++i) {

      u32 r = rand_below(afl, 8);

      switch (r) {

        case 0: {  /* flip a random bit */
          u32 off = rand_below(afl, temp_len);
          u8  bit = rand_below(afl, 8);
          out_buf[off] ^= 1 << bit;
          break;
        }

        case 1: {  /* XOR byte with random value */
          u32 pos = rand_below(afl, temp_len);
          u8  val = 1 + rand_below(afl, 255);
          out_buf[pos] ^= val;
          break;
        }

        case 2: {  /* set byte to 0 or 0xFF */
          u32 pos = rand_below(afl, temp_len);
          out_buf[pos] = rand_below(afl, 2) ? 0xFF : 0x00;
          break;
        }

        case 3: {  /* increment byte */
          out_buf[rand_below(afl, temp_len)]++;
          break;
        }

        case 4: {  /* decrement byte */
          out_buf[rand_below(afl, temp_len)]--;
          break;
        }

        case 5: {  /* set byte to interesting 8-bit value */
          u8 item = (u8)rand_below(afl, sizeof(interesting_8));
          out_buf[rand_below(afl, temp_len)] = interesting_8[item];
          break;
        }

        case 6: {  /* swap two bytes */
          if (temp_len >= 2) {
            u32 p1 = rand_below(afl, temp_len);
            u32 p2 = rand_below(afl, temp_len);
            u8  tmp = out_buf[p1];
            out_buf[p1] = out_buf[p2];
            out_buf[p2] = tmp;
          }
          break;
        }

        case 7: {  /* zero a random byte */
          out_buf[rand_below(afl, temp_len)] = 0;
          break;
        }

      }

    }

    u8 *config = bitmap_to_config(afl, out_buf);
    config_holder[afl->stage_cur] = strdup(config);
    ck_free(config);

  }

  /* Select configs */
  if (size_of_config_holder > 50) {

    afl->size_of_inject_arr = 50;
    afl->configs_to_inject_str =
        ck_alloc(sizeof(u8 *) * afl->size_of_inject_arr);
    afl->havoc_argv_scores =
        ck_alloc(sizeof(u128) * afl->size_of_inject_arr);
    memset(afl->havoc_argv_scores, 0,
           sizeof(u128) * afl->size_of_inject_arr);

    for (u32 i = 0; i < (u32)afl->size_of_inject_arr; i++) {
      u32 rand_idx = rand_below(afl, size_of_config_holder);
      afl->configs_to_inject_str[i] = strdup(config_holder[rand_idx]);
    }

  } else {

    afl->size_of_inject_arr = size_of_config_holder;
    afl->configs_to_inject_str =
        ck_alloc(sizeof(u8 *) * size_of_config_holder);
    afl->havoc_argv_scores =
        ck_alloc(sizeof(u128) * afl->size_of_inject_arr);
    memset(afl->havoc_argv_scores, 0,
           sizeof(u128) * afl->size_of_inject_arr);

    for (u32 i = 0; i < (u32)size_of_config_holder; i++) {
      afl->configs_to_inject_str[i] = strdup(config_holder[i]);
    }

  }

  ck_free(temp_buf);
  ck_free(out_buf);

  for (u32 i = 0; i < (u32)size_of_config_holder; i++) {
    ck_free(config_holder[i]);
  }
  ck_free(config_holder);

}

/* ---------- Config Injection ---------- */

u8 inject_config_to_fsrv(afl_state_t *afl,
                          struct option_setting **opt_setting_row) {

  FILE *temp_config_file = fopen(afl->temp_config_file_path, "w");
  if (temp_config_file == NULL) {
    PFATAL("Unable to open temp config file");
    return 0;
  }

  u8 *config_string = "";

  for (u32 j = 0; j < (u32)afl->options_count; j++) {
    struct option_setting *opt_set = opt_setting_row[j];
    if (opt_set->opt == NULL) { continue; }
    u8 *opt = opt_set->opt;
    u8 *type = hashOptGet(afl->options_hashmap, opt)->type;
    if (opt_set->is_negated && strcmp(type, "bool")) { continue; }

    if (!strcmp(type, "choice") || !strcmp(type, "string")) {
      config_string =
          alloc_printf("%s %s %s ", config_string, opt, opt_set->str_val);
    } else if (!strcmp(type, "intnum")) {
      config_string =
          alloc_printf("%s %s %d ", config_string, opt, opt_set->int_val);
    } else if (!strcmp(type, "realnum")) {
      config_string =
          alloc_printf("%s %s %f ", config_string, opt, opt_set->real_val);
    } else if (!strcmp(type, "bool") && opt_set->bool_val) {
      config_string = alloc_printf("%s %s ", config_string, opt);
    }
  }

  fprintf(temp_config_file, "%s", config_string);
  fclose(temp_config_file);

  if (strlen(config_string) > 1) { ck_free(config_string); }
  return 1;

}

u8 inject_config_str_to_fsrv(afl_state_t *afl, u8 *config) {

  FILE *temp_config_file = fopen(afl->temp_config_file_path, "w");
  if (temp_config_file == NULL) {
    PFATAL("Unable to open temp config file");
    return 0;
  }

  fprintf(temp_config_file, "%s", config);
  fclose(temp_config_file);
  return 1;

}

/* ---------- DeepFuzz: Initial Config Generation ---------- */

void generate_initial_configs(afl_state_t *afl) {

  u32 cfg_count = 50;
  if (afl->config_count > 0) { cfg_count = afl->config_count; }

  if (afl->configuration_file) {

    FILE *f = fopen(afl->configuration_file, "r");
    if (!f) {
      PFATAL("Unable to open configuration file: %s",
             afl->configuration_file);
    }

    u32 n = count_lines_in_file(afl->configuration_file);
    afl->size_of_inject_arr = n;
    afl->configs_to_inject_str = ck_alloc(sizeof(u8 *) * n);
    afl->havoc_argv_scores = ck_alloc(sizeof(u128) * n);
    memset(afl->havoc_argv_scores, 0, sizeof(u128) * n);

    char   *line = NULL;
    size_t  llen = 0;
    ssize_t read;
    u32     idx = 0;

    while ((read = getline(&line, &llen, f)) != -1 && idx < n) {
      if (read > 0 && line[read - 1] == '\n') { line[read - 1] = '\0'; }
      afl->configs_to_inject_str[idx] = strdup(line);
      idx++;
    }

    free(line);
    fclose(f);

  } else {

    u32 bitmap_len = (u32)ceil((double)afl->options_count / 8.0);
    u8  *zero_bitmap = ck_alloc(bitmap_len);
    memset(zero_bitmap, 0, bitmap_len);

    afl->stage_max = cfg_count;
    afl->stage_cur = 0;
    argv_havoc(afl, zero_bitmap);

    ck_free(zero_bitmap);

  }

  if (afl->size_of_inject_arr > 0) {

    afl->execs_per_selection = 5000;
    afl->data_triples = ck_alloc(sizeof(struct data_triple *) *
                                  afl->size_of_inject_arr);
    for (int i = 0; i < afl->size_of_inject_arr; i++) {
      afl->data_triples[i] =
          ck_alloc(sizeof(struct data_triple) * afl->execs_per_selection);
    }

  } else {

    afl->size_of_inject_arr = 1;
    afl->configs_to_inject_str = ck_alloc(sizeof(u8 *));
    afl->configs_to_inject_str[0] = strdup("");

  }

  ACTF("Initial config count: %d", afl->size_of_inject_arr);

}
