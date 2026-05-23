/*
   DeepFuzz -- option hashmap header
   ------------------------------------
   Retained from VAFuzz (UTD-FAST-Lab/VAFuzz).
   Used for config string hashing in afl-variability.c.
   No modifications from original.
 */

#ifndef AFL_HASHMAP_H
#define AFL_HASHMAP_H

#include "config.h"
#include "types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define XXH_INLINE_ALL
#include "xxhash.h"
#undef XXH_INLINE_ALL

/* forward declaration */
struct option_entry;

typedef struct HashIntNode {

  u8   *key;
  int   value;
  struct HashIntNode *next;
  u8    assigned;

} HashIntNode;

typedef struct HashIntMap {

  HashIntNode *buckets[100];

} HashIntMap;

typedef struct HashOptNode {

  char   *key;
  struct option_entry *option_payload;
  struct HashOptNode  *next;
  u8     assigned;

} HashOptNode;

typedef struct HashOptMap {

  HashOptNode *buckets[100];

} HashOptMap;

/* --- HashIntMap API --- */

HashIntMap *initHashIntMap(void);
void        hashIntInsert(HashIntMap *map, const char *key, int value);
int         hashIntGet(HashIntMap *map, const char *key);
void        freeHashIntMap(HashIntMap *map);
void        printHashIntMap(HashIntMap *map);
void        printHashIntMapToFile(HashIntMap *map, FILE *f);

/* --- HashOptMap API --- */

HashOptMap          *initHashOptMap(void);
void                 hashOptInsert(HashOptMap *map, const char *key,
                                   struct option_entry *opt_entry);
struct option_entry *hashOptGet(HashOptMap *map, const char *key);
struct option_entry **getAllOptionEntries(HashOptMap *map, int *numEntries);
void                 printHashOptMap(HashOptMap *map);

#endif
