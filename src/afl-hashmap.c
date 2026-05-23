#include "afl-hashmap.h"
#include "afl-fuzz.h"


#define TABLE_SIZE 100
#define LIST_SIZE 10

// Hash function
unsigned int hash(const char* key) {
    return XXH3_64bits(key, strlen(key)) % TABLE_SIZE;
}

// Create a new node
HashIntNode *createIntNode(const char *key, int value) {
    HashIntNode *newNode = (HashIntNode *)malloc(sizeof(HashIntNode));
    newNode->key = strdup(key); // strdup dynamically allocates memory for a copy of the string
    newNode->value = value;
    newNode->assigned = true;
    newNode->next = NULL;
    return newNode;
}

// Initialize the HashIntMap
HashIntMap * initHashIntMap() {
    struct HashIntMap *map;
    map = ck_alloc(sizeof(HashIntMap));
    for (int i = 0; i < TABLE_SIZE; ++i) {
        map->buckets[i] = ck_alloc(sizeof(HashIntNode) * LIST_SIZE);
        for (int j = 0; j < LIST_SIZE - 1; ++j) {
            map->buckets[i][j].assigned = false;
            map->buckets[i][j].next = &map->buckets[i][j + 1];
        }
        map->buckets[i][LIST_SIZE - 1].assigned = false;
    }

    return map;
}


void printHashIntMap(HashIntMap *map) {
    printf("HashOptMap Contents:\n");
    for (int i = 0; i < TABLE_SIZE; ++i) {
        HashIntNode *current = map->buckets[i];
        if (current->assigned == true) {
            printf("Bucket %d: ", i);
            while (current->assigned == true) {
                printf("Key: %s\n", current->key);
                printf("idx: %d\n", current->value);
                current = current->next;
            }
            printf("\n");
        }
    }
}

// Insert key-value pair into HashIntMap
void hashIntInsert(HashIntMap *map, const char *key, int value) {
    unsigned int index = hash(key);
    HashIntNode *newNode = createIntNode(key, value);

    // If the bucket is empty, insert the node as the first element
    struct HashIntNode *curNode = map->buckets[index];
    if (curNode->assigned == false) {

        map->buckets[index] = newNode;
        newNode->next = curNode->next;

    } else {
        // Collision: Insert the new node at the beginning of the chain
        newNode->next = map->buckets[index];
        map->buckets[index] = newNode;
    }
}


// Retrieve value associated with a key
int hashIntGet(HashIntMap *map, const char *key) {
    unsigned int index = hash(key);
    HashIntNode *current = map->buckets[index];

    // Traverse the chain at the given index
    while (current->assigned != false) {
        if (strcmp(current->key, key) == 0) {
            return current->value;
        }
        current = current->next;
    }

    // Key not found
    return -1;
}


void freeHashIntMap(HashIntMap *map) {
    if (map == NULL) return;

    for (int i = 0; i < TABLE_SIZE; ++i) {
        if (map->buckets[i] != NULL) {
            free(map->buckets[i]);
        }
    }

    free(map);
}

void printHashIntMapToFile(HashIntMap *map, FILE *f) {
    fprintf(f, "HashOptMap Contents:\n");
    for (int i = 0; i < TABLE_SIZE; ++i) {
        HashIntNode *current = map->buckets[i];
        if (current->assigned == true) {
            fprintf(f, "Bucket %d: ", i);
            while (current->assigned == true) {
                fprintf(f, "Key: %s\n", current->key);
                fprintf(f, "idx: %d\n", current->value);
                current = current->next;
            }
            fprintf(f, "\n");
        }
    }
}





// OPTION HASHMAP

// Create a new node
HashOptNode *createOptNode(const char *key, struct option_entry *opt_entry) {
    HashOptNode *newNode = (HashOptNode *)malloc(sizeof(HashOptNode));
    newNode->key = strdup(key); // strdup dynamically allocates memory for a copy of the string
    newNode->option_payload = ck_alloc(sizeof(struct option_entry));
    copy_option_entry(newNode->option_payload, opt_entry);
    newNode->assigned = true;
    newNode->next = NULL;
    return newNode;
}

// Initialize the Opt Hashmap
HashOptMap * initHashOptMap() {
    struct HashOptMap *map;
    map = ck_alloc(sizeof(HashOptMap));
    for (int i = 0; i < TABLE_SIZE; ++i) {
        map->buckets[i] = ck_alloc(sizeof(HashOptNode) * LIST_SIZE);
        for (int j = 0; j < LIST_SIZE - 1; ++j) {
            map->buckets[i][j].assigned = false;
            map->buckets[i][j].next = &map->buckets[i][j + 1];
        }
        map->buckets[i][LIST_SIZE - 1].assigned = false;
    }

    return map;
}

void printHashOptMap(HashOptMap *map) {
    printf("HashOptMap Contents:\n");
    for (int i = 0; i < TABLE_SIZE; ++i) {
        HashOptNode *current = map->buckets[i];
        if (current->assigned == true) {
            printf("Bucket %d: ", i);
            while (current->assigned == true) {
                printf("Key: %s\n", current->key);
                printf("ID: %d\n", current->option_payload->id);
                current = current->next;
            }
            printf("\n");
        }
    }
}

void copy_opt_node(HashOptNode *dest, HashOptNode *src) {
    dest->key = strdup(src->key);
    copy_option_entry(dest->option_payload, src->option_payload);
    dest->assigned = true;
}

// Insert key-value pair into HashIntMap
void hashOptInsert(HashOptMap *map, const char *key, struct option_entry *opt_entry) {
    unsigned int index = hash(key);
    HashOptNode *newNode = createOptNode(key, opt_entry);

    // If the bucket is empty, insert the node as the first element
    struct HashOptNode *curNode = map->buckets[index];
    if (curNode->assigned == false) {

        map->buckets[index] = newNode;
        newNode->next = curNode->next;

    } else {
        // Collision: Insert the new node at the beginning of the chain
        newNode->next = map->buckets[index];
        map->buckets[index] = newNode;
    }
}

// Retrieve value associated with a key
struct option_entry * hashOptGet(HashOptMap *map, const char *key) {
    unsigned int index = hash(key);
    HashOptNode *current = map->buckets[index];

    // Traverse the chain at the given index
    while (current->assigned != false) {
        if (strcmp(current->key, key) == 0) {
            return current->option_payload;
        }
        current = current->next;
    }

    // Key not found
    return NULL;
}

struct option_entry** getAllOptionEntries(HashOptMap *map, int *numEntries) {
    // Count the total number of option entries
    int totalEntries = 0;
    for (int i = 0; i < TABLE_SIZE; ++i) {
        HashOptNode *current = map->buckets[i];
        while (current != NULL) {
            if (current->assigned == true) {
                totalEntries++;
            }
            current = current->next;
        }
    }

    // Allocate memory for the array of option entries
    struct option_entry **entries = malloc(totalEntries * sizeof(struct option_entry*));
    if (entries == NULL) {
        // Memory allocation failed
        *numEntries = 0;
        return NULL;
    }

    // Copy option entries into the array
    int index = 0;
    for (int i = 0; i < TABLE_SIZE; ++i) {
        HashOptNode *current = map->buckets[i];
        while (current != NULL) {
            if (current->assigned == true) {
                entries[index] = current->option_payload;
                index++;
            }
            current = current->next;
        }
    }

    *numEntries = totalEntries;
    return entries;
}