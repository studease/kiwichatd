/*
 * stu_hash.h
 *
 *  Created on: 2017年11月15日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_HASH_H_
#define STUDEASE_CN_CORE_STU_HASH_H_

#include "../stu_config.h"
#include "stu_core.h"

#define STU_HASH_FLAGS_LOWCASE  0x01
#define STU_HASH_FLAGS_REPLACE  0x02

typedef void (*stu_hash_foreach_pt)(stu_str_t *key, void *value);
typedef struct stu_hash_elt_s stu_hash_elt_t;

struct stu_hash_elt_s {
	stu_queue_t     queue;

	stu_str_t       key;
	stu_uint32_t    key_hash;
	void           *value;

	stu_hash_elt_t *prev;
	stu_hash_elt_t *next;
};

typedef struct {
	void *(*malloc_fn)(size_t size);
	void  (*free_fn)(void *ptr);
} stu_hash_hooks_t;

typedef struct {
	stu_mutex_t       lock;

	stu_hash_elt_t  **buckets;
	stu_list_t       *keys;    // type: stu_hash_elt_t *
	stu_uint32_t      size;
	stu_uint32_t      length;

	stu_hash_hooks_t  hooks;
	stu_uint8_t       flags;

	unsigned          destroyed:1;
} stu_hash_t;

typedef struct {
	stu_uint32_t  hash;
	stu_str_t     key;
	stu_str_t     value;
	u_char       *lowcase_key;
} stu_table_elt_t;


#define stu_hash(key, c)  ((stu_uint32_t) key * 31 + c)
stu_uint32_t  stu_hash_key(u_char *data, size_t len, stu_uint8_t flags);

stu_int32_t   stu_hash_init(stu_hash_t *hash, stu_uint32_t size, stu_hash_hooks_t *hooks, stu_uint8_t flags);

stu_int32_t   stu_hash_insert(stu_hash_t *hash, stu_str_t *key, void *value);
stu_int32_t   stu_hash_insert_locked(stu_hash_t *hash, stu_str_t *key, void *value);
void         *stu_hash_find(stu_hash_t *hash, stu_uint32_t key, u_char *name, size_t len);
void         *stu_hash_find_locked(stu_hash_t *hash, stu_uint32_t key, u_char *name, size_t len);
void          stu_hash_remove(stu_hash_t *hash, stu_uint32_t key, u_char *name, size_t len);
void          stu_hash_remove_locked(stu_hash_t *hash, stu_uint32_t key, u_char *name, size_t len);
void          stu_hash_destroy(stu_hash_t *hash);
void          stu_hash_destroy_locked(stu_hash_t *hash);

void  stu_hash_foreach(stu_hash_t *hash, stu_hash_foreach_pt cb);
void  stu_hash_foreach_locked(stu_hash_t *hash, stu_hash_foreach_pt cb);

void  stu_hash_empty_free_pt(void *ptr);

#endif /* STUDEASE_CN_CORE_STU_HASH_H_ */
