/*
 * stu_hash.c
 *
 *  Created on: 2017年11月15日
 *      Author: Tony Lau
 */

#include "../stu_config.h"
#include "stu_core.h"

static stu_int32_t  stu_hash_grow(stu_hash_t *hash, stu_uint32_t size);
static stu_int32_t  stu_hash_ncmp(u_char *s1, u_char *s2, size_t n, stu_uint8_t flags);


stu_uint32_t
stu_hash_key(u_char *data, size_t len, stu_uint8_t flags) {
	stu_uint32_t  i, hk;

	hk = 0;

	if (flags & STU_HASH_FLAGS_LOWCASE) {
		for (i = 0; i < len; i++) {
			hk = stu_hash(hk, stu_tolower(data[i]));
		}
	} else {
		for (i = 0; i < len; i++) {
			hk = stu_hash(hk, data[i]);
		}
	}

	return hk;
}


stu_int32_t
stu_hash_init(stu_hash_t *hash, stu_uint32_t size, stu_hash_hooks_t *hooks, stu_uint8_t flags) {
	stu_hash_elt_t **buckets;
	stu_list_t      *keys;

	stu_mutex_init(&hash->lock, NULL);
	hash->size = size ? size : 8;
	hash->length = 0;
	hash->flags = flags;

	if (hooks == NULL || hooks->malloc_fn == NULL) {
		hash->hooks.malloc_fn = stu_calloc;
		hash->hooks.free_fn = stu_free;
	} else {
		hash->hooks.malloc_fn = hooks->malloc_fn;
		hash->hooks.free_fn = hooks->free_fn;
	}

	buckets = hash->hooks.malloc_fn(hash->size * sizeof(stu_hash_elt_t *));
	if (buckets == NULL) {
		stu_log_error(0, "Failed to malloc buckets of hash.");
		return STU_ERROR;
	}

	hash->buckets = buckets;

	keys = hash->hooks.malloc_fn(sizeof(stu_list_t));
	if (buckets == NULL) {
		stu_log_error(0, "Failed to malloc keys list of hash.");
		return STU_ERROR;
	}

	stu_list_init(keys, (stu_list_hooks_t *) hooks);
	hash->keys = keys;

	return STU_OK;
}

stu_int32_t
stu_hash_insert(stu_hash_t *hash, stu_str_t *key, void *value) {
	stu_int32_t  rc;

	stu_mutex_lock(&hash->lock);
	rc = stu_hash_insert_locked(hash, key, value);
	stu_mutex_unlock(&hash->lock);

	return rc;
}

stu_int32_t
stu_hash_insert_locked(stu_hash_t *hash, stu_str_t *key, void *value) {
	stu_hash_elt_t *e;
	stu_uint32_t    hk, i;

	if (hash->length >= hash->size) {
		if (stu_hash_grow(hash, hash->size) != STU_OK) {
			stu_log_error(0, "Failed to grow hash.");
			return STU_ERROR;
		}
	}

	hk = stu_hash_key(key->data, key->len, hash->flags);
	i = hk % hash->size;

	if (hash->flags & STU_HASH_FLAGS_REPLACE) {
		for (e = hash->buckets[i]; e; e = e->next) {
			if (e->key_hash != hk || e->key.len != key->len) {
				continue;
			}

			if (stu_hash_ncmp(e->key.data, key->data, key->len, hash->flags) == 0) {
				e->value = value;
				goto done;
			}
		}
	}

	e = hash->hooks.malloc_fn(sizeof(stu_hash_elt_t));
	if (e == NULL) {
		goto failed;
	}

	e->key.data = hash->hooks.malloc_fn(key->len + 1);
	if (e->key.data == NULL) {
		goto failed;
	}

	stu_strncpy(e->key.data, key->data, key->len);
	e->key.len = key->len;

	e->key_hash = hk;
	e->value = value;

	stu_queue_insert_tail(&hash->keys->elts.queue, &e->queue);

	if (hash->buckets[i]) {
		hash->buckets[i]->prev = e;
	}
	e->prev = NULL;
	e->next = hash->buckets[i];
	hash->buckets[i] = e;
	hash->length++;

done:

	stu_log_debug(1, "inserted into hash: key=%u, i=%u, name=%s.", hk, i, key->data);

	return STU_OK;

failed:

	stu_log_error(0, "Failed to insert into hash: key=%u, i=%u, name=%s.", hk, i, key->data);

	return STU_ERROR;
}

static stu_int32_t
stu_hash_grow(stu_hash_t *hash, stu_uint32_t size) {
	stu_hash_elt_t **buckets, *e;
	stu_list_elt_t  *elts;
	stu_list_t      *keys;
	stu_queue_t     *q;
	stu_uint32_t     hk, i;

	elts = &hash->keys->elts;

	buckets = hash->hooks.malloc_fn((hash->size + size) * sizeof(stu_hash_elt_t *));
	if (buckets == NULL) {
		stu_log_error(0, "Failed to malloc buckets of hash.");
		return STU_ERROR;
	}

	keys = hash->hooks.malloc_fn(sizeof(stu_list_t));
	if (buckets == NULL) {
		stu_log_error(0, "Failed to malloc keys list of hash.");
		return STU_ERROR;
	}

	stu_list_init(keys, (stu_list_hooks_t *) &hash->hooks);
	hash->size += size;

	for (q = stu_queue_head(&elts->queue); q != stu_queue_sentinel(&elts->queue); q = stu_queue_next(q)) {
		e = stu_queue_data(q, stu_hash_elt_t, queue);

		hk = stu_hash_key(e->key.data, e->key.len, hash->flags);
		i = hk % hash->size;

		stu_queue_remove(&e->queue);
		stu_queue_insert_tail(&keys->elts.queue, &e->queue);

		e->key_hash = hk;
		if (buckets[i]) {
			buckets[i]->prev = e;
		}
		e->prev = NULL;
		e->next = buckets[i];
		buckets[i] = e;
	}

	hash->buckets = buckets;
	hash->keys = keys;

	return STU_OK;
}

static stu_int32_t
stu_hash_ncmp(u_char *s1, u_char *s2, size_t n, stu_uint8_t flags) {
	if (flags & STU_HASH_FLAGS_LOWCASE) {
		return stu_strncasecmp(s1, s2, n);
	}

	return stu_strncmp(s1, s2, n);
}


void *
stu_hash_find(stu_hash_t *hash, stu_uint32_t hk, u_char *name, size_t len) {
	void *v;

	stu_mutex_lock(&hash->lock);
	v = stu_hash_find_locked(hash, hk, name, len);
	stu_mutex_unlock(&hash->lock);

	return v;
}

void *
stu_hash_find_locked(stu_hash_t *hash, stu_uint32_t hk, u_char *name, size_t len) {
	stu_hash_elt_t *e;
	stu_uint32_t    i;

	i = hk % hash->size;

	for (e = hash->buckets[i]; e; e = e->next) {
		if (e->key_hash != hk || e->key.len != len) {
			continue;
		}

		if (stu_hash_ncmp(e->key.data, name, len, hash->flags) == 0) {
			stu_log_debug(1, "found element %p in hash: hk=%u, i=%u, name=%s.", e->value, hk, i, name);
			return e->value;
		}
	}

	//stu_log_debug(1, "element not found in hash: hk=%u, i=%u, name=%s.", key, i, name);

	return NULL;
}

void
stu_hash_remove(stu_hash_t *hash, stu_uint32_t hk, u_char *name, size_t len) {
	stu_mutex_lock(&hash->lock);
	stu_hash_remove_locked(hash, hk, name, len);
	stu_mutex_unlock(&hash->lock);
}

void
stu_hash_remove_locked(stu_hash_t *hash, stu_uint32_t hk, u_char *name, size_t len) {
	stu_hash_elt_t *e;
	stu_uint32_t    i;

	i = hk % hash->size;

	for (e = hash->buckets[i]; e; e = e->next) {
		if (e->key_hash != hk || e->key.len != len) {
			continue;
		}

		if (stu_hash_ncmp(e->key.data, name, len, hash->flags) == 0) {
			stu_queue_remove(&e->queue);

			if (e->prev) {
				e->prev->next = e->next;
			} else {
				hash->buckets[i] = e->next;
			}
			if (e->next) {
				e->next->prev = e->prev;
			}

			hash->hooks.free_fn(e->key.data);
			hash->hooks.free_fn(e);

			hash->length--;

			stu_log_debug(1, "removed %p from hash: hk=%u, i=%u, name=%s.", e->value, hk, i, name);

			if (hash->flags & STU_HASH_FLAGS_REPLACE) {
				break;
			}
		}
	}
}

void
stu_hash_destroy(stu_hash_t *hash) {
	stu_mutex_lock(&hash->lock);
	stu_hash_destroy_locked(hash);
	stu_mutex_unlock(&hash->lock);
}

void
stu_hash_destroy_locked(stu_hash_t *hash) {
	stu_list_elt_t *elts;
	stu_hash_elt_t *e;
	stu_queue_t    *q;
	stu_uint32_t    i;

	elts = &hash->keys->elts;

	for (q = stu_queue_head(&elts->queue); q != stu_queue_sentinel(&elts->queue); /* void */) {
		e = stu_queue_data(q, stu_hash_elt_t, queue);
		q = stu_queue_next(q);

		stu_queue_remove(&e->queue);

		if (e->prev) {
			e->prev->next = e->next;
		} else {
			i = e->key_hash % hash->size;
			hash->buckets[i] = e->next;
		}
		if (e->next) {
			e->next->prev = e->prev;
		}

		hash->hooks.free_fn(e->key.data);
		hash->hooks.free_fn(e);

		hash->length--;
	}

	hash->hooks.free_fn(hash->buckets);
	hash->hooks.free_fn(hash->keys);

	hash->destroyed = TRUE;
}


void
stu_hash_foreach(stu_hash_t *hash, stu_hash_foreach_pt cb) {
	stu_mutex_lock(&hash->lock);
	stu_hash_foreach_locked(hash, cb);
	stu_mutex_unlock(&hash->lock);
}

void
stu_hash_foreach_locked(stu_hash_t *hash, stu_hash_foreach_pt cb) {
	stu_list_elt_t *elts;
	stu_hash_elt_t *e;
	stu_queue_t    *q;

	elts = &hash->keys->elts;

	for (q = stu_queue_head(&elts->queue); q != stu_queue_sentinel(&elts->queue); q = stu_queue_next(q)) {
		e = stu_queue_data(q, stu_hash_elt_t, queue);
		cb(&e->key, e->value);
	}
}


void
stu_hash_empty_free_pt(void *ptr) {

}
