/*
 * stu_palloc.c
 *
 *  Created on: 2017骞�11鏈�15鏃�
 *      Author: Tony Lau
 */

#include "../stu_config.h"
#include "stu_core.h"

static void             stu_pool_init(stu_pool_t *pool, size_t size);
static stu_pool_data_t *stu_pool_create_data(size_t size);


stu_pool_t *
stu_pool_create(size_t size) {
	stu_pool_t      *p;
	stu_pool_data_t *d;

	p = stu_calloc(sizeof(stu_pool_t));
	if (p == NULL) {
		stu_log_error(0, "Failed to create pool: size=%zu.", size);
		return NULL;
	}

	stu_pool_init(p, size);

	d = stu_pool_create_data(size);
	if (d == NULL) {
		stu_log_error(0, "Failed to create pool data: size=%zu.", size);
		return NULL;
	}

	stu_queue_insert_tail(&p->queue, &d->queue);

	return p;
}

void
stu_pool_reset(stu_pool_t *pool) {
	stu_queue_t     *q;
	stu_pool_data_t *d;

	for (q = stu_queue_head(&pool->queue); q != stu_queue_sentinel(&pool->queue); q = stu_queue_next(q)) {
		d = stu_queue_data(q, stu_pool_data_t, queue);
		d->last = d->start;
		d->failed = 0;
	}

	for (q = stu_queue_head(&pool->large); q != stu_queue_sentinel(&pool->large); /* void */) {
		d = stu_queue_data(q, stu_pool_data_t, queue);
		q = stu_queue_next(q);
		stu_free(d);
	}
}

void
stu_pool_destroy(stu_pool_t *pool) {
	stu_queue_t     *q;
	stu_pool_data_t *d;

	for (q = stu_queue_head(&pool->queue); q != stu_queue_sentinel(&pool->queue); /* void */) {
		d = stu_queue_data(q, stu_pool_data_t, queue);
		q = stu_queue_next(q);
		stu_free(d);
	}

	for (q = stu_queue_head(&pool->large); q != stu_queue_sentinel(&pool->large); /* void */) {
		d = stu_queue_data(q, stu_pool_data_t, queue);
		q = stu_queue_next(q);
		stu_free(d);
	}

	stu_log_debug(0, "free pool: %p", pool);
	stu_free(pool);
}


void *
stu_palloc(stu_pool_t *pool, size_t size) {
	stu_queue_t     *q;
	stu_pool_data_t *d;
	u_char          *m;

	if (size > pool->size) {
		d = stu_pool_create_data(size);
		if (d == NULL) {
			stu_log_error(0, "Failed to create pool data: size=%zu.", size);
			return NULL;
		}

		stu_queue_insert_tail(&pool->large, &d->queue);

		m = d->last;
		d->last += size;

		return m;
	}

	for (q = stu_queue_head(&pool->queue); q != stu_queue_sentinel(&pool->queue); q = stu_queue_next(q)) {
		d = stu_queue_data(q, stu_pool_data_t, queue);
		if (size > d->end - d->last) {
			d->failed++;
			continue;
		}

		m = d->last;
		d->last += size;

		return m;
	}

	d = stu_pool_create_data(pool->size);
	if (d == NULL) {
		stu_log_error(0, "Failed to create pool data: size=%zu.", pool->size);
		return NULL;
	}

	stu_queue_insert_tail(&pool->queue, &d->queue);

	m = d->last;
	d->last += size;

	return m;
}

void *
stu_pcalloc(stu_pool_t *pool, size_t size) {
	void *p;

	p = stu_palloc(pool, size);
	if (p) {
		stu_memzero(p, size);
	}

	return p;
}


static void
stu_pool_init(stu_pool_t *pool, size_t size) {
	stu_mutex_init(&pool->lock, NULL);
	stu_queue_init(&pool->queue);
	stu_queue_init(&pool->large);
	pool->size = size;
}

static stu_pool_data_t *
stu_pool_create_data(size_t size) {
	stu_pool_data_t *d;

	d = stu_calloc(sizeof(stu_pool_data_t) + size);
	if (d == NULL) {
		return NULL;
	}

	stu_queue_init(&d->queue);
	d->start = d->last = (u_char *) d + sizeof(stu_pool_data_t);
	d->end = d->start + size;
	d->failed = 0;

	return d;
}
