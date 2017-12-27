/*
 * stu_buf.c
 *
 *  Created on: 2017年11月29日
 *      Author: Tony Lau
 */

#include "../stu_config.h"
#include "stu_core.h"


stu_buf_t *
stu_buf_create(stu_pool_t *pool, size_t size) {
	stu_buf_t *b;

	b = stu_pcalloc(pool, sizeof(stu_buf_t) + size);
	if (b == NULL) {
		return NULL;
	}

	b->start = (u_char *) b + sizeof(stu_buf_t);
	b->end = b->start + size;
	b->size = size;

	b->pos = b->start;
	b->last = b->start;

	return b;
}

u_char *
stu_chain_read(stu_chain_t *chain, u_char *dst) {
	u_char *p;

	for (p = dst; chain; chain = chain->next) {
		if (chain->buf == NULL || chain->buf->pos == NULL) {
			continue;
		}

		p = stu_memcpy(p, chain->buf->pos, chain->buf->last - chain->buf->pos);
	}

	return p;
}
