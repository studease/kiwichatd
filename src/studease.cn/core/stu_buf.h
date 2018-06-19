/*
 * stu_buf.h
 *
 *  Created on: 2017年11月15日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_BUF_H_
#define STUDEASE_CN_CORE_STU_BUF_H_

#include "../stu_config.h"
#include "stu_core.h"

typedef struct stu_chain_s stu_chain_t;

typedef struct {
	u_char      *start;
	u_char      *pos;
	u_char      *last;
	u_char      *end;
	size_t       size;
} stu_buf_t;

struct stu_chain_s {
	stu_buf_t   *buf;
	stu_chain_t *next;
};

stu_buf_t *stu_buf_create(stu_pool_t *pool, size_t size);
u_char    *stu_chain_read(stu_chain_t *chain, u_char *dst);

#endif /* STUDEASE_CN_CORE_STU_BUF_H_ */
