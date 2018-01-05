/*
 * stu_palloc.h
 *
 *  Created on: 2017年11月15日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_PALLOC_H_
#define STUDEASE_CN_CORE_STU_PALLOC_H_

#include "../stu_config.h"
#include "stu_core.h"

#define STU_POOL_DEFAULT_SIZE 4096
#define STU_POOL_MAX_FAILURE  5

typedef struct {
	stu_queue_t   queue;
	u_char       *start;
	u_char       *last;
	u_char       *end;
	stu_uint32_t  failed;
} stu_pool_data_t;

typedef struct {
	stu_mutex_t   lock;
	stu_queue_t   queue;
	stu_queue_t   large;
	size_t        size;
} stu_pool_t;

stu_pool_t *stu_pool_create(size_t size);
void        stu_pool_reset(stu_pool_t *pool);
void        stu_pool_destroy(stu_pool_t *pool);

void       *stu_palloc(stu_pool_t *pool, size_t size);
void       *stu_pcalloc(stu_pool_t *pool, size_t size);

#endif /* STUDEASE_CN_CORE_STU_PALLOC_H_ */
