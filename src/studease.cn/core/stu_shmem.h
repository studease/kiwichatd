/*
 * stu_shmem.h
 *
 *  Created on: 2017年11月15日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_STU_SHMEM_H_
#define STUDEASE_CN_CORE_STU_SHMEM_H_

#include "../stu_config.h"
#include "stu_core.h"

typedef struct {
	u_char *addr;
	size_t  size;
} stu_shm_t;

stu_int32_t  stu_shm_alloc(stu_shm_t *shm);
void         stu_shm_free(stu_shm_t *shm);

#endif /* STUDEASE_CN_CORE_STU_SHMEM_H_ */
