/*
 * stu_shmem.h
 *
 *  Created on: 2018Äê3ÔÂ30ÈÕ
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_WIN32_STU_SHMEM_H_
#define STUDEASE_CN_CORE_WIN32_STU_SHMEM_H_

#include "../../stu_config.h"
#include "../stu_core.h"

typedef struct {
	u_char       *addr;
	size_t        size;
	HANDLE        handle;
	stu_str_t     name;
	stu_uint32_t  exists; /* unsigned  exists:1;  */
} stu_shm_t;

stu_int32_t  stu_shm_alloc(stu_shm_t *shm);
stu_int32_t  stu_shm_remap(stu_shm_t *shm, u_char *addr);
void         stu_shm_free(stu_shm_t *shm);

extern stu_uint32_t  stu_allocation_granularity;

#endif /* STUDEASE_CN_CORE_WIN32_STU_SHMEM_H_ */
