/*
 * stu_shmem.h
 *
 *  Created on: 2017骞�11鏈�15鏃�
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_UNIX_STU_SHMEM_H_
#define STUDEASE_CN_CORE_UNIX_STU_SHMEM_H_

#include "../../stu_config.h"
#include "../stu_core.h"

typedef struct {
	u_char       *addr;
	size_t        size;
	stu_str_t     name;
	stu_uint32_t  exists; /* unsigned  exists:1;  */
} stu_shm_t;

stu_int32_t  stu_shm_alloc(stu_shm_t *shm);
void         stu_shm_free(stu_shm_t *shm);

#endif /* STUDEASE_CN_CORE_UNIX_STU_SHMEM_H_ */
