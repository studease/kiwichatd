/*
 * stu_shmem.c
 *
 *  Created on: 2017年11月15日
 *      Author: Tony Lau
 */

#include "../stu_config.h"
#include "stu_core.h"


stu_int32_t
stu_shm_alloc(stu_shm_t *shm) {
	int  id;

	id = shmget(IPC_PRIVATE, shm->size, (SHM_R|SHM_W|IPC_CREAT));
	if (id == -1) {
		stu_log("shmget(%d) failed.", shm->size);
		return STU_ERROR;
	}

	shm->addr = shmat(id, NULL, 0);
	if (shm->addr == (void *) -1) {
		stu_log("shmat() failed.");
	}

	if (shmctl(id, IPC_RMID, NULL) == -1) {
		stu_log("shmctl(IPC_RMID) failed.");
	}

	return (shm->addr == (void *) -1) ? STU_ERROR : STU_OK;
}

void
stu_shm_free(stu_shm_t *shm) {
	if (shmdt(shm->addr) == -1) {
		stu_log_error(0, "shmdt(%p) failed", shm->addr);
	}
}
