/*
 * stu_shmem.c
 *
 *  Created on: 2017骞�11鏈�15鏃�
 *      Author: Tony Lau
 */

#include "../../stu_config.h"
#include "../stu_core.h"


#if (STU_HAVE_MAP_ANON)

stu_int_t
stu_shm_alloc(stu_shm_t *shm) {
	shm->addr = (u_char *) mmap(NULL, shm->size, PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0);
	if (shm->addr == MAP_FAILED) {
		stu_log_error(stu_errno, "mmap(MAP_ANON|MAP_SHARED, %uz) failed", shm->size);
		return STU_ERROR;
	}

	return STU_OK;
}

void
stu_shm_free(stu_shm_t *shm) {
	if (munmap((void *) shm->addr, shm->size) == -1) {
		stu_log_error(stu_errno, "munmap(%p, %uz) failed", shm->addr, shm->size);
	}
}

#elif (STU_HAVE_MAP_DEVZERO)

stu_int_t
stu_shm_alloc(stu_shm_t *shm) {
	stu_fd_t  fd;

	fd = open("/dev/zero", O_RDWR);
	if (fd == -1) {
		stu_log_error(stu_errno, "open(\"/dev/zero\") failed");
		return STU_ERROR;
	}

	shm->addr = (u_char *) mmap(NULL, shm->size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (shm->addr == MAP_FAILED) {
		stu_log_error(stu_errno, "mmap(/dev/zero, MAP_SHARED, %uz) failed", shm->size);
	}

	if (close(fd) == -1) {
		stu_log_error(stu_errno, "close(\"/dev/zero\") failed");
	}

	return (shm->addr == MAP_FAILED) ? STU_ERROR : STU_OK;
}

void
stu_shm_free(stu_shm_t *shm) {
	if (munmap((void *) shm->addr, shm->size) == -1) {
		stu_log_error(stu_errno, "munmap(%p, %uz) failed", shm->addr, shm->size);
	}
}

#elif (STU_HAVE_SYSVSHM)

#include <sys/ipc.h>
#include <sys/shm.h>

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

#endif
