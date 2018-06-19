/*
 * stu_shmem.c
 *
 *  Created on: 2018Äê3ÔÂ30ÈÕ
 *      Author: Tony Lau
 */

#include "../../stu_config.h"
#include "../stu_core.h"

/*
 * Base addresses selected by system for shared memory mappings are likely
 * to be different on Windows Vista and later versions due to address space
 * layout randomization.  This is however incompatible with storing absolute
 * addresses within the shared memory.
 *
 * To make it possible to store absolute addresses we create mappings
 * at the same address in all processes by starting mappings at predefined
 * addresses.  The addresses were selected somewhat randomly in order to
 * minimize the probability that some other library doing something similar
 * conflicts with us.  The addresses are from the following typically free
 * blocks:
 *
 * - 0x10000000 .. 0x70000000 (about 1.5 GB in total) on 32-bit platforms
 * - 0x000000007fff0000 .. 0x000007f68e8b0000 (about 8 TB) on 64-bit platforms
 *
 * Additionally, we allow to change the mapping address once it was detected
 * to be different from one originally used.  This is needed to support
 * reconfiguration.
 */

#ifdef _WIN64
#define STU_SHMEM_BASE  0x0000047047e00000
#else
#define STU_SHMEM_BASE  0x2efe0000
#endif

stu_uint32_t  stu_allocation_granularity;


stu_int32_t
stu_shm_alloc(stu_shm_t *shm) {
	static u_char *base = (u_char *) STU_SHMEM_BASE;
	u_char        *name;
	uint64_t       size;

	name = stu_alloc(shm->name.len + 2 + STU_INT32_LEN);
	if (name == NULL) {
		return STU_ERROR;
	}

	(void) stu_sprintf(name, "%V_%s%Z", &shm->name, stu_unique);

	stu_set_errno(0);

	size = shm->size;

	shm->handle = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
			(u_long) (size >> 32), (u_long) (size & 0xffffffff), (char *) name);

	if (shm->handle == NULL) {
		stu_log_error(stu_errno, "CreateFileMapping(%uz, %s) failed", shm->size, name);
		stu_free(name);
		return STU_ERROR;
	}

	stu_free(name);

	if (stu_errno == ERROR_ALREADY_EXISTS) {
		shm->exists = 1;
	}

	shm->addr = MapViewOfFileEx(shm->handle, FILE_MAP_WRITE, 0, 0, 0, base);

	if (shm->addr != NULL) {
		base += stu_align(size, stu_allocation_granularity);
		return STU_OK;
	}

	stu_log_error(stu_errno,
			"MapViewOfFileEx(%uz, %p) of file mapping \"%V\" failed, retry without a base address",
			shm->size, base, &shm->name);

	/*
	 * Order of shared memory zones may be different in the master process
	 * and worker processes after reconfiguration.  As a result, the above
	 * may fail due to a conflict with a previously created mapping remapped
	 * to a different address.  Additionally, there may be a conflict with
	 * some other uses of the memory.  In this case we retry without a base
	 * address to let the system assign the address itself.
	 */
	shm->addr = MapViewOfFile(shm->handle, FILE_MAP_WRITE, 0, 0, 0);
	if (shm->addr != NULL) {
		return STU_OK;
	}

	stu_log_error(stu_errno, "MapViewOfFile(%uz) of file mapping \"%V\" failed", shm->size, &shm->name);

	if (CloseHandle(shm->handle) == 0) {
		stu_log_error(stu_errno, "CloseHandle() of file mapping \"%V\" failed", &shm->name);
	}

	return STU_ERROR;
}

stu_int32_t
stu_shm_remap(stu_shm_t *shm, u_char *addr) {
	if (UnmapViewOfFile(shm->addr) == 0) {
		stu_log_error(stu_errno, "UnmapViewOfFile(%p) of file mapping \"%V\" failed", shm->addr, &shm->name);
		return STU_ERROR;
	}

	shm->addr = MapViewOfFileEx(shm->handle, FILE_MAP_WRITE, 0, 0, 0, addr);
	if (shm->addr != NULL) {
		return STU_OK;
	}

	stu_log_error(stu_errno, "MapViewOfFileEx(%uz, %p) of file mapping \"%V\" failed", shm->size, addr, &shm->name);

	return STU_ERROR;
}

void
stu_shm_free(stu_shm_t *shm) {
	if (UnmapViewOfFile(shm->addr) == 0) {
		stu_log_error(stu_errno, "UnmapViewOfFile(%p) of file mapping \"%V\" failed", shm->addr, &shm->name);
	}

	if (CloseHandle(shm->handle) == 0) {
		stu_log_error(stu_errno, "CloseHandle() of file mapping \"%V\" failed", &shm->name);
	}
}
