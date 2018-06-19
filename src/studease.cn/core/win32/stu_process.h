/*
 * stu_process.h
 *
 *  Created on: 2018Äê4ÔÂ2ÈÕ
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_WIN32_STU_PROCESS_H_
#define STUDEASE_CN_CORE_WIN32_STU_PROCESS_H_

#include "../../stu_config.h"
#include "../stu_core.h"

#define STU_PROCESS_MAXIMUM  (MAXIMUM_WAIT_OBJECTS - 4)

typedef DWORD                stu_pid_t;
#define STU_INVALID_PID      0

typedef void  (*stu_process_master_cycle_pt)();
typedef void  (*stu_process_worker_cycle_pt)(stu_int32_t threads, void *data);

#define STU_PROCESS_SYNC_NAME                                                 \
		(sizeof("stu_cache_manager_mutex_") + STU_INT32_LEN)

typedef struct {
	HANDLE                   handle;
	stu_pid_t                pid;
	char                    *name;

	HANDLE                   term;
	HANDLE                   quit;
	HANDLE                   reopen;

	u_char                   term_event[STU_PROCESS_SYNC_NAME];
	u_char                   quit_event[STU_PROCESS_SYNC_NAME];
	u_char                   reopen_event[STU_PROCESS_SYNC_NAME];

	unsigned                 just_spawn:1;
	unsigned                 exiting:1;
} stu_process_t;

typedef struct {
	char                    *path;
	char                    *name;
	char                    *args;
	char *const             *argv;
	char *const             *envp;
	HANDLE                   child;
} stu_exec_ctx_t;

#define stu_getpid           GetCurrentProcessId

#define stu_sched_yield()    SwitchToThread()

stu_int32_t  stu_process_init();

stu_int32_t  stu_process_start_workers(stu_int32_t n, stu_int32_t threads, stu_process_worker_cycle_pt proc);
void         stu_process_signal_workers(int signo);

#endif /* STUDEASE_CN_CORE_WIN32_STU_PROCESS_H_ */
