/*
 * stu_process.h
 *
 *  Created on: 2017骞�11鏈�16鏃�
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_CORE_UNIX_STU_PROCESS_H_
#define STUDEASE_CN_CORE_UNIX_STU_PROCESS_H_

#include "../../stu_config.h"
#include "../stu_core.h"

#define STU_PROCESS_MAXIMUM      32

typedef pid_t                    stu_pid_t;
#define STU_INVALID_PID         -1

typedef void  (*stu_process_master_cycle_pt)();
typedef void  (*stu_process_worker_cycle_pt)(stu_int32_t threads, void *data);

typedef struct {
	stu_pid_t                    pid;
	stu_int32_t                  status;
	stu_socket_t                 channel[2];

	stu_process_worker_cycle_pt  proc;
	void                        *data;
	char                        *name;

	unsigned                     exiting:1;
	unsigned                     exited:1;
} stu_process_t;

#define STU_CMD_OPEN_CHANNEL     1
#define STU_CMD_CLOSE_CHANNEL    2
#define STU_CMD_QUIT             3
#define STU_CMD_REOPEN           4

#define stu_getpid               getpid

#if (_SCHED_H)
#define stu_sched_yield()        sched_yield()
#else
#define stu_sched_yield()        usleep(1)
#endif

stu_int32_t  stu_process_init();

stu_int32_t  stu_process_start_workers(stu_int32_t n, stu_int32_t threads, stu_process_worker_cycle_pt proc);
void         stu_process_signal_workers(int signo);

#endif /* STUDEASE_CN_CORE_UNIX_STU_PROCESS_H_ */
