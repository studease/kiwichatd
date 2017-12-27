/*
 * stu_process.c
 *
 *  Created on: 2017年11月16日
 *      Author: Tony Lau
 */

#include "../stu_config.h"
#include "stu_core.h"

stu_process_t            stu_processes[STU_PROCESS_MAXIMUM];

stu_pid_t                stu_pid;
stu_int32_t              stu_process_slot;
stu_int32_t              stu_process_last;
stu_socket_t             stu_channel;

sig_atomic_t             stu_quit;
stu_uint32_t             stu_exiting;
sig_atomic_t             stu_reopen;

static stu_pid_t  stu_process_spawn(stu_int32_t threads, stu_process_worker_cycle_pt proc, void *data, char *name);
static void       stu_process_open_channel(stu_channel_t *ch);


stu_int32_t
stu_process_init() {
	stu_int32_t  i;

	for (i = 0; i < STU_PROCESS_MAXIMUM; i++) {
		stu_processes[i].pid = STU_INVALID_PID;
	}

	return STU_OK;
}


stu_int32_t
stu_process_start_workers(stu_int32_t n, stu_int32_t threads, stu_process_worker_cycle_pt proc) {
	stu_channel_t  ch;
	stu_int32_t    i;
	stu_pid_t      pid;

	stu_memzero(&ch, sizeof(stu_channel_t));
	ch.command = STU_CMD_OPEN_CHANNEL;

	for (i = 0; i < n; i++) {
		pid = stu_process_spawn(threads, proc, (void *) (intptr_t) i, "worker process");
		if (pid == STU_INVALID_PID) {
			return STU_ERROR;
		}

		ch.pid = stu_processes[stu_process_slot].pid;
		ch.fd = stu_processes[stu_process_slot].channel[0];
		ch.slot = stu_process_slot;

		stu_process_open_channel(&ch);
	}

	return STU_OK;
}

static stu_pid_t
stu_process_spawn(stu_int32_t threads, stu_process_worker_cycle_pt proc, void *data, char *name) {
	u_long       on;
	stu_pid_t    pid;
	stu_int32_t  s;

	for (s = 0; s < stu_process_last; s++) {
		if (stu_processes[s].pid == STU_INVALID_PID) {
			break;
		}
	}

	if (s == STU_PROCESS_MAXIMUM) {
		stu_log_error(0, "no more than %d processes can be spawned", STU_PROCESS_MAXIMUM);
		return STU_INVALID_PID;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, stu_processes[s].channel) == -1) {
		stu_log_error(stu_errno, "socketpair() failed while spawning \"%s\"", name);
		return STU_INVALID_PID;
	}

	stu_log_debug(2, "channel: %d, %d.", stu_processes[s].channel[0], stu_processes[s].channel[1]);

	if (stu_nonblocking(stu_processes[s].channel[0]) == -1) {
		stu_log_error(stu_errno, "fcntl(O_NONBLOCK) failed while spawning \"%s\"", name);
		stu_channel_close(stu_processes[s].channel);
		return STU_INVALID_PID;
	}

	if (stu_nonblocking(stu_processes[s].channel[1]) == -1) {
		stu_log_error(stu_errno, "fcntl(O_NONBLOCK) failed while spawning \"%s\"", name);
		stu_channel_close(stu_processes[s].channel);
		return STU_INVALID_PID;
	}

	on = 1;
	if (ioctl(stu_processes[s].channel[0], FIOASYNC, &on) == -1) {
		stu_log_error(stu_errno, "ioctl(FIOASYNC) failed while spawning \"%s\"", name);
		stu_channel_close(stu_processes[s].channel);
		return STU_INVALID_PID;
	}

	if (fcntl(stu_processes[s].channel[0], F_SETOWN, stu_pid) == -1) {
		stu_log_error(stu_errno, "fcntl(F_SETOWN) failed while spawning \"%s\"", name);
		stu_channel_close(stu_processes[s].channel);
		return STU_INVALID_PID;
	}

	if (fcntl(stu_processes[s].channel[0], F_SETFD, FD_CLOEXEC) == -1) {
		stu_log_error(stu_errno, "fcntl(FD_CLOEXEC) failed while spawning \"%s\"", name);
		stu_channel_close(stu_processes[s].channel);
		return STU_INVALID_PID;
	}

	if (fcntl(stu_processes[s].channel[1], F_SETFD, FD_CLOEXEC) == -1) {
		stu_log_error(stu_errno, "fcntl(FD_CLOEXEC) failed while spawning \"%s\"", name);
		stu_channel_close(stu_processes[s].channel);
		return STU_INVALID_PID;
	}

	stu_channel = stu_processes[s].channel[1];
	stu_process_slot = s;

	pid = fork();

	switch (pid) {
	case -1:
		stu_log_error(stu_errno, "fork() failed while spawning \"%s\"", name);
		stu_channel_close(stu_processes[s].channel);
		return STU_INVALID_PID;
	case 0:
		stu_pid = stu_getpid();
		proc(threads, data);
		break;
	default:
		break;
	}

	stu_log_debug(2, "started \"%s\", pid: %d", name, pid);

	stu_processes[s].pid = pid;
	stu_processes[s].status = 0;
	stu_processes[s].proc = proc;
	stu_processes[s].data = data;
	stu_processes[s].name = name;
	stu_processes[s].exiting = FALSE;
	stu_processes[s].exited = FALSE;

	if (s == stu_process_last) {
		stu_process_last++;
	}

	return pid;
}


static void
stu_process_open_channel(stu_channel_t *ch) {
	stu_int32_t  i;

	for (i = 0; i < stu_process_last; i++) {
		if (i == stu_process_slot || stu_processes[i].pid == STU_INVALID_PID || stu_processes[i].channel[0] == STU_SOCKET_INVALID) {
			continue;
		}

		stu_log_debug(2, "pass channel: slot=%d, pid=%lu, fd=%d, to slot=%d, pid=%lu, fd=%d.",
				ch->slot, ch->pid, ch->fd, i, stu_processes[i].pid, stu_processes[i].channel[0]);

		stu_channel_write(stu_processes[i].channel[0], ch, sizeof(stu_channel_t));
	}
}

void
stu_process_signal_workers(int signo) {
	stu_channel_t  ch;
	stu_int32_t    i, err;

	stu_memzero(&ch, sizeof(stu_channel_t));

	switch (signo) {
	case stu_signal_value(STU_SHUTDOWN_SIGNAL):
		ch.command = STU_CMD_QUIT;
		break;

	case stu_signal_value(STU_REOPEN_SIGNAL):
		ch.command = STU_CMD_REOPEN;
		break;

	default:
		ch.command = 0;
		break;
	}

	ch.fd = -1;

	for (i = 0; i < stu_process_last; i++) {
		stu_log_debug(2, "stu_processes[%d]: pid=%d, exiting=%d, exited=%d.", i, stu_processes[i].pid, stu_processes[i].exiting, stu_processes[i].exited);

		if (stu_processes[i].exited || stu_processes[i].pid == STU_INVALID_PID) {
			continue;
		}

		if (stu_processes[i].exiting && signo == stu_signal_value(STU_SHUTDOWN_SIGNAL)) {
			continue;
		}

		if (ch.command) {
			if (stu_channel_write(stu_processes[i].channel[0], &ch, sizeof(stu_channel_t)) == STU_OK) {
				if (signo != stu_signal_value(STU_REOPEN_SIGNAL)) {
					stu_processes[i].exiting = TRUE;
				}

				continue;
			}
		}

		stu_log_debug(2, "kill (%P, %d)", stu_processes[i].pid, signo);

		if (kill(stu_processes[i].pid, signo) == -1) {
			err = stu_errno;
			stu_log_error(err, "kill(%d, %d) failed", stu_processes[i].pid, signo);

			if (err == ESRCH) {
				stu_processes[i].exiting = FALSE;
				stu_processes[i].exited = TRUE;

				continue;
			}

			if (signo != stu_signal_value(STU_REOPEN_SIGNAL)) {
				stu_processes[i].exiting = TRUE;
			}
		}
	}
}
