/*
 * stu_process.c
 *
 *  Created on: 2018Äê4ÔÂ2ÈÕ
 *      Author: Tony Lau
 */

#include "../../stu_config.h"
#include "../stu_core.h"

stu_process_t  stu_processes[STU_PROCESS_MAXIMUM];

stu_pid_t      stu_pid;
stu_int32_t    stu_process_slot;
stu_int32_t    stu_process_last;

sig_atomic_t   stu_quit;
stu_uint32_t   stu_exiting;
sig_atomic_t   stu_reopen;

HANDLE         stu_master_process_event;
char           stu_master_process_event_name[STU_PROCESS_SYNC_NAME];

static stu_pid_t  stu_process_spawn(stu_int32_t threads, char *name);
static stu_pid_t  stu_execute(stu_exec_ctx_t *ctx);
static void       stu_close_handle(HANDLE h);


stu_int32_t
stu_process_init() {
	stu_int32_t  i;

	for (i = 0; i < STU_PROCESS_MAXIMUM; i++) {
		stu_processes[i].handle = NULL;
	}

	return STU_OK;
}


stu_int32_t
stu_process_start_workers(stu_int32_t n, stu_int32_t threads, stu_process_worker_cycle_pt proc) {
	stu_int32_t    i;
	stu_pid_t      pid;

	for (i = 0; i < n; i++) {
		pid = stu_process_spawn(threads, "worker");
		if (pid == STU_INVALID_PID) {
			return STU_ERROR;
		}
	}

	return STU_OK;
}

static stu_pid_t
stu_process_spawn(stu_int32_t threads, char *name) {
	char            file[MAX_PATH + 1];
	HANDLE          events[2];
	u_long          rc, n, code;
	stu_pid_t       pid;
	stu_int32_t     s;
	stu_exec_ctx_t  ctx;

	for (s = 0; s < stu_process_last; s++) {
		if (stu_processes[s].handle == NULL) {
			break;
		}
	}

	n = GetModuleFileName(NULL, file, MAX_PATH);
	if (n == 0) {
		stu_log_error(stu_errno, "GetModuleFileName() failed");
		return STU_INVALID_PID;
	}

	file[n] = '\0';

	stu_log_debug(2, "GetModuleFileName: \"%s\"", file);

	ctx.path = file;
	ctx.name = name;
	ctx.args = GetCommandLine();
	ctx.argv = NULL;
	ctx.envp = NULL;

	pid = stu_execute(&ctx);

	if (pid == STU_INVALID_PID) {
		return pid;
	}

	stu_memzero(&stu_processes[s], sizeof(stu_process_t));

	stu_processes[s].handle = ctx.child;
	stu_processes[s].pid = pid;
	stu_processes[s].name = name;

	stu_sprintf(stu_processes[s].term_event, "stu_%s_term_%ul", name, pid);
	stu_sprintf(stu_processes[s].quit_event, "stu_%s_quit_%ul", name, pid);
	stu_sprintf(stu_processes[s].reopen_event, "stu_%s_reopen_%ul", name, pid);

	events[0] = stu_master_process_event;
	events[1] = ctx.child;

	rc = WaitForMultipleObjects(2, events, 0, 5000);

	stu_time_update();
	stu_log_debug(2, "WaitForMultipleObjects: %ul", rc);

	switch (rc) {
	case WAIT_OBJECT_0:
		stu_processes[s].term = OpenEvent(EVENT_MODIFY_STATE, 0, (char *) stu_processes[s].term_event);
		if (stu_processes[s].term == NULL) {
			stu_log_error(stu_errno, "OpenEvent(\"%s\") failed", stu_processes[s].term_event);
			goto failed;
		}

		stu_processes[s].quit = OpenEvent(EVENT_MODIFY_STATE, 0, (char *) stu_processes[s].quit_event);
		if (stu_processes[s].quit == NULL) {
			stu_log_error(stu_errno, "OpenEvent(\"%s\") failed", stu_processes[s].quit_event);
			goto failed;
		}

		stu_processes[s].reopen = OpenEvent(EVENT_MODIFY_STATE, 0, (char *) stu_processes[s].reopen_event);
		if (stu_processes[s].reopen == NULL) {
			stu_log_error(stu_errno, "OpenEvent(\"%s\") failed", stu_processes[s].reopen_event);
			goto failed;
		}

		if (ResetEvent(stu_master_process_event) == 0) {
			stu_log_error(0, "ResetEvent(\"%s\") failed", stu_master_process_event_name);
			goto failed;
		}
		break;

	case WAIT_OBJECT_0 + 1:
		if (GetExitCodeProcess(ctx.child, &code) == 0) {
			stu_log_error(stu_errno, "GetExitCodeProcess(%P) failed", pid);
		}

		stu_log_error(0, "%s process %P exited with code %ul", name, pid, code);
		goto failed;

	case WAIT_TIMEOUT:
		stu_log_error(0, "the event \"%s\" was not signaled for 5s", stu_master_process_event_name);
		goto failed;

	case WAIT_FAILED:
		stu_log_error(stu_errno, "WaitForSingleObject(\"%s\") failed", stu_master_process_event_name);
		goto failed;
	}

	stu_processes[s].just_spawn = 0;

	if (s == stu_process_last) {
		stu_process_last++;
	}

	return pid;

failed:

	if (stu_processes[s].reopen) {
		stu_close_handle(stu_processes[s].reopen);
	}

	if (stu_processes[s].quit) {
		stu_close_handle(stu_processes[s].quit);
	}

	if (stu_processes[s].term) {
		stu_close_handle(stu_processes[s].term);
	}

	TerminateProcess(stu_processes[s].handle, 2);

	if (stu_processes[s].handle) {
		stu_close_handle(stu_processes[s].handle);
		stu_processes[s].handle = NULL;
	}

	return STU_INVALID_PID;
}

static stu_pid_t
stu_execute(stu_exec_ctx_t *ctx) {
	STARTUPINFO          si;
	PROCESS_INFORMATION  pi;

	stu_memzero(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);

	stu_memzero(&pi, sizeof(PROCESS_INFORMATION));

	if (CreateProcess(ctx->path, ctx->args, NULL, NULL, 0, CREATE_NO_WINDOW, NULL, NULL, &si, &pi) == 0) {
		stu_log_error(stu_errno, "CreateProcess(\"%s\") failed", ctx->name);
		return STU_INVALID_PID;
	}

	ctx->child = pi.hProcess;

	if (CloseHandle(pi.hThread) == 0) {
		stu_log_error(stu_errno, "CloseHandle(pi.hThread) failed");
	}

	stu_log_error(0, "start %s process %P", ctx->name, pi.dwProcessId);

	return pi.dwProcessId;
}

static void
stu_close_handle(HANDLE h) {
	if (CloseHandle(h) == 0) {
		stu_log_error(stu_errno, "CloseHandle(%p) failed", h);
	}
}
