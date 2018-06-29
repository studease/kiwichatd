/*
 * kcd_process.c
 *
 *  Created on: 2017年12月5日
 *      Author: Tony Lau
 */

#include "kcd_core.h"

stu_fd_t  kcd_evfd;

extern volatile kcd_cycle_t *kcd_cycle;

extern stu_process_t     stu_processes[STU_PROCESS_MAXIMUM];

extern stu_int32_t       stu_process_slot;
extern stu_int32_t       stu_process_last;
extern stu_socket_t      stu_channel;

extern sig_atomic_t      stu_quit;
extern stu_uint32_t      stu_exiting;
extern sig_atomic_t      stu_reopen;

extern stu_thread_t      stu_threads[STU_THREAD_MAXIMUM];
extern stu_thread_key_t  stu_thread_key;

static void  kcd_process_worker_init();
static void  kcd_process_channel_handler(stu_event_t *ev);

static void *kcd_process_worker_thread_cycle(void *data);


void
kcd_process_master_cycle() {
	kcd_conf_t *conf;
	sigset_t    set;

	conf = (kcd_conf_t *) &kcd_cycle->conf;

	sigemptyset(&set);
	sigaddset(&set, SIGCHLD);
	sigaddset(&set, SIGALRM);
	sigaddset(&set, SIGIO);
	sigaddset(&set, SIGINT);
	sigaddset(&set, stu_signal_value(STU_SHUTDOWN_SIGNAL));
	sigaddset(&set, stu_signal_value(STU_CHANGEBIN_SIGNAL));

	if (sigprocmask(SIG_BLOCK, &set, NULL) == -1) {
		stu_log_error(stu_errno, "sigprocmask() failed.");
	}

	if (stu_process_start_workers(conf->worker_processes, conf->worker_threads, kcd_process_worker_cycle) == STU_ERROR) {
		stu_log_error(0, "Failed to start workers: processes=%d, threads=%d.", conf->worker_processes, conf->worker_threads);
		return;
	}

	sigemptyset(&set);

	for ( ;; ) {
		stu_log_debug(2, "sigsuspending...");
		sigsuspend(&set);

		if (stu_quit) {
			stu_process_signal_workers(stu_signal_value(STU_SHUTDOWN_SIGNAL));
		}

		if (stu_reopen) {
			stu_reopen = FALSE;
			stu_process_signal_workers(stu_signal_value(STU_REOPEN_SIGNAL));
		}
	}
}


void
kcd_process_worker_cycle(stu_int32_t threads, void *data) {
	stu_int32_t  n, err;

	kcd_evfd = stu_event_create();
	if (kcd_evfd == -1) {
		stu_log_error(0, "Failed to create worker event.");
		exit(2);
	}

	kcd_process_worker_init();

	if (stu_thread_init(STU_THREAD_DEFAULT_STACKSIZE) == STU_ERROR) {
		stu_log_error(0, "Failed to init threads.");
		exit(2);
	}

	err = stu_thread_key_create(&stu_thread_key);
	if (err != STU_OK) {
		stu_log_error(err, "stu_thread_key_create failed");
		exit(2);
	}

	for (n = 0; n < threads; n++) {
		if (stu_thread_cond_init(&stu_threads[n].cond) == STU_ERROR) {
			stu_log_error(0, "stu_thread_cond_init failed.");
			exit(2);
		}

		if (stu_thread_create(&stu_threads[n].id, &stu_threads[n].evfd, kcd_process_worker_thread_cycle, (void *) &stu_threads[n]) == STU_ERROR) {
			stu_log_error(0, "Failed to create thread[%d].", n);
			exit(2);
		}
	}

	if (kcd_cycle->conf.push_user
			&& kcd_channel_add_push_user_timer(kcd_cycle->conf.push_user_interval) == STU_ERROR) {
		stu_log_error(0, "Failed to add push user timer.");
		exit(2);
	}

	if (kcd_cycle->conf.push_stat
			&& kcd_channel_add_push_stat_timer(kcd_cycle->conf.push_stat_interval) == STU_ERROR) {
		stu_log_error(0, "Failed to add push stat timer.");
		exit(2);
	}

	// listen
	if (stu_http_listen(kcd_evfd, kcd_cycle->conf.port) == STU_ERROR) {
		stu_log_error(0, "Failed to add http listen: port=\"%d\".", kcd_cycle->conf.port);
		exit(2);
	}

	// main thread of sub process, wait for signal
	for ( ;; ) {
		if (stu_exiting) {
			// TODO: remove timers, free memory
		}

		stu_event_process_events_and_timers(kcd_evfd);

		if (stu_reopen) {
			stu_log("reopening logs...");
		}

		if (stu_quit) {
			stu_log("worker process shutting down...");
			break;
		}
	}
}

static void
kcd_process_worker_init() {
	sigset_t     set;
	stu_int32_t  n;

	sigemptyset(&set);

	if (sigprocmask(SIG_SETMASK, &set, NULL) == -1) {
		stu_log_error(stu_errno, "sigprocmask() failed");
	}

	for (n = 0; n < stu_process_last; n++) {
		if (stu_processes[n].pid == STU_INVALID_PID) {
			continue;
		}

		if (n == stu_process_slot) {
			continue;
		}

		if (stu_processes[n].channel[1] == STU_SOCKET_INVALID) {
			continue;
		}

		if (close(stu_processes[n].channel[1]) == -1) {
			stu_log_error(stu_errno, "close() channel failed");
		}
	}

	if (close(stu_processes[stu_process_slot].channel[0]) == -1) {
		stu_log_error(stu_errno, "close() channel failed");
	}

	if (stu_channel_add_event(kcd_evfd, stu_channel, STU_READ_EVENT, kcd_process_channel_handler) == STU_ERROR) {
		/* fatal */
		exit(2);
	}
}

static void
kcd_process_channel_handler(stu_event_t *ev) {
	stu_connection_t *c;
	stu_int32_t       n;
	stu_channel_t     ch;

	stu_log_debug(2, "channel handler called.");

	if (ev->timedout) {
		ev->timedout = FALSE;
		return;
	}

	c = ev->data;

	for ( ;; ) {
		n = stu_channel_read(c->fd, &ch, sizeof(stu_channel_t));
		if (n == STU_ERROR) {
			stu_log_error(0, "Failed to read channel message.");

			stu_event_del(ev, STU_READ_EVENT, STU_CLOSE_EVENT);
			stu_connection_close(c);

			return;
		}

		if (n == STU_AGAIN) {
			return;
		}

		stu_log_debug(2, "channel command: %d.", ch.command);

		switch (ch.command) {
		case STU_CMD_QUIT:
			stu_quit = 1;
			break;

		case STU_CMD_REOPEN:
			stu_reopen = 1;
			break;

		case STU_CMD_OPEN_CHANNEL:
			stu_log_debug(2, "open channel: s=%i, pid=%d, fd=%d.", ch.slot, ch.pid, ch.fd);

			stu_processes[ch.slot].pid = ch.pid;
			stu_processes[ch.slot].channel[0] = ch.fd;
			break;

		case STU_CMD_CLOSE_CHANNEL:
			stu_log_debug(2, "close channel: s=%i, pid=%d, our=%d, fd=%d.", ch.slot, ch.pid, stu_processes[ch.slot].pid, stu_processes[ch.slot].channel[0]);

			if (close(stu_processes[ch.slot].channel[0]) == -1) {
				stu_log_error(stu_errno, "close() channel failed.");
			}
			stu_processes[ch.slot].channel[0] = -1;
			break;
		}
	}
}

static void *
kcd_process_worker_thread_cycle(void *data) {
	stu_thread_t *thr;
	sigset_t      set;

	thr = data;

	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);

	if (sigprocmask(SIG_BLOCK, &set, NULL) == -1) {
		stu_log_error(stu_errno, "sigprocmask() failed");
	}

	for ( ;; ) {
		stu_event_process_events_and_timers(thr->evfd);
	}

	stu_log_error(0, "worker thread exit.");

	return NULL;
}
