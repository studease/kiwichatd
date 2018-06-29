/*
 ============================================================================
 Name        : kiwichatd.c
 Author      : Tony Lau
 Version     : 2.x.xx
 Copyright   : kiwichatd.com
 Description : High-performance Websocket Chat Server
 ============================================================================
 */

#include "kiwichatd.com/core/kcd_core.h"
#include "kiwichatd.com/kcd_config.h"

extern const stu_str_t  __NAME;
extern const stu_str_t  __VERSION;

extern volatile kcd_cycle_t *kcd_cycle;


int main(void) {
	kcd_conf_t *conf;

	// init cycle
	if (kcd_cycle_init() == STU_ERROR) {
		stu_log_error(0, "Failed to init cycle.");
		return EXIT_FAILURE;
	}

	conf = (kcd_conf_t *) &kcd_cycle->conf;

	// server info
	stu_log("GCC " __VERSION__);
	stu_log("%s/%s (" __TIME__ ", " __DATE__ ")", __NAME.data, __VERSION.data);

	// license
	if (kcd_license_ckeck(conf) == STU_ERROR) {
		stu_log_error(0, "Failed to check license: %s.", conf->license.data);
		return EXIT_FAILURE;
	}

	// create pid
	if (kcd_cycle_create_pidfile(&conf->pid) == STU_ERROR) {
		stu_log_error(0, "Failed to create pid file: path=\"%s\".", conf->pid.name.data);
		return EXIT_FAILURE;
	}

	// master cycle
	kcd_process_master_cycle();

	// delete pid
	kcd_cycle_delete_pidfile(&conf->pid);

	return EXIT_SUCCESS;
}
