/*
 * kcd_conf.h
 *
 *  Created on: 2017年11月17日
 *      Author: Tony Lau
 */

#ifndef KIWICHATD_COM_CORE_KCD_CONF_H_
#define KIWICHATD_COM_CORE_KCD_CONF_H_

#include "kcd_core.h"

#define KCD_CONF_MAX_SIZE  4096

typedef struct {
	stu_file_t     log;
	stu_file_t     pid;

	stu_str_t      license;
	kcd_edition_t  edition;
	stu_uint8_t    mode;

	stu_bool_t     master_process;
	stu_int32_t    worker_processes;
	stu_int32_t    worker_threads;
	stu_uint8_t    debug;

	uint16_t       port;
	stu_str_t      root;
	stu_str_t      cors;

	stu_int32_t    push_history;
	stu_str_t      history_path;

	stu_bool_t     push_user;
	stu_msec_t     push_user_interval; // seconds

	stu_bool_t     push_stat;
	stu_msec_t     push_stat_interval; // seconds

	stu_list_t     ident;              // stu_upstream_server_t *
	stu_list_t     stats;              // stu_upstream_server_t *
	stu_list_t     check;              // stu_upstream_server_t *
} kcd_conf_t;

stu_int32_t  kcd_conf_parse_file(kcd_conf_t *conf, u_char *name);

#endif /* KIWICHATD_COM_CORE_KCD_CONF_H_ */
