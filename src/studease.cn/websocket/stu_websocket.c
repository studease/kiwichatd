/*
 * stu_websocket.c
 *
 *  Created on: 2017年11月24日
 *      Author: Tony Lau
 */

#include "../http/stu_http.h"
#include "stu_websocket.h"

extern stu_list_t        stu_http_phases;
extern stu_http_phase_t  stu_websocket_phase_upgrader;


stu_int32_t
stu_websocket_init() {
	stu_list_elt_t *e;
	stu_str_t       pattern;

	stu_str_set(&pattern, "/");

	if (stu_websocket_filter_init_hash() == STU_ERROR) {
		stu_log_error(0, "Failed to init websocket filter hash.");
		return STU_ERROR;
	}

	if (stu_websocket_phase_init() == STU_ERROR) {
		stu_log_error(0, "Failed to init websocket phase.");
		return STU_ERROR;
	}

	if (stu_http_filter_add(&pattern, stu_websocket_filter_upgrade_handler) == STU_ERROR) {
		stu_log_error(0, "Failed to add websocket upgrade filter.");
		return STU_ERROR;
	}

	e = stu_list_insert_tail(&stu_http_phases, &stu_websocket_phase_upgrader);
	if (e == NULL) {
		stu_log_error(0, "Failed to insert websocket upgrader phase.");
		return STU_ERROR;
	}

	return STU_OK;
}

stu_bool_t
stu_websocket_is_upgrade_request(stu_http_request_t *r) {
	if (r->headers_in.connection && r->headers_in.upgrade && r->headers_out.sec_websocket_accept
			&& stu_strncasestr(r->headers_in.connection->value.data, (char *) "Upgrade", 7) != NULL
			&& stu_strncasecmp(r->headers_in.upgrade->value.data, (u_char *) "websocket", 9) == 0) {

		return TRUE;
	}

	return FALSE;
}
