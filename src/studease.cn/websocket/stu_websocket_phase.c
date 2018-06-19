/*
 * stu_websocket_phase.c
 *
 *  Created on: 2017骞�11鏈�28鏃�
 *      Author: Tony Lau
 */

#include "stu_websocket.h"

stu_list_t  stu_websocket_phases;

stu_http_phase_t  stu_websocket_phase_upgrader = {
	stu_websocket_phase_upgrade_handler
};


stu_int32_t
stu_websocket_phase_init() {
	stu_list_init(&stu_websocket_phases, NULL);
	return STU_OK;
}

stu_int32_t
stu_websocket_phase_upgrade_handler(stu_http_request_t *r) {
	stu_connection_t *c;

	c = r->connection;

	stu_http_send_special_response(r, STU_HTTP_SWITCHING_PROTOCOLS);

	c->buffer.start = c->buffer.end = NULL;
	c->buffer.pos = c->buffer.last = NULL;
	c->buffer.size = 0;

	stu_pool_reset(c->pool);
	stu_http_free_request(r);

	c->read->handler = stu_websocket_request_read_handler;

	return STU_DECLINED;
}
