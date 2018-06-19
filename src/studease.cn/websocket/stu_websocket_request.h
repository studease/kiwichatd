/*
 * stu_websocket_request.h
 *
 *  Created on: 2017年11月27日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_WEBSOCKET_STU_WEBSOCKET_REQUEST_H_
#define STUDEASE_CN_WEBSOCKET_STU_WEBSOCKET_REQUEST_H_

#include "stu_websocket.h"

#define STU_WEBSOCKET_REQUEST_DEFAULT_SIZE  1024
#define STU_WEBSOCKET_REQUEST_LARGE_SIZE    4096

typedef void (*stu_websocket_event_handler_pt)(stu_websocket_request_t *r);

struct stu_websocket_request_s {
	stu_connection_t               *connection;

	stu_websocket_event_handler_pt  read_event_handler;
	stu_websocket_event_handler_pt  write_event_handler;

	stu_buf_t                      *frame_in;
	stu_buf_t                      *busy;

	stu_websocket_frame_t           frames_in;
	stu_websocket_frame_t           frames_out;

	stu_int32_t                     status;

	// used for parsing websocket request.
	stu_uint8_t                     state;
};

void  stu_websocket_request_read_handler(stu_event_t *ev);
void  stu_websocket_request_write_handler(stu_websocket_request_t *r);

stu_websocket_request_t *
      stu_websocket_create_request(stu_connection_t *c);
void  stu_websocket_process_request_frames(stu_event_t *ev);
void  stu_websocket_process_request(stu_websocket_request_t *r);
void  stu_websocket_finalize_request(stu_websocket_request_t *r, stu_int32_t rc);

void  stu_websocket_free_request(stu_websocket_request_t *r);
void  stu_websocket_close_request(stu_websocket_request_t *r);
void  stu_websocket_close_connection(stu_connection_t *c);

#endif /* STUDEASE_CN_WEBSOCKET_STU_WEBSOCKET_REQUEST_H_ */
