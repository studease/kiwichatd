/*
 * kcd_request.h
 *
 *  Created on: 2017年12月5日
 *      Author: Tony Lau
 */

#ifndef KIWICHATD_COM_CORE_KCD_REQUEST_H_
#define KIWICHATD_COM_CORE_KCD_REQUEST_H_

#include "kcd_core.h"

#define KCD_REQUEST_DEFAULT_SIZE  1024

stu_int32_t  kcd_request_init();

void  kcd_request_read_handler(stu_event_t *ev);

void  kcd_free_request(stu_websocket_request_t *r);
void  kcd_close_request(stu_websocket_request_t *r);
void  kcd_close_connection(stu_connection_t *c);

#endif /* KIWICHATD_COM_CORE_KCD_REQUEST_H_ */
