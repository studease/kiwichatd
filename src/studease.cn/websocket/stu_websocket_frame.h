/*
 * stu_websocket_frame.h
 *
 *  Created on: 2017年11月27日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_WEBSOCKET_STU_WEBSOCKET_FRAME_H_
#define STUDEASE_CN_WEBSOCKET_STU_WEBSOCKET_FRAME_H_

#include "stu_websocket.h"

#define STU_WEBSOCKET_OPCODE_TEXT    0x01
#define STU_WEBSOCKET_OPCODE_BINARY  0x02
#define STU_WEBSOCKET_OPCODE_CLOSE   0x08
#define STU_WEBSOCKET_OPCODE_PING    0x09
#define STU_WEBSOCKET_OPCODE_PONG    0x0A

#define STU_WEBSOCKET_EXTENDED_2     0x7E
#define STU_WEBSOCKET_EXTENDED_8     0x7F

typedef struct stu_websocket_frame_s stu_websocket_frame_t;

struct stu_websocket_frame_s {
	u_char        fin:1;
	u_char        rsv1:1;
	u_char        rsv2:1;
	u_char        rsv3:1;
	u_char        opcode:4;
	u_char        mask:1;
	u_char        payload_len:7;
	stu_uint64_t  extended;
	u_char        masking_key[4];
	stu_buf_t     payload_data;
};

stu_int32_t  stu_websocket_parse_frame(stu_websocket_request_t *r, stu_buf_t *b);
u_char      *stu_websocket_encode_frame_header(stu_websocket_frame_t *f, u_char *dst);
u_char      *stu_websocket_encode_frame(stu_websocket_frame_t *f, u_char *dst);

#endif /* STUDEASE_CN_WEBSOCKET_STU_WEBSOCKET_FRAME_H_ */
