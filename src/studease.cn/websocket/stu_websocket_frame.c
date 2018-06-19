/*
 * stu_websocket_frame.c
 *
 *  Created on: 2017年11月27日
 *      Author: Tony Lau
 */

#include "stu_websocket.h"


stu_int32_t
stu_websocket_parse_frame(stu_websocket_request_t *r, stu_buf_t *b) {
	u_char       *p;
	stu_uint64_t  i;
	enum {
		sw_start = 0,
		sw_payload_len,
		sw_extended_2,
		sw_extended_8,
		sw_masking_key,
		sw_payload_data
	} state;

	state = r->state;

	for (p = b->pos; p < b->last; p++) {
		switch (state) {
		case sw_start:
			r->frames_in.fin =  (*p >> 7) & 0x01;
			r->frames_in.rsv1 = (*p >> 6) & 0x01;
			r->frames_in.rsv2 = (*p >> 5) & 0x01;
			r->frames_in.rsv3 = (*p >> 4) & 0x01;
			r->frames_in.opcode = *p & 0x0F;

			state = sw_payload_len;
			break;

		case sw_payload_len:
			r->frames_in.mask = (*p >> 7) & 0x01;
			r->frames_in.payload_len = *p & 0x7F;
			if (r->frames_in.payload_len == 126) {
				state = sw_extended_2;
			} else if (r->frames_in.payload_len == 127) {
				state = sw_extended_8;
			} else {
				r->frames_in.extended = r->frames_in.payload_len;
				state = r->frames_in.mask ? sw_masking_key : sw_payload_data;
			}
			break;

		case sw_extended_2:
			if (b->last - p < 2) {
				goto again;
			}

			r->frames_in.extended =  *p++ << 8;
			r->frames_in.extended |= *p;

			state = r->frames_in.mask ? sw_masking_key : sw_payload_data;
			break;

		case sw_extended_8:
			if (b->last - p < 8) {
				goto again;
			}

			r->frames_in.extended =  (i = *p++) << 56;
			r->frames_in.extended |= (i = *p++) << 48;
			r->frames_in.extended |= (i = *p++) << 40;
			r->frames_in.extended |= (i = *p++) << 32;
			r->frames_in.extended |= (i = *p++) << 24;
			r->frames_in.extended |= (i = *p++) << 16;
			r->frames_in.extended |= (i = *p++) <<  8;
			r->frames_in.extended |= *p;

			state = r->frames_in.mask ? sw_masking_key : sw_payload_data;
			break;

		case sw_masking_key:
			if (b->last - p < 4) {
				goto again;
			}

			memcpy(r->frames_in.masking_key, p, 4);
			p += 3;

			state = sw_payload_data;
			break;

		case sw_payload_data:
			if (b->last - p < r->frames_in.extended) {
				goto again;
			}

			switch (r->frames_in.opcode) {
			case STU_WEBSOCKET_OPCODE_TEXT:
			case STU_WEBSOCKET_OPCODE_BINARY:
				if (r->frames_in.mask) {
					for (i = 0; i < r->frames_in.extended; i++) {
						p[i] ^= r->frames_in.masking_key[i % 4];
					}
					stu_log_debug(3, "unmasked: %s", p);
				}
				break;

			case STU_WEBSOCKET_OPCODE_CLOSE:
				stu_log_debug(4, "close frame.");
				break;

			case STU_WEBSOCKET_OPCODE_PING:
				stu_log_debug(3, "ping frame.");
				break;

			case STU_WEBSOCKET_OPCODE_PONG:
				stu_log_debug(3, "pong frame.");
				break;

			default:
				break;
			}

			r->frames_in.payload_data.start = r->frames_in.payload_data.pos = p;
			r->frames_in.payload_data.last = r->frames_in.payload_data.end = p + r->frames_in.extended;
			r->frames_in.payload_data.size = r->frames_in.extended;

			p = r->frames_in.payload_data.end;
			if (r->frames_in.fin) {
				goto frame_done;
			}

			goto done;
		}
	}

again:

	b->pos = p;
	r->state = state;

	return STU_AGAIN;

done:

	b->pos = p;
	r->state = sw_start;

	return STU_OK;

frame_done:

	b->pos = p;
	r->state = sw_start;

	return STU_DONE;
}

u_char *
stu_websocket_encode_frame_header(stu_websocket_frame_t *f, u_char *dst) {
	u_char       *p;
	stu_uint64_t  size;

	p = dst;
	size = f->payload_data.last - f->payload_data.pos;

	if (size < STU_WEBSOCKET_EXTENDED_2) {
		*p++ = 0x80 | f->opcode;
		*p++ = f->mask | size;
	} else if (size <= UINT16_MAX) {
		*p++ = 0x80 | f->opcode;
		*p++ = f->mask | STU_WEBSOCKET_EXTENDED_2;
		*p++ = size >> 8;
		*p++ = size;
	} else {
		*p++ = 0x80 | f->opcode;
		*p++ = f->mask | STU_WEBSOCKET_EXTENDED_8;
		*p++ = size >> 56;
		*p++ = size >> 48;
		*p++ = size >> 40;
		*p++ = size >> 32;
		*p++ = size >> 24;
		*p++ = size >> 16;
		*p++ = size >>  8;
		*p++ = size;
	}

	if (f->mask) {
		p = stu_memcpy(p, f->masking_key, 4);
	}

	return p;
}

u_char *
stu_websocket_encode_frame(stu_websocket_frame_t *f, u_char *dst) {
	u_char       *p;
	stu_uint64_t  size;

	size = f->payload_data.last - f->payload_data.pos;

	p = stu_websocket_encode_frame_header(f, dst);
	p = stu_strncpy(p, f->payload_data.pos, size);

	return p;
}
