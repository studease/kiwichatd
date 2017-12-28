/*
 * kcd_message.c
 *
 *  Created on: 2017年12月20日
 *      Author: Tony Lau
 */

#include "kcd_core.h"


stu_int32_t
kcd_message_init(kcd_message_t *m, stu_str_t * path, stu_str_t *id) {
	stu_rwlock_init(&m->lock, NULL);

	m->file.name.data = stu_calloc(STU_FILE_PATH_MAX_LEN);
	if (m->file.name.data == NULL) {
		stu_log_error(0, "Failed to calloc message file name.");
		return STU_ERROR;
	}

	stu_sprintf(m->file.name.data, (const char *) path->data, id->data);
	m->file.name.len = stu_strlen(m->file.name.data);

	if (stu_create_path(&m->file) == STU_ERROR) {
		stu_log_error(0, "Failed to create message path.");
		return STU_ERROR;
	}

	m->file.fd = stu_file_open(m->file.name.data, STU_FILE_CREATE_OR_OPEN, O_RDWR|O_APPEND, STU_FILE_DEFAULT_ACCESS);
	if (m->file.fd == STU_FILE_INVALID) {
		stu_log_error(stu_errno, "Failed to " stu_file_open_n " message file \"%s\".", m->file.name.data);
		return STU_ERROR;
	}

	if (stu_fd_info(m->file.fd, &m->file.info) == STU_ERROR) {
		stu_log_error(stu_errno, "Failed to " stu_fd_info_n " message file \"%s\".", m->file.name.data);
		return STU_ERROR;
	}

	m->file.offset = m->file.info.st_size;
	m->message_n = 0;

	return STU_OK;
}


off_t
kcd_message_push(kcd_message_t *m, u_char *data, size_t size) {
	off_t        offset;
	stu_int32_t  n, tmp;

	tmp = size;

	stu_rwlock_wrlock(&m->lock);

	offset = stu_atomic_fetch(&m->file.offset);

	n = stu_file_write(&m->file, data, size, offset);
	if (n == STU_ERROR) {
		offset = STU_ERROR;
		stu_log_error(0, "Failed to push message data: file=\"%s\".", m->file.name.data);
		goto failed;
	}

	n = stu_file_write(&m->file, (u_char *) &tmp, 4, stu_atomic_fetch(&m->file.offset));
	if (n == STU_ERROR) {
		offset = STU_ERROR;
		stu_log_error(0, "Failed to push message size: file=\"%s\".", m->file.name.data);
		goto failed;
	}

	m->message_n++;

failed:

	stu_rwlock_unlock(&m->lock);

	return offset;
}

u_char *
kcd_message_read(kcd_message_t *m, u_char *dst, off_t *offset) {
	stu_json_t   *ji, *ji_type;
	u_char       *p;
	off_t         off;
	ssize_t       v;
	size_t        size;
	stu_int32_t   len;
	stu_uint64_t  payload_len, i;
	enum {
		sw_payload_len = 0,
		sw_extended_2,
		sw_extended_8,
		sw_payload_data
	} state;

	p = dst;
	len = 0;
	size = 2;
	state = sw_payload_len;

	stu_rwlock_rdlock(&m->lock);

	/* read message length */
	if (*offset < 4) {
		goto failed;
	}

	*offset -= 4;

	v = pread(m->file.fd, (u_char *) &len, 4, *offset);
	if (v == -1) {
		stu_log_error(stu_errno, "pread() \"%s\" failed.", m->file.name.data);
		goto failed;
	}

	*offset -= len;
	off = *offset;

	/* read message data */
	for ( ;; ) {
		v = pread(m->file.fd, p, size, off);
		if (v == -1) {
			stu_log_error(stu_errno, "pread() \"%s\" failed.", m->file.name.data);
			goto failed;
		}

		if (v == 0) {
			goto done;
		}

		switch (state) {
		case sw_payload_len:
			payload_len = *(p + 1) & 0x7F;

			switch (payload_len) {
			case 126:
				size = 2;
				state = sw_extended_2;
				break;
			case 127:
				size = 8;
				state = sw_extended_8;
				break;
			default:
				size = payload_len;
				state = sw_payload_data;
				break;
			}

			p += 2;
			off += 2;
			break;

		case sw_extended_2:
			payload_len =  *p++ << 8;
			payload_len |= *p++;

			off += 2;
			size = payload_len;
			state = sw_payload_data;
			break;

		case sw_extended_8:
			payload_len =  (i = *p++) << 56;
			payload_len |= (i = *p++) << 48;
			payload_len |= (i = *p++) << 40;
			payload_len |= (i = *p++) << 32;
			payload_len |= (i = *p++) << 24;
			payload_len |= (i = *p++) << 16;
			payload_len |= (i = *p++) <<  8;
			payload_len |= *p++;

			off += 8;
			size = payload_len;
			state = sw_payload_data;
			break;

		case sw_payload_data:
			ji = stu_json_parse(p, payload_len);
			if (ji == NULL || ji->type != STU_JSON_TYPE_OBJECT) {
				stu_log_error(0, "Bad history message: %s.", p);
				p = dst;
				goto failed;
			}

			ji_type = stu_json_get_object_item_by(ji, &KCD_PROTOCOL_TYPE);
			if (ji_type == NULL || ji_type->type != STU_JSON_TYPE_NUMBER) {
				stu_log_error(0, "Bad history message: %s.", p);
				p = dst;
				goto failed;
			}

			*(stu_double_t *) ji_type->value = KCD_PROTOCOL_HISTORY;
			stu_json_stringify(ji, p);

			p += payload_len;
			off += payload_len;
			goto done;
		}
	}

failed:
done:

	stu_rwlock_unlock(&m->lock);

	return p;
}
