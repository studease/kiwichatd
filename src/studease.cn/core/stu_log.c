/*
 * stu_log.c
 *
 *  Created on: 2017年11月15日
 *      Author: Tony Lau
 */

#include "../stu_config.h"
#include "stu_core.h"

stu_uint8_t  STU_DEBUG = 4;

static stu_file_t *stu_logger = NULL;

static u_char *stu_log_prefix(u_char *buf, const stu_str_t prefix);
static u_char *stu_log_errno(u_char *buf, u_char *last, stu_int32_t err);


stu_int32_t
stu_log_init(stu_file_t *file) {
	if (stu_create_path(file) == STU_ERROR) {
		stu_log_error(0, "Failed to create log path.");
		return STU_ERROR;
	}

	file->fd = stu_file_open(file->name.data, STU_FILE_CREATE_OR_OPEN, STU_FILE_APPEND, STU_FILE_DEFAULT_ACCESS);
	if (file->fd == STU_FILE_INVALID) {
		stu_log_error(stu_errno, "Failed to " stu_file_open_n " log file \"%s\".", file->name.data);
		return STU_ERROR;
	}

	stu_logger = file;

	return STU_OK;
}

void
__stu_log(const char *fmt, ...) {
	u_char  *p, *last;
	u_char   tmp[STU_LOG_RECORD_MAX_LEN];
	va_list  args;

	last = tmp + STU_LOG_RECORD_MAX_LEN;

	p = stu_log_prefix(tmp, STU_LOG_PREFIX);

	va_start(args, fmt);
	p = stu_vsprintf(p, fmt, args);
	va_end(args);

	if (p >= last - 1) {
		p = last - 2;
	}
	*p++ = LF;
	*p = '\0';

	if (stu_logger) {
		stu_file_write(stu_logger, tmp, p - tmp, stu_atomic_fetch_add(&stu_logger->offset, 0));
	}

	stu_printf((const char *) tmp);
}

void
__stu_log_debug(stu_int32_t level, const char *fmt, ...) {
	u_char  *p, *last;
	u_char   tmp[STU_LOG_RECORD_MAX_LEN];
	va_list  args;

	last = tmp + STU_LOG_RECORD_MAX_LEN;

	if (level < STU_DEBUG) {
		return;
	}

	p = stu_log_prefix(tmp, STU_DEBUG_PREFIX);
	p = stu_sprintf(p, "[%d]", level);

	va_start(args, fmt);
	p = stu_vsprintf(p, fmt, args);
	va_end(args);

	if (p >= last - 1) {
		p = last - 2;
	}
	*p++ = LF;
	*p = '\0';

	if (stu_logger) {
		stu_file_write(stu_logger, tmp, p - tmp, stu_atomic_fetch_add(&stu_logger->offset, 0));
	}

	stu_printf((const char *) tmp);
}

void
__stu_log_error(stu_int32_t err, const char *fmt, ...) {
	u_char  *p, *last;
	u_char   tmp[STU_LOG_RECORD_MAX_LEN];
	va_list  args;

	last = tmp + STU_LOG_RECORD_MAX_LEN;

	p = stu_log_prefix(tmp, STU_ERROR_PREFIX);

	va_start(args, fmt);
	p = stu_vsprintf(p, fmt, args);
	va_end(args);

	if (err) {
		p = stu_log_errno(p, last, err);
	} else {
		*p++ = LF;
	}

	if (p >= last - 1) {
		p = last - 2;
	}
	*p++ = LF;
	*p = '\0';

	if (stu_logger) {
		stu_file_write(stu_logger, tmp, p - tmp, stu_atomic_fetch_add(&stu_logger->offset, 0));
	}

	stu_printf((const char *) tmp);
}


static u_char *
stu_log_prefix(u_char *buf, const stu_str_t prefix) {
	u_char *p;

	p = stu_memcpy(buf, stu_cached_log_time.data, stu_cached_log_time.len);
	p = stu_memcpy(p, prefix.data, prefix.len);

	return p;
}

static u_char *
stu_log_errno(u_char *buf, u_char *last, stu_int32_t err) {
	if (buf > last - 50) {
		buf = last - 50;
		*buf++ = '.';
		*buf++ = '.';
		*buf++ = '.';
	}

	buf = stu_sprintf(buf, " (%d: ", err);

	buf = stu_strerror(err, buf, last - buf);
	if (buf < last - 1) {
		*buf++ = ')';
	}
	*buf++ = LF;
	*buf = '\0';

	return buf;
}
