/*
 * stu_http_status.c
 *
 *  Created on: 2017年11月23日
 *      Author: Tony Lau
 */

#include "stu_http.h"

static stu_hash_t         http_status_hash;

static stu_http_status_t  http_status[] = {
	{ STU_HTTP_CONTINUE,                        stu_string("Continue") },
	{ STU_HTTP_SWITCHING_PROTOCOLS,             stu_string("Switching Protocols") },
	{ STU_HTTP_PROCESSING,                      stu_string("Processing") },

	{ STU_HTTP_OK,                              stu_string("OK") },
	{ STU_HTTP_CREATED,                         stu_string("Created") },
	{ STU_HTTP_ACCEPTED,                        stu_string("Accepted") },
	{ STU_HTTP_NON_AUTHORITATIVE_INFO,          stu_string("Non-Authoritative Information") },
	{ STU_HTTP_NO_CONTENT,                      stu_string("No Content") },
	{ STU_HTTP_RESET_CONTENT,                   stu_string("Reset Content") },
	{ STU_HTTP_PARTIAL_CONTENT,                 stu_string("Partial Content") },
	{ STU_HTTP_MULTI_STATUS,                    stu_string("Multi-Status") },
	{ STU_HTTP_ALREADY_REPORTED,                stu_string("Already Reported") },
	{ STU_HTTP_IM_USED,                         stu_string("IM Used") },

	{ STU_HTTP_MULTIPLE_CHOICES,                stu_string("Multiple Choices") },
	{ STU_HTTP_MOVED_PERMANENTLY,               stu_string("Moved Permanently") },
	{ STU_HTTP_MOVED_TEMPORARILY,               stu_string("Moved Temporarily") },
	{ STU_HTTP_SEE_OTHER,                       stu_string("See Other") },
	{ STU_HTTP_NOT_MODIFIED,                    stu_string("Not Modified") },
	{ STU_HTTP_USE_PROXY,                       stu_string("Use Proxy") },
	{ STU_HTTP_TEMPORARY_REDIRECT,              stu_string("Temporary Redirect") },
	{ STU_HTTP_PERMANENT_REDIRECT,              stu_string("Permanent Redirect") },

	{ STU_HTTP_BAD_REQUEST,                     stu_string("Bad Request") },
	{ STU_HTTP_UNAUTHORIZED,                    stu_string("Unauthorized") },
	{ STU_HTTP_PAYMENT_REQUIRED,                stu_string("Payment Required") },
	{ STU_HTTP_FORBIDDEN,                       stu_string("Forbidden") },
	{ STU_HTTP_NOT_FOUND,                       stu_string("Not Found") },
	{ STU_HTTP_METHOD_NOT_ALLOWED,              stu_string("Method Not Allowed") },
	{ STU_HTTP_NOT_ACCEPTABLE,                  stu_string("Not Acceptable") },
	{ STU_HTTP_PROXY_AUTH_REQUIRED,             stu_string("Proxy Authentication Required") },
	{ STU_HTTP_REQUEST_TIMEOUT,                 stu_string("Request Timeout") },
	{ STU_HTTP_CONFLICT,                        stu_string("Conflict") },
	{ STU_HTTP_GONE,                            stu_string("Gone") },
	{ STU_HTTP_LENGTH_REQUIRED,                 stu_string("Length Required") },
	{ STU_HTTP_PRECONDITION_FAILED,             stu_string("Precondition Failed") },
	{ STU_HTTP_REQUEST_ENTITY_TOO_LARGE,        stu_string("Request Entity Too Large") },
	{ STU_HTTP_REQUEST_URI_TOO_LARGE,           stu_string("Request URI Too Long") },
	{ STU_HTTP_UNSUPPORTED_MEDIA_TYPE,          stu_string("Unsupported Media Type") },
	{ STU_HTTP_REQUESTED_RANGE_NOT_SATISFIABLE, stu_string("Requested Range Not Satisfiable") },
	{ STU_HTTP_EXPECTATION_FAILED,              stu_string("Expectation Failed") },
	{ STU_HTTP_TEAPOT,                          stu_string("I'm a teapot") },
	{ STU_HTTP_MISDIRECTED_REQUEST,             stu_string("Misdirected Request") },
	{ STU_HTTP_UNPROCESSABLE_ENTITY,            stu_string("Unprocessable Entity") },
	{ STU_HTTP_LOCKED,                          stu_string("Locked") },
	{ STU_HTTP_FAILED_DEPENDENCY,               stu_string("Failed Dependency") },
	{ STU_HTTP_UPGRADE_REQUIRED,                stu_string("Upgrade Required") },
	{ STU_HTTP_PRECONDITION_REQUIRED,           stu_string("Precondition Required") },
	{ STU_HTTP_TOO_MANY_REQUESTS,               stu_string("Too Many Requests") },

	{ STU_HTTP_INTERNAL_SERVER_ERROR,           stu_string("Internal Server Error") },
	{ STU_HTTP_NOT_IMPLEMENTED,                 stu_string("Not Implemented") },
	{ STU_HTTP_BAD_GATEWAY,                     stu_string("Bad Gateway") },
	{ STU_HTTP_SERVICE_UNAVAILABLE,             stu_string("Service Unavailable") },
	{ STU_HTTP_GATEWAY_TIMEOUT,                 stu_string("Gateway Timeout") },
	{ STU_HTTP_VERSION_NOT_SUPPORTED,           stu_string("HTTP Version Not Supported") },
	{ STU_HTTP_VARIANT_ALSO_NEGOTIATES,         stu_string("Variant Also Negotiates") },
	{ STU_HTTP_INSUFFICIENT_STORAGE,            stu_string("Insufficient Storage") },
	{ STU_HTTP_LOOP_DETECTED,                   stu_string("Loop Detected") },
	{ STU_HTTP_NOT_EXTENDED,                    stu_string("Not Extended") },
	{ STU_HTTP_NETWORK_AUTH_REQUIRED,           stu_string("Network Authentication Required") },
	{ 0,                                        stu_null_string }
};


stu_int32_t
stu_http_status_init_hash() {
	stu_http_status_t *status;
	u_char             tmp[4];
	stu_str_t          code;

	code.data = (u_char *) tmp;
	code.len = 3;

	if (stu_hash_init(&http_status_hash, STU_HTTP_STATUS_MAX_RECORDS, NULL, 0) == STU_ERROR) {
		return STU_ERROR;
	}

	for (status = http_status; status->code; status++) {
		stu_sprintf(tmp, "%d\0", status->code);
		if (stu_hash_insert(&http_status_hash, &code, status) == STU_ERROR) {
			return STU_ERROR;
		}
	}

	return STU_OK;
}

u_char *
stu_http_status_text(stu_int32_t rc) {
	stu_http_status_t *status;
	u_char             tmp[4];
	stu_uint32_t       hk;

	stu_sprintf(tmp, "%d\0", rc);
	hk = stu_hash_key(tmp, 3, http_status_hash.flags);

	// no need to lock
	status = (stu_http_status_t *) stu_hash_find_locked(&http_status_hash, hk, tmp, 3);
	if (status == NULL) {
		return NULL;
	}

	return status->text.data;
}
