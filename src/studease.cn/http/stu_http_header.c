/*
 * stu_http_header.c
 *
 *  Created on: 2017年11月21日
 *      Author: Tony Lau
 */

#include "stu_http.h"

stu_http_headers_t    stu_http_headers_in_hash;
stu_http_headers_t    stu_http_upstream_headers_in_hash;

extern stu_http_header_t  http_headers_in[];
extern stu_http_header_t  http_upstream_headers_in[];


stu_int32_t
stu_http_header_init_hash() {
	stu_http_header_t *header;

	if (stu_hash_init(&stu_http_headers_in_hash, STU_HTTP_HEADER_MAX_RECORDS, NULL, STU_HASH_FLAGS_LOWCASE|STU_HASH_FLAGS_REPLACE) == STU_ERROR) {
		return STU_ERROR;
	}

	if (stu_hash_init(&stu_http_upstream_headers_in_hash, STU_HTTP_HEADER_MAX_RECORDS, NULL, STU_HASH_FLAGS_LOWCASE|STU_HASH_FLAGS_REPLACE) == STU_ERROR) {
		return STU_ERROR;
	}

	for (header = http_headers_in; header->name.len; header++) {
		if (stu_hash_insert(&stu_http_headers_in_hash, &header->name, header) == STU_ERROR) {
			return STU_ERROR;
		}
	}

	for (header = http_upstream_headers_in; header->name.len; header++) {
		if (stu_hash_insert(&stu_http_upstream_headers_in_hash, &header->name, header) == STU_ERROR) {
			return STU_ERROR;
		}
	}

	return STU_OK;
}


void
stu_http_header_set(stu_http_headers_t *h, stu_str_t *key, stu_str_t *value) {
	stu_hash_insert(h, key, value);
}

stu_str_t *
stu_http_header_get(stu_http_headers_t *h, stu_str_t *key) {
	stu_uint32_t  hk;

	hk = stu_hash_key(key->data, key->len, h->flags);

	return stu_hash_find(h, hk, key->data, key->len);
}

void
stu_http_header_del(stu_http_headers_t *h, stu_str_t *key) {
	stu_uint32_t  hk;

	hk = stu_hash_key(key->data, key->len, h->flags);

	return stu_hash_remove(h, hk, key->data, key->len);
}
