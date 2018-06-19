/*
 * stu_http_filter.c
 *
 *  Created on: 2017骞�11鏈�24鏃�
 *      Author: Tony Lau
 */

#include "stu_http.h"

static stu_int32_t    stu_http_filter_static_handler(stu_http_request_t *r);

stu_hash_t            stu_http_filter_hash;

static stu_http_filter_t  http_filter[] = {
	{ stu_string("/"), stu_http_filter_static_handler },
	{ stu_null_string, NULL }
};


stu_int32_t
stu_http_filter_init_hash() {
	stu_http_filter_t *f;

	if (stu_hash_init(&stu_http_filter_hash, STU_HTTP_FILTER_MAX_RECORDS, NULL, STU_HASH_FLAGS_LOWCASE) == STU_ERROR) {
		return STU_ERROR;
	}

	for (f = http_filter; f->handler; f++) {
		if (stu_http_filter_add(&f->pattern, f->handler) == STU_ERROR) {
			return STU_ERROR;
		}
	}

	return STU_OK;
}

stu_int32_t
stu_http_filter_add(stu_str_t *pattern, stu_http_filter_handler_pt handler) {
	stu_list_t        *list;
	stu_list_elt_t    *e;
	stu_http_filter_t *f;
	stu_uint32_t       hk;
	stu_int32_t        rc;

	rc = STU_ERROR;

	stu_mutex_lock(&stu_http_filter_hash.lock);

	hk = stu_hash_key(pattern->data, pattern->len, stu_http_filter_hash.flags);

	list = stu_hash_find_locked(&stu_http_filter_hash, hk, pattern->data, pattern->len);
	if (list == NULL) {
		list = stu_calloc(sizeof(stu_list_t));
		if (list == NULL) {
			goto failed;
		}

		stu_list_init(list, (stu_list_hooks_t *) &stu_http_filter_hash.hooks);

		if (stu_hash_insert_locked(&stu_http_filter_hash, pattern, list) == STU_ERROR) {
			goto failed;
		}
	}

	f = stu_calloc(sizeof(stu_http_filter_t));
	if (f == NULL) {
		goto failed;
	}

	f->pattern = *pattern;
	f->handler = handler;

	stu_mutex_lock(&list->lock);
	e = stu_list_insert_tail(list, f);
	stu_mutex_unlock(&list->lock);

	if (e) {
		rc = STU_OK;
	}

failed:

	stu_mutex_unlock(&stu_http_filter_hash.lock);

	return rc;
}

stu_int32_t
stu_http_filter_del(stu_str_t *pattern, stu_http_filter_handler_pt handler) {
	stu_list_t        *list;
	stu_list_elt_t    *elts, *e;
	stu_queue_t       *q;
	stu_http_filter_t *f;
	stu_uint32_t       hk;

	stu_mutex_lock(&stu_http_filter_hash.lock);

	hk = stu_hash_key(pattern->data, pattern->len, stu_http_filter_hash.flags);

	if (handler == NULL) {
		list = stu_hash_remove_locked(&stu_http_filter_hash, hk, pattern->data, pattern->len);
		stu_list_destroy(list, stu_free);
		stu_free(list);
		goto done;
	}

	list = stu_hash_find_locked(&stu_http_filter_hash, hk, pattern->data, pattern->len);
	if (list == NULL) {
		goto done;
	}

	stu_mutex_lock(&list->lock);

	elts = &list->elts;

	for (q = stu_queue_head(&elts->queue); q != stu_queue_sentinel(&elts->queue); q = stu_queue_next(q)) {
		e = stu_queue_data(q, stu_list_elt_t, queue);
		f = e->value;

		if (f->handler == handler) {
			stu_list_remove(list, e);
			stu_free(f);
			break;
		}
	}

	stu_mutex_unlock(&list->lock);

done:

	stu_mutex_unlock(&stu_http_filter_hash.lock);

	return STU_OK;
}


static stu_int32_t
stu_http_filter_static_handler(stu_http_request_t *r) {
	r->headers_out.status = STU_HTTP_NOT_IMPLEMENTED;
	return STU_DECLINED;
}
