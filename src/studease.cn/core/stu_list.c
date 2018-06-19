/*
 * stu_list.c
 *
 *  Created on: 2017骞�11鏈�15鏃�
 *      Author: Tony Lau
 */

#include "../stu_config.h"
#include "stu_core.h"


void
stu_list_init(stu_list_t *list, stu_list_hooks_t *hooks) {
	stu_mutex_init(&list->lock, NULL);

	stu_queue_init(&list->elts.queue);
	list->elts.list = list;
	list->elts.value = NULL;
	list->current = NULL;
	list->length = 0;

	if (hooks == NULL || hooks->malloc_fn == NULL) {
		list->hooks.malloc_fn = stu_calloc;
		list->hooks.free_fn = stu_free;
	} else {
		list->hooks.malloc_fn = hooks->malloc_fn;
		list->hooks.free_fn = hooks->free_fn;
	}
}


stu_list_elt_t *
stu_list_insert_before(stu_list_t *list, void *value, stu_list_elt_t *elt) {
	stu_list_elt_t *e;

	e = list->hooks.malloc_fn(sizeof(stu_list_elt_t));
	if (e == NULL) {
		stu_log_error(0, "Failed to malloc stu_list_elt_t.");
		return NULL;
	}

	e->list = list;
	e->value = value;

	stu_queue_insert_before(&elt->queue, &e->queue);
	list->length++;

	return e;
}

stu_list_elt_t *
stu_list_insert_after(stu_list_t *list, void *value, stu_list_elt_t *elt) {
	stu_list_elt_t *e;

	e = list->hooks.malloc_fn(sizeof(stu_list_elt_t));
	if (e == NULL) {
		stu_log_error(0, "Failed to malloc stu_list_elt_t.");
		return NULL;
	}

	e->list = list;
	e->value = value;

	stu_queue_insert_after(&elt->queue, &e->queue);
	list->length++;

	return e;
}

stu_list_elt_t *
stu_list_insert_head(stu_list_t *list, void *value) {
	stu_list_elt_t *e;

	e = list->hooks.malloc_fn(sizeof(stu_list_elt_t));
	if (e == NULL) {
		stu_log_error(0, "Failed to malloc stu_list_elt_t.");
		return NULL;
	}

	e->list = list;
	e->value = value;

	stu_queue_insert_head(&list->elts.queue, &e->queue);
	list->length++;

	return e;
}

stu_list_elt_t *
stu_list_insert_tail(stu_list_t *list, void *value) {
	stu_list_elt_t *e;

	e = list->hooks.malloc_fn(sizeof(stu_list_elt_t));
	if (e == NULL) {
		stu_log_error(0, "Failed to malloc stu_list_elt_t.");
		return NULL;
	}

	e->list = list;
	e->value = value;

	stu_queue_insert_tail(&list->elts.queue, &e->queue);
	list->length++;

	return e;
}


void *
stu_list_remove(stu_list_t *list, stu_list_elt_t *elt) {
	void *v;

	v = elt->value;

	stu_queue_remove(&elt->queue);
	list->length--;

	list->hooks.free_fn(elt);

	return v;
}

void
stu_list_destroy(stu_list_t *list, stu_list_cleanup_pt cleanup) {
	stu_list_elt_t *elts, *e;
	stu_queue_t    *q;

	elts = &list->elts;

	for (q = stu_queue_head(&elts->queue); q != stu_queue_sentinel(&elts->queue); /* void */) {
		e = stu_queue_data(q, stu_list_elt_t, queue);
		q = stu_queue_next(q);

		if (cleanup) {
			cleanup(e->value);
		}

		stu_queue_remove(&e->queue);
		list->length--;

		list->hooks.free_fn(e);
	}
}


void
stu_list_foreach(stu_list_t *list, stu_list_foreach_pt cb) {
	stu_list_elt_t *elts, *e;
	stu_queue_t    *q;

	elts = &list->elts;

	for (q = stu_queue_head(&elts->queue); q != stu_queue_sentinel(&elts->queue); q = stu_queue_next(q)) {
		e = stu_queue_data(q, stu_list_elt_t, queue);
		cb(e->value);
	}
}


void
stu_list_empty_free_pt(void *ptr) {

}
