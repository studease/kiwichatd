/*
 * stu_mq.c
 *
 *  Created on: 2017年12月29日
 *      Author: Tony Lau
 */

#include "../stu_config.h"
#include "stu_core.h"

static stu_str_t   stu_mq_path;
static stu_hash_t  stu_mq_list;

static stu_mq_t      *stu_mq_get_locked(stu_str_t *name, stu_uint8_t mode, size_t size);
static stu_mq_page_t *stu_mq_create_page(stu_mq_t *mq, off_t off, stu_bool_t reverse);
static void           stu_mq_insert_value(stu_rbtree_node_t *root, stu_rbtree_node_t *node, stu_rbtree_node_t *sentinel);


stu_int32_t
stu_mq_init(stu_str_t *path, stu_uint32_t size) {
	stu_int32_t  rc;

	if (path->data == NULL || path->len == 0 || size == 0) {
		return STU_ERROR;
	}

	stu_mq_path = *path;
	rc = stu_hash_init(&stu_mq_list, size, NULL, STU_HASH_FLAGS_LOWCASE | STU_HASH_FLAGS_REPLACE);

	return rc;
}


off_t
stu_mq_push(stu_str_t *name, u_char *data, size_t len, stu_uint8_t mode) {
	stu_mq_t      *mq;
	stu_mq_page_t *mp;
	stu_queue_t   *q;
	u_char        *p;
	off_t          offset;
	stu_int32_t    n;

	offset = STU_ERROR;

	stu_mutex_lock(&stu_mq_list.lock);

	mq = stu_mq_get_locked(name, mode, STU_MQ_PAGE_DEFAULT_SIZE);
	if (mq == NULL) {
		stu_log_error(0, "Failed to get mq: name=\"%s\".", name->data);
		goto done;
	}

	stu_rwlock_wrlock(&mq->lock);

	q = stu_queue_tail(&mq->queue);
	if (q != stu_queue_sentinel(&mq->queue)) {
		mp = stu_queue_data(q, stu_mq_page_t, queue);
	}

	if (q == stu_queue_sentinel(&mq->queue) || mp->end - mp->last < len) {
		mp = stu_mq_create_page(mq, mq->file.offset, FALSE);
		if (mp == NULL) {
			stu_log_error(0, "Failed to create mq page: name=\"%s\".", name->data);
			goto failed;
		}
	}

	offset = mp->offset + (mp->last - mp->start);

	if (data == NULL || len == 0) {
		goto failed;
	}

	p = mp->last;
	mp->last = stu_memcpy(mp->last, (u_char *) &len, 2);
	mp->last = stu_memcpy(mp->last, data, len);

	len += 2;
	mp->last = stu_memcpy(mp->last, (u_char *) &len, 2);

	// TODO: lazy write
	n = stu_file_write(&mq->file, p, len + 2, offset);
	if (n == STU_ERROR) {
		stu_log_error(0, "Failed to push message data: file=\"%s\".", mq->file.name.data);
	}

	mq->message_n++;

failed:

	stu_rwlock_unlock(&mq->lock);

done:

	stu_mutex_unlock(&stu_mq_list.lock);

	return offset;
}

u_char *
stu_mq_read(stu_str_t *name, u_char *dst, off_t *offset, stu_bool_t reverse) {
	stu_mq_t      *mq;
	stu_mq_page_t *mp;
	stu_queue_t   *q;
	u_char        *p, *src;
	stu_uint32_t   hk;
	stu_int32_t    n;
	off_t          off;

	p = dst;
	hk = stu_hash_key(name->data, name->len, stu_mq_list.flags);

	stu_mutex_lock(&stu_mq_list.lock);

	mq = stu_hash_find_locked(&stu_mq_list, hk, name->data, name->len);
	if (mq == NULL) {
		stu_log_error(0, "Failed to get mq: name=\"%s\".", name->data);
		goto done;
	}

	stu_rwlock_rdlock(&mq->lock);

	for (q = stu_queue_tail(&mq->queue); q != stu_queue_sentinel(&mq->queue); q = stu_queue_prev(q)) {
		mp = stu_queue_data(q, stu_mq_page_t, queue);
		if (*offset < mp->offset || *offset > mp->offset + (mp->last - mp->start)) {
			continue;
		}

		off = *offset - mp->offset;
		src = mp->start + off;

		if (reverse) {
			if (off < 2) {
				goto failed;
			}

			src -= 2;
			n = *(stu_int16_t *) src;
			n -= 2;

			if (off < n) {
				goto failed;
			}

			src -= n;
			p = stu_memcpy(dst, src, n);

			*offset -= n + 4;
		} else {
			if (src + 4 > mp->last) {
				goto failed;
			}

			n = *(stu_int16_t *) src;
			src += 2;

			if (src + n + 2 > mp->last) {
				goto failed;
			}

			p = stu_memcpy(dst, src, n);

			*offset += n + 4;

			goto failed;
		}

		break;
	}

failed:

	stu_rwlock_unlock(&mq->lock);

done:

	stu_mutex_unlock(&stu_mq_list.lock);

	return p;
}


void
stu_mq_destory(stu_str_t *name) {
	stu_mq_t      *mq;
	stu_mq_page_t *mp;
	stu_queue_t   *q;
	stu_uint32_t   hk;

	hk = stu_hash_key(name->data, name->len, stu_mq_list.flags);

	stu_mutex_lock(&stu_mq_list.lock);

	mq = stu_hash_find_locked(&stu_mq_list, hk, name->data, name->len);
	if (mq == NULL) {
		goto done;
	}

	stu_rwlock_wrlock(&mq->lock);

	for ( ; (q = stu_queue_head(&mq->queue)) != stu_queue_sentinel(&mq->queue); ) {
		mp = stu_queue_data(q, stu_mq_page_t, queue);

		stu_queue_remove(q);
		stu_free(mp);
	}

	// TODO: empty mq->tree
	stu_queue_init(&mq->queue);
	stu_file_close(mq->file.fd);
	mq->destroyed = TRUE;

	stu_rwlock_unlock(&mq->lock);

done:

	stu_log_debug(4, "mq destroyed: name= \"%s\".", name->data);

	stu_mutex_unlock(&stu_mq_list.lock);
}


static stu_mq_t *
stu_mq_get_locked(stu_str_t *name, stu_uint8_t mode, size_t size) {
	stu_mq_t     *mq;
	stu_uint32_t  hk;

	hk = stu_hash_key(name->data, name->len, stu_mq_list.flags);

	mq = stu_hash_find_locked(&stu_mq_list, hk, name->data, name->len);
	if (mq == NULL) {
		mq = stu_calloc(sizeof(stu_mq_t));
		if (mq == NULL) {
			stu_log_error(stu_errno, "Failed to calloc mq.");
			goto done;
		}

		mq->file.name.data = stu_calloc(STU_FILE_PATH_MAX_LEN);
		if (mq->file.name.data == NULL) {
			stu_log_error(stu_errno, "Failed to calloc mq file name.");
			goto failed;
		}

		stu_sprintf(mq->file.name.data, (const char *) stu_mq_path.data, name->data);
		mq->file.name.len = stu_strlen(mq->file.name.data);

		stu_rwlock_init(&mq->lock, NULL);
		stu_queue_init(&mq->queue);
		stu_rbtree_init(&mq->tree, &mq->sentinel, stu_mq_insert_value, NULL);

		mq->mode = mode;
		mq->size = size;
		mq->message_n = 0;
		mq->destroyed = TRUE;

		if (stu_hash_insert_locked(&stu_mq_list, name, mq) == STU_ERROR) {
			stu_log_error(0, "Failed to insert mq: name=\"%s\".", name->data);
			goto failed;
		}

		stu_log_debug(5, "new mq inserted: name=\"%s\", total=%d.", name->data, stu_mq_list.length);
	}

	if (mq->destroyed) {
		if (stu_create_path(&mq->file) == STU_ERROR) {
			stu_log_error(0, "Failed to create mq file path.");
			goto failed;
		}

		mq->file.fd = stu_file_open(mq->file.name.data, STU_FILE_CREATE_OR_OPEN, O_RDWR|O_APPEND, STU_FILE_DEFAULT_ACCESS);
		if (mq->file.fd == STU_FILE_INVALID) {
			stu_log_error(stu_errno, "Failed to " stu_file_open_n " mq file \"%s\".", mq->file.name.data);
			goto failed;
		}

		if (stu_fd_info(mq->file.fd, &mq->file.info) == STU_ERROR) {
			stu_log_error(stu_errno, "Failed to " stu_fd_info_n " mq file \"%s\".", mq->file.name.data);
			goto failed;
		}

		mq->file.offset = mq->file.info.st_size;
		mq->destroyed = FALSE;

		stu_mq_create_page(mq, mq->file.offset, TRUE);
	}

	goto done;

failed:

	if (mq) {
		stu_free(mq);
	}

	if (mq->file.name.data) {
		stu_free(mq->file.name.data);
	}

	mq = NULL;

done:

	return mq;
}

static stu_mq_page_t *
stu_mq_create_page(stu_mq_t *mq, off_t off, stu_bool_t reverse) {
	stu_mq_page_t *mp;
	ssize_t        v;

	mp = stu_calloc(sizeof(stu_mq_page_t) + mq->size);
	if (mp == NULL) {
		stu_log_error(stu_errno, "Failed to calloc mq page.");
		return NULL;
	}

	mp->start = (u_char *) mp + sizeof(stu_mq_page_t);
	mp->pos = mp->last = mp->start;
	mp->end = mp->start + mq->size;

	if (reverse == FALSE) {
		mp->offset = off;
		stu_queue_insert_tail(&mq->queue, &mp->queue);
		goto done;
	}

	mp->offset = stu_max(0, off - (off_t) mq->size);
	stu_queue_insert_head(&mq->queue, &mp->queue);

	v = pread(mq->file.fd, mp->start, mq->size, mp->offset);
	if (v == -1) {
		stu_log_error(stu_errno, "pread() \"%s\" failed.", mq->file.name.data);
		goto done;
	}

	if (v == 0) {
		goto done;
	}

	mp->last += v;

done:

	return mp;
}

static void
stu_mq_insert_value(stu_rbtree_node_t *tmp, stu_rbtree_node_t *node, stu_rbtree_node_t *sentinel) {
	stu_rbtree_node_t **p;
	stu_mq_node_t      *n;

	for ( ;; ) {
		if (node->key == tmp->key) {
			n = (stu_mq_node_t *) tmp;
			n->count++;
			return;
		}

		p = (node->key < tmp->key) ? &tmp->left : &tmp->right;
		if (*p == sentinel) {
			break;
		}

		tmp = *p;
	}

	*p = node;
	node->parent = tmp;
	node->left = sentinel;
	node->right = sentinel;
	stu_rbtree_red(node);
}
