/*
 * stu_connection.c
 *
 *  Created on: 2017年11月16日
 *      Author: Tony Lau
 */

#include "../stu_config.h"
#include "stu_core.h"

static void  stu_connection_free(stu_connection_t *c);


stu_connection_t *
stu_connection_get(stu_socket_t s) {
	stu_connection_t *c;

	c = stu_calloc(sizeof(stu_connection_t));
	if (c == NULL) {
		return NULL;
	}

	c->pool = stu_pool_create(STU_CONNECTION_POOL_DEFAULT_SIZE);
	if (c->pool == NULL) {
		stu_free(c);
		return NULL;
	}

	c->fd = s;
	c->read.data = (void *) c;
	c->write.data = (void *) c;
	c->idle = TRUE;

	stu_log_debug(3, "got connection: c=%p, fd=%d.", c, c->fd);

	return c;
}

void
stu_connection_close(stu_connection_t *c) {
	stu_socket_t  fd;

	if (c->fd == (stu_socket_t) STU_SOCKET_INVALID) {
		stu_log_error(0, "connection already closed.");
		return;
	}
/*
	if (c->read->timer_set) {
		stu_del_timer(c->read);
	}

	if (c->write->timer_set) {
		stu_del_timer(c->write);
	}
*/
	stu_event_del(&c->read, STU_READ_EVENT, STU_CLOSE_EVENT);
	stu_event_del(&c->write, STU_WRITE_EVENT, STU_CLOSE_EVENT);

	fd = c->fd;

	c->fd = (stu_socket_t) -1;
	c->close = TRUE;
	stu_close_socket(fd);

	stu_log_debug(3, "freed connection: c=%p, fd=%d.", c, fd);
	stu_connection_free(c);
}


static void
stu_connection_free(stu_connection_t *c) {
	stu_upstream_cleanup(c);
	c->destroyed = TRUE;

	stu_pool_destroy(c->pool);
	stu_free((void *) c);
}
