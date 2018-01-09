/*
 * kcd_request.c
 *
 *  Created on: 2017年12月5日
 *      Author: Tony Lau
 */

#include "kcd_core.h"

static stu_int32_t  kcd_filter_handler(stu_websocket_request_t *r);
static stu_int32_t  kcd_phase_upgrade_handler(stu_http_request_t *r);

static stu_int32_t  kcd_upgrade_preview_handler(stu_http_request_t *r);
static stu_int32_t  kcd_upgrade_enterprise_handler(stu_http_request_t *r);

static stu_int32_t  kcd_request_phase_handler(stu_websocket_request_t *r);
static void         kcd_request_analyze_protocol(stu_websocket_request_t *r);
static void         kcd_request_send_error(stu_websocket_request_t *r, stu_int32_t err, stu_double_t req);
static stu_int32_t  kcd_request_send_ident(stu_connection_t *c);
static stu_int32_t  kcd_request_send_history(stu_connection_t *c, stu_int32_t n);

static stu_int32_t  kcd_request_analyze_ident_upstream_response(stu_connection_t *pc);
static void         kcd_request_finalize_ident_upstream_handler(stu_connection_t *c, stu_int32_t rc);


extern volatile kcd_cycle_t   *kcd_cycle;
extern stu_list_t              stu_http_phases;
extern stu_list_t              stu_websocket_phases;

static stu_websocket_filter_t  kcd_filter = {
	stu_string("/"), kcd_filter_handler
};

static stu_http_phase_t        kcd_phase_upgrader = {
	kcd_phase_upgrade_handler
};

static stu_websocket_phase_t   kcd_phase_responder = {
	kcd_request_phase_handler
};

static stu_str_t  KCD_UPSTREAM_IDENT      = stu_string("ident");

static stu_str_t  KCD_REQUEST_ARG_CHANNEL = stu_string("channel");
static stu_str_t  KCD_REQUEST_ARG_TOKEN   = stu_string("token");

static stu_str_t  KCD_REQUEST_IDENT_RESPONSE = stu_string(
	"{"
		"\"raw\":\"ident\","
		"\"user\":{"
			"\"id\":\"%s\","
			"\"name\":\"%s\","
			"\"icon\":\"%s\","
			"\"role\":%d"
		"},"
		"\"channel\":{"
			"\"id\":\"%s\","
			"\"state\":%d,"
			"\"total\":%u"
		"}"
	"}"
);


stu_int32_t
kcd_request_init() {
	stu_list_elt_t *e;

	if (stu_websocket_filter_add(&kcd_filter.pattern, kcd_filter.handler) == STU_ERROR) {
		stu_log_error(0, "Failed to add kcd filter.");
		return STU_ERROR;
	}

	e = stu_list_insert_tail(&stu_http_phases, &kcd_phase_upgrader);
	if (e == NULL) {
		stu_log_error(0, "Failed to insert kcd upgrader phase.");
		return STU_ERROR;
	}

	e = stu_list_insert_tail(&stu_websocket_phases, &kcd_phase_responder);
	if (e == NULL) {
		stu_log_error(0, "Failed to insert kcd responder phase.");
		return STU_ERROR;
	}

	return STU_OK;
}


static stu_int32_t
kcd_filter_handler(stu_websocket_request_t *r) {
	r->status = STU_DECLINED;
	return STU_OK;
}

static stu_int32_t
kcd_phase_upgrade_handler(stu_http_request_t *r) {
	stu_int32_t  rc;

	rc = STU_ERROR;

	/* upgrade */
	switch (kcd_cycle->conf.edition) {
	case PREVIEW:
		rc = kcd_upgrade_preview_handler(r);
		break;

	case ENTERPRISE:
		rc = kcd_upgrade_enterprise_handler(r);
		break;

	default:
		stu_log_error(0, "unknown edition: %d.", kcd_cycle->conf.edition);
		break;
	}

	return rc;
}


static stu_int32_t
kcd_upgrade_preview_handler(stu_http_request_t *r) {
	stu_connection_t *c;
	kcd_channel_t    *ch;
	kcd_user_t       *user;
	u_char           *dst, *src;
	u_char            chan_s[KCD_CHANNEL_ID_MAX_LEN + 1];
	u_char            usid_s[KCD_USER_ID_MAX_LEN + 1];
	u_char            name_s[KCD_USER_NAME_MAX_LEN + 1];
	u_char            icon_s[KCD_USER_ICON_MAX_LEN + 1];
	stu_str_t         chan, usid, name, icon, v;
	stu_uint8_t       stat, role;

	c = r->connection;

	stat = role = STU_USER_ROLE_VISITOR;

	/* copy request info before pollution */
	stu_strncpy(chan_s, r->uri.data + 1, stu_min(r->uri.len - 1, KCD_CHANNEL_ID_MAX_LEN));
	chan.data = chan_s;
	chan.len = stu_strlen(chan_s);

	if (stu_http_arg(r, KCD_PROTOCOL_STATE.data, KCD_PROTOCOL_STATE.len, &v) == STU_OK) {
		stat = atoi((const char *) v.data);
	}

	stu_memzero(usid_s, KCD_USER_ID_MAX_LEN + 1);
	stu_sprintf(usid_s, "%u", stu_atomic_fetch_add(&kcd_cycle->auto_user_id, 1));
	usid.data = usid_s;
	usid.len = stu_strlen(usid_s);

	if (stu_http_arg(r, KCD_PROTOCOL_NAME.data, KCD_PROTOCOL_NAME.len, &name) == STU_OK) {
		stu_strncpy(name_s, name.data, stu_min(name.len, KCD_USER_NAME_MAX_LEN));

		dst = src = name_s;
		stu_unescape_uri(&dst, &src, name.len, 0);

		name.data = name_s;
		name.len = dst - name.data;
	} else {
		kcd_close_connection(c);
		goto done;
	}

	if (stu_http_arg(r, KCD_PROTOCOL_ROLE.data, KCD_PROTOCOL_ROLE.len, &v) == STU_OK) {
		role = atoi((const char *) v.data);
	}

	if (stu_http_arg(r, KCD_PROTOCOL_ICON.data, KCD_PROTOCOL_ICON.len, &icon) == STU_OK) {
		stu_strncpy(icon_s, icon.data, stu_min(icon.len, KCD_USER_ICON_MAX_LEN));
		icon.data = icon_s;
		icon.len = stu_strlen(icon_s);
	} else {
		icon.len = 0;
	}

	/* set user */
	user = stu_pcalloc(c->pool, sizeof(kcd_user_t));
	if (user == NULL) {
		kcd_close_connection(c);
		return STU_ERROR;
	}

	user->connection = c;
	kcd_user_init(user, &usid, &name, &icon, NULL, NULL);
	kcd_user_set_role(user, role);

	c->data = user;

	/* insert user into channel */
	if (kcd_channel_insert(&chan, user) == STU_ERROR) {
		kcd_close_connection(c);
		goto done;
	}

	ch = user->channel;
	c->read.handler = kcd_request_read_handler;

	if (stat && (user->role & 0xF0)) {
		stu_atomic_test_set(&ch->state, stat);
	}

	if (ch->record) {
		user->history = user->current = stu_mq_push(&ch->id, NULL, 0, kcd_cycle->conf.mode);
	}

	/* ident response */
	if (kcd_request_send_ident(c) == STU_ERROR) {
		kcd_close_connection(c);
	}

	kcd_request_send_history(c, kcd_cycle->conf.push_history);

done:

	return STU_OK;
}

static stu_int32_t
kcd_upgrade_enterprise_handler(stu_http_request_t *r) {
	stu_json_t         *jo, *jo_chan, *jo_token;
	stu_connection_t   *c, *pc;
	kcd_user_t         *user;
	stu_upstream_t     *u;
	stu_http_request_t *pr;
	stu_buf_t          *body;
	u_char              chan_s[KCD_CHANNEL_ID_MAX_LEN + 1];
	u_char              token_s[KCD_USER_TOKEN_MAX_LEN + 1];
	stu_str_t           token, chan;

	c = r->connection;

	/* copy request info before pollution */
	stu_strncpy(chan_s, r->uri.data + 1, stu_min(r->uri.len - 1, KCD_CHANNEL_ID_MAX_LEN));
	chan.data = chan_s;
	chan.len = stu_strlen(chan_s);

	stu_memzero(token_s, KCD_USER_TOKEN_MAX_LEN + 1);
	stu_str_set(&token, "");

	if (stu_http_arg(r, KCD_REQUEST_ARG_TOKEN.data, KCD_REQUEST_ARG_TOKEN.len, &token) == STU_OK) {
		stu_strncpy(token_s, token.data, stu_min(token.len, KCD_USER_TOKEN_MAX_LEN));
		token.data = token_s;
		token.len = stu_strlen(token_s);
	}

	/* set user */
	user = stu_pcalloc(c->pool, sizeof(kcd_user_t));
	if (user == NULL) {
		kcd_close_connection(c);
		return STU_ERROR;
	}

	user->connection = c;
	kcd_user_init(user, NULL, NULL, NULL, &token, &chan);
	kcd_user_set_role(user, STU_USER_ROLE_VISITOR);

	c->data = user;

	/* create ident upstream */
	if (stu_upstream_create(c, KCD_UPSTREAM_IDENT.data, KCD_UPSTREAM_IDENT.len) == STU_ERROR) {
		stu_log_error(0, "Failed to create http upstream \"%s\".", KCD_UPSTREAM_IDENT.data);
		kcd_close_connection(c);
		goto done;
	}

	c->upstream->read_event_handler = stu_http_upstream_read_handler;
	c->upstream->write_event_handler = stu_http_upstream_write_handler;

	c->upstream->create_request_pt = stu_http_upstream_create_request;
	c->upstream->reinit_request_pt = stu_http_upstream_reinit_request;
	c->upstream->generate_request_pt = stu_http_upstream_generate_request;
	c->upstream->process_response_pt = stu_http_upstream_process_response;
	c->upstream->analyze_response_pt = kcd_request_analyze_ident_upstream_response;
	c->upstream->finalize_handler_pt = kcd_request_finalize_ident_upstream_handler;
	c->upstream->cleanup_pt = stu_http_upstream_cleanup;

	/* create ident request */
	u = c->upstream;
	pc = u->peer;

	pc->request = (void *) u->create_request_pt(pc);
	if (pc->request == NULL) {
		stu_log_error(0, "Failed to create ident request.");
		u->cleanup_pt(c);
		goto done;
	}

	pr = pc->request;
	pr->uri = u->server->target;

	/* create request body */
	if (pc->buffer.start == NULL) {
		pc->buffer.start = (u_char *) stu_pcalloc(pc->pool, STU_HTTP_REQUEST_DEFAULT_SIZE);
		pc->buffer.pos = pc->buffer.last = pc->buffer.start;
		pc->buffer.end = pc->buffer.start + STU_HTTP_REQUEST_DEFAULT_SIZE;
		pc->buffer.size = STU_HTTP_REQUEST_DEFAULT_SIZE;
	}
	pc->buffer.pos = pc->buffer.last = pc->buffer.start;

	pr->request_body = (stu_http_request_body_t *) pc->buffer.last;
	pc->buffer.last += sizeof(stu_http_request_body_t);

	pr->request_body->bufs = (stu_chain_t *) pc->buffer.last;
	pc->buffer.last += sizeof(stu_chain_t);

	pr->request_body->bufs->buf = (stu_buf_t *) pc->buffer.last;
	pc->buffer.last += sizeof(stu_buf_t);

	body = pr->request_body->bufs->buf;
	body->start = body->pos = pc->buffer.last;

	/* generate request body */
	switch (u->server->method) {
	case STU_HTTP_GET:
		pc->buffer.last = stu_sprintf(pc->buffer.last, "?%s=%s&%s=%s",
			KCD_REQUEST_ARG_CHANNEL.data, chan.data, KCD_REQUEST_ARG_TOKEN.data, token.data);
		break;

	case STU_HTTP_POST:
		jo = stu_json_create_object(NULL);
		jo_chan = stu_json_create_string(&KCD_REQUEST_ARG_CHANNEL, chan.data, chan.len);
		jo_token = stu_json_create_string(&KCD_REQUEST_ARG_TOKEN, token.data, token.len);
		stu_json_add_item_to_object(jo, jo_chan);
		stu_json_add_item_to_object(jo, jo_token);

		pc->buffer.last = stu_json_stringify(jo, pc->buffer.last);
		stu_json_delete(jo);
		break;

	default:
		stu_log_error(0, "Method not supported while generating http upstream request: fd=%d, method=%hd.", c->fd, u->server->method);
		u->cleanup_pt(c);
		goto done;
	}

	body->last = body->end = pc->buffer.last;

	/* connect ident upstream */
	if (stu_upstream_connect(pc) == STU_ERROR) {
		stu_log_error(0, "Failed to connect http upstream \"%s\".", KCD_UPSTREAM_IDENT.data);
		kcd_close_connection(c);
	}

done:

	return STU_OK;
}


static stu_int32_t
kcd_request_phase_handler(stu_websocket_request_t *r) {
	stu_connection_t *c;

	c = r->connection;

	switch (r->frames_in.opcode) {
	case STU_WEBSOCKET_OPCODE_TEXT:
	case STU_WEBSOCKET_OPCODE_BINARY:
		kcd_request_analyze_protocol(r);
		break;

	case STU_WEBSOCKET_OPCODE_CLOSE:
		stu_log_debug(5, "close frame.");
		kcd_close_connection(c);
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

	return STU_OK;
}

static void
kcd_request_analyze_protocol(stu_websocket_request_t *r) {
	stu_json_t            *ji, *ji_req, *ji_cmd, *ji_data, *ji_type, *ji_chan, *ji_user, *ji_uid;
	stu_json_t            *jo, *jo_req, *jo_raw, *jo_data, *jo_type, *jo_chan, *jo_user, *jo_uid, *jo_uname, *jo_uicon, *jo_urole;
	stu_connection_t      *c, *mc;
	kcd_user_t            *user, *mate;
	kcd_channel_t         *ch;
	stu_str_t             *cmd, *mid;
	u_char                 tmp[KCD_REQUEST_DEFAULT_SIZE];
	stu_websocket_frame_t  f;
	struct timeval         tm;
	stu_int32_t            sec, req, type, n;
	stu_uint32_t           hk;
	size_t                 size;
	off_t                  off;

	c = r->connection;
	user = c->data;
	ch = user->channel;

	req = 0;
	stu_memzero(tmp, KCD_REQUEST_DEFAULT_SIZE);

	f.fin = TRUE;
	f.opcode = STU_WEBSOCKET_OPCODE_BINARY;
	f.mask = FALSE;
	f.payload_data.start = tmp;
	f.payload_data.pos = f.payload_data.last = f.payload_data.start + 10;
	f.payload_data.end = tmp + KCD_REQUEST_DEFAULT_SIZE;
	f.payload_data.size = KCD_REQUEST_DEFAULT_SIZE;

	/* parse request */
	ji = stu_json_parse(r->frames_in.payload_data.pos, r->frames_in.payload_data.size);
	if (ji == NULL || ji->type != STU_JSON_TYPE_OBJECT) {
		stu_log_error(0, "Failed to analyze kcd request: %s.", stu_http_status_text(STU_HTTP_BAD_REQUEST));
		kcd_request_send_error(r, STU_HTTP_BAD_REQUEST, req);
		return;
	}

	ji_req = stu_json_get_object_item_by(ji, &KCD_PROTOCOL_REQ);
	if (ji_req && ji_req->type == STU_JSON_TYPE_NUMBER) {
		req = *(stu_double_t *) ji_req->value;
	}

	/* check interval */
	stu_gettimeofday(&tm);
	sec = tm.tv_sec * 1000 + tm.tv_usec / 1000;

	if (user->active + user->interval > sec) {
		stu_log_error(0, "Failed to analyze kcd request: %s.", stu_http_status_text(STU_HTTP_TOO_MANY_REQUESTS));
		kcd_request_send_error(r, STU_HTTP_TOO_MANY_REQUESTS, req);
		return;
	}

	user->active = sec;

	/* analyze protocol */
	ji_cmd = stu_json_get_object_item_by(ji, &KCD_PROTOCOL_CMD);
	ji_data = stu_json_get_object_item_by(ji, &KCD_PROTOCOL_DATA);
	ji_type = stu_json_get_object_item_by(ji, &KCD_PROTOCOL_TYPE);
	ji_chan = stu_json_get_object_item_by(ji, &KCD_PROTOCOL_CHANNEL);
	if (ji_cmd == NULL || ji_cmd->type != STU_JSON_TYPE_STRING
			|| ji_data == NULL || ji_data->type != STU_JSON_TYPE_STRING
			|| ji_type == NULL || ji_type->type != STU_JSON_TYPE_NUMBER
			|| ji_chan == NULL || ji_chan->type != STU_JSON_TYPE_OBJECT) {
		stu_log_error(0, "Failed to analyze kcd request: %s.", stu_http_status_text(STU_HTTP_BAD_REQUEST));
		stu_json_delete(ji);
		kcd_request_send_error(r, STU_HTTP_BAD_REQUEST, req);
		return;
	}

	cmd = (stu_str_t *) ji_cmd->value;
	type = *(stu_double_t *) ji_type->value;

	if (stu_strncmp(cmd->data, KCD_PROTOCOL_CMD_TEXT.data, KCD_PROTOCOL_CMD_TEXT.len) == 0) {
		if (user->role < ch->state) {
			stu_log_error(0, "Failed to analyze kcd request: %s.", stu_http_status_text(STU_HTTP_FORBIDDEN));
			stu_json_delete(ji);
			kcd_request_send_error(r, STU_HTTP_FORBIDDEN, req);
			return;
		}
	} else if (stu_strncmp(cmd->data, KCD_PROTOCOL_CMD_EXTERN.data, KCD_PROTOCOL_CMD_EXTERN.len) == 0) {
		if (user->role < STU_USER_ROLE_ASSISTANT) {
			stu_log_error(0, "Failed to analyze kcd request: %s.", stu_http_status_text(STU_HTTP_FORBIDDEN));
			stu_json_delete(ji);
			kcd_request_send_error(r, STU_HTTP_FORBIDDEN, req);
			return;
		}
	} else {
		stu_log_error(0, "Failed to analyze kcd request: %s.", stu_http_status_text(STU_HTTP_METHOD_NOT_ALLOWED));
		stu_json_delete(ji);
		kcd_request_send_error(r, STU_HTTP_METHOD_NOT_ALLOWED, req);
		return;
	}

	/* genarate response */
	jo = stu_json_create_object(NULL);
	jo_raw = stu_json_create_string(&KCD_PROTOCOL_RAW, cmd->data, cmd->len);
	jo_data = stu_json_duplicate(ji_data, FALSE);
	jo_type = stu_json_duplicate(ji_type, FALSE);
	jo_chan = stu_json_duplicate(ji_chan, TRUE);
	jo_user = stu_json_create_object(&KCD_PROTOCOL_USER);

	jo_uid = stu_json_create_string(&KCD_PROTOCOL_ID, user->id.data, user->id.len);
	jo_uname = stu_json_create_string(&KCD_PROTOCOL_NAME, user->name.data, user->name.len);
	jo_uicon = stu_json_create_string(&KCD_PROTOCOL_ICON, user->icon.data, user->icon.len);
	jo_urole = stu_json_create_number(&KCD_PROTOCOL_ROLE, (stu_double_t) user->role);

	stu_json_add_item_to_object(jo_user, jo_uid);
	stu_json_add_item_to_object(jo_user, jo_uname);
	stu_json_add_item_to_object(jo_user, jo_uicon);
	stu_json_add_item_to_object(jo_user, jo_urole);

	if (ji_req) {
		jo_req = stu_json_duplicate(ji_req, FALSE);
		stu_json_add_item_to_object(jo, jo_req);
	}
	stu_json_add_item_to_object(jo, jo_raw);
	stu_json_add_item_to_object(jo, jo_data);
	stu_json_add_item_to_object(jo, jo_type);
	stu_json_add_item_to_object(jo, jo_chan);
	stu_json_add_item_to_object(jo, jo_user);

	f.payload_data.last = stu_json_stringify(jo, (u_char *) f.payload_data.pos);

	/* handle message */
	switch (type) {
	case KCD_PROTOCOL_UNI:
		ji_user = stu_json_get_object_item_by(ji, &KCD_PROTOCOL_USER);
		if (ji_user == NULL || ji_user->type != STU_JSON_TYPE_OBJECT) {
			stu_log_error(0, "Failed to analyze kcd request: %s.", stu_http_status_text(STU_HTTP_BAD_REQUEST));
			kcd_request_send_error(r, STU_HTTP_BAD_REQUEST, req);
			goto failed;
		}

		ji_uid = stu_json_get_object_item_by(ji_user, &KCD_PROTOCOL_ID);
		if (ji_uid == NULL || ji_uid->type != STU_JSON_TYPE_STRING) {
			stu_log_error(0, "Failed to analyze kcd request: %s.", stu_http_status_text(STU_HTTP_BAD_REQUEST));
			kcd_request_send_error(r, STU_HTTP_BAD_REQUEST, req);
			goto failed;
		}

		stu_mutex_lock(&ch->userlist.lock);

		mid = (stu_str_t *) ji_uid->value;
		hk = stu_hash_key(mid->data, mid->len, ch->userlist.flags);

		mate = stu_hash_find_locked(&ch->userlist, hk, mid->data, mid->len);
		if (mate == NULL) {
			kcd_request_send_error(r, STU_HTTP_NOT_FOUND, req);
		} else {
			f.payload_data.last = stu_websocket_encode_frame(&f, f.payload_data.start);
			size = f.payload_data.last - f.payload_data.start;

			n = send(c->fd, f.payload_data.start, size, 0);
			if (n == -1) {
				//stu_log_error(stu_errno, "Failed to send uni message to \"%s\": , fd=%d.", user->id.data, c->fd);
			}

			mc = mate->connection;
			if (mc == c) {
				goto uni_done;
			}

			n = send(mc->fd, f.payload_data.start, size, 0);
			if (n == -1) {
				//stu_log_error(stu_errno, "Failed to send uni message to \"%s\": , fd=%d.", mate->id.data, mc->fd);
			}
		}

uni_done:

		stu_mutex_unlock(&ch->userlist.lock);
		break;

	case KCD_PROTOCOL_MULTI:
		size = f.payload_data.last - f.payload_data.pos;

		if (ch->record) {
			off = stu_mq_push(&ch->id, f.payload_data.pos, size, kcd_cycle->conf.mode);
		}

		stu_mutex_lock(&ch->userlist.lock);
		kcd_channel_broadcast(ch, f.payload_data.pos, size, off);
		stu_mutex_unlock(&ch->userlist.lock);
		break;

	case KCD_PROTOCOL_HISTORY:
		kcd_request_send_history(c, kcd_cycle->conf.push_history);
		break;

	default:
		break;
	}

failed:

	stu_json_delete(ji);
	stu_json_delete(jo);
}

static void
kcd_request_send_error(stu_websocket_request_t *r, stu_int32_t err, stu_double_t req) {
	stu_json_t            *jo, *jo_req, *jo_raw, *jo_err, *jo_code;
	stu_connection_t      *c;
	u_char                 tmp[KCD_REQUEST_DEFAULT_SIZE];
	stu_websocket_frame_t  f;
	stu_int32_t            n;

	c = r->connection;

	stu_memzero(tmp, KCD_REQUEST_DEFAULT_SIZE);

	f.fin = TRUE;
	f.opcode = STU_WEBSOCKET_OPCODE_BINARY;
	f.mask = FALSE;
	f.payload_data.start = tmp;
	f.payload_data.pos = f.payload_data.last = f.payload_data.start + 10;
	f.payload_data.end = tmp + KCD_REQUEST_DEFAULT_SIZE;
	f.payload_data.size = KCD_REQUEST_DEFAULT_SIZE;

	/* genarate frame data */
	jo = stu_json_create_object(NULL);

	jo_raw = stu_json_create_string(&KCD_PROTOCOL_RAW, KCD_PROTOCOL_RAW_ERROR.data, KCD_PROTOCOL_RAW_ERROR.len);
	jo_err = stu_json_create_object(&KCD_PROTOCOL_ERROR);

	jo_code = stu_json_create_number(&KCD_PROTOCOL_CODE, (stu_double_t) err);
	stu_json_add_item_to_object(jo_err, jo_code);

	if (req) {
		jo_req = stu_json_create_number(&KCD_PROTOCOL_REQ, req);
		stu_json_add_item_to_object(jo, jo_req);
	}
	stu_json_add_item_to_object(jo, jo_raw);
	stu_json_add_item_to_object(jo, jo_err);

	f.payload_data.last = stu_json_stringify(jo, (u_char *) f.payload_data.last);
	f.payload_data.last = stu_websocket_encode_frame(&f, f.payload_data.start);
	f.payload_data.pos = f.payload_data.start;

	stu_json_delete(jo);

	/* send frame */
	n = send(c->fd, f.payload_data.pos, f.payload_data.last - f.payload_data.pos, 0);
	if (n == -1) {
		stu_log_error(stu_errno, "Failed to send kcd error: fd=%d.", c->fd);
		return;
	}

	stu_log_debug(5, "sent kcd error frame: fd=%d, err=%d.", c->fd, err);
}

static stu_int32_t
kcd_request_send_ident(stu_connection_t *c) {
	kcd_user_t            *user;
	kcd_channel_t         *ch;
	u_char                 tmp[KCD_REQUEST_DEFAULT_SIZE];
	stu_websocket_frame_t  f;
	stu_int32_t            n;

	user = c->data;
	ch = user->channel;

	stu_memzero(tmp, KCD_REQUEST_DEFAULT_SIZE);

	f.fin = TRUE;
	f.opcode = STU_WEBSOCKET_OPCODE_BINARY;
	f.mask = FALSE;
	f.payload_data.start = tmp;
	f.payload_data.pos = f.payload_data.last = f.payload_data.start + 10;
	f.payload_data.end = tmp + KCD_REQUEST_DEFAULT_SIZE;
	f.payload_data.size = KCD_REQUEST_DEFAULT_SIZE;

	f.payload_data.last = stu_sprintf(f.payload_data.last, (const char *) KCD_REQUEST_IDENT_RESPONSE.data,
		user->id.data, user->name.data, user->icon.data, user->role, ch->id.data, ch->state, ch->userlist.length);

	f.payload_data.last = stu_websocket_encode_frame(&f, f.payload_data.start);
	f.payload_data.pos = f.payload_data.start;

	/* send frame */
	n = send(c->fd, f.payload_data.pos, f.payload_data.last - f.payload_data.pos, 0);
	if (n == -1) {
		stu_log_error(stu_errno, "Failed to send kcd ident: fd=%d, id=\"%s\", ch=\"%s\".", c->fd, user->id.data, ch->id.data);
		return STU_ERROR;
	}

	stu_log_debug(5, "sent kcd ident frame: fd=%d, id=\"%s\", ch=\"%s\".", c->fd, user->id.data, ch->id.data);

	return STU_OK;
}

static stu_int32_t
kcd_request_send_history(stu_connection_t *c, stu_int32_t n) {
	stu_json_t            *ji, *ji_type;
	kcd_user_t            *user;
	kcd_channel_t         *ch;
	u_char                 tmp[KCD_REQUEST_DEFAULT_SIZE];
	stu_websocket_frame_t  f;
	stu_int32_t            v;
	size_t                 size;
	off_t                  off;

	user = c->data;
	ch = user->channel;
	off = user->history;

	stu_memzero(tmp, KCD_REQUEST_DEFAULT_SIZE);

	f.fin = TRUE;
	f.opcode = STU_WEBSOCKET_OPCODE_BINARY;
	f.mask = FALSE;
	f.payload_data.start = tmp;
	f.payload_data.pos = f.payload_data.last = f.payload_data.start + 10;
	f.payload_data.end = tmp + KCD_REQUEST_DEFAULT_SIZE;
	f.payload_data.size = KCD_REQUEST_DEFAULT_SIZE;

	for (/* void */; n > 0; n--) {
		f.payload_data.last = stu_mq_read(&ch->id, f.payload_data.pos, &off, TRUE);

		size = f.payload_data.last - f.payload_data.pos;
		if (size == 0) {
			break;
		}

		ji = stu_json_parse(f.payload_data.pos, size);
		if (ji == NULL || ji->type != STU_JSON_TYPE_OBJECT) {
			stu_log_error(0, "Bad kcd history message: %s.", f.payload_data.pos);
			return STU_ERROR;
		}

		ji_type = stu_json_get_object_item_by(ji, &KCD_PROTOCOL_TYPE);
		if (ji_type == NULL || ji_type->type != STU_JSON_TYPE_NUMBER) {
			stu_log_error(0, "Bad kcd history message format: %s.", f.payload_data.pos);
			return STU_ERROR;
		}

		*(stu_double_t *) ji_type->value = KCD_PROTOCOL_HISTORY;

		f.payload_data.last = stu_json_stringify(ji, f.payload_data.pos);
		f.payload_data.last = stu_websocket_encode_frame(&f, f.payload_data.start);

		size = f.payload_data.last - f.payload_data.start;

		v = send(c->fd, f.payload_data.start, size, 0);
		if (v == -1) {
			//stu_log_error(stu_errno, "Failed to send cache: fd=%d.", fd);
			break;
		}

		user->history = off;
	}

	return STU_OK;
}


void
kcd_request_read_handler(stu_event_t *ev) {
	stu_connection_t *c;
	stu_int32_t       n, err;

	c = (stu_connection_t *) ev->data;

	//stu_mutex_lock(&c->lock);

	if (c->buffer.start == NULL) {
		c->buffer.start = (u_char *) stu_pcalloc(c->pool, KCD_REQUEST_DEFAULT_SIZE);
		c->buffer.pos = c->buffer.last = c->buffer.start;
		c->buffer.end = c->buffer.start + KCD_REQUEST_DEFAULT_SIZE;
		c->buffer.size = KCD_REQUEST_DEFAULT_SIZE;
	}
	c->buffer.pos = c->buffer.last = c->buffer.start;
	stu_memzero(c->buffer.start, c->buffer.size);

again:

	n = recv(c->fd, c->buffer.last, c->buffer.size, 0);
	if (n == -1) {
		err = stu_errno;
		if (err == EINTR) {
			stu_log_debug(3, "recv trying again: fd=%d, errno=%d.", c->fd, err);
			goto again;
		}

		if (err == EAGAIN) {
			stu_log_debug(3, "no data received: fd=%d, errno=%d.", c->fd, err);
			goto done;
		}

		stu_log_error(err, "Failed to recv data: fd=%d.", c->fd);
		goto failed;
	}

	if (n == 0) {
		stu_log_debug(5, "remote client has closed connection: fd=%d.", c->fd);
		goto failed;
	}

	c->buffer.last += n;
	stu_log_debug(4, "recv: fd=%d, bytes=%d.", c->fd, n);

	c->request = (void *) stu_websocket_create_request(c);
	if (c->request == NULL) {
		stu_log_error(0, "Failed to create websocket request.");
		goto failed;
	}

	//ev->handler = stu_websocket_process_request_frames;
	stu_websocket_process_request_frames(ev);

	goto done;

failed:

	kcd_close_connection(c);

done:

	stu_log_debug(4, "kcd request done.");

	//stu_mutex_unlock(&c->lock);
}

static stu_int32_t
kcd_request_analyze_ident_upstream_response(stu_connection_t *pc) {
	stu_json_t         *ji, *ji_status, *ji_chan, *ji_cid, *ji_state;
	stu_json_t         *ji_user, *ji_uid, *ji_uname, *ji_uicon, *ji_urole;
	stu_http_request_t *pr;
	stu_upstream_t     *u;
	stu_connection_t   *c;
	kcd_user_t         *user;
	stu_str_t          *cid;
	stu_int32_t         rc;

	pr = pc->request;
	u = pc->upstream;
	c = u->connection;
	user = c->data;

	rc = STU_ERROR;

	if (pr->headers_out.status != STU_HTTP_OK) {
		stu_log_error(0, "Failed to load ident data: %d - %s.", pr->headers_out.status, stu_http_status_text(pr->headers_out.status));
		return STU_ERROR;
	}

	/* parse response */
	stu_utf8_decode(&pc->buffer.pos, pr->headers_in.content_length_n);

	ji = stu_json_parse(pc->buffer.pos, pr->headers_in.content_length_n);
	if (ji == NULL || ji->type != STU_JSON_TYPE_OBJECT) {
		stu_log_error(0, "Failed to parse ident response.");
		return STU_ERROR;
	}

	ji_status = stu_json_get_object_item_by(ji, &KCD_PROTOCOL_STATUS);
	if (ji_status == NULL || ji_status->type != STU_JSON_TYPE_BOOLEAN) {
		stu_log_error(0, "Failed to analyze ident response: Bad format.");
		goto failed;
	}

	if (ji_status->value == FALSE) {
		stu_log_error(0, "Access denied: token=%s, ch=%s.", user->token.data, user->chan.data);
		goto failed;
	}

	ji_chan = stu_json_get_object_item_by(ji, &KCD_PROTOCOL_CHANNEL);
	ji_user = stu_json_get_object_item_by(ji, &KCD_PROTOCOL_USER);
	if (ji_chan == NULL || ji_chan->type != STU_JSON_TYPE_OBJECT
			|| ji_user == NULL || ji_user->type != STU_JSON_TYPE_OBJECT) {
		stu_log_error(0, "Failed to analyze ident response: Bad format.");
		goto failed;
	}

	ji_cid = stu_json_get_object_item_by(ji_chan, &KCD_PROTOCOL_ID);
	ji_state = stu_json_get_object_item_by(ji_chan, &KCD_PROTOCOL_STATE);

	ji_uid = stu_json_get_object_item_by(ji_user, &KCD_PROTOCOL_ID);
	ji_uname = stu_json_get_object_item_by(ji_user, &KCD_PROTOCOL_NAME);
	ji_uicon = stu_json_get_object_item_by(ji_user, &KCD_PROTOCOL_ICON);
	ji_urole = stu_json_get_object_item_by(ji_user, &KCD_PROTOCOL_ROLE);

	if (ji_cid == NULL || ji_cid->type != STU_JSON_TYPE_STRING
			|| ji_state == NULL || ji_state->type != STU_JSON_TYPE_NUMBER
			|| ji_uid == NULL || ji_uid->type != STU_JSON_TYPE_STRING
			|| ji_uname == NULL || ji_uname->type != STU_JSON_TYPE_STRING
			|| ji_uicon == NULL || ji_uicon->type != STU_JSON_TYPE_STRING
			|| ji_urole == NULL || ji_urole->type != STU_JSON_TYPE_NUMBER) {
		stu_log_error(0, "Failed to analyze ident response: Bad format.");
		goto failed;
	}

	/* get channel id */
	cid = (stu_str_t *) ji_cid->value;
	if (stu_strncmp(user->chan.data, cid->data, cid->len) != 0) {
		stu_log_error(0, "Failed to analyze ident response: channel id not match.");
		goto failed;
	}

	/* reset user info */
	kcd_user_init(user, (stu_str_t *) ji_uid->value, (stu_str_t *) ji_uname->value, (stu_str_t *) ji_uicon->value, NULL, NULL);
	kcd_user_set_role(user, *(stu_double_t *) ji_urole->value);

	/* insert user into channel */
	if (kcd_channel_insert(&user->chan, user) == STU_ERROR) {
		goto failed;
	}

	c->read.handler = kcd_request_read_handler;

	/* ident response */
	if (kcd_request_send_ident(c) == STU_ERROR) {
		goto failed;
	}

	kcd_request_send_history(c, kcd_cycle->conf.push_history);

	rc = STU_OK;

failed:

	stu_json_delete(ji);

	u->cleanup_pt(c);

	return rc;
}

static void
kcd_request_finalize_ident_upstream_handler(stu_connection_t *c, stu_int32_t rc) {

	stu_log_debug(5, "finalize kcd ident upstream: %d.", rc);

	if (rc == STU_DONE || rc == STU_ERROR
			|| c->timedout || c->close || c->error || c->destroyed) {
		kcd_close_connection(c);
		return;
	}

	if (rc == STU_HTTP_CREATED || rc == STU_HTTP_NO_CONTENT || rc >= STU_HTTP_MULTIPLE_CHOICES) {
		// TODO: empty handler
		//c->read.handler = stu_http_request_write_handler;
		//c->write.handler = stu_http_request_write_handler;
		kcd_close_connection(c);
	}

	c->upstream->cleanup_pt(c);
}


void
kcd_free_request(stu_websocket_request_t *r) {
	stu_websocket_free_request(r);
}

void
kcd_close_request(stu_websocket_request_t *r) {
	stu_connection_t *c;

	c = r->connection;

	kcd_free_request(r);
	kcd_close_connection(c);
}

void
kcd_close_connection(stu_connection_t *c) {
	kcd_user_t *user;

	user = c->data;

	if (user && user->channel) {
		kcd_channel_remove(user->channel, user);
	}

	stu_websocket_close_connection(c);
}

