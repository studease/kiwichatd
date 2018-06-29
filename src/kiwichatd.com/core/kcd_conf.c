/*
 * kcd_conf.c
 *
 *  Created on: 2017年11月17日
 *      Author: Tony Lau
 */

#include "kcd_core.h"

stu_str_t         KCD_CONF_DEFAULT_PATH = stu_string("conf/chatd.conf");

extern stu_str_t  KCD_LICENSE_SERVERS;

extern stu_uint8_t                STU_DEBUG;
extern stu_hash_t                 stu_upstreams;
extern stu_str_t                  stu_http_root;
extern stu_http_method_bitmask_t  stu_http_upstream_method_mask[];

static kcd_mode_mask_t  kcd_mode_mask[] = {
	{ stu_string("smooth"), STU_MQ_MODE_SMOOTH },
	{ stu_string("strict"), STU_MQ_MODE_STRICT },
	{ stu_null_string, 0x00 }
};

static stu_str_t  KCD_CONF_DEFAULT_PID     = stu_string("chatd.pid");
static stu_str_t  KCD_CONF_DEFAULT_RECORDS = stu_string("histories/%s.kcm");

static stu_str_t  KCD_CONF_LOG = stu_string("log");
static stu_str_t  KCD_CONF_PID = stu_string("pid");

static stu_str_t  KCD_CONF_LICENSE = stu_string("license");
static stu_str_t  KCD_CONF_MODE    = stu_string("mode");

static stu_str_t  KCD_CONF_MASTER_PROCESS   = stu_string("master_process");
static stu_str_t  KCD_CONF_WORKER_PROCESSES = stu_string("worker_processes");
static stu_str_t  KCD_CONF_WORKER_THREADS   = stu_string("worker_threads");
static stu_str_t  KCD_CONF_DEBUG            = stu_string("debug");

static stu_str_t  KCD_CONF_SERVER                    = stu_string("server");
static stu_str_t  KCD_CONF_SERVER_LISTEN             = stu_string("listen");
static stu_str_t  KCD_CONF_SERVER_ROOT               = stu_string("root");
static stu_str_t  KCD_CONF_SERVER_CORS               = stu_string("cors");
static stu_str_t  KCD_CONF_SERVER_PUSH_HISTORY       = stu_string("push_history");
static stu_str_t  KCD_CONF_SERVER_HISTORY_PATH       = stu_string("history_path");
static stu_str_t  KCD_CONF_SERVER_PUSH_USER          = stu_string("push_user");
static stu_str_t  KCD_CONF_SERVER_PUSH_USER_INTERVAL = stu_string("push_user_interval");
static stu_str_t  KCD_CONF_SERVER_PUSH_STAT          = stu_string("push_stat");
static stu_str_t  KCD_CONF_SERVER_PUSH_STAT_INTERVAL = stu_string("push_stat_interval");

static stu_str_t  KCD_CONF_IDENT              = stu_string("ident");
static stu_str_t  KCD_CONF_STATS              = stu_string("stats");
static stu_str_t  KCD_CONF_CHECK              = stu_string("check");
static stu_str_t  KCD_CONF_UPSTREAM_PROTOCOL  = stu_string("protocol");
static stu_str_t  KCD_CONF_UPSTREAM_METHOD    = stu_string("method");
static stu_str_t  KCD_CONF_UPSTREAM_TARGET    = stu_string("target");
static stu_str_t  KCD_CONF_UPSTREAM_ADDRESS   = stu_string("address");
static stu_str_t  KCD_CONF_UPSTREAM_PORT      = stu_string("port");
static stu_str_t  KCD_CONF_UPSTREAM_WEIGHT    = stu_string("weight");
static stu_str_t  KCD_CONF_UPSTREAM_TIMEOUT   = stu_string("timeout");
static stu_str_t  KCD_CONF_UPSTREAM_MAX_FAILS = stu_string("max_fails");

static stu_int32_t  kcd_conf_get_default(kcd_conf_t *conf);
static stu_int32_t  kcd_conf_copy_upstream_servers(stu_list_t *list, stu_str_t *name, stu_json_t *item);


stu_int32_t
kcd_conf_parse_file(kcd_conf_t *conf, u_char *name) {
	stu_json_t         *root, *item, *sub;
	stu_str_t          *v_string;
	stu_double_t       *v_double;
	kcd_mode_mask_t    *m;
	u_char              tmp[KCD_CONF_MAX_SIZE];
	stu_file_t          file;
	stu_int32_t         rc;

	rc = STU_ERROR;
	stu_memzero(&file, sizeof(stu_file_t));
	stu_memzero(tmp, KCD_CONF_MAX_SIZE);

	if (kcd_conf_get_default(conf) == STU_ERROR) {
		stu_log_error(0, "Failed to get default conf.");
		return STU_ERROR;
	}

	// read conf file
	file.fd = stu_file_open(name, STU_FILE_CREATE_OR_OPEN, STU_FILE_RDONLY, STU_FILE_DEFAULT_ACCESS);
	if (file.fd == STU_FILE_INVALID) {
		stu_log_error(stu_errno, "Failed to " stu_file_open_n " conf file \"%s\".", name);
		return STU_ERROR;
	}

	if (stu_file_read(&file, tmp, KCD_CONF_MAX_SIZE, 0) == STU_ERROR) {
		stu_log_error(stu_errno, "Failed to " stu_file_read_n " conf file \"%s\".", name);
		stu_file_close(file.fd);
		return STU_ERROR;
	}

	if (file.offset > KCD_CONF_MAX_SIZE) {
		stu_log_error(0, "conf file too large: %d.", file.offset);
		stu_file_close(file.fd);
		return STU_ERROR;
	}

	// parse conf file
	root = stu_json_parse((u_char *) tmp, file.offset);
	if (root == NULL || root->type != STU_JSON_TYPE_OBJECT) {
		stu_log_error(0, "Bad conf file format.");
		stu_file_close(file.fd);
		return STU_ERROR;
	}

	// log
	item = stu_json_get_object_item_by(root, &KCD_CONF_LOG);
	if (item && item->type == STU_JSON_TYPE_STRING) {
		/* use default */
	}

	// pid
	item = stu_json_get_object_item_by(root, &KCD_CONF_PID);
	if (item && item->type == STU_JSON_TYPE_STRING) {
		v_string = (stu_str_t *) item->value;

		conf->pid.name.data = stu_calloc(v_string->len + 1);
		if (conf->pid.name.data == NULL) {
			stu_log_error(0, "Failed to calloc pid name.");
			goto failed;
		}

		stu_strncpy(conf->pid.name.data, v_string->data, v_string->len);
		conf->pid.name.len = v_string->len;
	}

	// license
	item = stu_json_get_object_item_by(root, &KCD_CONF_LICENSE);
	if (item && item->type == STU_JSON_TYPE_STRING) {
		v_string = (stu_str_t *) item->value;

		conf->license.data = stu_calloc(v_string->len + 1);
		if (conf->license.data == NULL) {
			stu_log_error(0, "Failed to calloc license data.");
			goto failed;
		}

		stu_strncpy(conf->license.data, v_string->data, v_string->len);
		conf->license.len = v_string->len;
	}

	// mode
	item = stu_json_get_object_item_by(root, &KCD_CONF_MODE);
	if (item && item->type == STU_JSON_TYPE_STRING) {
		v_string = (stu_str_t *) item->value;

		for (m = kcd_mode_mask; m->name.len; m++) {
			if (stu_strncasecmp(v_string->data, m->name.data, m->name.len) == 0) {
				conf->mode = m->mask;
				break;
			}
		}
	}

	// master_process
	item = stu_json_get_object_item_by(root, &KCD_CONF_MASTER_PROCESS);
	if (item && item->type == STU_JSON_TYPE_BOOLEAN) {
		conf->master_process = item->value & TRUE;
	}

	// worker_processes
	item = stu_json_get_object_item_by(root, &KCD_CONF_WORKER_PROCESSES);
	if (item && item->type == STU_JSON_TYPE_NUMBER) {
		v_double = (stu_double_t *) item->value;
		conf->worker_processes = *v_double;
	}

	// worker_threads
	item = stu_json_get_object_item_by(root, &KCD_CONF_WORKER_THREADS);
	if (item && item->type == STU_JSON_TYPE_NUMBER) {
		v_double = (stu_double_t *) item->value;
		conf->worker_threads = *v_double;
	}

	// debug
	item = stu_json_get_object_item_by(root, &KCD_CONF_DEBUG);
	if (item && item->type == STU_JSON_TYPE_NUMBER) {
		v_double = (stu_double_t *) item->value;
		conf->debug = *v_double;

		STU_DEBUG = conf->debug;
	}

	// server
	item = stu_json_get_object_item_by(root, &KCD_CONF_SERVER);
	if (item && item->type == STU_JSON_TYPE_OBJECT) {
		// listen
		sub = stu_json_get_object_item_by(item, &KCD_CONF_SERVER_LISTEN);
		if (sub && sub->type == STU_JSON_TYPE_NUMBER) {
			v_double = (stu_double_t *) sub->value;
			conf->port = (stu_uint64_t) *v_double;
		}

		// root
		sub = stu_json_get_object_item_by(item, &KCD_CONF_SERVER_ROOT);
		if (sub && sub->type == STU_JSON_TYPE_STRING) {
			v_string = (stu_str_t *) sub->value;

			conf->root.data = stu_calloc(v_string->len + 1);
			if (conf->root.data == NULL) {
				stu_log_error(0, "Failed to calloc cors data.");
				goto failed;
			}

			stu_strncpy(conf->root.data, v_string->data, v_string->len);
			conf->root.len = v_string->len;
		}

		// cors
		sub = stu_json_get_object_item_by(item, &KCD_CONF_SERVER_CORS);
		if (sub && sub->type == STU_JSON_TYPE_STRING) {
			v_string = (stu_str_t *) sub->value;

			conf->cors.data = stu_calloc(v_string->len + 1);
			if (conf->cors.data == NULL) {
				stu_log_error(0, "Failed to calloc cors data.");
				goto failed;
			}

			stu_strncpy(conf->cors.data, v_string->data, v_string->len);
			conf->cors.len = v_string->len;
		}

		// push_history
		sub = stu_json_get_object_item_by(item, &KCD_CONF_SERVER_PUSH_HISTORY);
		if (sub && sub->type == STU_JSON_TYPE_NUMBER) {
			v_double = (stu_double_t *) sub->value;
			conf->push_history = *v_double;
		}

		// history_path
		sub = stu_json_get_object_item_by(item, &KCD_CONF_SERVER_HISTORY_PATH);
		if (sub && sub->type == STU_JSON_TYPE_STRING) {
			v_string = (stu_str_t *) sub->value;

			conf->history_path.data = stu_calloc(v_string->len + 1);
			if (conf->history_path.data == NULL) {
				stu_log_error(0, "Failed to calloc history path data.");
				goto failed;
			}

			stu_strncpy(conf->history_path.data, v_string->data, v_string->len);
			conf->history_path.len = v_string->len;
		}

		// push_user
		sub = stu_json_get_object_item_by(item, &KCD_CONF_SERVER_PUSH_USER);
		if (sub && sub->type == STU_JSON_TYPE_BOOLEAN) {
			conf->push_user = sub->value & TRUE;
		}

		// push_user_interval
		sub = stu_json_get_object_item_by(item, &KCD_CONF_SERVER_PUSH_USER_INTERVAL);
		if (sub && sub->type == STU_JSON_TYPE_NUMBER) {
			v_double = (stu_double_t *) sub->value;
			conf->push_user_interval = *v_double * 1000;
		}

		// push_stat
		sub = stu_json_get_object_item_by(item, &KCD_CONF_SERVER_PUSH_STAT);
		if (sub && sub->type == STU_JSON_TYPE_BOOLEAN) {
			conf->push_stat = sub->value & TRUE;
		}

		// push_stat_interval
		sub = stu_json_get_object_item_by(item, &KCD_CONF_SERVER_PUSH_STAT_INTERVAL);
		if (sub && sub->type == STU_JSON_TYPE_NUMBER) {
			v_double = (stu_double_t *) sub->value;
			conf->push_stat_interval = *v_double * 1000;
		}
	}

	// ident
	item = stu_json_get_object_item_by(root, &KCD_CONF_IDENT);
	if (item && item->type == STU_JSON_TYPE_ARRAY) {
		if (kcd_conf_copy_upstream_servers(&conf->ident, &KCD_CONF_IDENT, item) == STU_ERROR) {
			stu_log_error(0, "Failed to copy upstream server list: name=\"%s\".", KCD_CONF_IDENT.data);
			goto failed;
		}
	}

	// stats
	item = stu_json_get_object_item_by(root, &KCD_CONF_STATS);
	if (item && item->type == STU_JSON_TYPE_ARRAY) {
		if (kcd_conf_copy_upstream_servers(&conf->stats, &KCD_CONF_STATS, item) == STU_ERROR) {
			stu_log_error(0, "Failed to copy upstream server list: name=\"%s\".", KCD_CONF_STATS.data);
			goto failed;
		}
	}

	// check
	item = stu_json_parse(KCD_LICENSE_SERVERS.data, KCD_LICENSE_SERVERS.len);
	if (item && item->type == STU_JSON_TYPE_ARRAY) {
		if (kcd_conf_copy_upstream_servers(&conf->check, &KCD_CONF_CHECK, item) == STU_ERROR) {
			stu_log_error(0, "Failed to copy upstream server list: name=\"%s\".", KCD_CONF_CHECK.data);
			goto failed;
		}
	}

	rc = STU_OK;

failed:

	stu_file_close(file.fd);
	stu_json_delete(root);

	return rc;
}

static stu_int32_t
kcd_conf_copy_upstream_servers(stu_list_t *list, stu_str_t *name, stu_json_t *item) {
	stu_json_t                *sub, *property;
	stu_str_t                 *v_string;
	stu_double_t              *v_double;
	stu_upstream_server_t     *server;
	stu_http_method_bitmask_t *method;

	for (sub = (stu_json_t *) item->value; sub; sub = sub->next) {
		if (sub->type != STU_JSON_TYPE_OBJECT) {
			continue;
		}

		server = stu_calloc(sizeof(stu_upstream_server_t));
		if (server == NULL) {
			stu_log_error(0, "Failed to calloc upstream server.");
			return STU_ERROR;
		}

		server->name = *name;
		server->method = STU_HTTP_GET;

		// protocol
		property = stu_json_get_object_item_by(sub, &KCD_CONF_UPSTREAM_PROTOCOL);
		if (property && property->type == STU_JSON_TYPE_STRING) {
			v_string = (stu_str_t *) property->value;

			server->protocol.data = stu_calloc(v_string->len + 1);
			if (server->protocol.data == NULL) {
				stu_log_error(0, "Failed to calloc upstream server protocol.");
				return STU_ERROR;
			}

			stu_strncpy(server->protocol.data, v_string->data, v_string->len);
			server->protocol.len = v_string->len;
		}

		// method
		property = stu_json_get_object_item_by(sub, &KCD_CONF_UPSTREAM_METHOD);
		if (property && property->type == STU_JSON_TYPE_STRING) {
			v_string = (stu_str_t *) property->value;

			for (method = stu_http_upstream_method_mask; method->name.len; method++) {
				if (stu_strncasecmp(v_string->data, method->name.data, method->name.len) == 0) {
					server->method = method->mask;
					break;
				}
			}
		}

		// target
		property = stu_json_get_object_item_by(sub, &KCD_CONF_UPSTREAM_TARGET);
		if (property && property->type == STU_JSON_TYPE_STRING) {
			v_string = (stu_str_t *) property->value;
			server->target.data = stu_calloc(v_string->len + 1);
			server->target.len = v_string->len;
			stu_strncpy(server->target.data, v_string->data, v_string->len);
		}

		// address
		property = stu_json_get_object_item_by(sub, &KCD_CONF_UPSTREAM_ADDRESS);
		if (property && property->type == STU_JSON_TYPE_STRING) {
			v_string = (stu_str_t *) property->value;

			server->addr.name.data = stu_calloc(v_string->len + 1);
			if (server->addr.name.data == NULL) {
				stu_log_error(0, "Failed to calloc upstream server address.");
				return STU_ERROR;
			}

			stu_strncpy(server->addr.name.data, v_string->data, v_string->len);
			server->addr.name.len = v_string->len;
		}

		// port
		property = stu_json_get_object_item_by(sub, &KCD_CONF_UPSTREAM_PORT);
		if (property && property->type == STU_JSON_TYPE_NUMBER) {
			v_double = (stu_double_t *) property->value;
			server->port = *v_double;
		}

		// weight
		property = stu_json_get_object_item_by(sub, &KCD_CONF_UPSTREAM_WEIGHT);
		if (property && property->type == STU_JSON_TYPE_NUMBER) {
			v_double = (stu_double_t *) property->value;
			server->weight = *v_double;
		}

		// timeout
		property = stu_json_get_object_item_by(sub, &KCD_CONF_UPSTREAM_TIMEOUT);
		if (property && property->type == STU_JSON_TYPE_NUMBER) {
			v_double = (stu_double_t *) property->value;
			server->timeout = *v_double;
		}

		// max_fails
		property = stu_json_get_object_item_by(sub, &KCD_CONF_UPSTREAM_MAX_FAILS);
		if (property && property->type == STU_JSON_TYPE_NUMBER) {
			v_double = (stu_double_t *) property->value;
			server->max_fails = *v_double;
		}

		server->addr.sockaddr.sin_family = AF_INET;
		server->addr.sockaddr.sin_addr.s_addr = inet_addr((const char *) server->addr.name.data);
		server->addr.sockaddr.sin_port = htons(server->port);
		bzero(&(server->addr.sockaddr.sin_zero), 8);
		server->addr.socklen = sizeof(struct sockaddr);

		stu_list_insert_tail(list, server);
	}

	return STU_OK;
}

static stu_int32_t
kcd_conf_get_default(kcd_conf_t *conf) {
	struct timeval  tv;
	stu_tm_t        tm;

	// log
	stu_gettimeofday(&tv);
	stu_localtime(tv.tv_sec, &tm);

	conf->log.name.data = stu_calloc(STU_MAX_PATH);
	if (conf->log.name.data == NULL) {
		stu_log_error(0, "Failed to calloc log file name.");
		return STU_ERROR;
	}

	stu_sprintf(conf->log.name.data, "logs/%4d-%02d-%02d %02d:%02d:%02d.log",
			tm.stu_tm_year, tm.stu_tm_mon, tm.stu_tm_mday,
			tm.stu_tm_hour, tm.stu_tm_min, tm.stu_tm_sec);
	conf->log.name.len = stu_strlen(conf->log.name.data);

	// pid
	conf->pid.name = KCD_CONF_DEFAULT_PID;

	// edition
	conf->edition = PREVIEW;

	// worker
	conf->master_process = TRUE;
	conf->worker_processes = 1;
	conf->worker_threads = 4;

	// server
	conf->port = 80;
	conf->root = stu_http_root;
	stu_str_null(&conf->cors);

	conf->push_history = 0;
	conf->history_path = KCD_CONF_DEFAULT_RECORDS;

	conf->push_user = TRUE;
	conf->push_user_interval = KCD_CHANNEL_PUSH_USER_DEFAULT_INTERVAL * 1000;

	conf->push_stat = FALSE;
	conf->push_stat_interval = KCD_CHANNEL_PUSH_STAT_DEFAULT_INTERVAL * 1000;

	// upstream
	stu_list_init(&conf->ident, NULL);
	stu_list_init(&conf->stats, NULL);
	stu_list_init(&conf->check, NULL);

	if (stu_upstream_init_hash() == STU_ERROR) {
		return STU_ERROR;
	}

	if (stu_hash_insert(&stu_upstreams, &KCD_CONF_IDENT, &conf->ident) == STU_ERROR) {
		stu_log_error(0, "Failed to insert upstream list into hash, name=\"%d\".", KCD_CONF_IDENT.data);
		return STU_ERROR;
	}

	if (stu_hash_insert(&stu_upstreams, &KCD_CONF_STATS, &conf->stats) == STU_ERROR) {
		stu_log_error(0, "Failed to insert upstream list into hash, name=\"%d\".", KCD_CONF_STATS.data);
		return STU_ERROR;
	}

	if (stu_hash_insert(&stu_upstreams, &KCD_CONF_CHECK, &conf->check) == STU_ERROR) {
		stu_log_error(0, "Failed to insert upstream list into hash, name=\"%d\".", KCD_CONF_CHECK.data);
		return STU_ERROR;
	}

	return STU_OK;
}
