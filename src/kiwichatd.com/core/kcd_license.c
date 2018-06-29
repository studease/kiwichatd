/*
 * kcd_license.c
 *
 *  Created on: 2018年6月25日
 *      Author: Tony Lau
 */

#include "kcd_core.h"

stu_str_t  KCD_LICENSE_SERVERS = stu_string(
	"[{"
		"\"protocol\": \"http\","
		"\"method\":   \"POST\","
		"\"target\":   \"/websocket/data/check.json\","
		"\"address\":  \"192.168.2.51\","
		"\"port\":       80,"
		"\"weight\":     32,"
		"\"timeout\":    3,"
		"\"max_fails\":  0"
	"}]"
);
/*
static stu_str_t  KCD_PRIVATE_KEY = stu_string(
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"MIICXwIBAAKBgQCmXPJmY3IAfxg1909fgePtQ4mhjH4S1yEDDe908Bpn5oZTgI7J\n"
	"lelgibFwELjZ9kJDjNDWLC5GdzfeoixIC6k+9Yrf84exkNK2l7jPEBHgrhB+V+Js\n"
	"DrQSiGYiRa6DPyKu7Gg/k1sP0vmE3dAbaXtCwV3U7/mG9en/hF1OMoZn6wIDAQAB\n"
	"AoGBAI9bZN5qL2DSJHDMji9E5L4eBsmZIULm8uGI7qGcDYUfFv15uJFph1PTE334\n"
	"SvI3zN4cyBDmvXGnZhOJOBNVSR89a6y3pDXBmffGVipCe8nyfL01GPW69f636Sjb\n"
	"Fz+R+GGx5v/Yyo2GDFRioFDbxJRjiLdtgR6egxpG4MbpdHuhAkEA23orFRRsuW2+\n"
	"JYc8dBvzzwR8taQ2JMdfD2Q5v58yRbbmhM3QwkcQR17NmQ6do8wHgQML2AMc1ADR\n"
	"bISK9yHwkwJBAMIMF1t3xLhH3v7/83ygv0R3agDwF9nTDfGkTBGKphcvcLTzxYRX\n"
	"NodTaK3bLY4Ht0/HuDrIdTaCpdIGFcl6ukkCQQCOlvZ6gYSJjATnOM9L2AU0UAP9\n"
	"tqv+hRD7XPAv0GvG4ycszNJ+BdFLrQoCEH7WNe4CIUqGkq8eBVIKIKpwGLrFAkEA\n"
	"r0HqaqNOmj3XaypSiHJKrZTIudYfRI35XxDL32ABSJmBSv2MnE2Eo06zEasOhuPz\n"
	"LWwtuXHJY5U2HO2ACfv9eQJBAJxbr4Di2G910UdpXCDTI5zdRZ6sj4o5hVPWbfNp\n"
	"wkUMuPR2DcHi+qQYdYMh93x/MhP+vW9kpuWdfEB0SElgSOM=\n"
	"-----END RSA PRIVATE KEY-----\n"
);
*/
static stu_str_t  KCD_PUBLIC_KEY = stu_string(
	"-----BEGIN PUBLIC KEY-----\n"
	"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmXPJmY3IAfxg1909fgePtQ4mh\n"
	"jH4S1yEDDe908Bpn5oZTgI7JlelgibFwELjZ9kJDjNDWLC5GdzfeoixIC6k+9Yrf\n"
	"84exkNK2l7jPEBHgrhB+V+JsDrQSiGYiRa6DPyKu7Gg/k1sP0vmE3dAbaXtCwV3U\n"
	"7/mG9en/hF1OMoZn6wIDAQAB\n"
	"-----END PUBLIC KEY-----\n"
);

extern sig_atomic_t  stu_quit;
extern stu_uint32_t  stu_exiting;
extern sig_atomic_t  stu_reopen;

static BIO         *kcd_license_bio;
static RSA         *kcd_license_rsa;

static stu_str_t    KCD_UPSTREAM_CHECK   = stu_string("check");
static stu_str_t    KCD_LICENSE_ARG_CODE = stu_string("code");
static stu_str_t    KCD_LICENSE_RESPONSE;

static stu_int32_t  kcd_license_generate_request(stu_str_t *license, u_char md5[32]);
static stu_int32_t  kcd_license_analyze_upstream_response(stu_connection_t *pc);
static void         kcd_license_finalize_upstream_handler(stu_connection_t *c, stu_int32_t rc);


stu_int32_t
kcd_license_init() {
	stu_int32_t  rc;

	rc = STU_ERROR;

	kcd_license_bio = BIO_new_mem_buf(KCD_PUBLIC_KEY.data, -1);
	if (kcd_license_bio == NULL) {
		return STU_ERROR;
	}

	kcd_license_rsa = PEM_read_bio_RSA_PUBKEY(kcd_license_bio, NULL, NULL, NULL);
	if (kcd_license_rsa == NULL) {
		goto failed;
	}

	KCD_LICENSE_RESPONSE.data = stu_calloc(512);
	if (KCD_LICENSE_RESPONSE.data == NULL) {
		goto failed;
	}

	KCD_LICENSE_RESPONSE.len = 512;

	rc = STU_OK;

failed:

	//BIO_free_all(kcd_license_bio);

	return rc;
}


stu_int32_t
kcd_license_ckeck(kcd_conf_t *conf) {
	stu_json_t    *ji, *ji_code;
	u_char        *pos, *last;
	u_char         tmp[16+32+12], out[16], md5[32], buf[512];
	stu_str_t      src, dst;
	stu_md5_ctx_t  ctx;
	stu_int32_t    rc;

	pos = tmp;
	stu_str_set(&dst, buf);
	stu_memzero(buf, 512);
	stu_memzero(&ctx, sizeof(stu_md5_ctx_t));

	ji = NULL;
	rc = STU_ERROR;

	// hardware info
	pos = stu_hardware_get_cpuid(pos);
	//pos = stu_hardware_get_serial(pos);
	pos = stu_hardware_get_macaddr(pos);

	// machine code
	stu_md5_init(&ctx);
	stu_md5_update(&ctx, tmp, pos - tmp);
	stu_md5_final(out, &ctx);

	stu_sprintf(md5, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
			out[0], out[1], out[2],  out[3],  out[4],  out[5],  out[6],  out[7],
			out[8], out[9], out[10], out[11], out[12], out[13], out[14], out[15]);

	// response code
	last = conf->license.data + conf->license.len;
	pos = stu_strlchr(conf->license.data, last, '?');

	if (pos == NULL) {
		if (kcd_license_generate_request(&conf->license, md5) == STU_ERROR) {
			stu_log_error(0, "Failed to generate license request.");
			goto failed;
		}
	} else {
		conf->license.len = pos - conf->license.data;
		*pos++ = '\0';

		KCD_LICENSE_RESPONSE.len = last - pos;
		stu_strncpy(KCD_LICENSE_RESPONSE.data, pos, KCD_LICENSE_RESPONSE.len);
	}

	// check response
	stu_utf8_decode(&KCD_LICENSE_RESPONSE.data, KCD_LICENSE_RESPONSE.len);

	ji = stu_json_parse(KCD_LICENSE_RESPONSE.data, KCD_LICENSE_RESPONSE.len);
	if (ji == NULL || ji->type != STU_JSON_TYPE_OBJECT) {
		stu_log_error(0, "Failed to parse license response.");
		goto failed;
	}

	ji_code = stu_json_get_object_item_by(ji, &KCD_LICENSE_ARG_CODE);
	if (ji_code == NULL || ji_code->type != STU_JSON_TYPE_STRING) {
		stu_log_error(0, "Failed to get license response code.");
		goto failed;
	}

	src = *(stu_str_t *) ji_code->value;
	stu_base64_decode(&src, &src);

	dst.len = RSA_public_decrypt(src.len, src.data, dst.data, kcd_license_rsa, RSA_PKCS1_PADDING);
	if (dst.len == -1 || dst.len < conf->license.len + 33) {
		stu_log_error(0, "Bad license response code[1].");
		goto failed;
	}

	if (stu_strncasecmp(dst.data, conf->license.data, conf->license.len) != 0) {
		stu_log_error(0, "Bad license response code[2].");
		goto failed;
	}

	if (stu_strncasecmp(dst.data + conf->license.len + 1, md5, sizeof(md5)) != 0) {
		stu_log_error(0, "Bad license response code[3].");
		goto failed;
	}

	rc = STU_OK;

failed:

	stu_json_delete(ji);
	//BIO_free_all(kcd_license_bio);

	return rc;
}

static stu_int32_t
kcd_license_generate_request(stu_str_t *license, u_char md5[32]) {
	stu_json_t         *jo, *jo_code;
	stu_connection_t   *c, *pc;
	stu_upstream_t     *u;
	stu_http_request_t *r, *pr;
	u_char             *pos;
	u_char              tmp[128], buf[512], b64[512];
	stu_str_t           src, dst;
	stu_fd_t            evfd;
	stu_int32_t         rc;

	rc = STU_ERROR;
	stu_str_set(&src, buf);
	stu_str_set(&dst, b64);
	stu_memzero(tmp, 128);
	stu_memzero(buf, 512);
	stu_memzero(b64, 512);

	evfd = stu_event_create();
	if (evfd == -1) {
		stu_log_error(0, "Failed to create master event.");
		return STU_ERROR;
	}

	// source
	pos = stu_sprintf(tmp, "%s\n%s", license->data, md5);

	// encrypt
	src.len = RSA_public_encrypt(pos - tmp, tmp, src.data, kcd_license_rsa, RSA_PKCS1_PADDING);
	if (src.len == -1) {
		//BIO_free_all(kcd_license_bio);
		return STU_ERROR;
	}

	stu_base64_encode(&dst, &src);

	/* create check upstream */
	c = stu_connection_get((stu_socket_t) STU_SOCKET_INVALID);
	if (c == NULL) {
		stu_log_error(0, "Failed to get connection for license check.");
		return STU_ERROR;
	}

	c->read->evfd = evfd;
	c->write->evfd = evfd;
	c->recv = stu_os_io.recv;
	c->send = stu_os_io.send;

	r = stu_http_create_request(c);
	if (r == NULL) {
		stu_log_error(0, "Failed to create http request.");
		goto failed;
	}

	c->request = r;

	if (stu_upstream_create(c, KCD_UPSTREAM_CHECK.data, KCD_UPSTREAM_CHECK.len) == STU_ERROR) {
		stu_log_error(0, "Failed to create http upstream \"%s\".", KCD_UPSTREAM_CHECK.data);
		goto failed;
	}

	c->upstream->read_event_handler = stu_http_upstream_read_handler;
	c->upstream->write_event_handler = stu_http_upstream_write_handler;

	c->upstream->create_request_pt = stu_http_upstream_create_request;
	c->upstream->reinit_request_pt = stu_http_upstream_reinit_request;
	c->upstream->generate_request_pt = stu_http_upstream_generate_request;
	c->upstream->process_response_pt = stu_http_upstream_process_response;
	c->upstream->analyze_response_pt = kcd_license_analyze_upstream_response;
	c->upstream->finalize_handler_pt = kcd_license_finalize_upstream_handler;
	c->upstream->cleanup_pt = stu_http_upstream_cleanup;

	/* create ident request */
	u = c->upstream;
	pc = u->peer;

	pc->request = (void *) u->create_request_pt(pc);
	if (pc->request == NULL) {
		stu_log_error(0, "Failed to create check request.");
		u->cleanup_pt(c);
		goto failed;
	}

	pr = pc->request;
	pr->uri = u->server->target;

	/* generate request body */
	if (pc->buffer.start == NULL) {
		pc->buffer.start = (u_char *) stu_pcalloc(pc->pool, STU_HTTP_REQUEST_DEFAULT_SIZE);
		pc->buffer.end = pc->buffer.start + STU_HTTP_REQUEST_DEFAULT_SIZE;
		pc->buffer.size = STU_HTTP_REQUEST_DEFAULT_SIZE;
	}
	pc->buffer.pos = pc->buffer.last = pc->buffer.start;

	switch (u->server->method) {
	case STU_HTTP_GET:
		pc->buffer.last = stu_sprintf(pc->buffer.last, "?%s=%s", KCD_LICENSE_ARG_CODE.data, dst.data);
		break;

	case STU_HTTP_POST:
		jo = stu_json_create_object(NULL);
		jo_code = stu_json_create_string(&KCD_LICENSE_ARG_CODE, dst.data, dst.len);
		stu_json_add_item_to_object(jo, jo_code);

		pc->buffer.last = stu_json_stringify(jo, pc->buffer.last);
		stu_json_delete(jo);
		break;

	default:
		stu_log_error(0, "Method not supported while generating http upstream request: fd=%d, method=%hd.", c->fd, u->server->method);
		u->cleanup_pt(c);
		goto failed;
	}

	pr->request_body = pc->buffer;
	pr->request_body.size = pr->request_body.last - pr->request_body.pos;

	/* connect check upstream */
	rc = stu_upstream_connect(pc);
	if (rc == STU_ERROR) {
		stu_log_error(0, "Failed to connect http upstream \"%s\".", KCD_UPSTREAM_CHECK.data);
		u->cleanup_pt(c);
		goto failed;
	}

	// main thread of master process, wait for signal
	for ( ;; ) {
		if (stu_exiting) {
			// TODO: remove timers, free memory
		}

		stu_event_process_events_and_timers(evfd);

		if (r->headers_out.status) {
			break;
		}

		if (stu_reopen) {
			stu_log("reopening logs...");
		}

		if (stu_quit) {
			stu_log("worker process shutting down...");
			break;
		}
	}

	if (stu_file_close(evfd) == -1) {
		stu_log_error(stu_errno, stu_file_close_n " failed.");
	}

	u->cleanup_pt(c);

failed:

	if (rc == STU_ERROR) {
		stu_connection_close(c);
	}

	return rc;
}

static stu_int32_t
kcd_license_analyze_upstream_response(stu_connection_t *pc) {
	stu_http_request_t *r, *pr;
	stu_upstream_t     *u;
	stu_connection_t   *c;

	pr = pc->request;
	u = pc->upstream;
	c = u->connection;
	r = c->request;

	if (pr->headers_out.status != STU_HTTP_OK) {
		stu_log_error(0, "Failed to load license response code: %d - %s.", pr->headers_out.status, stu_http_status_text(pr->headers_out.status));
		return STU_ERROR;
	}

	memcpy(KCD_LICENSE_RESPONSE.data, pr->header_in->pos, pr->headers_out.content_length_n);
	KCD_LICENSE_RESPONSE.len = pr->headers_out.content_length_n;

	r->headers_out.status = pr->headers_out.status;

	return STU_OK;
}

static void
kcd_license_finalize_upstream_handler(stu_connection_t *c, stu_int32_t rc) {

}
