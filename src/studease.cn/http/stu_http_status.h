/*
 * stu_http_status.h
 *
 *  Created on: 2017年11月22日
 *      Author: Tony Lau
 */

#ifndef STUDEASE_CN_HTTP_STU_HTTP_STATUS_H_
#define STUDEASE_CN_HTTP_STU_HTTP_STATUS_H_

#include "stu_http.h"

#define STU_HTTP_STATUS_MAX_RECORDS               64

#define STU_HTTP_CONTINUE                         100
#define STU_HTTP_SWITCHING_PROTOCOLS              101
#define STU_HTTP_PROCESSING                       102

#define STU_HTTP_OK                               200
#define STU_HTTP_CREATED                          201
#define STU_HTTP_ACCEPTED                         202
#define STU_HTTP_NON_AUTHORITATIVE_INFO           203
#define STU_HTTP_NO_CONTENT                       204
#define STU_HTTP_RESET_CONTENT                    205
#define STU_HTTP_PARTIAL_CONTENT                  206
#define STU_HTTP_MULTI_STATUS                     207
#define STU_HTTP_ALREADY_REPORTED                 208
#define STU_HTTP_IM_USED                          226

#define STU_HTTP_MULTIPLE_CHOICES                 300
#define STU_HTTP_MOVED_PERMANENTLY                301
#define STU_HTTP_MOVED_TEMPORARILY                302
#define STU_HTTP_SEE_OTHER                        303
#define STU_HTTP_NOT_MODIFIED                     304
#define STU_HTTP_USE_PROXY                        305
#define STU_HTTP_SWITCH_PROXY                     306 // unused
#define STU_HTTP_TEMPORARY_REDIRECT               307
#define STU_HTTP_PERMANENT_REDIRECT               308

#define STU_HTTP_BAD_REQUEST                      400
#define STU_HTTP_UNAUTHORIZED                     401
#define STU_HTTP_PAYMENT_REQUIRED                 402
#define STU_HTTP_FORBIDDEN                        403
#define STU_HTTP_NOT_FOUND                        404
#define STU_HTTP_METHOD_NOT_ALLOWED               405
#define STU_HTTP_NOT_ACCEPTABLE                   406
#define STU_HTTP_PROXY_AUTH_REQUIRED              407
#define STU_HTTP_REQUEST_TIMEOUT                  408
#define STU_HTTP_CONFLICT                         409
#define STU_HTTP_GONE                             410
#define STU_HTTP_LENGTH_REQUIRED                  411
#define STU_HTTP_PRECONDITION_FAILED              412
#define STU_HTTP_REQUEST_ENTITY_TOO_LARGE         413
#define STU_HTTP_REQUEST_URI_TOO_LARGE            414
#define STU_HTTP_UNSUPPORTED_MEDIA_TYPE           415
#define STU_HTTP_REQUESTED_RANGE_NOT_SATISFIABLE  416
#define STU_HTTP_EXPECTATION_FAILED               417
#define STU_HTTP_TEAPOT                           418
#define STU_HTTP_MISDIRECTED_REQUEST              421
#define STU_HTTP_UNPROCESSABLE_ENTITY             422
#define STU_HTTP_LOCKED                           423
#define STU_HTTP_FAILED_DEPENDENCY                424
#define STU_HTTP_UPGRADE_REQUIRED                 426
#define STU_HTTP_PRECONDITION_REQUIRED            428
#define STU_HTTP_TOO_MANY_REQUESTS                429
#define STU_HTTP_REQUEST_HEADER_TOO_LARGE         494 // nginx

#define STU_HTTP_INTERNAL_SERVER_ERROR            500
#define STU_HTTP_NOT_IMPLEMENTED                  501
#define STU_HTTP_BAD_GATEWAY                      502
#define STU_HTTP_SERVICE_UNAVAILABLE              503
#define STU_HTTP_GATEWAY_TIMEOUT                  504
#define STU_HTTP_VERSION_NOT_SUPPORTED            505
#define STU_HTTP_VARIANT_ALSO_NEGOTIATES          506
#define STU_HTTP_INSUFFICIENT_STORAGE             507
#define STU_HTTP_LOOP_DETECTED                    508
#define STU_HTTP_NOT_EXTENDED                     510
#define STU_HTTP_NETWORK_AUTH_REQUIRED            511

typedef struct {
	stu_int32_t  code;
	stu_str_t    text;
} stu_http_status_t;

stu_int32_t  stu_http_status_init_hash();

u_char      *stu_http_status_text(stu_int32_t rc);

#endif /* STUDEASE_CN_HTTP_STU_HTTP_STATUS_H_ */
