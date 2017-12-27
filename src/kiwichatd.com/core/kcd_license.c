/*
 * kcd_license.c
 *
 *  Created on: 2017年12月27日
 *      Author: Tony Lau
 */

#include "kcd_core.h"

static stu_str_t  KCD_LICENSE_PUBKEY = stu_string(
		"-----BEGIN PUBLIC KEY-----\n"
		"MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAN4vEDaUW8ponyXNZr/jBScgc2DYN9fM\n"
		"jTOHtRAa1n0DMOAX4FDvICiGoMBxQDC65ZVNhn2VVCKGRVBTC5Rji2MCAwEAAQ==\n"
		"-----END PUBLIC KEY-----\n");


kcd_edition_t
kcd_license_check(stu_str_t *key, stu_str_t *response) {
	BIO           *bio;
	RSA           *rsa;
	u_char        *pos;
	u_char         tmp[KCD_LICENSE_SOURCE_DEFAULT_SIZE];
	u_char         enc[KCD_LICENSE_ENCRYPT_MAX_SIZE];
	u_char         req[KCD_LICENSE_REQUEST_MAX_SIZE];
	u_char         res[KCD_LICENSE_RESPONSE_MAX_SIZE];
	kcd_edition_t  edition;
	stu_str_t      dst, src;
	size_t         len;

	edition = PREVIEW;
	bio = NULL;
	rsa = NULL;
	pos = tmp;
	stu_memzero(tmp, KCD_LICENSE_SOURCE_DEFAULT_SIZE);
	stu_memzero(enc, KCD_LICENSE_ENCRYPT_MAX_SIZE);
	stu_memzero(req, KCD_LICENSE_REQUEST_MAX_SIZE);
	stu_memzero(res, KCD_LICENSE_RESPONSE_MAX_SIZE);

	if (key->len != KCD_LICENSE_LENGTH) {
		stu_log_error(0, "License length not match.");
		goto failed;
	}

	/* source string */
	pos = stu_hardware_get_hwaddr(pos);
	if (pos == NULL) {
		stu_log_error(0, "Failed to detect hardware info.");
		goto failed;
	}

	*pos++ = LF;
	pos = stu_strncpy(pos, key->data, key->len);

	/* public encrypt */
	bio = BIO_new_mem_buf(KCD_LICENSE_PUBKEY.data, KCD_LICENSE_PUBKEY.len);
	if (bio == NULL) {
		stu_log_error(0, "BIO_new_mem_buf() failed.");
		goto failed;
	}

	rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
	if (rsa == NULL) {
		stu_log_error(0, "PEM_read_bio_RSA_PUBKEY() failed.");
		goto failed;
	}

	if (RSA_public_encrypt(pos - tmp, tmp, enc, rsa, RSA_PKCS1_PADDING) == -1) {
		stu_log_error(0, "RSA_public_encrypt() failed.");
		goto failed;
	}

	/* format request code */
	src.data = enc;
	src.len = len = RSA_size(rsa);

	dst.data = req;

	stu_base64_encode(&dst, &src);

	stu_log("Request code: \n%s", req);

	/* check response code */
	if (response->data == NULL || response->len == 0) {
		stu_log_error(0, "Response code not found.");
		goto failed;
	}

	src = *response;
	dst.data = res;

	if (stu_base64_decode(&dst, &src) == STU_ERROR) {
		stu_log_error(0, "Bad response code[1].");
		goto failed;
	}

	if (RSA_public_decrypt(dst.len, res, enc, rsa, RSA_PKCS1_PADDING) == -1) {
		stu_log_error(0, "RSA_public_decrypt() failed.");
		goto failed;
	}

	if (stu_strncmp(enc, req, len) != 0) {
		stu_log_error(0, "Bad response code[2].");
		goto failed;
	}

	edition = ENTERPRISE;

failed:

	if (bio) {
		BIO_free_all(bio);
	}

	if (rsa) {
		RSA_free(rsa);
		CRYPTO_cleanup_all_ex_data();
	}

	return edition;
}
