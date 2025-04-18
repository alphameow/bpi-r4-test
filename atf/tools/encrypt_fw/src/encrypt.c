/*
 * Copyright (c) 2019, Linaro Limited. All rights reserved.
 * Author: Sumit Garg <sumit.garg@linaro.org>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <firmware_encrypted.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <stdio.h>
#include <string.h>
#include "debug.h"
#include "encrypt.h"

#define BUFFER_SIZE		256
#define IV_SIZE			12
#define IV_STRING_SIZE		24
#define TAG_SIZE		16
#define KEY_SIZE		32
#define KEY_STRING_SIZE		64

static int gcm_encrypt(unsigned short fw_enc_status, char *key_string,
		       char *nonce_string, const char *ip_name,
		       const char *op_name)
{
	FILE *ip_file;
	FILE *op_file;
	EVP_CIPHER_CTX *ctx;
	unsigned char data[BUFFER_SIZE], enc_data[BUFFER_SIZE];
	unsigned char key[KEY_SIZE], iv[IV_SIZE], tag[TAG_SIZE];
	int bytes, enc_len = 0, i, j, ret = 0;
	unsigned int image_len = 0;
	struct fw_enc_hdr header;

	memset(&header, 0, sizeof(struct fw_enc_hdr));

	if (strlen(key_string) != KEY_STRING_SIZE) {
		ERROR("Unsupported key size: %lu\n", strlen(key_string));
		return -1;
	}

	for (i = 0, j = 0; i < KEY_SIZE; i++, j += 2) {
		if (sscanf(&key_string[j], "%02hhx", &key[i]) != 1) {
			ERROR("Incorrect key format\n");
			return -1;
		}
	}

	if (strlen(nonce_string) != IV_STRING_SIZE) {
		ERROR("Unsupported IV size: %lu\n", strlen(nonce_string));
		return -1;
	}

	for (i = 0, j = 0; i < IV_SIZE; i++, j += 2) {
		if (sscanf(&nonce_string[j], "%02hhx", &iv[i]) != 1) {
			ERROR("Incorrect IV format\n");
			return -1;
		}
	}

	ip_file = fopen(ip_name, "rb");
	if (ip_file == NULL) {
		ERROR("Cannot read %s\n", ip_name);
		return -1;
	}

	op_file = fopen(op_name, "wb");
	if (op_file == NULL) {
		ERROR("Cannot write %s\n", op_name);
		fclose(ip_file);
		return -1;
	}

	ret = fseek(op_file, sizeof(struct fw_enc_hdr), SEEK_SET);
	if (ret) {
		ERROR("fseek failed\n");
		goto out_file;
	}

	ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		ERROR("EVP_CIPHER_CTX_new failed\n");
		ret = -1;
		goto out_file;
	}

	ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
	if (ret != 1) {
		ERROR("EVP_EncryptInit_ex failed\n");
		ret = -1;
		goto out;
	}

	ret = EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
	if (ret != 1) {
		ERROR("EVP_EncryptInit_ex failed\n");
		goto out;
	}

	while ((bytes = fread(data, 1, BUFFER_SIZE, ip_file)) != 0) {
		ret = EVP_EncryptUpdate(ctx, enc_data, &enc_len, data, bytes);
		if (ret != 1) {
			ERROR("EVP_EncryptUpdate failed\n");
			ret = -1;
			goto out;
		}

		fwrite(enc_data, 1, enc_len, op_file);
		image_len += bytes;
	}

	ret = EVP_EncryptFinal_ex(ctx, enc_data, &enc_len);
	if (ret != 1) {
		ERROR("EVP_EncryptFinal_ex failed\n");
		ret = -1;
		goto out;
	}

	ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag);
	if (ret != 1) {
		ERROR("EVP_CIPHER_CTX_ctrl failed\n");
		ret = -1;
		goto out;
	}

	header.magic = ENC_HEADER_MAGIC;
	header.flags |= fw_enc_status & FW_ENC_STATUS_FLAG_MASK;
	header.dec_algo = KEY_ALG_GCM;
	header.iv_len = IV_SIZE;
	header.tag_len = TAG_SIZE;
	header.image_len = image_len;
	memcpy(header.iv, iv, IV_SIZE);
	memcpy(header.tag, tag, TAG_SIZE);

	ret = fseek(op_file, 0, SEEK_SET);
	if (ret) {
		ERROR("fseek failed\n");
		goto out;
	}

	fwrite(&header, 1, sizeof(struct fw_enc_hdr), op_file);

out:
	EVP_CIPHER_CTX_free(ctx);

out_file:
	fclose(ip_file);
	fclose(op_file);

	/*
	 * EVP_* APIs returns 1 as success but enctool considers
	 * 0 as success.
	 */
	if (ret == 1)
		ret = 0;

	return ret;
}

int encrypt_file(unsigned short fw_enc_status, int enc_alg, char *key_string,
		 char *nonce_string, const char *ip_name, const char *op_name)
{
	switch (enc_alg) {
	case KEY_ALG_GCM:
		return gcm_encrypt(fw_enc_status, key_string, nonce_string,
				   ip_name, op_name);
	default:
		return -1;
	}
}

static int hex2bin(char *hex, int hex_len, uint8_t *out)
{
	int i, j;

	for (i = 0, j = 0; j < hex_len; i ++, j += 2) {
		if (sscanf(&hex[j], "%02hhx", &out[i]) != 1) {
			ERROR("Incorrect key format\n");
			return -1;
		}
	}
	return 0;
}

static int bin2hex(uint8_t *bin, int bin_len, char *out)
{
	int i, j;

	for (i = 0, j = 0; i < bin_len; i ++, j += 2) {
		if (sprintf(&out[j], "%02x", bin[i]) < 0) {
			ERROR("Incorrect key format\n");
			return -1;
		}
	}
	return 0;
}

int do_hkdf(char *key_hex, uint32_t key_hex_len,
	    char *salt_hex, uint32_t salt_hex_len,
	    char *buf, size_t out_len)
{
	EVP_PKEY_CTX *pctx;
	uint8_t key[ROE_KEY_SIZE] = { 0 };
	uint8_t salt[SALT_SIZE] = { 0 };
	uint8_t out_key[FIP_KEY_SIZE] = { 0 };
	uint32_t ret = 0;

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (!pctx) {
		ERROR("EVP_PKEY_CTX_new_id: error\n");
		return -1;
	}

	ret = hex2bin(key_hex, key_hex_len, key);
	if (ret) {
		ERROR("hex2bin key error\n");
		goto out;
	}

	ret = hex2bin(salt_hex, salt_hex_len, salt);
	if (ret) {
		ERROR("hex2bin salt error\n");
		goto out;
	}

	ret = EVP_PKEY_derive_init(pctx);
	if (ret <= 0) {
		ERROR("Init Failed, ret:%x\n", ret);
		goto out;
	}

	ret = EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
	if (ret <= 0) {
		ERROR("md Failed, ret:%x\n", ret);
		goto out;
	}

	ret = EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, sizeof(salt));
	if (ret <= 0) {
		ERROR("Salt Failed, ret:%x\n", ret);
		goto out;
	}

	ret = EVP_PKEY_CTX_set1_hkdf_key(pctx, key, sizeof(key));
	if (ret <= 0) {
		ERROR("Key Failed, ret:%x\n", ret);
		goto out;
	}

	ret = EVP_PKEY_derive(pctx, out_key, &out_len);
	if (ret <= 0) {
		ERROR("Out Failed, ret:%x\n", ret);
		goto out;
	}

	ret = bin2hex(out_key, sizeof(out_key), buf);
	if (ret) {
		ERROR("bin2hex key error\n");
		goto out;
	}

out:
	EVP_PKEY_CTX_free(pctx);
	return ret;
}
