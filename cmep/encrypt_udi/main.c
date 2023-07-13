/* THIS FILE IS A PART OF PSP2ETOI
 *
 * Copyright (C) 2012-2023 skgleba
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include "../spl-defs.h"
#include "udienc_defs.h"

static int ks_to_mem(uint32_t op, uint32_t ks, uint32_t dst, uint32_t sz, uint32_t iv, uint32_t src) {
	*(volatile uint32_t*)0xE0050000 = src;
	*(volatile uint32_t*)0xE0050004 = dst;
	*(volatile uint32_t*)0xE0050008 = sz;
	*(volatile uint32_t*)0xE005000C = op;
	*(volatile uint32_t*)0xE0050010 = ks;
	*(volatile uint32_t*)0xE0050014 = iv;
	*(volatile uint32_t*)0xE005001C = 1;
	while (*(volatile uint32_t*)0xE0050024 & 1) {}
	return *(volatile uint32_t*)0xE0050024;
}

// based on aimgr's verify_cid
static int recrypt_cid(void* cid_block, void* work_buf) {
	int (*gkey_x1z1_to_ks0_w_ks204)(void) = (void*)0x0080b698;
	int (*x33b_to_mem_w_ks212)(void* dst, void* src, uint32_t sz) = (void*)0x0080b71a;

	// encrypt the plaintext cid using ks0x212
	if (x33b_to_mem_w_ks212(work_buf, cid_block, 0xD8) < 0)
		return -1;

	// derive cid enc key to ks0 using ks0x204 and hardcoded seed
	if (gkey_x1z1_to_ks0_w_ks204() < 0)
		return -2;

	// aes-128-ctr encrypt cid with ks0
	if (ks_to_mem(0x112, 0, cid_block + 0xD8, 0x10, work_buf, work_buf + 0xD8))
		return -3;

	return 0;
}

int __attribute__((section(".text.start"))) start(ct_args* arg) {
	
	if (arg->magic != 0xCC1D)
		return 0xBADF00D0;

	if (arg->c_func & 1) {
		if (recrypt_cid(arg->cid_block, arg->tmp) < 0)
			return 0xBADF00D1;
	}

	int (*verify_cid)(void* cid_block, uint32_t size) = (void*)0x0080b7d4;
	return verify_cid(arg->cid_block, 0x100);
}