/* 
	psp2etoi by SKGleba
	This software may be modified and distributed under the terms of the MIT license.
	See the LICENSE file for details.
*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <taihen.h>
#include <psp2kern/kernel/modulemgr.h>
#include <vitasdkkern.h>

#include "../cmep/encrypt_udi/udienc.h"
#include "../cmep/encrypt_udi/udienc_defs.h"
#include "../cmep/patch_ussm_snvs_rw/pussm.h"

#include "crc32.c"

#define printf ksceDebugPrintf

#define DACR_OFF(stmt)                 \
do {                                   \
    unsigned prev_dacr;                \
    __asm__ volatile(                  \
        "mrc p15, 0, %0, c3, c0, 0 \n" \
        : "=r" (prev_dacr)             \
    );                                 \
    __asm__ volatile(                  \
        "mcr p15, 0, %0, c3, c0, 0 \n" \
        : : "r" (0xFFFF0000)           \
    );                                 \
    stmt;                              \
    __asm__ volatile(                  \
        "mcr p15, 0, %0, c3, c0, 0 \n" \
        : : "r" (prev_dacr)            \
    );                                 \
} while (0)

static int g_ret = -1;
static int g_leaf_num = -1;
static uint32_t g_leaf_crc = 0;
static unsigned char g_leaf_data[512];

static int siofix(void* func) {
	int ret = 0, res = 0, uid = 0;
	ret = uid = ksceKernelCreateThread("siofix", func, 64, 0x10000, 0, 0, 0);
	if ((ret < 0) || ((ret = ksceKernelStartThread(uid, 0, NULL)) < 0) || ((ret = ksceKernelWaitThreadEnd(uid, &res, NULL)) < 0)) {
		ret = -1;
		goto cleanup;
	}
	ret = res;
cleanup:
	if (uid > 0)
		ksceKernelDeleteThread(uid);
	return ret;
}

int is_pm_patched(void* buf) {
	*(uint8_t*)buf = 4;
	return 0;
}

static int read_leaf() {
	g_ret = ksceIdStorageReadLeaf(g_leaf_num, g_leaf_data);
	g_leaf_crc = crc32(0, g_leaf_data, 0x200);
	return 0;
}

static int write_leaf() {
	g_ret = -1;
	if (crc32(0, g_leaf_data, 0x200) == g_leaf_crc)
		g_ret = ksceIdStorageWriteLeaf(g_leaf_num, g_leaf_data);
	return 0;
}

uint32_t g_hook_ref;
int etoiPatchIdstorCheck(int patch, int hook) {
	int state = 0;
	ENTER_SYSCALL(state);
	int ret = -1;
	if (patch) {
		g_hook_ref = 0;
		ret = taiHookFunctionImportForKernel(KERNEL_PID, &g_hook_ref, "SceIdStorage", 0xF13F32F9, 0x2AC815A2, is_pm_patched);
	} else
		ret = taiHookReleaseForKernel(hook, g_hook_ref);
	EXIT_SYSCALL(state);
	return ret;
}

int etoiRwLeaf(int write, int leaf_num, void* u_leaf_data, uint32_t u_ioutcrc[2]) {
	int state = 0;
	ENTER_SYSCALL(state);

	uint32_t ioutcrc[2];
	ksceKernelMemcpyUserToKernel(ioutcrc, (uint32_t)u_ioutcrc, 8);
	uint32_t leaf_crc_in = ioutcrc[0];
	uint32_t u_leaf_crc_out = ioutcrc[1];

	g_ret = -1;
	if (write) {
		memset(g_leaf_data, 0, 0x200);
		ksceKernelMemcpyUserToKernel(g_leaf_data, (uint32_t)u_leaf_data, 0x200);
		if (crc32(0, g_leaf_data, 0x200) != leaf_crc_in)
			goto RWIDEXIT;
		
		g_leaf_num = leaf_num;
		g_leaf_crc = leaf_crc_in;
		siofix(write_leaf);

		if (g_ret < 0) {
			g_ret = -2;
			goto RWIDEXIT;
		}

		g_ret = 0;
	}

	if (u_leaf_crc_out) {
		memset(g_leaf_data, 0, 0x200);
		g_leaf_crc = 0;
		g_leaf_num = leaf_num;
		siofix(read_leaf);
		if (g_ret < 0) {
			g_ret = -4;
			goto RWIDEXIT;
		}

		ksceKernelMemcpyKernelToUser((uint32_t)u_leaf_crc_out, &g_leaf_crc, 4);
		ksceKernelMemcpyKernelToUser((uint32_t)u_leaf_data, g_leaf_data, 0x200);

		g_ret = 0;
	}

RWIDEXIT:
	printf("etoiRwLeaf ret 0x%08X\n", g_ret);
	EXIT_SYSCALL(state);
	return g_ret;
}

int etoiEncryptUDIBlock(void *u_udi_block, uint32_t in_crc, uint32_t *out_crc) {
	int state = 0, ret = -1;
	ENTER_SYSCALL(state);

	void* tachyon_edram = NULL;
	SceKernelAllocMemBlockKernelOpt optp;
	optp.size = 0x58;
	optp.attr = 2;
	optp.paddr = 0x1c000000;
	int tedram_block_id = ksceKernelAllocMemBlock("Tachyon-eDRAM", 0x10208006, 0x00200000, &optp);
	ksceKernelGetMemBlockBase(tedram_block_id, (void**)&tachyon_edram);
	if (!tachyon_edram)
		goto EUDIEXIT;

	ret = -2;
	ct_args* cmep_args = tachyon_edram;
	memset(tachyon_edram, 0, sizeof(ct_args));
	ksceKernelMemcpyUserToKernel(cmep_args->cid_block, (uint32_t)u_udi_block, 0x100);
	if (crc32(0, cmep_args->cid_block, 0x100) != in_crc)
		goto EUDIEXIT;

	ret = -3;
	int (*load_sm)(void) = NULL, (*stop_sm)(void) = NULL;
	module_get_offset(KERNEL_PID, ksceKernelSearchModuleByName("SceSblSsMgr"), 0, 0x3398 | 1, (uintptr_t*)&load_sm);
	module_get_offset(KERNEL_PID, ksceKernelSearchModuleByName("SceSblSsMgr"), 0, 0x340c | 1, (uintptr_t*)&stop_sm);
	if (!load_sm || !stop_sm)
		goto EUDIEXIT;

	ret = -4;
	if (load_sm())
		goto EUDIEXIT;

	ret = -5;
	cmep_args->magic = 0xCC1D;
	cmep_args->c_func = 1;
	ret = spl_exec_code(udienc_nmp, udienc_nmp_len, 0x1c000000, 1);

	stop_sm();

	if (ret < 0)
		goto EUDIEXIT;

	uint32_t k_out_crc = crc32(0, cmep_args->cid_block, 0x100);
	ksceKernelMemcpyKernelToUser((uint32_t)out_crc, &k_out_crc, 4);
	ksceKernelMemcpyKernelToUser((uint32_t)u_udi_block, cmep_args->cid_block, 0x100);
	
	ret = 0;

EUDIEXIT:
	ksceKernelFreeMemBlock(tedram_block_id);
	printf("etoiEncryptUDIBlock ret 0x%08X\n", ret);
	EXIT_SYSCALL(state);
	return ret;
}

/*
	flags/status are inverted
	~flags & 1 - os producting mode
	~flags & 2 - gc slot producting mode
	~status & 1 - SNVS initialized
	~status & 2 - QAF NVS initialized
*/
int etoiGsManagementData(int set, uint32_t flags_in, uint32_t status_in, uint32_t u_outdata[2]) {
	int state = 0, m_ret = -1;
	ENTER_SYSCALL(state);

	uint32_t outdata[2];
	ksceKernelMemcpyUserToKernel(outdata, (uint32_t)u_outdata, 8);
	uint32_t u_flags_out = outdata[0];
	uint32_t u_status_out = outdata[1];

	int sm_ctx = -1;

	int (*stop_sm)(int* ctx_io) = NULL;
	int (*load_sm)(int use_host0, int* ctx_out, int unk) = NULL;
	int (*get_mgmt_data)(uint32_t * out_flags, uint32_t * out_status, int load_ussm, int ussm_ctx) = NULL;
	module_get_offset(KERNEL_PID, ksceKernelSearchModuleByName("SceSblUpdateMgr"), 0, 0x51a8 | 1, (uintptr_t*)&load_sm);
	module_get_offset(KERNEL_PID, ksceKernelSearchModuleByName("SceSblUpdateMgr"), 0, 0x5278 | 1, (uintptr_t*)&stop_sm);
	module_get_offset(KERNEL_PID, ksceKernelSearchModuleByName("SceSblUpdateMgr"), 0, 0x8638 | 1, (uintptr_t*)&get_mgmt_data);
	if (!load_sm || !stop_sm)
		goto SMGMTEXIT;

	m_ret = -2;
	// load & start the update sm
	if (load_sm(0, &sm_ctx, 0))
		goto SMGMTEXIT;

	if (set) { // write mgmt data
		m_ret = -3;
		int resp;
		uint8_t mgmt_iobuf[0x70];
		memset(mgmt_iobuf, 0, 0x70);
		*(uint32_t*)(mgmt_iobuf) = 2;
		*(uint32_t*)(mgmt_iobuf + 8) = flags_in;
		*(uint32_t*)(mgmt_iobuf + 12) = status_in;
		int ret = ksceSblSmCommCallFunc(sm_ctx, 0xC0002, &resp, mgmt_iobuf, 0x70);
		if (!ret && !resp) {
			ret = ksceSysconNvsWriteSecureData(mgmt_iobuf + 0x10, 0x30, mgmt_iobuf + 0x40, 0x10);
			if (!ret) {
				*(uint32_t*)(mgmt_iobuf) = 3;
				ret = ksceSblSmCommCallFunc(sm_ctx, 0xc0002, &resp, mgmt_iobuf, 0x70);
				if (!ret && !resp)
					m_ret = 0;
			}
		}
		if (m_ret) {
			stop_sm(&sm_ctx);
			goto SMGMTEXIT;
		}
	}

	m_ret = -4;
	// read mgmt data
	uint32_t flags_out = 0, status_out = 0;
	if (!get_mgmt_data(&flags_out, &status_out, 0, sm_ctx))
		m_ret = 0;

	// stop & unload the update sm
	stop_sm(&sm_ctx);

	// copyout the mgmt data
	if (!m_ret) {
		ksceKernelMemcpyKernelToUser((uint32_t)u_flags_out, &flags_out, 4);
		ksceKernelMemcpyKernelToUser((uint32_t)u_status_out, &status_out, 4);
	}

SMGMTEXIT:
	printf("etoiGsManagementData ret 0x%08X\n", m_ret);
	EXIT_SYSCALL(state);
	return m_ret;
}

int etoiNvsRwSecure(int write, int sector, void* io_data, uint32_t u_ioutcrc[2]) {
	int state = 0, ret = -1;
	ENTER_SYSCALL(state);

	uint32_t ioutcrc[2];
	ksceKernelMemcpyUserToKernel(ioutcrc, (uint32_t)u_ioutcrc, 8);
	uint32_t in_crc = ioutcrc[0];
	uint32_t out_crc = ioutcrc[1];

	int (*stop_sm)(int* ctx) = NULL;
	int (*load_sm)(int sm_type, int* ctx, int unk1) = NULL;
	module_get_offset(KERNEL_PID, ksceKernelSearchModuleByName("SceSblUpdateMgr"), 0, 0x5278 | 1, (uintptr_t*)&stop_sm);
	module_get_offset(KERNEL_PID, ksceKernelSearchModuleByName("SceSblUpdateMgr"), 0, 0x51a8 | 1, (uintptr_t*)&load_sm);
	if (!stop_sm || !load_sm)
		goto SNVSEXIT;

	ret = -2;
	int sm_ctx = -1;
	if (load_sm(0, &sm_ctx, 0))
		goto SNVSEXIT;

	ret = -3;
	if (spl_exec_code(pussm_nmp, pussm_nmp_len, 0x0000C162, 1)) {
		if (spl_exec_code(pussm_nmp, pussm_nmp_len, 0x0000C1C2, 1)) {
			stop_sm(&sm_ctx);
			goto SNVSEXIT;
		}
	}

	int resp;
	uint8_t sc_pbuf[0x88];

	if (write) {
		ret = -4;
		memset(sc_pbuf, 0, 0x88);
		sc_pbuf[0] = 2;
		sc_pbuf[4] = sector;
		ksceKernelMemcpyUserToKernel(sc_pbuf + 8, (uint32_t)io_data, 0x20);
		if (crc32(0, sc_pbuf + 8, 0x20) != in_crc) {
			stop_sm(&sm_ctx);
			goto SNVSEXIT;
		}

		ret = -5;
		if (ksceSblSmCommCallFunc(sm_ctx, 0xb0002, &resp, sc_pbuf, 0x88) || resp) {
			stop_sm(&sm_ctx);
			goto SNVSEXIT;
		}

		ret = -6;
		if (ksceSysconNvsWriteSecureData(sc_pbuf + 0x28, 0x30, sc_pbuf + 0x58, 0x10)) {
			stop_sm(&sm_ctx);
			goto SNVSEXIT;
		}

		ret = -7;
		sc_pbuf[0] = 3;
		if (ksceSblSmCommCallFunc(sm_ctx, 0xb0002, &resp, sc_pbuf, 0x88) || resp) {
			stop_sm(&sm_ctx);
			goto SNVSEXIT;
		}
	}

	ret = -8;
	memset(sc_pbuf, 0, 0x88);
	sc_pbuf[4] = sector;
	if (ksceSblSmCommCallFunc(sm_ctx, 0xb0002, &resp, sc_pbuf, 0x88) || resp) {
		stop_sm(&sm_ctx);
		goto SNVSEXIT;
	}

	ret = -9;
	if (ksceSysconNvsReadSecureData(sc_pbuf + 0x28, 0x10, sc_pbuf + 0x58, 0x30)) {
		stop_sm(&sm_ctx);
		goto SNVSEXIT;
	}

	ret = -10;
	sc_pbuf[0] = 1;
	if (ksceSblSmCommCallFunc(sm_ctx, 0xb0002, &resp, sc_pbuf, 0x88) || resp) {
		stop_sm(&sm_ctx);
		goto SNVSEXIT;
	}

	stop_sm(&sm_ctx);

	uint32_t k_out_crc = crc32(0, sc_pbuf + 8, 0x20);
	ksceKernelMemcpyKernelToUser((uint32_t)out_crc, &k_out_crc, 4);
	ksceKernelMemcpyKernelToUser((uint32_t)io_data, sc_pbuf + 8, 0x20);

	ret = 0;

SNVSEXIT:
	printf("etoiNvsRwSecure ret 0x%08X\n", ret);
	EXIT_SYSCALL(state);
	return ret;
}

static uint8_t g_nvs_buf[0x760];
int etoiNvsRw(int write, int start_offset, void* io_data, uint32_t u_szioutcrc[3]) {
	int state = 0, ret = -1;
	ENTER_SYSCALL(state);

	uint32_t szioutcrc[3];
	ksceKernelMemcpyUserToKernel(szioutcrc, (uint32_t)u_szioutcrc, 12);
	int size = (int)szioutcrc[0];
	uint32_t in_crc = szioutcrc[1];
	uint32_t out_crc = szioutcrc[2];

	if (start_offset < 0x400 || (uint32_t)(start_offset + size) > 0xB60 || size % 0x10)
		goto NVSEXIT;

	if (write) {
		ret = -2;
		ksceKernelMemcpyUserToKernel(g_nvs_buf + (start_offset - 0x400), (uint32_t)io_data, size);
		if (crc32(0, g_nvs_buf + (start_offset - 0x400), size) != in_crc)
			goto NVSEXIT;
		
		ksceKernelSignalNvsAcquire(0);
		ksceSysconNvsSetRunMode(0);
		for (int i = start_offset; i < (start_offset + size); i -= -0x10) {
			ret = ksceSysconNvsWriteData(i, g_nvs_buf + (i - 0x400), 0x10);
			if (ret) {
				ksceKernelSignalNvsFree(0);
				goto NVSEXIT;
			}
		}
		ksceKernelSignalNvsFree(0);
	}

	memset(g_nvs_buf, 0, 0x760);

	ret = -3;
	ksceKernelSignalNvsAcquire(0);
	ksceSysconNvsSetRunMode(0);
	for (int i = start_offset; i < (start_offset + size); i -= -0x10) {
		ret = ksceSysconNvsReadData(i, g_nvs_buf + (i - 0x400), 0x10);
		if (ret) {
			ksceKernelSignalNvsFree(0);
			goto NVSEXIT;
		}
	}
	ksceKernelSignalNvsFree(0);

	uint32_t k_out_crc = crc32(0, g_nvs_buf + (start_offset - 0x400), size);
	ksceKernelMemcpyKernelToUser((uint32_t)out_crc, &k_out_crc, 4);
	ksceKernelMemcpyKernelToUser((uint32_t)io_data, g_nvs_buf + (start_offset - 0x400), size);

	ret = 0;

NVSEXIT:
	printf("etoiNvsRw ret 0x%08X\n", ret);
	EXIT_SYSCALL(state);
	return ret;
}

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args)
{
	ksceDebugPrintf("psp2etoiK started\n");
	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
	return SCE_KERNEL_STOP_SUCCESS;
}
