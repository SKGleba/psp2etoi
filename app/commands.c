#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "commands.h"

static uint8_t g_leaf_buf[0x400]; // lets have it ready

int proxy_etoiRwLeaf(int write, int leaf_num, void* u_leaf_data, uint32_t leaf_crc_in, uint32_t* u_leaf_crc_out) {
    uint32_t ioutcrc[2];
    ioutcrc[0] = leaf_crc_in;
    ioutcrc[1] = (uint32_t)u_leaf_crc_out;
    return etoiRwLeaf(write, leaf_num, u_leaf_data, ioutcrc);
}

int proxy_etoiGsManagementData(int set, uint32_t flags_in, uint32_t status_in, uint32_t* flags_out, uint32_t* status_out) {
    uint32_t outdata[2];
    outdata[0] = (uint32_t)flags_out;
    outdata[1] = (uint32_t)status_out;
    return etoiGsManagementData(set, flags_in, status_in, outdata);
}

int proxy_etoiNvsRwSecure(int write, int sector, void* io_data, uint32_t in_crc, uint32_t* out_crc) {
    uint32_t ioutcrc[2];
    ioutcrc[0] = in_crc;
    ioutcrc[1] = (uint32_t)out_crc;
    return etoiNvsRwSecure(write, sector, io_data, ioutcrc);
}

int proxy_etoiNvsRw(int write, int start_offset, void* io_data, int size, uint32_t in_crc, uint32_t* out_crc) {
    uint32_t szioutcrc[3];
    szioutcrc[0] = (uint32_t)size;
    szioutcrc[1] = in_crc;
    szioutcrc[2] = (uint32_t)out_crc;
    return etoiNvsRw(write, start_offset, io_data, szioutcrc);
}

int set_opsid(uint8_t* opsid) {
    int ret = -1;
    uint8_t* leafs = g_leaf_buf;
    memset(leafs, 0, 0x400);

    uint32_t in_leaf_crc = 0;
    if (proxy_etoiRwLeaf(0, 0x46, leafs, 0, &in_leaf_crc) || crc32(0, leafs, 0x200) != in_leaf_crc)
        return ret;

    ret = -2;
    in_leaf_crc = 0;
    if (proxy_etoiRwLeaf(0, 0x47, leafs + 0x200, 0, &in_leaf_crc) || crc32(0, leafs + 0x200, 0x200) != in_leaf_crc)
        return ret;

    ret = -3;
    uint8_t udi_block[0x100];
    memset(udi_block, 0, 0x100);
    memcpy(udi_block, leafs + 0x128, 0x100);
    memcpy(udi_block, opsid, 0x10);

    uint32_t in_udi_crc = 0;
    if (etoiEncryptUDIBlock(udi_block, crc32(0, udi_block, 0x100), &in_udi_crc)
        || crc32(0, udi_block, 0x100) != in_udi_crc) return ret;

    ret = -4;
    memcpy(leafs + 0x128, udi_block, 0x100);
    if (memcmp(udi_block, leafs + 0x128, 0x100))
        return ret;

    ret = -5;
    int hook = etoiPatchIdstorCheck(1, 0);
    if (hook < 0)
        return ret;

    ret = -6;
    uint32_t crc_0 = crc32(0, leafs, 0x200);
    uint32_t crc_x200 = crc32(0, leafs + 0x200, 0x200);
    if (proxy_etoiRwLeaf(1, 0x46, leafs, crc_0, NULL) || proxy_etoiRwLeaf(1, 0x47, leafs + 0x200, crc_x200, NULL)) {
        etoiPatchIdstorCheck(0, hook);
        return ret;
    }

    etoiPatchIdstorCheck(0, hook);

    ret = -7;
    uint32_t post_crc_0 = 0;
    uint32_t post_crc_x200 = 0;
    proxy_etoiRwLeaf(0, 0x46, leafs, 0, &post_crc_0);
    proxy_etoiRwLeaf(0, 0x47, leafs + 0x200, 0, &post_crc_x200);
    if (post_crc_0 != crc_0 || post_crc_x200 != crc_x200)
        return ret;

    return 0;
}

int validate_cid(void* cid) {
    if (!*(uint32_t*)cid || *(uint32_t*)cid & 0xFEFFFFFF)
        return -1;
    cid -= -4;
    if (!*(uint32_t*)cid || *(uint32_t*)cid & 0x0000F0FE)
        return -2;
    return 0;
}

int set_cid(uint8_t* cid, uint8_t type) {
    int ret = -1;
    uint8_t* leaf = g_leaf_buf;
    memset(leaf, 0, 0x200);
    uint32_t in_leaf_crc = 0;
    if (proxy_etoiRwLeaf(0, 0x44, leaf, 0, &in_leaf_crc) || crc32(0, leaf, 0x200) != in_leaf_crc)
        return ret;

    ret = -2;
    uint8_t udi_block[0x100];
    memset(udi_block, 0, 0x100);
    memcpy(udi_block, leaf + 0xA0, 0x100);
    if (cid)
        memcpy(udi_block, cid, 0x10);
    else
        udi_block[5] = type;
    if (validate_cid(udi_block))
        return ret;

    ret = -3;
    uint32_t in_udi_crc = 0;
    if (etoiEncryptUDIBlock(udi_block, crc32(0, udi_block, 0x100), &in_udi_crc)
        || crc32(0, udi_block, 0x100) != in_udi_crc) return ret;

    ret = -4;
    memcpy(leaf + 0xA0, udi_block, 0x100);
    if (memcmp(udi_block, leaf + 0xA0, 0x100))
        return ret;

    ret = -5;
    int hook = etoiPatchIdstorCheck(1, 0);
    if (hook < 0)
        return ret;

    ret = -6;
    uint32_t post_crc = 0;
    uint32_t pre_crc = crc32(0, leaf, 0x200);
    if (proxy_etoiRwLeaf(1, 0x44, leaf, pre_crc, &post_crc) || (pre_crc != post_crc)) {
        etoiPatchIdstorCheck(0, hook);
        return ret;
    }

    etoiPatchIdstorCheck(0, hook);

    return 0;
}