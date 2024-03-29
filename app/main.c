/* THIS FILE IS A PART OF PSP2ETOI
 *
 * Copyright (C) 2012-2023 skgleba
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/devctl.h>
#include <psp2/ctrl.h>
#include <psp2/shellutil.h>
#include <psp2/sysmodule.h>
#include <psp2/kernel/sysmem.h>
#include <psp2/io/stat.h>
#include <taihen.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "graphics.h"

#include "commands.h"
#include "main.h"

static int DO_WRITE_CONFIG = 0;
static int CURRENT_CMD = 0;

int handler_input(char* arg) {
    if (!memcmp(arg, "true", 4))
        DO_WRITE_CONFIG = 1;
    else
        DO_WRITE_CONFIG = 0;
    return 0;
}

int handler_consoleid(char* arg) {
    g_cmd_args[CMD_DeviceType].used = 0;
    uint8_t cid[0x10];
    if (antoh(arg, cid, 0x10))
        return -21;

    char cid_a[0x20];
    if (hntoa(cid, cid_a, 0x20))
        return -22;

    if (memcmp(arg, cid_a, 0x20))
        return -23;
    
    return set_cid(cid, 0);
}

int handler_openpsid(char* arg) {
    uint8_t openpsid[0x10];
    if (antoh(arg, openpsid, 0x10))
        return -1;
    
    char openpsid_a[0x20];
    if (hntoa(openpsid, openpsid_a, 0x20))
        return -22;

    if (memcmp(arg, openpsid_a, 0x20))
        return -23;
    
    return set_opsid(openpsid);
}

int handler_devicetype(char* arg) {
    g_cmd_args[CMD_ConsoleID].used = 0;
    uint8_t type;
    if (antoh(arg + 2, &type, 1))
        return -21;

    char type_a[2];
    if (hntoa(&type, type_a, 2))
        return -22;

    if (memcmp(arg + 2, type_a, 2))
        return -23;

    return set_cid(NULL, type);
}

int handler_mgmtflags(char *arg) {
    g_cmd_args[CMD_SoftwareProductingMode].used = 0;
    g_cmd_args[CMD_VCSlotProductingMode].used = 0;

    uint32_t flags = 0;
    if (antoh(arg + 2, &flags, 4))
        return -21;

    char flags_a[8];
    if (hntoa(&flags, flags_a, 8))
        return -22;

    if (memcmp(arg + 2, flags_a, 8))
        return -23;

    flags = BSWAP32(flags);
    flags = ~flags;

    uint32_t prev_flags, prev_status;
    int ret = proxy_etoiGsManagementData(0, 0, 0, &prev_flags, &prev_status);
    if (ret)
        return ret;

    return proxy_etoiGsManagementData(1, flags, prev_status, &prev_flags, &prev_status);
}

int handler_mgmtflags_det(char* arg) {
    g_cmd_args[CMD_mgmtFlags].used = 0;

    uint32_t prev_flags, prev_status;
    int ret = proxy_etoiGsManagementData(0, 0, 0, &prev_flags, &prev_status);
    if (ret)
        return ret;

    uint32_t flags = ~prev_flags;

    if (g_cmd_args[CMD_SoftwareProductingMode].used) {
        g_cmd_args[CMD_SoftwareProductingMode].used = 0;
        if (!memcmp(g_cmd_args[CMD_SoftwareProductingMode].ascii_arg, "true", 4))
            flags |= 1;
        else
            flags = ~(prev_flags | 1);
    }

    prev_flags = ~flags;

    if (g_cmd_args[CMD_VCSlotProductingMode].used) {
        g_cmd_args[CMD_VCSlotProductingMode].used = 0;
        if (!memcmp(g_cmd_args[CMD_VCSlotProductingMode].ascii_arg, "true", 4))
            flags |= 2;
        else
            flags = ~(prev_flags | 2);
    }

    flags = ~flags;

    if (flags < 0xFFFFFFAA)
        return -21;

    return proxy_etoiGsManagementData(1, flags, prev_status, &prev_flags, &prev_status);
}

int handler_mgmtstatus(char* arg) {
    g_cmd_args[CMD_isSnvsInitialized].used = 0;
    g_cmd_args[CMD_isQaFlagged].used = 0;

    uint32_t status = 0;
    if (antoh(arg + 2, &status, 4))
        return -21;

    char status_a[8];
    if (hntoa(&status, status_a, 8))
        return -22;

    if (memcmp(arg + 2, status_a, 8))
        return -23;

    status = BSWAP32(status);
    status = ~status;

    uint32_t prev_flags, prev_status;
    int ret = proxy_etoiGsManagementData(0, 0, 0, &prev_flags, &prev_status);
    if (ret)
        return ret;

    return proxy_etoiGsManagementData(1, prev_flags, status, &prev_flags, &prev_status);
}

int handler_mgmtstatus_det(char* arg) {
    g_cmd_args[CMD_mgmtStatus].used = 0;

    uint32_t prev_flags, prev_status;
    int ret = proxy_etoiGsManagementData(0, 0, 0, &prev_flags, &prev_status);
    if (ret)
        return ret;

    uint32_t status = ~prev_status;

    if (g_cmd_args[CMD_isSnvsInitialized].used) {
        g_cmd_args[CMD_isSnvsInitialized].used = 0;
        if (!memcmp(g_cmd_args[CMD_isSnvsInitialized].ascii_arg, "true", 4))
            status |= 1;
        else
            status = ~(prev_status | 1);
    }

    prev_status = ~status;

    if (g_cmd_args[CMD_isQaFlagged].used) {
        g_cmd_args[CMD_isQaFlagged].used = 0;
        if (!memcmp(g_cmd_args[CMD_isQaFlagged].ascii_arg, "true", 4))
            status |= 2;
        else
            status = ~(prev_status | 2);
    }

    status = ~status;

    if (status < 0xFFFFFFAA)
        return -21;

    return proxy_etoiGsManagementData(1, prev_flags, status, &prev_flags, &prev_status);
}

int handler_nvs_op(char* arg) {
    if (CURRENT_CMD < CMD_NVS_OP0_OFFSET || CURRENT_CMD > CMD_NVS_OP3_OFFSET)
        return -20;

    if (!g_cmd_args[CURRENT_CMD + (CMD_NVS_OP0_RWSIZE - CMD_NVS_OP0_OFFSET)].used || !g_cmd_args[CURRENT_CMD + (CMD_NVS_OP0_BUFCRC - CMD_NVS_OP0_OFFSET)].used)
        return -20;

    if (!g_cmd_args[CURRENT_CMD + (CMD_NVS_OP0_IOFILE - CMD_NVS_OP0_OFFSET)].used && !g_cmd_args[CURRENT_CMD + (CMD_NVS_OP0_INRAWH - CMD_NVS_OP0_OFFSET)].used)
        return -20;

    // get offset
    uint16_t offset = 0;
    if (antoh(arg + 2, &offset, 2))
        return -21;

    char offset_a[4];
    if (hntoa(&offset, offset_a, 4))
        return -22;

    if (memcmp(arg + 2, offset_a, 4))
        return -23;

    offset = BSWAP16(offset);

    // get size
    uint16_t size = 0;
    if (antoh(g_cmd_args[CURRENT_CMD + (CMD_NVS_OP0_RWSIZE - CMD_NVS_OP0_OFFSET)].ascii_arg + 2, &size, 2))
        return -24;

    char size_a[4];
    if (hntoa(&size, size_a, 4))
        return -25;

    if (memcmp(g_cmd_args[CURRENT_CMD + (CMD_NVS_OP0_RWSIZE - CMD_NVS_OP0_OFFSET)].ascii_arg + 2, size_a, 4))
        return -26;

    size = BSWAP16(size);

    // check offset/size args
    if ((offset < 0x400 && offset % 0x20) || (offset >= 0x400 && offset % 0x10))
        return -27;

    if ((offset < 0x400 && size % 0x20) || (offset >= 0x400 && size % 0x10))
        return -28;

    if (offset < 0x400 && (offset + size) > 0x400)
        return -29;

    // get data crc
    uint32_t crc = 0;
    if (antoh(g_cmd_args[CURRENT_CMD + (CMD_NVS_OP0_BUFCRC - CMD_NVS_OP0_OFFSET)].ascii_arg + 2, &crc, 4))
        return -30;

    char crc_a[8];
    if (hntoa(&crc, crc_a, 8))
        return -31;

    if (memcmp(g_cmd_args[CURRENT_CMD + (CMD_NVS_OP0_BUFCRC - CMD_NVS_OP0_OFFSET)].ascii_arg + 2, crc_a, 8))
        return -32;

    crc = BSWAP32(crc);

    // alloc buf for data
    uint8_t* data_buf = malloc(size);
    if (!data_buf)
        return -33;

    if (g_cmd_args[CURRENT_CMD + (CMD_NVS_OP0_IOFILE - CMD_NVS_OP0_OFFSET)].used) { // read file
        FILE* fp = fopen(g_cmd_args[CURRENT_CMD + (CMD_NVS_OP0_IOFILE - CMD_NVS_OP0_OFFSET)].ascii_arg, "rb");
        if (!fp) {
            free(data_buf);
            return -34;
        }
        fread(data_buf, size, 1, fp);
        fclose(fp);
    } else { // read data
        if ((size * 2) > strlen(g_cmd_args[CURRENT_CMD + (CMD_NVS_OP0_INRAWH - CMD_NVS_OP0_OFFSET)].ascii_arg)) {
            free(data_buf);
            return -34;
        }
        if (antoh(g_cmd_args[CURRENT_CMD + (CMD_NVS_OP0_INRAWH - CMD_NVS_OP0_OFFSET)].ascii_arg, data_buf, size)) {
            free(data_buf);
            return -34;
        }
    }

    // verify file
    if (crc32(0, data_buf, size) != crc) {
        free(data_buf);
        return -35;
    }

    if (offset < 0x400) { // write snvs
        int snvs_sector_start = offset / 0x20;
        int snvs_sector_count = size / 0x20;
        uint32_t tmp_crc32_in, tmp_crc32_out;
        for (int i = 0; i < snvs_sector_count; i++) {
            tmp_crc32_in = crc32(0, data_buf + (i * 0x20), 0x20);
            int ret = proxy_etoiNvsRwSecure(1, snvs_sector_start + i, data_buf + (i * 0x20), tmp_crc32_in, &tmp_crc32_out);
            if (ret || (tmp_crc32_in != tmp_crc32_out && (snvs_sector_start > 1 || i))) {
                free(data_buf);
                return -36;
            }
        }
    } else { // write nvs
        uint32_t tmp_crc32_in, tmp_crc32_out;
        tmp_crc32_in = crc32(0, data_buf, size);
        int ret = proxy_etoiNvsRw(1, offset, data_buf, size, tmp_crc32_in, &tmp_crc32_out);
        if (ret || tmp_crc32_in != tmp_crc32_out) {
            free(data_buf);
            return -37;
        }
    }

    free(data_buf);
    return 0;
}

void dispatch_table_to_garray(void) {
    void* dispatch_table[COMMAND_COUNT] = {
        0,
        handler_input,
        handler_consoleid,
        handler_openpsid,
        handler_devicetype,
        handler_mgmtflags,
        handler_mgmtflags_det,
        handler_mgmtflags_det,
        handler_mgmtstatus,
        handler_mgmtstatus_det,
        handler_mgmtstatus_det,
        handler_nvs_op,
        handler_nvs_op,
        handler_nvs_op,
        handler_nvs_op,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    };

    for (int i = 0; i < COMMAND_COUNT; i++)
        g_cmd_args[i].cmd_handler = dispatch_table[i];
}

int get_command_idx(char* line, char* end) {
    int cmd_len = 0;
    int max_cmd_len = end - line;
    for (int i = 1; i < COMMAND_COUNT; i++) {
        cmd_len = strlen(valid_commands[i]);
        if (cmd_len < max_cmd_len) {
            if (!memcmp(line, valid_commands[i], cmd_len))
                return i;
        }
    }
    return 0;
}

void prepare_command_by_idx(int idx, char* command_line, char* end) {
    char* arg = command_line + strlen(valid_commands[idx]);
    if (*(uint8_t*)arg != 0x3D)
        return;
    arg++;

    int arglen = end - arg;

    // cut invalid and comments (" " and "#")
    for (int i = 0; i < arglen; i++) {
        if (*(uint8_t*)(arg + i) == 0x20 || *(uint8_t*)(arg + i) == 0x23) {
            arglen = i;
            break;
        }
    }

    if (!arglen || arglen < g_cmd_args[idx].min_ascii_arg_len || arglen > g_cmd_args[idx].max_ascii_arg_len)
        return;

    g_cmd_args[idx].ascii_arg = malloc(arglen + 1);
    if (g_cmd_args[idx].ascii_arg) {
        g_cmd_args[idx].ascii_arg[arglen] = 0;
        memcpy(g_cmd_args[idx].ascii_arg, arg, arglen);
        if (!memcmp(g_cmd_args[idx].ascii_arg, arg, arglen))
            g_cmd_args[idx].used = 1;
    }
}

#include "utils.c"

void parse_config(void* data_start, uint32_t data_size) {
    char* startconfig = data_start;
    char* endconfig = startconfig + data_size;

    char* current_line = startconfig;
    char* end_line = startconfig;
    int command_idx = 0;
    while (current_line < endconfig) {
        end_line = find_endline(current_line, endconfig);
        command_idx = get_command_idx(current_line, end_line);
        if (command_idx)
            prepare_command_by_idx(command_idx, current_line, end_line);
        current_line = find_nextline(end_line, endconfig);
        if (!current_line)
            break;
    }
}

int selftest(void);
int generate_config(char* dest, bool based, bool custom);

int dump_udi_blocks(void) {
    printf("dumping UDI\n");
    {
        void* tmp_data = malloc(0x800);
        uint8_t* udi = tmp_data + 0x600;
        uint8_t* cid_leaf = tmp_data;
        uint8_t* opsid_leaf_0 = tmp_data + 0x200;
        uint8_t* opsid_leaf_1 = tmp_data + 0x400;
        uint32_t tmp_crc;
        int ret = proxy_etoiRwLeaf(0, 0x44, cid_leaf, 0, &tmp_crc);
        if (!ret) {
            ret = proxy_etoiRwLeaf(0, 0x46, opsid_leaf_0, 0, &tmp_crc);
            if (!ret)
                ret = proxy_etoiRwLeaf(0, 0x47, opsid_leaf_1, 0, &tmp_crc);
        }
        if (ret) {
            free(tmp_data);
            psvDebugScreenSetFgColor(COLOR_RED);
            printf("get_udi_blocks FAILED : 0x%08X\n\n", ret);
            psvDebugScreenSetFgColor(COLOR_WHITE);
            press_exit();
            return -1;
        }
        memcpy(udi, cid_leaf + 0xA0, 0x100);
        memcpy(udi + 0x100, opsid_leaf_0 + 0x128, 0x100);
        int fd = sceIoOpen(UDI_OUTPUT_FILE, SCE_O_WRONLY | SCE_O_TRUNC | SCE_O_CREAT, 0777);
        if (fd < 0) {
            free(tmp_data);
            psvDebugScreenSetFgColor(COLOR_RED);
            printf("write_udi_blocks FAILED : 0x%08X\n\n", ret);
            psvDebugScreenSetFgColor(COLOR_WHITE);
            press_exit();
            return -1;
        }
        sceIoWrite(fd, udi, 0x200);
        sceIoClose(fd);
        free(tmp_data);
    }
    psvDebugScreenSetFgColor(COLOR_GREEN);
    printf("udi blocks dumped to %s\n\n", UDI_OUTPUT_FILE);
    psvDebugScreenSetFgColor(COLOR_WHITE);
    return 0;
}

int apply_config(void) {
    if (file_exists(CFG_INPUT_PATH)) {
        dispatch_table_to_garray();

        FILE* fp = fopen(CFG_INPUT_PATH, "rb");
        fseek(fp, 0, SEEK_END);
        uint32_t config_size = ftell(fp);
        rewind(fp);

        char* config = malloc(config_size);
        if (!config) {
            fclose(fp);
            printf("\nfailed to alloc for config reader\n");
            press_exit();
            return -1;
        }

        fread(config, config_size, 1, fp);
        fclose(fp);

        printf("parsing config\n");
        parse_config(config, config_size);
        printf("parsed\n{\n");

        int actually_used = 0;
        psvDebugScreenSetFgColor(COLOR_PURPLE);
        for (int i = 0; i < COMMAND_COUNT; i++) {
            if (g_cmd_args[i].used) {
                printf("%s = %s\n", valid_commands[i], (i >= CMD_NVS_OP0_INRAWH && i <= CMD_NVS_OP3_INRAWH) ? "[DATA]" : g_cmd_args[i].ascii_arg);
                actually_used = 1;
            }
        }
        psvDebugScreenSetFgColor(COLOR_WHITE);
        printf("}\n");

        if (!actually_used) {
            psvDebugScreenSetFgColor(COLOR_RED);
            printf("\nconfig empty?\n");
            psvDebugScreenSetFgColor(COLOR_WHITE);
            free(config);
            press_exit();
            return -1;
        }

        if (!g_cmd_args[CMD_INPUT].used) {
            psvDebugScreenSetFgColor(COLOR_RED);
            printf("\nno INPUT field!\n");
            psvDebugScreenSetFgColor(COLOR_WHITE);
            free(config);
            press_exit();
            return -1;
        }

        g_cmd_args[CMD_INPUT].cmd_handler(g_cmd_args[CMD_INPUT].ascii_arg);
        if (!DO_WRITE_CONFIG) {
            psvDebugScreenSetFgColor(COLOR_RED);
            printf("\nINPUT set to 'false' !\n");
            psvDebugScreenSetFgColor(COLOR_WHITE);
            free(config);
            press_exit();
            return -1;
        }

        sceKernelDelayThread(3 * 1000 * 1000);
        
        psvDebugScreenSetFgColor(COLOR_CYAN);
        printf("Press TRIANGLE to flash the configuration.\n");
        psvDebugScreenSetFgColor(COLOR_WHITE);
        if (get_key() == SCE_CTRL_TRIANGLE) {

            psvDebugScreenClear(COLOR_BLACK);
            psvDebugScreenSetFgColor(COLOR_BLUE);
            printf(PSP2ETOI_INFO);
            psvDebugScreenSetFgColor(COLOR_WHITE);

            printf("Generating a backup based on input.cfg... ");
            if (generate_config(CFG_BACKUP_PATH, true, false) == 0) {
                printf("OK!\nInstalling the new input.cfg\n");

                psvDebugScreenSetFgColor(COLOR_YELLOW);

                for (int i = 2; i < COMMAND_COUNT; i++) {
                    if (g_cmd_args[i].used && g_cmd_args[i].cmd_handler) {
                        printf("%s... ", valid_commands[i]);
                        CURRENT_CMD = i;
                        int ret = g_cmd_args[i].cmd_handler(g_cmd_args[i].ascii_arg);
                        if (ret) {
                            psvDebugScreenSetFgColor(COLOR_RED);
                            printf("FAILED : 0x%X\n", ret);
                            psvDebugScreenSetFgColor(COLOR_WHITE);
                            free(config);
                            press_exit();
                            return -1;
                        } else {
                            psvDebugScreenSetFgColor(COLOR_GREEN);
                            printf("OK => %s\n", g_cmd_args[i].ascii_arg);
                            psvDebugScreenSetFgColor(COLOR_YELLOW);
                        }
                    }
                }

                psvDebugScreenSetFgColor(COLOR_WHITE);

                printf("all done, cleaning\n");
            } else
                printf("FAILED!\nCleaning\n");
        }

        for (int i = 0; i < COMMAND_COUNT; i++) {
            if (g_cmd_args[i].used)
                free(g_cmd_args[i].ascii_arg);
        }

        free(config);

        press_exit_reboot();

        while (1) {};
    } else
        printf("input config not found!");
    return -1;
}

int create_config_from_req(void) {
    if (file_exists(CFG_INREQ_PATH)) {
        dispatch_table_to_garray();

        FILE* fp = fopen(CFG_INREQ_PATH, "rb");
        fseek(fp, 0, SEEK_END);
        uint32_t config_size = ftell(fp);
        rewind(fp);

        char* config = malloc(config_size);
        if (!config) {
            fclose(fp);
            printf("\nfailed to alloc for config reader\n");
            press_exit();
            return -1;
        }

        fread(config, config_size, 1, fp);
        fclose(fp);

        printf("parsing config\n");
        parse_config(config, config_size);
        printf("parsed\n{\n");

        int actually_used = 0;
        psvDebugScreenSetFgColor(COLOR_PURPLE);
        for (int i = 0; i < COMMAND_COUNT; i++) {
            if (g_cmd_args[i].used) {
                printf("%s = %s\n", valid_commands[i], (i >= CMD_NVS_OP0_INRAWH && i <= CMD_NVS_OP3_INRAWH) ? "[DATA]" : g_cmd_args[i].ascii_arg);
                actually_used = 1;
            }
        }
        psvDebugScreenSetFgColor(COLOR_WHITE);
        printf("}\n");

        if (!actually_used) {
            psvDebugScreenSetFgColor(COLOR_RED);
            printf("\nconfig empty?\n");
            psvDebugScreenSetFgColor(COLOR_WHITE);
            free(config);
            press_exit();
            return -1;
        }

        if (!g_cmd_args[CMD_INPUT].used) {
            psvDebugScreenSetFgColor(COLOR_RED);
            printf("\nno INPUT field!\n");
            psvDebugScreenSetFgColor(COLOR_WHITE);
            free(config);
            press_exit();
            return -1;
        }

        g_cmd_args[CMD_INPUT].cmd_handler(g_cmd_args[CMD_INPUT].ascii_arg);
        if (DO_WRITE_CONFIG) {
            psvDebugScreenSetFgColor(COLOR_RED);
            printf("\nINPUT set to 'true' !\n");
            psvDebugScreenSetFgColor(COLOR_WHITE);
            free(config);
            press_exit();
            return -1;
        }

        psvDebugScreenClear(COLOR_BLACK);
        psvDebugScreenSetFgColor(COLOR_BLUE);
        printf(PSP2ETOI_INFO);
        psvDebugScreenSetFgColor(COLOR_WHITE);

        printf("Generating a configuration based on input.req... ");
        if (generate_config(CFG_CUSTOM_PATH, true, true) == 0)
            printf("all done, cleaning\n");
        else
            printf("FAILED!\nCleaning\n");

        for (int i = 0; i < COMMAND_COUNT; i++) {
            if (g_cmd_args[i].used)
                free(g_cmd_args[i].ascii_arg);
        }

        free(config);

        press_exit_reboot();

        while (1) {};
    } else
        printf("input config not found!");
    return -1;
}

int create_backup(void) {
    printf("generating output config\n");
    int ret = generate_config(CFG_OUTPUT_PATH, false, false);
    if (ret) {
        psvDebugScreenSetFgColor(COLOR_RED);
        printf("gen_config FAILED : 0x%08X\n\n", ret);
        psvDebugScreenSetFgColor(COLOR_WHITE);
        press_exit();
        return -1;
    }

    psvDebugScreenSetFgColor(COLOR_GREEN);
    printf("output config generated @ %s\n\n", CFG_OUTPUT_PATH);
    psvDebugScreenSetFgColor(COLOR_WHITE);
    return 0;
}

void draw_main_menu(int sel) {
    psvDebugScreenClear(COLOR_BLACK);
    psvDebugScreenSetFgColor(COLOR_BLUE);
    printf(PSP2ETOI_INFO);
    psvDebugScreenSetFgColor(COLOR_WHITE);
    for (int i = MENU_APPLY_INPUTCFG; i < MENU_END; i++) {
        if (sel == i)
            psvDebugScreenSetFgColor(COLOR_PURPLE);
        printf("%s\n", main_opt_str[i]);
        psvDebugScreenSetFgColor(COLOR_WHITE);
    }
    psvDebugScreenSetFgColor(COLOR_WHITE);
}

int main() {
    tai_module_args_t argg;
    argg.size = sizeof(argg);
    argg.pid = KERNEL_PID;
    argg.args = 0;
    argg.argp = NULL;
    argg.flags = 0;
    taiLoadStartKernelModuleForUser("ux0:app/SKGPP2E2I/psp2spl.skprx", &argg);
    
    memset(&argg, 0, sizeof(argg));
    argg.size = sizeof(argg);
    argg.pid = KERNEL_PID;
    argg.args = 0;
    argg.argp = NULL;
    argg.flags = 0;
    SceUID mod_id = taiLoadStartKernelModuleForUser("ux0:app/SKGPP2E2I/psp2etoi.skprx", &argg);
    if (mod_id > 0)
        sceAppMgrLoadExec("app0:eboot.bin", NULL, NULL);

    psvDebugScreenInit();

    sceIoMkdir(PSP2ETOI_DIR, 0777);

    psvDebugScreenClear(COLOR_BLACK);
    psvDebugScreenSetFgColor(COLOR_BLUE);
    printf(PSP2ETOI_INFO);
    psvDebugScreenSetFgColor(COLOR_WHITE);

    psvDebugScreenSetFgColor(COLOR_RED);
    printf("This software will make PERMANENT modifications to your Vita\nIf anything goes wrong, there is NO RECOVERY.\n\n");
    psvDebugScreenSetFgColor(COLOR_GREEN);
    printf("\n\n -> I understood, continue.\n\n");
    psvDebugScreenSetFgColor(COLOR_WHITE);
    if (get_key() != SCE_CTRL_CROSS) {
        press_exit();
    }

    psvDebugScreenClear(COLOR_BLACK);
    psvDebugScreenSetFgColor(COLOR_BLUE);
    printf(PSP2ETOI_INFO);
    psvDebugScreenSetFgColor(COLOR_WHITE);

    int ret = selftest();
    if (ret) {
        psvDebugScreenSetFgColor(COLOR_RED);
        printf("\nselftest FAILED : 0x%08X\n\n", ret);
        psvDebugScreenSetFgColor(COLOR_WHITE);
        press_exit();
        return -1;
    }

    psvDebugScreenSetFgColor(COLOR_GREEN);
    printf("\nselftest PASSED\n\n");
    psvDebugScreenSetFgColor(COLOR_WHITE);

    sceKernelDelayThread(1000 * 1000);

    int sel = 0;
    SceCtrlData pad;
    draw_main_menu(sel);
    while (1) {
        sceCtrlPeekBufferPositive(0, &pad, 1);
        if (pad.buttons == SCE_CTRL_CROSS) {
            switch (sel) {
            case MENU_APPLY_INPUTCFG:
                apply_config();
                sceKernelDelayThread(3 * 1000 * 1000);
                sel = MENU_EXIT;
                draw_main_menu(sel);
                break;
            case MENU_CREATE_INPUTCFG:
                create_config_from_req();
                sceKernelDelayThread(3 * 1000 * 1000);
                sel = MENU_EXIT;
                draw_main_menu(sel);
                break;
            case MENU_DUMP_INPUTCFG:
                create_backup();
                sceKernelDelayThread(3 * 1000 * 1000);
                sel = MENU_EXIT;
                draw_main_menu(sel);
                break;
            case MENU_DUMP_UDI:
                dump_udi_blocks();
                sceKernelDelayThread(3 * 1000 * 1000);
                sel = MENU_EXIT;
                draw_main_menu(sel);
                break;
            default:
                sceKernelExitProcess(0);
                break;
            }
        } else if (pad.buttons == SCE_CTRL_UP) {
            if (sel != 0)
                sel--;
            draw_main_menu(sel);
            sceKernelDelayThread(0.3 * 1000 * 1000);
        } else if (pad.buttons == SCE_CTRL_DOWN) {
            if (sel + 1 < MENU_END)
                sel++;
            draw_main_menu(sel);
            sceKernelDelayThread(0.3 * 1000 * 1000);
        }
    }

    press_exit_reboot();

    return 0;
}

static uint8_t g_selftest_buf[0x400]; // lets have it ready

int selftest(void) {
    printf("starting selftest\n");
    int ret = -1;
    uint8_t udi_block[0x100];
    { // CID test
        uint8_t* leaf = g_selftest_buf + 0x200;
        memset(leaf, 0, 0x200);
        memset(udi_block, 0, 0x100);
        uint32_t current_leaf_crc = 0;
        printf("reading cid leaf from idstorage...\n");
        if (proxy_etoiRwLeaf(0, 0x44, leaf, 0, &current_leaf_crc) || crc32(0, leaf, 0x200) != current_leaf_crc)
            return ret;

        ret = -2;
        printf("validating cid...\n");
        if (validate_cid(leaf + 0xA0))
            return ret;

        ret = -3;
        memcpy(udi_block, leaf + 0xA0, 0x100);
        uint32_t gen_udi_crc = 0;
        uint32_t current_udi_crc = crc32(0, udi_block, 0x100);
        printf("encrypting the cid udi block...\n");
        if (etoiEncryptUDIBlock(udi_block, current_udi_crc, &gen_udi_crc)
            || crc32(0, udi_block, 0x100) != gen_udi_crc) return ret;

        ret = -4;
        printf("comparing cid udi block with prev...\n");
        if (gen_udi_crc != current_udi_crc)
            return ret;

        hexdump(udi_block, 0x100);
    }
    ret = -5;
    { // opsid test
        uint8_t* leafs = g_selftest_buf;
        memset(leafs, 0, 0x400);
        memset(udi_block, 0, 0x100);
        uint32_t current_leaf_crc = 0;
        printf("reading openpsid leaf from idstorage [1]...\n");
        if (proxy_etoiRwLeaf(0, 0x46, leafs, 0, &current_leaf_crc) || crc32(0, leafs, 0x200) != current_leaf_crc)
            return ret;

        ret = -6;
        current_leaf_crc = 0;
        printf("reading openpsid leaf from idstorage [2]...\n");
        if (proxy_etoiRwLeaf(0, 0x47, leafs + 0x200, 0, &current_leaf_crc) || crc32(0, leafs + 0x200, 0x200) != current_leaf_crc)
            return ret;

        ret = -7;
        memcpy(udi_block, leafs + 0x128, 0x100);
        uint32_t gen_udi_crc = 0;
        uint32_t current_udi_crc = crc32(0, udi_block, 0x100);
        printf("encrypting the openpsid udi block...\n");
        if (etoiEncryptUDIBlock(udi_block, current_udi_crc, &gen_udi_crc)
            || crc32(0, udi_block, 0x100) != gen_udi_crc) return ret;

        ret = -8;
        printf("comparing openpsid udi block with prev...\n");
        if (gen_udi_crc != current_udi_crc)
            return ret;

        hexdump(udi_block, 0x100);
    }
    ret = -6;
    { // mgmt data test
        uint32_t mgmt_flags = 0, mgmt_status = 0;
        printf("getting mgmt data...\n");
        if (proxy_etoiGsManagementData(0, 0, 0, &mgmt_flags, &mgmt_status))
            return ret;

        sceClibPrintf("mgmt data: 0x%08X | 0x%08X\n", mgmt_flags, mgmt_status);
    }
    ret = -7;
    { // snvs read test
        uint8_t snvs_test_data[0x20];
        memset(snvs_test_data, 0, 0x20);
        uint32_t snvs_test_data_crc = 0;
        printf("getting snvs sector 0...\n");
        if (proxy_etoiNvsRwSecure(0, 0, snvs_test_data, 0, &snvs_test_data_crc)
            || crc32(0, snvs_test_data, 0x20) != snvs_test_data_crc) return ret;

        hexdump(snvs_test_data, 0x20);
    }
    ret = -8;
    { // nvs read test
        uint8_t nvs_test_data[0x20];
        memset(nvs_test_data, 0, 0x20);
        uint32_t nvs_test_data_crc = 0;
        printf("getting nvs sector 0x500...\n");
        if (proxy_etoiNvsRw(0, 0x500, nvs_test_data, 0x20, 0, &nvs_test_data_crc)
            || crc32(0, nvs_test_data, 0x20) != nvs_test_data_crc) return ret;

        hexdump(nvs_test_data, 0x20);
    }
    printf("self test finished!\n");
    memset(g_selftest_buf, 0, 0x400);
    return 0;
}

int get_nvs_from_ascii_args(uint8_t* nvs, char* ascii_offset, char* ascii_size, char* output, uint32_t* crc_out, bool ascii_out) {
    if (!nvs || !ascii_offset || !ascii_size || !output || !crc_out)
        return -20;
    
    // get offset
    uint16_t offset = 0;
    if (antoh(ascii_offset + 2, &offset, 2))
        return -21;
    offset = BSWAP16(offset);

    // get size
    uint16_t size = 0;
    if (antoh(ascii_size + 2, &size, 2))
        return -24;
    size = BSWAP16(size);

    // check offset/size args
    if ((offset < 0x400 && offset % 0x20) || (offset >= 0x400 && offset % 0x10))
        return -27;

    if ((offset < 0x400 && size % 0x20) || (offset >= 0x400 && size % 0x10))
        return -28;

    if (offset < 0x400 && (offset + size) > 0x400)
        return -29;

    if (ascii_out) {
        if (hntoa(nvs + offset, output, size * 2))
            return -30;
    } else {
        int fd = sceIoOpen(output, SCE_O_WRONLY | SCE_O_TRUNC | SCE_O_CREAT, 0777);
        if (fd < 0)
            return -31;
        sceIoWrite(fd, nvs + offset, size);
        sceIoClose(fd);
    }

    *crc_out = crc32(0, nvs + offset, size);

    return 0;
}

int generate_config(char* dest, bool based, bool custom) {
    uint8_t* tmp_buf = malloc(0x1000);
    if (!tmp_buf)
        return -1;

    int ret = -1;
    
    char* custom_nvs_out = NULL;
    
    char* config = malloc(0x4000);
    if (!config)
        goto CFG_FREEXIT;

    if (custom) {
        custom_nvs_out = malloc(0x1800);
        if (!custom_nvs_out)
            goto CFG_FREEXIT;
    }

    memset(tmp_buf, 0, 0x1000);

    ret = -2;
    uint8_t cid[0x10];
    { // get ConsoleID
        uint32_t tmp_crc;
        uint8_t* tmp_leaf = tmp_buf + 0xE00;
        if (proxy_etoiRwLeaf(0, 0x44, tmp_leaf, 0, &tmp_crc))
            goto CFG_FREEXIT;
        memcpy(cid, tmp_leaf + 0xA0, 0x10);
    }
    ret = -3;
    uint8_t opsid[0x10];
    { // get OpenPSID
        uint32_t tmp_crc;
        uint8_t* tmp_leaf = tmp_buf + 0xE00;
        if (proxy_etoiRwLeaf(0, 0x46, tmp_leaf, 0, &tmp_crc))
            goto CFG_FREEXIT;
        memcpy(opsid, tmp_leaf + 0x128, 0x10);
    }
    ret = -4;
    uint32_t mgmt_flags = 0;
    uint32_t mgmt_status = 0;
    { // get mgmt data
        if (proxy_etoiGsManagementData(0, 0, 0, &mgmt_flags, &mgmt_status))
            goto CFG_FREEXIT;
    }
    ret = -5;
    uint8_t* nvs = tmp_buf;
    uint16_t nvs_offset, nvs_size;
    uint32_t nvs_crc;
    { // get nvs
        uint32_t tmp_crc;
        for (int i = 0; i < 0x20; i++) {
            if (proxy_etoiNvsRwSecure(0, i, nvs + (i * 0x20), 0, &tmp_crc))
                goto CFG_FREEXIT;
        }
        if (proxy_etoiNvsRw(0, 0x400, nvs + 0x400, 0x760, 0, &tmp_crc))
            goto CFG_FREEXIT;
        nvs_offset = 0;
        nvs_size = 0xB60;
        nvs_crc = crc32(0, nvs, nvs_size);
    }
    if (!based) {
        ret = -7;
        { // writeout nvs
            int fd = sceIoOpen(NVS_OUTPUT_FILE, SCE_O_WRONLY | SCE_O_TRUNC | SCE_O_CREAT, 0777);
            if (fd < 0)
                goto CFG_FREEXIT;
            sceIoWrite(fd, nvs, nvs_size);
            sceIoClose(fd);
        }
    }
    ret = -9;
    { // create the config
        memset(config, 0, 0x4000);
        char* pen = config;
        char* cid_ascii = tmp_buf + 0xC00;
        char* opsid_ascii = tmp_buf + 0xC40;

        // header
#define CFG_START_INFO "# psp2etoi configuration file\r\n"
        memcpy(pen, CFG_START_INFO, strlen(CFG_START_INFO));
        pen += strlen(CFG_START_INFO);

        // input
        snprintf(pen, 0x1000, "#-- -- Config type -- --\r\n%s=%s # If set, the config is written to the device\r\n", valid_commands[CMD_INPUT], "false");
        pen += strlen(pen);

        memcpy(pen, "\r\n", strlen("\r\n"));
        pen += strlen("\r\n");

        // ConsoleID
        if (!based || g_cmd_args[CMD_ConsoleID].used || g_cmd_args[CMD_DeviceType].used) {
#define CFG_CID_WARNING_STRING "#-- -- Console ID -- ---\r\n# WARNING: Editing the ConsoleID may render the device unusable\r\n"
            memcpy(pen, CFG_CID_WARNING_STRING, strlen(CFG_CID_WARNING_STRING));
            pen += strlen(CFG_CID_WARNING_STRING);
            if (!based || g_cmd_args[CMD_ConsoleID].used) {
                hntoa(cid, cid_ascii, 0x20);
                cid_ascii[0x20] = 0;
                snprintf(pen, 0x1000, "%s=%s\r\n", valid_commands[CMD_ConsoleID], cid_ascii);
                pen += strlen(pen);
            }
            if (!based || g_cmd_args[CMD_DeviceType].used) {
                snprintf(pen, 0x1000, "%s%s=0x%02X # 0x00: internal, 0x01: DevKit, 0x02: TestKit, 0x03-0x11: Retail\r\n", based ? "" : "#", valid_commands[CMD_DeviceType], cid[5]);
                pen += strlen(pen);
            }
            memcpy(pen, "\r\n", strlen("\r\n"));
            pen += strlen("\r\n");
        }

        // OpenPSID
        if (!based || g_cmd_args[CMD_OpenPSID].used) {
            hntoa(opsid, opsid_ascii, 0x20);
            opsid_ascii[0x20] = 0;
            snprintf(pen, 0x1000, "#-- -- OpenPSID -- ---\r\n%s=%s\r\n", valid_commands[CMD_OpenPSID], opsid_ascii);
            pen += strlen(pen);

            memcpy(pen, "\r\n", strlen("\r\n"));
            pen += strlen("\r\n");
        }

        // mgmt flags
        if (!based || g_cmd_args[CMD_mgmtFlags].used || g_cmd_args[CMD_SoftwareProductingMode].used || g_cmd_args[CMD_VCSlotProductingMode].used) {
#define CFG_MGMTFLAGS_STRING "#-- Management Flags ---\r\n"
            memcpy(pen, CFG_MGMTFLAGS_STRING, strlen(CFG_MGMTFLAGS_STRING));
            pen += strlen(CFG_MGMTFLAGS_STRING);
            if (!based || g_cmd_args[CMD_mgmtFlags].used) {
                snprintf(pen, 0x1000, "%s%s=0x%08X\r\n", based ? "" : "#", valid_commands[CMD_mgmtFlags], ~mgmt_flags);
                pen += strlen(pen);
            }
            if (!based || g_cmd_args[CMD_SoftwareProductingMode].used) {
                snprintf(pen, 0x1000, "%s=%s # false: Manufacturing Mode, true: Producting Mode\r\n", valid_commands[CMD_SoftwareProductingMode], (~mgmt_flags & 1) ? "true" : "false");
                pen += strlen(pen);
            }
            if (!based || g_cmd_args[CMD_VCSlotProductingMode].used) {
                snprintf(pen, 0x1000, "%s=%s # false: SD card mode, true: Vita card mode\r\n", valid_commands[CMD_VCSlotProductingMode], (~mgmt_flags & 2) ? "true" : "false");
                pen += strlen(pen);
            }

            memcpy(pen, "\r\n", strlen("\r\n"));
            pen += strlen("\r\n");
        }

        // mgmt status
        if (!based || g_cmd_args[CMD_mgmtStatus].used || g_cmd_args[CMD_isSnvsInitialized].used || g_cmd_args[CMD_isQaFlagged].used) {
#define CFG_MGMTSTATUS_WARNING_STRING "#-- Management Status --\r\n# WARNING: Editing the mgmt status may render the device unusable\r\n"
            memcpy(pen, CFG_MGMTSTATUS_WARNING_STRING, strlen(CFG_MGMTSTATUS_WARNING_STRING));
            pen += strlen(CFG_MGMTSTATUS_WARNING_STRING);
            if (!based || g_cmd_args[CMD_mgmtStatus].used) {
                snprintf(pen, 0x1000, "%s%s=0x%08X\r\n", based ? "" : "#", valid_commands[CMD_mgmtStatus], ~mgmt_status);
                pen += strlen(pen);
            }
            if (!based || g_cmd_args[CMD_isSnvsInitialized].used) {
                snprintf(pen, 0x1000, "%s=%s # if not set, firmware checks are skipped and SNVS reset\r\n", valid_commands[CMD_isSnvsInitialized], (~mgmt_status & 1) ? "true" : "false");
                pen += strlen(pen);
            }
            if (!based || g_cmd_args[CMD_isQaFlagged].used) {
                snprintf(pen, 0x1000, "%s=%s # if not set, SL will ignore the QA flags\r\n", valid_commands[CMD_isQaFlagged], (~mgmt_status & 2) ? "true" : "false");
                pen += strlen(pen);
            }

            memcpy(pen, "\r\n", strlen("\r\n"));
            pen += strlen("\r\n");
        }

        // nvs data r/w
        if (!based || g_cmd_args[CMD_NVS_OP0_OFFSET].used) {
#define CFG_SNVS_WARNING_STRING "#-- NVS data R/W --\r\n# WARNING: Editing the s/nvs may render the device unusable\r\n# NOTE: SNVS (0-0x400) and NVS (0x400-0xB60) must be addressed separately in input config\r\n"
            memcpy(pen, CFG_SNVS_WARNING_STRING, strlen(CFG_SNVS_WARNING_STRING));
            pen += strlen(CFG_SNVS_WARNING_STRING);
            if (based) {
                uint32_t based_nvs_crc;
                if (g_cmd_args[CMD_NVS_OP0_OFFSET].used) {
                    if (custom)
                        memset(custom_nvs_out, 0, 0x1800);
                    if (get_nvs_from_ascii_args(nvs, g_cmd_args[CMD_NVS_OP0_OFFSET].ascii_arg, g_cmd_args[CMD_NVS_OP0_RWSIZE].ascii_arg, (custom) ? custom_nvs_out : BACKUP_NVS_OP0_FILE, &based_nvs_crc, custom))
                        goto CFG_FREEXIT;
                    snprintf(pen, 0x1000, "%s=%s\r\n", valid_commands[CMD_NVS_OP0_OFFSET], g_cmd_args[CMD_NVS_OP0_OFFSET].ascii_arg);
                    pen += strlen(pen);
                    snprintf(pen, 0x1000, "%s=%s\r\n", valid_commands[CMD_NVS_OP0_RWSIZE], g_cmd_args[CMD_NVS_OP0_RWSIZE].ascii_arg);
                    pen += strlen(pen);
                    snprintf(pen, 0x1000, "%s=0x%08X\r\n", valid_commands[CMD_NVS_OP0_BUFCRC], based_nvs_crc);
                    pen += strlen(pen);
                    if (custom)
                        snprintf(pen, 0x4000, "%s=%s\r\n", valid_commands[CMD_NVS_OP0_INRAWH], custom_nvs_out);
                    else
                        snprintf(pen, 0x1000, "%s=%s\r\n", valid_commands[CMD_NVS_OP0_IOFILE], BACKUP_NVS_OP0_FILE);
                    pen += strlen(pen);
                }
                if (g_cmd_args[CMD_NVS_OP1_OFFSET].used) {
                    if (custom)
                        memset(custom_nvs_out, 0, 0x1800);
                    if (get_nvs_from_ascii_args(nvs, g_cmd_args[CMD_NVS_OP1_OFFSET].ascii_arg, g_cmd_args[CMD_NVS_OP1_RWSIZE].ascii_arg, (custom) ? custom_nvs_out : BACKUP_NVS_OP1_FILE, &based_nvs_crc, custom))
                        goto CFG_FREEXIT;
                    snprintf(pen, 0x1000, "%s=%s\r\n", valid_commands[CMD_NVS_OP1_OFFSET], g_cmd_args[CMD_NVS_OP1_OFFSET].ascii_arg);
                    pen += strlen(pen);
                    snprintf(pen, 0x1000, "%s=%s\r\n", valid_commands[CMD_NVS_OP1_RWSIZE], g_cmd_args[CMD_NVS_OP1_RWSIZE].ascii_arg);
                    pen += strlen(pen);
                    snprintf(pen, 0x1000, "%s=0x%08X\r\n", valid_commands[CMD_NVS_OP1_BUFCRC], based_nvs_crc);
                    pen += strlen(pen);
                    if (custom)
                        snprintf(pen, 0x4000, "%s=%s\r\n", valid_commands[CMD_NVS_OP1_INRAWH], custom_nvs_out);
                    else
                        snprintf(pen, 0x1000, "%s=%s\r\n", valid_commands[CMD_NVS_OP1_IOFILE], BACKUP_NVS_OP1_FILE);
                    pen += strlen(pen);
                }
                if (g_cmd_args[CMD_NVS_OP2_OFFSET].used) {
                    if (custom)
                        memset(custom_nvs_out, 0, 0x1800);
                    if (get_nvs_from_ascii_args(nvs, g_cmd_args[CMD_NVS_OP2_OFFSET].ascii_arg, g_cmd_args[CMD_NVS_OP2_RWSIZE].ascii_arg, (custom) ? custom_nvs_out : BACKUP_NVS_OP2_FILE, &based_nvs_crc, custom))
                        goto CFG_FREEXIT;
                    snprintf(pen, 0x1000, "%s=%s\r\n", valid_commands[CMD_NVS_OP2_OFFSET], g_cmd_args[CMD_NVS_OP2_OFFSET].ascii_arg);
                    pen += strlen(pen);
                    snprintf(pen, 0x1000, "%s=%s\r\n", valid_commands[CMD_NVS_OP2_RWSIZE], g_cmd_args[CMD_NVS_OP2_RWSIZE].ascii_arg);
                    pen += strlen(pen);
                    snprintf(pen, 0x1000, "%s=0x%08X\r\n", valid_commands[CMD_NVS_OP2_BUFCRC], based_nvs_crc);
                    pen += strlen(pen);
                    if (custom)
                        snprintf(pen, 0x4000, "%s=%s\r\n", valid_commands[CMD_NVS_OP2_INRAWH], custom_nvs_out);
                    else
                        snprintf(pen, 0x1000, "%s=%s\r\n", valid_commands[CMD_NVS_OP2_IOFILE], BACKUP_NVS_OP2_FILE);
                    pen += strlen(pen);
                }
                if (g_cmd_args[CMD_NVS_OP3_OFFSET].used) {
                    if (custom)
                        memset(custom_nvs_out, 0, 0x1800);
                    if (get_nvs_from_ascii_args(nvs, g_cmd_args[CMD_NVS_OP3_OFFSET].ascii_arg, g_cmd_args[CMD_NVS_OP3_RWSIZE].ascii_arg, (custom) ? custom_nvs_out : BACKUP_NVS_OP3_FILE, &based_nvs_crc, custom))
                        goto CFG_FREEXIT;
                    snprintf(pen, 0x1000, "%s=%s\r\n", valid_commands[CMD_NVS_OP3_OFFSET], g_cmd_args[CMD_NVS_OP3_OFFSET].ascii_arg);
                    pen += strlen(pen);
                    snprintf(pen, 0x1000, "%s=%s\r\n", valid_commands[CMD_NVS_OP3_RWSIZE], g_cmd_args[CMD_NVS_OP3_RWSIZE].ascii_arg);
                    pen += strlen(pen);
                    snprintf(pen, 0x1000, "%s=0x%08X\r\n", valid_commands[CMD_NVS_OP3_BUFCRC], based_nvs_crc);
                    pen += strlen(pen);
                    if (custom)
                        snprintf(pen, 0x4000, "%s=%s\r\n", valid_commands[CMD_NVS_OP3_INRAWH], custom_nvs_out);
                    else
                        snprintf(pen, 0x1000, "%s=%s\r\n", valid_commands[CMD_NVS_OP3_IOFILE], BACKUP_NVS_OP3_FILE);
                    pen += strlen(pen);
                }
            } else {
                snprintf(pen, 0x1000, "%s=0x%04X # aligned to 0x20 for snvs, 0x10 for nvs\r\n", valid_commands[CMD_NVS_OP0_OFFSET], nvs_offset);
                pen += strlen(pen);
                snprintf(pen, 0x1000, "%s=0x%04X # aligned to 0x20 for snvs, 0x10 for nvs\r\n", valid_commands[CMD_NVS_OP0_RWSIZE], nvs_size);
                pen += strlen(pen);
                snprintf(pen, 0x1000, "%s=0x%08X # uint32 data crc32\r\n", valid_commands[CMD_NVS_OP0_BUFCRC], nvs_crc);
                pen += strlen(pen);
                snprintf(pen, 0x1000, "%s=%s\r\n", valid_commands[CMD_NVS_OP0_IOFILE], NVS_OUTPUT_FILE);
                pen += strlen(pen);
            }
        }
    }
    ret = -10;
    { // writeout config
        int fd = sceIoOpen(dest, SCE_O_WRONLY | SCE_O_TRUNC | SCE_O_CREAT, 0777);
        if (fd < 0)
            goto CFG_FREEXIT;
        sceIoWrite(fd, config, strlen(config));
        sceIoClose(fd);
    }

    ret = 0;

CFG_FREEXIT:
    free(tmp_buf);
    if (config)
        free(config);
    if (custom_nvs_out)
        free(custom_nvs_out);
    return ret;
}