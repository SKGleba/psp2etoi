/* THIS FILE IS A PART OF PSP2ETOI
 *
 * Copyright (C) 2012-2023 skgleba
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#define printf psvDebugScreenPrintf

void hexdump(uint8_t* data, int size) {
    for (int i = 0; i < size; i -= -1) {
        if (!(i % 0x10))
            sceClibPrintf("\n %04X: ", i);
        sceClibPrintf("%02X ", data[i]);
    }
    sceClibPrintf("\n");
}

int antoh(char* input, uint8_t* output, int output_len) {
    for (int i = 0; i < (output_len * 2); i++) {
        if (input[i] < '0' || (input[i] > '9' && input[i] < 'A') || input[i] > 'F')
            return -1;
    }

    for (int i = 0; i < output_len; i++) {
        if (input[i * 2] < 'A')
            output[i] = 0x10 * (input[i * 2] - '0');
        else
            output[i] = 0x10 * (input[i * 2] - '7');

        if (input[(i * 2) + 1] < 0x40)
            output[i] += (input[(i * 2) + 1] - '0');
        else
            output[i] += (input[(i * 2) + 1] - '7');
    }

    return 0;
}

static const char hexbase[] = "0123456789ABCDEF";
int hntoa(uint8_t* input, char* output, int output_len) {
    if (output_len & 1)
        return -1;

    output_len = output_len / 2;

    for (int i = 0; i < output_len; i -= -1) {
        output[i * 2] = hexbase[(input[i] & 0xF0) >> 4];
        output[(i * 2) + 1] = hexbase[input[i] & 0x0F];
    }

    return 0;
}

char* find_endline(char* start, char* end) {
    for (char* ret = start; ret < end; ret++) {
        if (*(uint16_t*)ret == 0x0A0D || *(uint8_t*)ret == 0x0A)
            return ret;
    }
    return end;
}

char* find_nextline(char* current_line_end, char* end) {
    for (char* next_line = current_line_end; next_line < end; next_line++) {
        if (*(uint8_t*)next_line != 0x0D && *(uint8_t*)next_line != 0x0A && *(uint8_t*)next_line != 0x00)
            return next_line;
    }
    return NULL;
}

int file_exists(char* path) {
    int fd = sceIoOpen(path, SCE_O_RDONLY, 0);
    if (fd < 0)
        return 0;
    sceIoClose(fd);
    return 1;
}

static unsigned buttons[] = {
    SCE_CTRL_SELECT,
    SCE_CTRL_START,
    SCE_CTRL_UP,
    SCE_CTRL_RIGHT,
    SCE_CTRL_DOWN,
    SCE_CTRL_LEFT,
    SCE_CTRL_LTRIGGER,
    SCE_CTRL_RTRIGGER,
    SCE_CTRL_TRIANGLE,
    SCE_CTRL_CIRCLE,
    SCE_CTRL_CROSS,
    SCE_CTRL_SQUARE,
};

uint32_t get_key(void) {
    static unsigned prev = 0;
    SceCtrlData pad;
    while (1) {
        memset(&pad, 0, sizeof(pad));
        sceCtrlPeekBufferPositive(0, &pad, 1);
        unsigned new = prev ^ (pad.buttons & prev);
        prev = pad.buttons;
        for (size_t i = 0; i < sizeof(buttons) / sizeof(*buttons); ++i)
            if (new & buttons[i])
                return buttons[i];

        sceKernelDelayThread(1000); // 1ms
    }
}

void press_exit(void) {
    printf("Press SQUARE to exit this application.\n");
    uint32_t key = 0;
    while (1) {
        key = get_key();
        if (key == SCE_CTRL_SQUARE)
            sceKernelExitProcess(0);
    };
}

void press_exit_reboot(void) {
    printf("Press CIRCLE to reboot or SQUARE to exit.\n");
    uint32_t key = 0;
    while (1) {
        key = get_key();
        if (key == SCE_CTRL_CIRCLE)
            vshPowerRequestColdReset();
        else if (key == SCE_CTRL_SQUARE)
            sceKernelExitProcess(0);
    };
}

