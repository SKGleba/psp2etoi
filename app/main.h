#define PSP2ETOI_INFO "------------------------->\npsp2etoi v1.0.0 by skgleba\n------------------------->\n\n"

#define BSWAP16(x) (((x << 8) & 0xff00) | ((x >> 8) & 0x00ff))
#define BSWAP32(x) (((x << 24) & 0xff000000 ) | ((x <<  8) & 0x00ff0000 ) | ((x >>  8) & 0x0000ff00 ) | ((x >> 24) & 0x000000ff ))

#define PSP2ETOI_DIR "ux0:data/psp2etoi"
#define CFG_INPUT_PATH "ux0:data/psp2etoi/input.cfg"
#define CFG_INREQ_PATH "ux0:data/psp2etoi/input.req"
#define CFG_OUTPUT_PATH "ux0:data/psp2etoi/output.cfg"
#define UDI_OUTPUT_FILE "ux0:data/psp2etoi/udi.bin"
#define NVS_OUTPUT_FILE "ux0:data/psp2etoi/nvs.bin"
#define CFG_BACKUP_PATH "ux0:data/psp2etoi/backup_input.cfg"
#define CFG_CUSTOM_PATH "ux0:data/psp2etoi/custom_input.cfg"
#define BACKUP_NVS_OP0_FILE "ux0:data/psp2etoi/backup_nvs_op0.bin"
#define BACKUP_NVS_OP1_FILE "ux0:data/psp2etoi/backup_nvs_op1.bin"
#define BACKUP_NVS_OP2_FILE "ux0:data/psp2etoi/backup_nvs_op2.bin"
#define BACKUP_NVS_OP3_FILE "ux0:data/psp2etoi/backup_nvs_op3.bin"

enum MENU_OPTIONS {
    MENU_APPLY_INPUTCFG = 0,
    MENU_CREATE_INPUTCFG,
    MENU_DUMP_INPUTCFG,
    MENU_DUMP_UDI,
    MENU_EXIT,
    MENU_END
};
static char* main_opt_str[] = { " -> Apply a custom device configuration", " -> Create a custom device configuration", " -> Dump the current device configuration", " -> Backup the current Unique Device Indentifiers", " -> Exit" };

#define COMMAND_COUNT 31

const char* valid_commands[COMMAND_COUNT] = {
    "INVALID",
    "INPUT",
    "ConsoleID",
    "OpenPSID",
    "DeviceType",
    "mgmtFlags",
    "SoftwareProductingMode",
    "VCSlotProductingMode",
    "mgmtStatus",
    "isSnvsInitialized",
    "isQaFlagged",
    "NVS_OP0_OFFSET",
    "NVS_OP1_OFFSET",
    "NVS_OP2_OFFSET",
    "NVS_OP3_OFFSET",
    "NVS_OP0_RWSIZE",
    "NVS_OP1_RWSIZE",
    "NVS_OP2_RWSIZE",
    "NVS_OP3_RWSIZE",
    "NVS_OP0_IOFILE",
    "NVS_OP1_IOFILE",
    "NVS_OP2_IOFILE",
    "NVS_OP3_IOFILE",
    "NVS_OP0_BUFCRC",
    "NVS_OP1_BUFCRC",
    "NVS_OP2_BUFCRC",
    "NVS_OP3_BUFCRC",
    "NVS_OP0_INRAWH",
    "NVS_OP1_INRAWH",
    "NVS_OP2_INRAWH",
    "NVS_OP3_INRAWH",
};

enum CMD_ENUMS {
    CMD_INVALID = 0,
    CMD_INPUT,
    CMD_ConsoleID,
    CMD_OpenPSID,
    CMD_DeviceType,
    CMD_mgmtFlags,
    CMD_SoftwareProductingMode,
    CMD_VCSlotProductingMode,
    CMD_mgmtStatus,
    CMD_isSnvsInitialized,
    CMD_isQaFlagged,
    CMD_NVS_OP0_OFFSET,
    CMD_NVS_OP1_OFFSET,
    CMD_NVS_OP2_OFFSET,
    CMD_NVS_OP3_OFFSET,
    CMD_NVS_OP0_RWSIZE,
    CMD_NVS_OP1_RWSIZE,
    CMD_NVS_OP2_RWSIZE,
    CMD_NVS_OP3_RWSIZE,
    CMD_NVS_OP0_IOFILE,
    CMD_NVS_OP1_IOFILE,
    CMD_NVS_OP2_IOFILE,
    CMD_NVS_OP3_IOFILE,
    CMD_NVS_OP0_BUFCRC,
    CMD_NVS_OP1_BUFCRC,
    CMD_NVS_OP2_BUFCRC,
    CMD_NVS_OP3_BUFCRC,
    CMD_NVS_OP0_INRAWH,
    CMD_NVS_OP1_INRAWH,
    CMD_NVS_OP2_INRAWH,
    CMD_NVS_OP3_INRAWH,
};

struct _cmd_args {
    int used;
    int min_ascii_arg_len;
    int max_ascii_arg_len; // we assume no args larger than signed int +range...
    char* ascii_arg;
    int (*cmd_handler)(char* arg);
} __attribute__((packed));

static struct _cmd_args g_cmd_args[COMMAND_COUNT] = {
    {0, 0, 0, NULL, NULL}, // inv
    {0, 4, 5, NULL, NULL}, // INPUT
    {0, 32, 32, NULL, NULL}, // ConsoleID
    {0, 32, 32, NULL, NULL}, // OpenPSID
    {0, 4, 4, NULL, NULL}, // DeviceType
    {0, 10, 10, NULL, NULL}, // mgmtFlags
    {0, 4, 5, NULL, NULL}, // SoftwareProductingMode
    {0, 4, 5, NULL, NULL}, // VCSlotProductingMode
    {0, 10, 10, NULL, NULL}, // mgmtStatus
    {0, 4, 5, NULL, NULL}, // isSnvsInitialized
    {0, 4, 5, NULL, NULL}, // isQaFlagged
    {0, 6, 6, NULL, NULL}, // offset for NV op 0
    {0, 6, 6, NULL, NULL}, // offset for NV op 1
    {0, 6, 6, NULL, NULL}, // offset for NV op 2
    {0, 6, 6, NULL, NULL}, // offset for NV op 3
    {0, 6, 6, NULL, NULL}, // size for NV op 0
    {0, 6, 6, NULL, NULL}, // size for NV op 1
    {0, 6, 6, NULL, NULL}, // size for NV op 2
    {0, 6, 6, NULL, NULL}, // size for NV op 3
    {0, 4, 63, NULL, NULL}, // path for NV op 0 
    {0, 4, 63, NULL, NULL}, // path for NV op 1 
    {0, 4, 63, NULL, NULL}, // path for NV op 2 
    {0, 4, 63, NULL, NULL}, // path for NV op 3
    {0, 10, 10, NULL, NULL}, // crc32 for NV op 0
    {0, 10, 10, NULL, NULL}, // crc32 for NV op 1
    {0, 10, 10, NULL, NULL}, // crc32 for NV op 2
    {0, 10, 10, NULL, NULL}, // crc32 for NV op 3
    {0, 0x20, 0x1000, NULL, NULL}, // hex data for NV op 0
    {0, 0x20, 0x1000, NULL, NULL}, // hex data for NV op 1
    {0, 0x20, 0x1000, NULL, NULL}, // hex data for NV op 2
    {0, 0x20, 0x1000, NULL, NULL}, // hex data for NV op 3
};