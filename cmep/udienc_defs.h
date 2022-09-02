struct _ct_args {
    uint16_t magic;
    uint16_t c_func;
    unsigned char tmp[0xFC];
    unsigned char cid_block[0x100];
} __attribute__((packed));
typedef struct _ct_args ct_args;