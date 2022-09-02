typedef unsigned char uint8_t;             ///< Unsigned 8-bit type
typedef unsigned short int uint16_t;       ///< Unsigned 16-bit type
typedef unsigned int uint32_t;             ///< Unsigned 32-bit type

typedef struct {
  uint16_t magic;
  uint8_t unused;
  uint8_t status;
  uint32_t codepaddr;
  uint32_t arg;
  uint32_t resp;
} __attribute__((packed)) fm_nfo;