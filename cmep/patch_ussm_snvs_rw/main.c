#include "../spl-defs.h"

int __attribute__((section(".text.start"))) start(uint32_t patch_offset) {
	if (*(uint16_t*)(0x00800000 + patch_offset) == 0x0033) {
		*(uint16_t*)(0x00040000 + patch_offset) = (uint16_t)0x7002; // uncached, for good measure
		*(uint16_t*)(0x00800000 + patch_offset) = (uint16_t)0x7002; // cached
		return 0;
	}
	return 0xBADF00D0;
}