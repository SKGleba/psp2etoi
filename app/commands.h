extern int etoiRwLeaf(int write, int leaf_num, void* u_leaf_data, uint32_t u_ioutcrc[2]);
extern int etoiEncryptUDIBlock(void* u_udi_block, uint32_t in_crc, uint32_t* out_crc);
extern int etoiPatchIdstorCheck(int patch, int hook);
extern int etoiGsManagementData(int set, uint32_t flags_in, uint32_t status_in, uint32_t u_outdata[2]);
extern int etoiNvsRwSecure(int write, int sector, void* io_data, uint32_t u_ioutcrc[2]);
extern int etoiNvsRw(int write, int start_offset, void* io_data, uint32_t u_szioutcrc[3]);

extern int proxy_etoiRwLeaf(int write, int leaf_num, void* u_leaf_data, uint32_t leaf_crc_in, uint32_t* u_leaf_crc_out);
extern int proxy_etoiGsManagementData(int set, uint32_t flags_in, uint32_t status_in, uint32_t* flags_out, uint32_t* status_out);
extern int proxy_etoiNvsRwSecure(int write, int sector, void* io_data, uint32_t in_crc, uint32_t* out_crc);
extern int proxy_etoiNvsRw(int write, int start_offset, void* io_data, int size, uint32_t in_crc, uint32_t* out_crc);

extern int set_opsid(uint8_t* opsid);
extern int validate_cid(void* cid);
extern int set_cid(uint8_t* cid, uint8_t type);