# psp2etoi configuration
A summary on the psp2etoi's configuration file

## Structure
The input configuration is parsed line by line
 - expected line structure is `TAG=DATA`
 - empty lines are ignored
 - comments start with `#`, everything after that character is ignored
   - eg `# The configuration below writes TAG which is ...`
   - eg `TAG=DATA # set TAG which allows you...`
<br>

## Allowed tags
Tags supported by psp2etoi

### INPUT
 - defines if the configuration is writable
 - the data is one of
   - `true` : the configuration can be written to a device
   - `false` : the configuration cannot be written to a device
 - eg `INPUT=true` lets the app know that `input.cfg` is a valid configuration

### ConsoleID
 - device-unique ConsoleID
 - the data is 16 bytes, in ascii
 - eg `ConsoleID=00000001010100100400028A1F7EA815` sets ConsoleID to the one of my DevKit
 - WARNING: Editing the ConsoleID may render the device unusable

### DeviceType
 - only the DeviceType byte of ConsoleID (`cid[5]`)
 - reminder:
   - 0x00: internal (emulator)
   - 0x01: DevKit (TOOL)
   - 0x02: TestKit (DEX)
   - 0x03-0x11: Retail (CEX)
 - the data is one byte, ascii, formatted in hex
 - eg `DeviceType=0x02` makes the target a TestKit
 - WARNING: Editing the ConsoleID may render the device unusable

### OpenPSID
 - device-unique OpenPSID
 - the data is 16 bytes, in ascii
 - eg `OpenPSID=6A244B19A35418F6BA0CBCE784B4218F` sets OpenPSID to the one of my DevKit

### mgmtFlags
 - Management Flags bitfield
 - the data is 4 bytes, ascii, formatted in hex as little endian
 - eg `mgmtFlags=0x00000003` sets Producting Mode for both OS and the GameCard slot

### SoftwareProductingMode
 - "OS Producting Mode" mgmt flags bit
 - the data is one of
   - `true` : Producting Mode
   - `false` : Manufacturing Mode
 - eg `SoftwareProductingMode=true` is the default setting

### VCSlotProductingMode
 - "GameCard slot Producting Mode" mgmt flags bit
 - reminder: it is checked only in OS manufacturing mode
 - the data is one of
   - `true` : Vita GameCard mode
   - `false` : SD card mode
 - eg `VCSlotProductingMode=true` is the default setting

### mgmtStatus
 - Management Status bitfield
 - the data is 4 bytes, ascii, formatted in hex as little endian
 - eg `mgmtStatus=0x00000001` sets status to SNVS initialized, no QAF present
 - WARNING: Editing the mgmt status may render the device unusable

### isSnvsInitialized
 - "SNVS initialized" mgmt status bit
 - reminder: if not set then SNVS is reset
 - the data is one of
   - `true` : SNVS initialized
   - `false` : SNVS not initialized
 - eg `isSnvsInitialized=true` is the default setting
 - WARNING: Editing the mgmt status may render the device unusable

### isQaFlagged
 - "is QA flagged" mgmt status bit
 - the data is one of
   - `true` : has QA flags
   - `false` : does not have QA flags
 - eg `isQaFlagged=true` lets second_loader know that there are QA flags to check

### NVS_OPx_OFFSET
 - NVS offset where `x` is the operation id - one of 0,1,2,3
 - data is the target NVS offset, 2 bytes, ascii, formatted in hex as little endian
 - eg `NVS_OP0_OFFSET=0x0020` will set NVS operation 0 offset to 0x20

### NVS_OPx_RWSIZE
 - NVS read/write size where `x` is the operation id - one of 0,1,2,3
 - data is the desired NVS read/write size, 2 bytes, ascii, formatted in hex as little endian
 - eg `NVS_OP3_RWSIZE=0x0010` will set NVS operation 3 read/write size to 16 bytes

### NVS_OPx_INRAWH
 - data for nvs write, where `x` is the operation id - one of 0,1,2,3
 - data is `NVS_OPx_RWSIZE` bytes, in ascii, only one line!
 - eg `NVS_OP3_INRAWH=0000FFFF01FFFFFFFFFFFFFFFFFFFFFF` will set the NVS operation 3 write buffer to those 16 bytes

### NVS_OPx_IOFILE
 - input/output file for nvs write/read, where `x` is the operation id - one of 0,1,2,3
 - data is the file path
 - eg `NVS_OP0_IOFILE=ux0:fw_vers.bin` will set NVS operation 0 input/output file to `ux0:fw_vers.bin`

### NVS_OPx_BUFCRC
 - nvs input/output CRC32, where `x` is the operation id - one of 0,1,2,3
 - data is the buffer CRC32, 4 bytes, ascii, u32 formatted in hex
 - eg `NVS_OP3_BUFCRC=0x832D2B4D` will make psp2etoi compare NVS op 3 write buffer CRC32 to `0x832D2B4D`

<br>

## Mutually exclusive tags
Certain tags conflict with others
 - only one of `ConsoleID` and `DeviceType` can be set in one configuration
 - only one of `mgmtFlags` and (`SoftwareProductingMode`,`VCSlotProductingMode`) can be set in one configuration
 - only one of `mgmtStatus` and (`isSnvsInitialized`,`isQaFlagged`) can be set in one configuration
 - only one of `NVS_OPx_IOFILE` and `NVS_OPx_INRAWH` can be set for a specific operation in one configuration

<br>

## NVS operations
A brief summary on NVS operations
 - There are 4 possible operation slots (0,1,2,3)
 - The operations are performed consecutively from slot 0 to slot 3
 - Each slot must have set:
   - `NVS_OPx_OFFSET`
   - `NVS_OPx_RWSIZE`
   - `NVS_OPx_INRAWH` OR `NVS_OPx_IOFILE`
   - if flashing, `NVS_OP0_BUFCRC` must be set
 - SNVS (0x0000-0x0400) must be handled in separate operations from the rest of NVS (0x0400-0x0B60)
 - Both offset and size have alignment restrictions:
   - for SNVS (0x0000-0x0400), both must be aligned to 0x20
   - for the rest of NVS (0x0400-0x0B60), both must be aligned to 0x10