#ifndef PE_STRUCT_H
#define PE_STRUCT_H

#include <stdint.h>
#include <stdio.h>
#include <wchar.h>

#define PEFILE_DATA_DIR_LEN 16
#define PEFILE_FUNCTION_NAME_MAX_LEN 64
#define PEFILE_MODULE_NAME_MAX_LEN 64
#define PEFILE_RESOURCE_NAME_MAX_LEN 32
#define PEFILE_SECTION_NAME_MAX_LEN 8
#define PEFILE_DOS_SIG_LEN 2
#define PEFILE_NT_SIG_LEN 4
#define HAS_DIR(dir) ((dir) != NULL)

/* metadata about the imported function */
#define STRUCT_THUNK_DATA(BITS)                \
struct thunk_data_##BITS {                     \
    union {                                    \
        struct {                               \
            uint##BITS##_t ordinal : BITS - 1; \
            uint##BITS##_t isOrd   : 1;        \
        };                                     \
        /* offset to import_by_name */         \
        uint##BITS##_t addressOfData;          \
    };                                         \
};

#define STRUCT_TLS_TABLE(BITS)            \
struct tls_table_##BITS {                 \
    uint##BITS##_t startAddressOfRawData; \
    uint##BITS##_t endAddressOfRawData;   \
    uint##BITS##_t addressOfIndex;        \
    uint##BITS##_t addressOfCallBacks;    \
    uint32_t       sizeOfZeroFill;        \
    uint32_t       characteristics;       \
};

#define STRUCT_LOAD_CONFIG(BITS)                   \
struct load_config_##BITS {                        \
    uint32_t       characteristics;                \
    uint32_t       timeDateStamp;                  \
    uint16_t       majorVersion;                   \
    uint16_t       minorVersion;                   \
    uint32_t       globalFlagsClear;               \
    uint32_t       globalFlagsSet;                 \
    uint32_t       criticalSectionDefaultTimeout;  \
    uint##BITS##_t deCommitFreeBlockThreshold;     \
    uint##BITS##_t deCommitTotalFreeThreshold;     \
    uint##BITS##_t lockPrefixTable;                \
    uint##BITS##_t maximumAllocationSize;          \
    uint##BITS##_t virtualMemoryThreshold;         \
    uint##BITS##_t processAffinityMask;            \
    uint32_t       processHeapFlags;               \
    uint16_t       csdVersion;                     \
    uint16_t       reserved;                       \
    uint##BITS##_t editList;                       \
    uint##BITS##_t securityCookie;                 \
    uint##BITS##_t seHandlerTable;                 \
    uint##BITS##_t guardCfCheckFunctionPointer;    \
    uint##BITS##_t guardCfDispatchFunctionPointer; \
    uint##BITS##_t guardCfFunctionTable;           \
    uint##BITS##_t guardCfFunctionCount;           \
    uint32_t       guardFlags;                     \
    char           codeIntegrity[12];              \
    uint##BITS##_t guardAddressTakenIatEntryTable; \
    uint##BITS##_t guardAddressTakenIatEntryCount; \
    uint##BITS##_t guardLongJumpTargetTable;       \
    uint##BITS##_t guardLongJumpTargetCount;       \
};

enum optional_magic {
    PE_OH_32=0x10B,
    PE_OH_64=0x20B,
};

enum directory_entries {
    PE_DE_EXPORT,
    PE_DE_IMPORT,
    PE_DE_RESOURCE,
    PE_DE_EXCEPTION,
    PE_DE_CERTIFICATE,
    PE_DE_RELOCATION,
    PE_DE_DEBUG,
    PE_DE_ARCHITECTURE, // unused, all zero
    PE_DE_GLOBALPTR,
    PE_DE_TLS,
    PE_DE_LOAD_CONFIG,
    PE_DE_BOUND_IMPORT,
    PE_DE_IAT,
    PE_DE_DELAY_IMPORT,
    PE_DE_CLR,
    PE_DE_NULL,         // null terminator
};

enum resource_types {
    PE_RT_CURSOR,
    PE_RT_BITMAP,
    PE_RT_ICON,
    PE_RT_MENU,
    PE_RT_DIALOG,
    PE_RT_STRING,
    PE_RT_FONTDIR,
    PE_RT_FONT,
    PE_RT_ACCELERATOR,
    PE_RT_RCDATA,
    PE_RT_MESSAGETABLE,
};

enum file_characteristics {
    PE_FC_RELOCS_STRIPPED         = 0x0001,
    PE_FC_EXECUTABLE_IMAGE        = 0x0002,
    PE_FC_LINE_NUMS_STRIPPED      = 0x0004,
    PE_FC_LOCAL_SYMS_STRIPPED     = 0x0008,
    PE_FC_AGGRESIVE_WS_TRIM       = 0x0010,
    PE_FC_LARGE_ADDRESS_AWARE     = 0x0020,
    PE_FC_BYTES_REVERSED_LO       = 0x0080,
    PE_FC_32BIT_MACHINE           = 0x0100,
    PE_FC_DEBUG_STRIPPED          = 0x0200,
    PE_FC_REMOVABLE_RUN_FROM_SWAP = 0x0400,
    PE_FC_NET_RUN_FROM_SWAP       = 0x0800,
    PE_FC_SYSTEM                  = 0x1000,
    PE_FC_IS_DLL                  = 0x2000,
    PE_FC_UP_SYSTEM_ONLY          = 0x4000,
};

enum windows_subsystem {
    PE_WS_UNKNOWN                  = 0,
    PE_WS_NATIVE                   = 1,
    PE_WS_WINDOWS_GUI              = 2,
    PE_WS_WINDOWS_CUI              = 3,
    PE_WS_OS2_CUI                  = 5,
    PE_WS_POSIX_CUI                = 7,
    PE_WS_WINDOWS_CE_GUI           = 9,
    PE_WS_EFI_APPLICATION          = 10,
    PE_WS_EFI_BOOT_SERVICE_DRIVER  = 11,
    PE_WS_EFI_RUNTIME_DRIVER       = 12,
    PE_WS_EFI_ROM                  = 13,
    PE_WS_XBOX                     = 14,
    PE_WS_WINDOWS_BOOT_APPLICATION = 16,
};

enum dll_characteristics {
    PE_DC_DYNAMIC_BASE          = 0x0040,
    PE_DC_FORCE_INTEGRITY       = 0x0080,
    PE_DC_NX_COMPAT             = 0x0100,
    PE_DC_NO_ISOLATION          = 0x0200,
    PE_DC_NO_SEH                = 0x0400,
    PE_DC_NO_BIND               = 0x0800,
    PE_DC_WDM_DRIVER            = 0x2000,
    PE_DC_TERMINAL_SERVER_AWARE = 0x8000,
};

enum section_characteristics {
    PE_SC_TYPE_NO_PAD            = 0x00000008,
    PE_SC_CNT_CODE               = 0x00000020,
    PE_SC_CNT_INITIALIZED_DATA   = 0x00000040,
    PE_SC_CNT_UNINITIALIZED_DATA = 0x00000080,
    PE_SC_LNK_OTHER              = 0x00000100,
    PE_SC_LNK_INFO               = 0x00000200,
    PE_SC_LNK_REMOVE             = 0x00000800,
    PE_SC_LNK_COMDAT             = 0x00001000,
    PE_SC_NO_DEFER_SPEC_EXC      = 0x00004000,
    PE_SC_GPREL                  = 0x00008000,
    PE_SC_MEM_PURGEABLE          = 0x00020000,
    PE_SC_MEM_LOCKED             = 0x00040000,
    PE_SC_MEM_PRELOAD            = 0x00080000,
    PE_SC_ALIGN_1BYTES           = 0x00100000,
    PE_SC_ALIGN_2BYTES           = 0x00200000,
    PE_SC_ALIGN_4BYTES           = 0x00300000,
    PE_SC_ALIGN_8BYTES           = 0x00400000,
    PE_SC_ALIGN_16BYTES          = 0x00500000,
    PE_SC_ALIGN_32BYTES          = 0x00600000,
    PE_SC_ALIGN_64BYTES          = 0x00700000,
    PE_SC_ALIGN_128BYTES         = 0x00800000,
    PE_SC_ALIGN_256BYTES         = 0x00900000,
    PE_SC_ALIGN_512BYTES         = 0x00A00000,
    PE_SC_ALIGN_1024BYTES        = 0x00B00000,
    PE_SC_ALIGN_2048BYTES        = 0x00C00000,
    PE_SC_ALIGN_4096BYTES        = 0x00D00000,
    PE_SC_ALIGN_8192BYTES        = 0x00E00000,
    PE_SC_LNK_NRELOC_OVFL        = 0x01000000,
    PE_SC_MEM_DISCARDABLE        = 0x02000000,
    PE_SC_MEM_NOT_CACHED         = 0x04000000,
    PE_SC_MEM_NOT_PAGED          = 0x08000000,
    PE_SC_MEM_SHARED             = 0x10000000,
    PE_SC_MEM_EXECUTE            = 0x20000000,
    PE_SC_MEM_READ               = 0x40000000,
    PE_SC_MEM_WRITE              = 0x80000000,
};

enum certificate_versions {
    PE_CERT_V1=0x100,
    PE_CERT_V2=0x200,
};

enum certificate_types {
    PE_CERT_TYPE_X509=1,
    PE_CERT_TYPE_PKCS_SIGNED_DATA,
    PE_CERT_TYPE_RESERVED_1,
    PE_CERT_TYPE_TS_STACK_SIGNED,
};

enum relocation_types {
    PE_RELOC_TYPE_ABSOLUTE       = 0x0,
    PE_RELOC_TYPE_HIGH           = 0x1,
    PE_RELOC_TYPE_LOW            = 0x2,
    PE_RELOC_TYPE_HIGHLOW        = 0x3,
    PE_RELOC_TYPE_HIGHADJ        = 0x4,
    PE_RELOC_TYPE_MIPS_JMPADDR   = 0x5,
    PE_RELOC_TYPE_ARM_MOV32      = 0x5,
    PE_RELOC_TYPE_RISCV_HIGH20   = 0x5,
    PE_RELOC_TYPE_THUMB_MOV32    = 0x7,
    PE_RELOC_TYPE_RISCV_LOW12I   = 0x7,
    PE_RELOC_TYPE_RISCV_LOW12S   = 0x8,
    PE_RELOC_TYPE_MIPS_JMPADDR16 = 0x9,
    PE_RELOC_TYPE_DIR64          = 0xA,
};

struct dos_h {
    char     e_magic[PEFILE_DOS_SIG_LEN]; // signature
    uint16_t e_cblp;     // count of bytes on last page
    uint16_t e_cp;       // count of pages
    uint16_t e_crlc;     // count of relocations
    uint16_t e_cparhdr;  // count of paragraph headers
    uint16_t e_minalloc; // minimum allocations
    uint16_t e_maxalloc; // maximum allocations
    uint16_t e_ss;       // initial SS
    uint16_t e_sp;       // initial SP
    uint16_t e_csum;     // checksum
    uint16_t e_ip;       // initial IP
    uint16_t e_cs;       // initial CS
    uint16_t e_lfarlc;   // offset to relocations
    uint16_t e_ovno;     // overlay number
    uint16_t e_res[4];   // reserved1
    uint16_t e_oemid;    // oem Identifier
    uint16_t e_oeminfo;  // oem Info
    uint16_t e_res2[10]; // reserved2
    uint32_t e_lfanew;   // file offset to NT header
};

struct file_h {
    uint16_t machine;              // type of cpu the binary was compiled for
    uint16_t numberOfSections;     // number of section headers
    uint32_t timeDateStamp;        // file creation time as UNIX epoch
    uint32_t pointerToSymbolTable; // deprecated
    uint32_t numberOfSymbols;      // deprecated
    uint16_t sizeOfOptionalHeader; // size of optional header in bytes
    uint16_t characteristics;      // bitfields for various things
    /* 0x0001 IMAGE_FILE_RELOCS_STRIPPED
     * 0x0002 IMAGE_FILE_EXECUTABLE_IMAGE
     * 0x0004 IMAGE_FILE_LINE_NUMS_STRIPPED
     * 0x0008 IMAGE_FILE_LOCAL_SYMS_STRIPPED
     * 0x0010 IMAGE_FILE_AGGRESIVE_WS_TRIM
     * 0x0020 IMAGE_FILE_LARGE_ADDRESS_AWARE
     * 0x0080 IMAGE_FILE_BYTES_REVERSED_LO
     * 0x0100 IMAGE_FILE_32BIT_MACHINE
     * 0x0200 IMAGE_FILE_DEBUG_STRIPPED
     * 0x0400 IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP
     * 0x0800 IMAGE_FILE_NET_RUN_FROM_SWAP
     * 0x1000 IMAGE_FILE_SYSTEM
     * 0x2000 IMAGE_FILE_IS_DLL
     * 0x4000 IMAGE_FILE_UP_SYSTEM_ONLY
     */
};

struct data_dir {
    uint32_t virtualAddress;
    uint32_t size;
};

struct optional_32_h {
    uint32_t sizeOfStackReserve;
    uint32_t sizeOfStackCommit;
    uint32_t sizeOfHeapReserve;
    uint32_t sizeOfHeapCommit;
};

struct optional_64_h {
    uint64_t sizeOfStackReserve;
    uint64_t sizeOfStackCommit;
    uint64_t sizeOfHeapReserve;
    uint64_t sizeOfHeapCommit;
};

struct optional_common_h {
    uint16_t magic;
    /* 0x10b IMAGE_NT_OPTIONAL_HDR32_MAGIC
     * 0x20b IMAGE_NT_OPTIONAL_HDR64_MAGIC
     * 0x107 IMAGE_ROM_OPTIONAL_HDR_MAGIC
     */
    char     majorLinkerVersion;
    char     minorLinkerVersion;
    uint32_t sizeOfCode;
    uint32_t sizeOfInitializedData;
    uint32_t sizeOfUninitializedData;
    uint32_t addressOfEntryPoint;         // RVA to beginning of executable code
    uint32_t baseOfCode;
    union {
        struct {
            uint32_t baseOfData;          // Preferred base address
            uint32_t imageBase32;
        };
        uint64_t imageBase64;             // Preferred base address
    };
    uint32_t sectionAlignment;
    uint32_t fileAlignment;
    uint16_t majorOperatingSystemVersion;
    uint16_t minorOperatingSystemVersion;
    uint16_t majorImageVersion;
    uint16_t minorImageVersion;
    uint16_t majorSubsystemVersion;
    uint16_t minorSubsystemVersion;
    uint32_t win32VersionValue;
    uint32_t sizeOfImage;
    uint32_t sizeOfHeaders;
    uint32_t checksum;
    uint16_t subsystem;
    /* 0 IMAGE_SUBSYSTEM_UNKNOWN
     * 1 IMAGE_SUBSYSTEM_NATIVE
     * 2 IMAGE_SUBSYSTEM_WINDOWS_GUI
     * 3 IMAGE_SUBSYSTEM_WINDOWS_CUI
     * 5 IMAGE_SUBSYSTEM_OS2_CUI
     * 7 IMAGE_SUBSYSTEM_POSIX_CUI
     * 9 IMAGE_SUBSYSTEM_WINDOWS_CE_GUI
     * 10 IMAGE_SUBSYSTEM_EFI_APPLICATION
     * 11 IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER
     * 12 IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER
     * 13 IMAGE_SUBSYSTEM_EFI_ROM
     * 14 IMAGE_SUBSYSTEM_XBOX
     * 16 IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION
     */
    uint16_t dllCharacteristics;
    /* 0x0040 IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
     * 0x0080 IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY
     * 0x0100 IMAGE_DLLCHARACTERISTICS_NX_COMPAT
     * 0x0200 IMAGE_DLLCHARACTERISTICS_NO_ISOLATION
     * 0x0400 IMAGE_DLLCHARACTERISTICS_NO_SEH
     * 0x0800 IMAGE_DLLCHARACTERISTICS_NO_BIND
     * 0x2000 IMAGE_DLLCHARACTERISTICS_WDM_DRIVER
     * 0x8000 IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE
     */
    uint32_t loaderFlags;
    uint32_t numberOfRvaAndSizes;
    struct   data_dir ddir[PEFILE_DATA_DIR_LEN];
    union {
        struct optional_32_h opt32;
        struct optional_64_h opt64;
    };
};

struct nt_h {
    char   signature[PEFILE_NT_SIG_LEN];
    struct file_h file;
    struct optional_common_h opt;
};

struct section_h {
    char     name[PEFILE_SECTION_NAME_MAX_LEN];
    union {
        uint32_t physicalAddress;
        uint32_t virtualSize;
    } misc;
    uint32_t virtualAddress; // rva
    uint32_t sizeOfRawData;
    uint32_t pointerToRawData;
    uint32_t pointerToRelocations;
    uint32_t pointerToLinenumbers;
    uint16_t numberOfRelocations;
    uint16_t numberOfLinenumbers;
    uint32_t characteristics;
    /* 0x00000008 IMAGE_SCN_TYPE_NO_PAD
     * 0x00000020 IMAGE_SCN_CNT_CODE
     * 0x00000040 IMAGE_SCN_CNT_INITIALIZED_DATA
     * 0x00000080 IMAGE_SCN_CNT_UNINITIALIZED_DATA
     * 0x00000100 IMAGE_SCN_LNK_OTHER
     * 0x00000200 IMAGE_SCN_LNK_INFO
     * 0x00000800 IMAGE_SCN_LNK_REMOVE
     * 0x00001000 IMAGE_SCN_LNK_COMDAT
     * 0x00004000 IMAGE_SCN_NO_DEFER_SPEC_EXC
     * 0x00008000 IMAGE_SCN_GPREL
     * 0x00020000 IMAGE_SCN_MEM_PURGEABLE
     * 0x00040000 IMAGE_SCN_MEM_LOCKED
     * 0x00080000 IMAGE_SCN_MEM_PRELOAD
     * 0x00100000 IMAGE_SCN_ALIGN_1BYTES
     * 0x00200000 IMAGE_SCN_ALIGN_2BYTES
     * 0x00300000 IMAGE_SCN_ALIGN_4BYTES
     * 0x00400000 IMAGE_SCN_ALIGN_8BYTES
     * 0x00500000 IMAGE_SCN_ALIGN_16BYTES
     * 0x00600000 IMAGE_SCN_ALIGN_32BYTES
     * 0x00700000 IMAGE_SCN_ALIGN_64BYTES
     * 0x00800000 IMAGE_SCN_ALIGN_128BYTES
     * 0x00900000 IMAGE_SCN_ALIGN_256BYTES
     * 0x00A00000 IMAGE_SCN_ALIGN_512BYTES
     * 0x00B00000 IMAGE_SCN_ALIGN_1024BYTES
     * 0x00C00000 IMAGE_SCN_ALIGN_2048BYTES
     * 0x00D00000 IMAGE_SCN_ALIGN_4096BYTES
     * 0x00E00000 IMAGE_SCN_ALIGN_8192BYTES
     * 0x01000000 IMAGE_SCN_LNK_NRELOC_OVFL
     * 0x02000000 IMAGE_SCN_MEM_DISCARDABLE
     * 0x04000000 IMAGE_SCN_MEM_NOT_CACHED
     * 0x08000000 IMAGE_SCN_MEM_NOT_PAGED
     * 0x10000000 IMAGE_SCN_MEM_SHARED
     * 0x20000000 IMAGE_SCN_MEM_EXECUTE
     * 0x40000000 IMAGE_SCN_MEM_READ
     * 0x80000000 IMAGE_SCN_MEM_WRITE
     */
};

struct export_dir {
    uint32_t characteristics;
    uint32_t timeDateStamp;
    uint16_t majorVersion;
    uint16_t minorVersion;
    uint32_t name;
    uint32_t base;
    uint32_t numberOfFunctions;
    uint32_t numberOfNames;
    uint32_t addressOfFunctions;
    uint32_t addressOfNames;
    uint32_t addressOfOrdinals;
};

/* metadata about the imported module */
struct import_desc {
    union {
        uint32_t characteristics;
        uint32_t originalFirstThunk; // RVA to import names table
        uint32_t addressOfInt;
    };
    int32_t  timeDateStamp;
    int32_t  forwarderChain;
    uint32_t name;
    union {
        uint32_t firstThunk; // RVA to import address table
        uint32_t addressOfIat;
    };
};

STRUCT_THUNK_DATA(32) STRUCT_THUNK_DATA(64)

struct import_by_name {
    uint16_t hint;
    char     name[PEFILE_FUNCTION_NAME_MAX_LEN];
};

struct resource_header {
    uint32_t characteristics;
    uint32_t timeDateStamp;
    uint16_t majorVersion;
    uint16_t minorVersion;
    uint16_t numberOfNamedEntries;
    uint16_t numberOfIdEntries;
};

struct debug_dir {
    uint32_t characteristics;
    uint32_t timeDateStamp;
    uint16_t majorVersion;
    uint16_t minorVersion;
    uint32_t type;
    uint32_t sizeOfData;
    uint32_t addressOfRawData;
    uint32_t pointerToRawData;
};

STRUCT_TLS_TABLE(32) STRUCT_TLS_TABLE(64)

struct delay_import_desc {
    uint32_t grAttrs;
    uint32_t szName;
    uint32_t phmod;
    uint32_t pIAT;
    uint32_t pINT;
    uint32_t pBoundIAT;
    uint32_t pUnloadIAT;
    uint32_t dwTimeStamp;
};

struct resource_entry {
    union { // string or ID
        struct {
            uint32_t nameOffset   : 31;
            uint32_t nameIsString : 1;
        };
        uint32_t name;
        uint16_t id;
    };
    union { // dir ptr or data ptr
        uint32_t offsetToData;
        struct {
            uint32_t offsetToDirectory : 31;
            uint32_t dataIsDirectory   : 1;  // 1 ? offset to another resource table : offset to resource data
        };
    };
};

struct resource_metadata {
    uint32_t offsetToData;
    uint32_t size;
    uint32_t codePage;
    uint32_t reserved;
};

struct certificate_metadata {
    uint32_t size;
    uint16_t version;
    /* 0x0100 WIN_CERT_REVISION_1_0
     * 0x0200 WIN_CERT_REVISION_2_0
     */
    uint16_t type;
    /* 0x0001 WIN_CERT_TYPE_X509
     * 0x0002 WIN_CERT_TYPE_PKCS_SIGNED_DATA
     * 0x0003 WIN_CERT_TYPE_RESERVED_1
     * 0x0004 WIN_CERT_TYPE_TS_STACK_SIGNED
     */
};

struct relocation_entry {
    uint16_t offset : 12;
    uint16_t type   : 4;
};

struct relocation_header {
    uint32_t rva;
    uint32_t size;
};

STRUCT_LOAD_CONFIG(32) STRUCT_LOAD_CONFIG(64)

/* -==============-
 *  CUSTOM STRUCTS
 * -==============-
 * structures here do not occur literally in the PE file and are used to better organize data
 */

struct import_lookup {
    union {
        struct thunk_data_32 mtdt32;
        struct thunk_data_64 mtdt64;
    };
    struct import_by_name ibn;
};

struct import_table {
    char                  name[PEFILE_MODULE_NAME_MAX_LEN];
    struct import_desc    mtdt;
    struct import_lookup *ils; // array
    int                   ilsLen;
};

/* offset to the exported function name and the name itself */
struct export_by_name { // address_of_name (Pointers to strings)
    char     name[PEFILE_FUNCTION_NAME_MAX_LEN];
    uint32_t rva;
};

struct export_func_ptr {
    uint32_t rva;
    uint32_t pointerToCode;
};

struct export_table {
    struct export_dir        edir;
    struct export_func_ptr  *addrs; // address_of_function (Indexed by Ordinals)
    uint16_t                *nords; // name_ordinal (array of WORDs)
    struct export_by_name   *names; // array
    int                      addrsLen;
    int                      nordsLen;
    int                      namesLen;
};

struct resource_table {
    struct resource_header  hdr;  // get nNamed and nId entries here
    struct resource_node   *branches; // array
    int                     branchesLen;
};

struct resource_name {
    wchar_t  name[PEFILE_RESOURCE_NAME_MAX_LEN];
    uint16_t len;
};

struct resource_node {
    struct resource_entry     entry; // entry metadata
    struct resource_metadata  mtdt;  // file metadata
    struct resource_name      rname; // if nameIsString
    struct resource_table    *tbl;   // if dataIsDirectory
};

struct exception_dir_32 {
    uint32_t beginAddress;
    uint32_t endAddress;
    uint32_t exceptionHandler;
    uint32_t handlerData;
    uint32_t prologEndAddress;
};

struct exception_dir_64 {
    uint32_t beginAddress;
    uint32_t endAddress;
    uint32_t unwindInformation;
};

struct cert_table {
    struct  certificate_metadata mtdt;
    char   *data;
};

struct reloc_table {
    struct relocation_header  header;
    struct relocation_entry  *entries; // array
    int                       entriesLen;
};

struct pefile {
    FILE *file;
    struct dos_h dos;
    struct nt_h nt;
    struct section_h          *sctns;  // array
    // data directory structures
    struct export_table       *xprt;
    struct import_table       *mprts;  // array
    struct resource_table     *rsrc;
    union {
        struct exception_dir_32   *xcpts32;
        struct exception_dir_64   *xcpts64;
    };
    struct cert_table         *certs;  // array
    struct reloc_table        *relocs; // array
    struct debug_dir          *dbgs;   // array
//  struct architecture       *rchtr;  // unused, all zero
    struct globalptr          *gptr;   // TODO: find a file with a global pointer
    union { // Consider typecast instead of union
        struct tls_table_32   *tlst32;
        struct tls_table_64   *tlst64;
    };
    union { // Consider typecast instead of union
        struct load_config_32 *ldcfg32;
        struct load_config_64 *ldcfg64;
    };
    struct bound_import       *bmprt;  // TODO: find a file with bound imports
    struct iat_data           *iat;    // TODO: find documentation on this dir
    struct delay_import       *dmprt;  // TODO: find a file with delay imports
    struct clr_data           *clr;    // TODO: find a file with clr runtime
    int mprtsLen;
    int xcptsLen;
    int certsLen;
    int relocsLen;
    int dbgsLen;
};

#endif

