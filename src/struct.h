#ifndef PE_STRUCT_H
#define PE_STRUCT_H

#include <stdint.h>
#include <stdio.h>
#include <wchar.h>

#define PEFILE_DATA_DIR_LEN 16
#define PEFILE_NAME_FUNCTION_MAX_LEN 64
#define PEFILE_NAME_MODULE_MAX_LEN 64
#define PEFILE_NAME_RESOURCE_MAX_LEN 32
#define PEFILE_NAME_SECTION_MAX_LEN 8
#define PEFILE_PATH_MAX_LEN 256
#define PEFILE_SIG_LEN_DOS 2
#define PEFILE_SIG_LEN_NT 4

/* metadata about the imported function */
#define STRUCT_THUNK_DATA(BITS)                \
struct thunk_data_##BITS {                     \
    union {                                    \
        struct {                               \
            uint##BITS##_t ordinal : BITS - 1; \
            uint##BITS##_t is_ordinal : 1;     \
        };                                     \
        /* offset to import_by_name */         \
        uint##BITS##_t rva;                    \
    };                                         \
};

#define STRUCT_TLS_TABLE(BITS)      \
struct tls_table_##BITS {           \
    uint##BITS##_t data_start_ava;  \
    uint##BITS##_t data_end_ava;    \
    uint##BITS##_t index_ava;       \
    uint##BITS##_t callbacks_ava;   \
    uint32_t       zero_fill_size;  \
    uint32_t       characteristics; \
};

#define STRUCT_LOAD_CONFIG(BITS)                        \
struct load_config_##BITS {                             \
    uint32_t       characteristics;                     \
    uint32_t       timestamp;                           \
    uint16_t       version_major;                       \
    uint16_t       version_minor;                       \
    uint32_t       global_flags_clear;                  \
    uint32_t       global_flags_set;                    \
    uint32_t       critical_section_default_timeout;    \
    uint##BITS##_t de_commit_free_block_threshold;      \
    uint##BITS##_t de_commit_total_free_threshold;      \
    uint##BITS##_t lock_prefix_table;                   \
    uint##BITS##_t maximum_allocation_size;             \
    uint##BITS##_t virtual_memory_threshold;            \
    uint##BITS##_t process_affinity_mask;               \
    uint32_t       process_heap_flags;                  \
    uint16_t       csd_version;                         \
    uint16_t       reserved;                            \
    uint##BITS##_t edit_list;                           \
    uint##BITS##_t security_cookie;                     \
    uint##BITS##_t se_handler_table;                    \
    uint##BITS##_t guard_cf_check_function_pointer;     \
    uint##BITS##_t guard_cf_dispatch_function_pointer;  \
    uint##BITS##_t guard_cf_function_table;             \
    uint##BITS##_t guard_cf_function_count;             \
    uint32_t       guard_flags;                         \
    char           code_integrity[12];                  \
    uint##BITS##_t guard_address_taken_iat_entry_table; \
    uint##BITS##_t guard_address_taken_iat_entry_count; \
    uint##BITS##_t guard_long_jump_target_table;        \
    uint##BITS##_t guard_long_jump_target_count;        \
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
    char     e_magic[PEFILE_SIG_LEN_DOS]; // signature
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
    uint16_t number_of_sections;   // number of section headers
    uint32_t timestamp;            // file creation time as UNIX epoch
    uint32_t symbol_table_apa;     // deprecated
    uint32_t number_of_symbols;    // deprecated
    uint16_t optional_header_size; // size of optional header in bytes
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
    uint32_t rva;
    uint32_t size;
};

struct optional_32_h {
    uint32_t stack_reserve_size;
    uint32_t stack_commit_size;
    uint32_t heap_reserve_size;
    uint32_t heap_commit_size;
};

struct optional_64_h {
    uint64_t stack_reserve_size;
    uint64_t stack_commit_size;
    uint64_t heap_reserve_size;
    uint64_t heap_commit_size;
};

struct optional_common_h {
    uint16_t magic;
    /* 0x10b IMAGE_NT_OPTIONAL_HDR32_MAGIC
     * 0x20b IMAGE_NT_OPTIONAL_HDR64_MAGIC
     * 0x107 IMAGE_ROM_OPTIONAL_HDR_MAGIC
     */
    char     linker_version_major;
    char     linker_version_minor;
    uint32_t code_size;
    uint32_t initialized_data_size;
    uint32_t uninitialized_data_size;
    uint32_t entry_point_rva;         // RVA to beginning of executable code
    uint32_t code_base_rva;
    union {
        struct {
            uint32_t data_base_rva;
            uint32_t base_address_32; // Preferred base address
        };
        uint64_t base_address_64;     // Preferred base address
    };
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t operating_system_version_major;
    uint16_t operating_system_version_minor;
    uint16_t image_version_major;
    uint16_t image_version_minor;
    uint16_t subsystem_version_major;
    uint16_t subsystem_version_minor;
    uint32_t win32_version;
    uint32_t image_size;
    uint32_t headers_size;
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
    uint16_t dll_characteristics;
    /* 0x0040 IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
     * 0x0080 IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY
     * 0x0100 IMAGE_DLLCHARACTERISTICS_NX_COMPAT
     * 0x0200 IMAGE_DLLCHARACTERISTICS_NO_ISOLATION
     * 0x0400 IMAGE_DLLCHARACTERISTICS_NO_SEH
     * 0x0800 IMAGE_DLLCHARACTERISTICS_NO_BIND
     * 0x2000 IMAGE_DLLCHARACTERISTICS_WDM_DRIVER
     * 0x8000 IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE
     */
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    struct   data_dir ddir[PEFILE_DATA_DIR_LEN];
    union {
        struct optional_32_h opt_32;
        struct optional_64_h opt_64;
    };
};

struct nt_h {
    char   signature[PEFILE_SIG_LEN_NT];
    struct file_h file;
    struct optional_common_h opt;
};

struct section_h {
    char     name[PEFILE_NAME_SECTION_MAX_LEN];
    uint32_t size_in_memory;
    uint32_t data_rva;
    uint32_t size_on_disk;
    uint32_t data_apa;
    uint32_t relocations_apa;
    uint32_t linenumbers_apa;
    uint16_t number_of_relocations;
    uint16_t number_of_linenumbers;
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
    uint32_t timestamp;
    uint16_t version_major;
    uint16_t version_minor;
    uint32_t name;
    uint32_t base;
    uint32_t number_of_functions;
    uint32_t number_of_names;
    uint32_t functions_rva;
    uint32_t names_rva;
    uint32_t ordinals_rva;
};

/* metadata about the imported module */
struct import_desc {
    union {
        uint32_t characteristics;
        uint32_t original_first_thunk; // RVA to import names table
        uint32_t import_names_table_rva;
    };
    int32_t  timestamp;
    int32_t  forwarder_chain;
    uint32_t name;
    union {
        uint32_t first_thunk; // RVA to import address table
        uint32_t import_address_table_rva;
    };
};

STRUCT_THUNK_DATA(32) STRUCT_THUNK_DATA(64)

struct import_by_name {
    uint16_t hint;
    char     name[PEFILE_NAME_FUNCTION_MAX_LEN];
};

struct resource_header {
    uint32_t characteristics;
    uint32_t timestamp;
    uint16_t version_major;
    uint16_t version_minor;
    uint16_t number_of_named_entries;
    uint16_t number_of_id_entries;
};

struct debug_dir {
    uint32_t characteristics;
    uint32_t timestamp;
    uint16_t version_major;
    uint16_t version_minor;
    uint32_t type;
    uint32_t data_size;
    uint32_t data_rva;
    uint32_t data_apa;
};

STRUCT_TLS_TABLE(32) STRUCT_TLS_TABLE(64)

struct delay_import_desc {
    uint32_t attributes;
    uint32_t name;
    uint32_t module_handle;
    uint32_t delay_import_address_table_rva;
    uint32_t delay_import_names_table_rva;
    uint32_t bound_import_address_table_rva;
    uint32_t unload_import_address_table_rva;
    uint32_t timestamp;
};

struct resource_entry {
    union { // string or ID
        struct {
            uint32_t name_offset     : 31;
            uint32_t has_name_string : 1;
        };
        uint32_t name;
        uint16_t id; // TODO: this ID identifies resource type only at root level
    };
    union { // dir ptr or data ptr
        uint32_t data_offset;
        struct {
            uint32_t directory_offset : 31;
            uint32_t is_directory     : 1;  // 1 ? offset to another resource table : offset to resource data
        };
    };
};

struct resource_metadata {
    uint32_t data_offset;
    uint32_t size;
    uint32_t code_page;
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
        struct thunk_data_32 metadata32;
        struct thunk_data_64 metadata64;
    };
    struct import_by_name function_name;
};

struct import_table {
    char                  name[PEFILE_NAME_MODULE_MAX_LEN];
    struct import_desc    metadata;
    struct import_lookup *lookups; // array
    unsigned int          lookups_len;
};

/* offset to the exported function name and the name itself */
struct export_by_name { // address_of_name (Pointers to strings)
    char     name[PEFILE_NAME_FUNCTION_MAX_LEN];
    uint32_t name_rva;
};

struct export_func_ptr {
    uint32_t code_rva;
    uint32_t code_apa;
};

struct export_table {
    struct export_dir       edir;
    struct export_func_ptr *addrs;     // address_of_function (Indexed by Ordinals)
    uint16_t               *nords;     // name_ordinal (array of WORDs)
    struct export_by_name  *names;     // array
    unsigned int            addrs_len;
    unsigned int            nords_len;
    unsigned int            names_len;
};

struct resource_table {
    struct resource_header  header;
    struct resource_node   *nodes;     // array
    unsigned int            nodes_len;
};

struct resource_name {
    wchar_t  name[PEFILE_NAME_RESOURCE_MAX_LEN];
    uint16_t name_len;
};

struct resource_node {
    struct resource_entry     entry;    // entry metadata
    struct resource_metadata  metadata; // file metadata
    struct resource_name      res_name; // if has_name_string
    struct resource_table    *table;    // if is_directory
};

struct exception_func_ptr {
    uint32_t code_apa;
    uint32_t code_size;
};

struct exception_dir_32 {
    uint32_t start_rva;
    uint32_t end_rva;
    uint32_t exception_handler;
    uint32_t handler_data;
    uint32_t prolog_end_address;
};

struct exception_dir_64 {
    uint32_t start_rva;
    uint32_t end_rva;
    uint32_t unwind_information;
};

struct exception_table {
    struct exception_func_ptr function;
    union {
        struct exception_dir_32 entry32;
        struct exception_dir_64 entry64;
    };
};

struct cert_table {
    struct  certificate_metadata metadata;
    char   *data;
};

struct reloc_table {
    struct relocation_header  header;
    struct relocation_entry  *entries; // array
    unsigned int              entries_len;
};

struct debug_data {
    char unknown[24]; // TODO: what are the 24 bytes for?
    char pdb_path[PEFILE_PATH_MAX_LEN];
};

struct debug_table {
    struct debug_dir  header;
    struct debug_data data;
};

// TODO: may need 64 bit callbacks?
struct callback_func_ptr {
    uint32_t code_ava;
    uint32_t code_apa;
};

struct tls_dir {
    union {
        struct tls_table_32 tlst32;
        struct tls_table_64 tlst64;
    };
    struct callback_func_ptr *callbacks;     // array
    unsigned int              callbacks_len;
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
    struct exception_table    *xcpts;
    struct cert_table         *certs;  // array
    struct reloc_table        *relocs; // array
    struct debug_table        *dbgs;   // array
//  struct architecture       *rchtr;  // unused, all zero
    struct globalptr          *gptr;   // TODO: find a file with a global pointer
    struct tls_dir            *tlst;
    union { // Consider typecast instead of union
        struct load_config_32 *ldcfg32;
        struct load_config_64 *ldcfg64;
    };
    struct bound_import       *bmprt;  // TODO: find a file with bound imports
    struct iat_data           *iat;    // TODO: find documentation on this dir
    struct delay_import       *dmprt;  // TODO: find a file with delay imports
    struct clr_data           *clr;    // TODO: find a file with clr runtime
    unsigned int mprts_len;
    unsigned int xcpts_len;
    unsigned int certs_len;
    unsigned int relocs_len;
    unsigned int dbgs_len;
};

#endif

