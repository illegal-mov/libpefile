#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wctype.h>
#include "errors.h"
#include "utils.h"

const char* pefile_field_name_dos(int index)
{
    switch (index) {
        case PE_DH_MAGIC   : return "Signature";
        case PE_DH_CBLP    : return "Count of Bytes on Last Page";
        case PE_DH_CP      : return "Count of Pages";
        case PE_DH_CRLC    : return "Count of Relocations";
        case PE_DH_CPARHDR : return "Count of Paragraph Headers";
        case PE_DH_MINALLOC: return "Minimum Allocations";
        case PE_DH_MAXALLOC: return "Maximum Allocations";
        case PE_DH_SS      : return "Initial SS";
        case PE_DH_SP      : return "Initial SP";
        case PE_DH_CSUM    : return "Checksum";
        case PE_DH_IP      : return "Initial IP";
        case PE_DH_CS      : return "Initial CS";
        case PE_DH_LFARLC  : return "Offset to Relocations";
        case PE_DH_OVNO    : return "Overlay Number";
        case PE_DH_RES     : return "Reserved1";
        case PE_DH_OEMID   : return "OEM Identifier";
        case PE_DH_OEMINFO : return "OEM Info";
        case PE_DH_RES2    : return "Reserved2";
        case PE_DH_LFANEW  : return "File Offset to NT Header";
        default            : return "<UNKNOWN>";
    }
}

const char* pefile_field_name_file(int index)
{
    switch (index) {
        case PE_FH_MACHINE   : return "Machine";
        case PE_FH_NUMSEC    : return "Number of Sections";
        case PE_FH_TIMESTAMP : return "Timestamp";
        case PE_FH_SYMPTR    : return "Pointer to Symbols";
        case PE_FH_NUMSYM    : return "Number of Symbols";
        case PE_FH_OPTHDRSIZE: return "Optional Header Size";
        case PE_FH_CHARACT   : return "Characteristics";
        default              : return "<UNKNOWN>";
    }
}

const char* pefile_characteristics_name_file(int index)
{
    switch (index) {
        case PE_FC_RELOCS_STRIPPED        : return "Relocations Stripped";
        case PE_FC_EXECUTABLE_IMAGE       : return "Image is Executable";
        case PE_FC_LINE_NUMS_STRIPPED     : return "Line Numbers Stripped";
        case PE_FC_LOCAL_SYMS_STRIPPED    : return "Local Symbols Stripped";
        case PE_FC_AGGRESIVE_WS_TRIM      : return "Working Set Trimmed";
        case PE_FC_LARGE_ADDRESS_AWARE    : return "Supports >2GB Addresses";
        case PE_FC_RESERVED               : return "<Reserved>";
        case PE_FC_BYTES_REVERSED_LO      : return "Little Endian";
        case PE_FC_32BIT_MACHINE          : return "32-bit Word Architecture";
        case PE_FC_DEBUG_STRIPPED         : return "Debug Information Stripped";
        case PE_FC_REMOVABLE_RUN_FROM_SWAP: return "Copy from External to Swap";
        case PE_FC_NET_RUN_FROM_SWAP      : return "Copy from Network to Swap";
        case PE_FC_SYSTEM                 : return "Image is System File";
        case PE_FC_IS_DLL                 : return "File is DLL";
        case PE_FC_UP_SYSTEM_ONLY         : return "Multiprocessors Unsupported";
        case PE_FC_BYTES_REVERSED_HI      : return "Big Endian";
        default                           : return "<UNKNOWN>";
    }
}

const char* pefile_field_name_optional(int index)
{
    switch (index) {
        case PE_OH_MAGIC       : return "Magic";
        case PE_OH_LINKVERMAJ  : return "Major Linker Version";
        case PE_OH_LINKVERMIN  : return "Minor Linker Version";
        case PE_OH_CODESIZE    : return "Size of Code";
        case PE_OH_INITSIZE    : return "Size of Initialized Data";
        case PE_OH_UNINITSIZE  : return "Size of Uninitialized Data";
        case PE_OH_ENTRYPTR    : return "Address of Entry Point";
        case PE_OH_CODEPTR     : return "Base of Code";
        case PE_OH_DATAPTR     : return "Base of Data"; // 32-bit only
        case PE_OH_BASEADDR    : return "Image Base Address";
        case PE_OH_SECALIGN    : return "Section Alignment";
        case PE_OH_FILEALIGN   : return "File Alignment";
        case PE_OH_OSVERMAJ    : return "OS Major Version";
        case PE_OH_OSVERMIN    : return "OS Minor Version";
        case PE_OH_IMGVERMAJ   : return "Image Major Version";
        case PE_OH_IMGVERMIN   : return "Image Minor Version";
        case PE_OH_SYSVERMAJ   : return "Subsystem Major Version";
        case PE_OH_SYSVERMIN   : return "Subsystem Minor Version";
        case PE_OH_WINVER      : return "Win32 Version";
        case PE_OH_IMGSIZE     : return "Size of Image";
        case PE_OH_HDRSIZE     : return "Size of Headers";
        case PE_OH_CHECKSUM    : return "Image File Checksum";
        case PE_OH_SUBSYS      : return "Required Subsystem";
        case PE_OH_DLLCHARACT  : return "DLL Characteristics";
        case PE_OH_STACKRESSIZE: return "Size of Stack Reserve";
        case PE_OH_STACKCOMSIZE: return "Size of Stack Commit";
        case PE_OH_HEAPRESSIZE : return "Size of Heap Reserve";
        case PE_OH_HEAPCOMSIZE : return "Size of Heap Commit";
        case PE_OH_LDRFLAGS    : return "Loader Flags";
        case PE_OH_DDIRLEN     : return "Data Directory Length";
        case PE_OH_DATADIR     : return "Data Directory";
        default                : return "<UNKNOWN>";
    }
}

const char* pefile_characteristics_name_optional(int index)
{
    switch (index) {
        case PE_DC_HIGH_ENTROPY_VA      : return "High Entropy Address Support";
        case PE_DC_DYNAMIC_BASE         : return "ASLR Support";
        case PE_DC_FORCE_INTEGRITY      : return "Code Integrity Checks Enabled";
        case PE_DC_NX_COMPAT            : return "DEP Support";
        case PE_DC_NO_ISOLATION         : return "Isolation Disabled";
        case PE_DC_NO_SEH               : return "SEH Disabled";
        case PE_DC_NO_BIND              : return "Image Binding Disabled";
        case PE_DC_APPCONTAINER         : return "Must Execute in AppContainer";
        case PE_DC_WDM_DRIVER           : return "Image is WDM Driver";
        case PE_DC_GUARD_CF             : return "Control Flow Guard Support";
        case PE_DC_TERMINAL_SERVER_AWARE: return "Terminal Server Aware";
        default                         : return "<UNKNOWN>";
    }
}

const char* pefile_field_name_section(int index)
{
    switch (index) {
        case PE_SH_NAME    : return "Name";
        case PE_SH_MEMSIZE : return "Virtual Size";
        case PE_SH_DATAPTR : return "Virtual Address";
        case PE_SH_DISKSIZE: return "Size of Raw Data";
        case PE_SH_DATAOFFS: return "Pointer to Raw Data";
        case PE_SH_RELOCPTR: return "Pointer to Relocations";
        case PE_SH_LNNUMPTR: return "Pointer to Line Numbers";
        case PE_SH_NUMRELOC: return "Number of Relocations";
        case PE_SH_NUMLNNUM: return "Number of Line Numbers";
        case PE_SH_CHARACT : return "Characteristics";
        default            : return "<UNKNOWN>";
    }
}

const char* pefile_characteristics_name_section(int index)
{
    switch (index) {
        case PE_SC_RESERVED_1     : return "<Reserved>";
        case PE_SC_RESERVED_2     : return "<Reserved>";
        case PE_SC_RESERVED_4     : return "<Reserved>";
        case PE_SC_TYPE_NO_PAD    : return "Not Padded";
        case PE_SC_RESERVED_10    : return "<Reserved>";
        case PE_SC_CNT_CODE       : return "Contains Executable Code";
        case PE_SC_CNT_INIT_DATA  : return "Contains Initialized Data";
        case PE_SC_CNT_UNINIT_DATA: return "Contains Uninitialized Data";
        case PE_SC_RESERVED_100   : return "<Reserved>";
        case PE_SC_LNK_INFO       : return "Contains Miscellaneous Information";
        case PE_SC_RESERVED_400   : return "<Reserved>";
        case PE_SC_LNK_REMOVE     : return "Not Part of Image";
        case PE_SC_LNK_COMDAT     : return "Contains COMDAT Data";
        case PE_SC_RESERVED_2000  : return "<Reserved>";
        case PE_SC_RESERVED_4000  : return "<Reserved>";
        case PE_SC_GPREL          : return "Referenced by Global Pointer";
        case PE_SC_MEM_PURGEABLE  : return "<Reserved>";
        case PE_SC_MEM_16BIT      : return "<Reserved>";
        case PE_SC_MEM_LOCKED     : return "<Reserved>";
        case PE_SC_MEM_PRELOAD    : return "<Reserved>";
        case PE_SC_LNK_NRELOC_OVFL: return "Contains Extended Relocations";
        case PE_SC_MEM_DISCARDABLE: return "Discardable";
        case PE_SC_MEM_NOT_CACHED : return "Uncacheable";
        case PE_SC_MEM_NOT_PAGED  : return "Unpageable";
        case PE_SC_MEM_SHARED     : return "Sharable";
        case PE_SC_MEM_EXECUTE    : return "Executable";
        case PE_SC_MEM_READ       : return "Readable";
        case PE_SC_MEM_WRITE      : return "Writable";
        default                   : return "<UNKNOWN>";
    }
}

const char* pefile_characteristics_alignment_name_section(int alignNybble)
{
    switch (alignNybble) {
        case PE_SC_ALIGN_1BYTES   : return "1-byte Alignment";
        case PE_SC_ALIGN_2BYTES   : return "2-byte Alignment";
        case PE_SC_ALIGN_4BYTES   : return "4-byte Alignment";
        case PE_SC_ALIGN_8BYTES   : return "8-byte Alignment";
        case PE_SC_ALIGN_16BYTES  : return "16-byte Alignment";
        case PE_SC_ALIGN_32BYTES  : return "32-byte Alignment";
        case PE_SC_ALIGN_64BYTES  : return "64-byte Alignment";
        case PE_SC_ALIGN_128BYTES : return "128-byte Alignment";
        case PE_SC_ALIGN_256BYTES : return "256-byte Alignment";
        case PE_SC_ALIGN_512BYTES : return "512-byte Alignment";
        case PE_SC_ALIGN_1024BYTES: return "1024-byte Alignment";
        case PE_SC_ALIGN_2048BYTES: return "2048-byte Alignment";
        case PE_SC_ALIGN_4096BYTES: return "4096-byte Alignment";
        case PE_SC_ALIGN_8192BYTES: return "8192-byte Alignment";
        default                   : return "<UNKNOWN>";
    }
}

const char* pefile_field_name_debug_dir(int index)
{
    switch (index) {
        case PE_DD_CHARACT  : return "Characteristics";
        case PE_DD_TIMESTAMP: return "Timestamp";
        case PE_DD_DBGVERMAJ: return "Major Version";
        case PE_DD_DBGVERMIN: return "Minor Version";
        case PE_DD_DBGTYPE  : return "Type";
        case PE_DD_DISKSIZE : return "Size of Raw Data";
        case PE_DD_DATAPTR  : return "Virtual Address";
        case PE_DD_DATAOFFS : return "Pointer to Raw Data";
        default             : return "<UNKNOWN>";
    }
}

const char* pefile_field_name_loadconfig_dir(int index)
{
    switch (index) {
        case PE_LD_CHARACT    : return "Characteristics";
        case PE_LD_TIMESTAMP  : return "Timestamp";
        case PE_LD_VERMAJ     : return "Major Version";
        case PE_LD_VERMIN     : return "Minor Version";
        case PE_LD_FLAGSCLEAR : return "Global Flags to Clear";
        case PE_LD_FLAGSSET   : return "Global Flags to Set";
        case PE_LD_TIMEOUT    : return "Critical Section Default Timeout";
        case PE_LD_MEMFREE    : return "Memory to Free";
        case PE_LD_TOTALMEM   : return "Total Free Memory";
        case PE_LD_LOCKPTR    : return "Pointer to LOCK Prefix Table";
        case PE_LD_MAXALLOC   : return "Maximum Allocation Size";
        case PE_LD_MINALLOC   : return "Maximum Memory Size";
        case PE_LD_AFFINITY   : return "Affinity Mask";
        case PE_LD_HEAPFLAGS  : return "Heap Flags";
        case PE_LD_SERVPACKID : return "Service Pack Version ID";
        case PE_LD_RESERVED   : return "<Reserved>";
        case PE_LD_EDITLIST   : return "<Unknown>"; // TODO: what is EDIT_LIST?
        case PE_LD_COOKIEPTR  : return "Cookie Pointer";
        case PE_LD_EXCEPTPTR  : return "Pointer to Exception Handlers";
        case PE_LD_EXCEPTLEN  : return "Number of Exception Handlers";
        case PE_LD_CHECKPTR   : return "Pointer to Guard Check";
        case PE_LD_DISPATCHPTR: return "Pointer to Guard Dispatch";
        case PE_LD_FUNCPTR    : return "Pointer to Guard Functions";
        case PE_LD_FUNCLEN    : return "Number of Guard Functions";
        case PE_LD_GUARDFLAGS : return "Guard Flags";
        case PE_LD_CODEINTEG  : return "Code Integrity";
        case PE_LD_TAKENPTR   : return "Pointer to Address Taken";
        case PE_LD_TAKENLEN   : return "Number of Address Taken";
        case PE_LD_JUMPSPTR   : return "Pointer to Long Jumps";
        case PE_LD_JUMPSLEN   : return "Number of Long Jumps";
        default               : return "<UNKNOWN>";
    }
}

/* Get index of the section a directory entry was merged into
 * Returns the index of the relevant section or PEFILE_NO_SECTION if not found
 */
int pefile_get_section_of_dir(
    const struct pefile   *pe,
    const struct data_dir *entry)
{
    if (entry->rva == 0 || entry->size == 0)
        return PEFILE_NO_SECTION; // -1

    int num_sections = pe->nt.file.number_of_sections;
    for (int i=0; i < num_sections; i++) {
        uint32_t va = pe->sctns[i].data_rva;
        uint32_t sz = pe->sctns[i].size_in_memory;
        if (va <= entry->rva &&
            entry->rva < va + sz)
            return i;
    }
    return PEFILE_NO_SECTION; // -1
}

/* Adjust offsets when a data directory entry is merged into some section.
 * Is used to convert a Relative Virtual Address into an Absolute Physical Address.
 * Returns the integer difference between the virtual address and raw address.
 */
int pefile_get_rva_to_apa_diff(
    const struct section_h *sctns,
    int                     section_index)
{
    assert(sctns[section_index].data_rva >=
           sctns[section_index].data_apa);
    return sctns[section_index].data_rva -
           sctns[section_index].data_apa;
}

/* Get directory name from index
 */
char* pefile_dir_to_str(
    int index)
{
    switch (index) {
        case PE_DE_EXPORT:       return "Export directory";
        case PE_DE_IMPORT:       return "Import directory";
        case PE_DE_RESOURCE:     return "Resource directory";
        case PE_DE_EXCEPTION:    return "Exception directory";
        case PE_DE_CERTIFICATE:  return "Certificate directory";
        case PE_DE_RELOCATION:   return "Relocation directory";
        case PE_DE_DEBUG:        return "Debug directory";
        case PE_DE_ARCHITECTURE: return "Architecture directory";
        case PE_DE_GLOBALPTR:    return "Global pointer directory";
        case PE_DE_TLS:          return "TLS directory";
        case PE_DE_LOAD_CONFIG:  return "Load config directory";
        case PE_DE_BOUND_IMPORT: return "Bound import directory";
        case PE_DE_IAT:          return "IAT directory";
        case PE_DE_DELAY_IMPORT: return "Delay import directory";
        case PE_DE_CLR:          return "CLR directory";
        default:                 return "<UNKNOWN_DIRECTORY>";
    }
}

/* Resize allocated memory
 * Calls error handler if allocation fails
 */
void* pefile_realloc(
    void       *buf,
    size_t      size,
    const char *err_msg,
    char       *err_buf)
{
    void *tmp = realloc(buf, size);
    if (tmp == NULL) {
        strcpy(err_buf, "Failed to resize memory for ");
        strncat(err_buf, err_msg, PEFILE_ERRBUF_LEN);
        pefile_error_handler(PEFILE_FAILED_ALLOC, err_buf);
    }
    return tmp;
}

/* Allocate memory
 * Calls error handler if allocation fails
 */
void* pefile_malloc(
    size_t      size,
    const char *err_msg,
    char       *err_buf)
{
    void *tmp = malloc(size);
    if (tmp == NULL) {
        strcpy(err_buf, "Failed to allocate memory for ");
        strncat(err_buf, err_msg, PEFILE_ERRBUF_LEN);
        pefile_error_handler(PEFILE_FAILED_ALLOC, err_buf);
    }
    return tmp;
}

/* Call error handler function if EOF was reached
 */
void pefile_is_trunc(
    FILE       *fp,
    const char *err_msg,
    char       *err_buf)
{
    if (feof(fp)) {
        strncpy(err_buf, err_msg, PEFILE_ERRBUF_LEN);
        strncat(err_buf, " truncated", PEFILE_ERRBUF_LEN);
        pefile_error_handler(PEFILE_IS_TRUNCATED, err_buf);
    }
}

/* Push a breadcrumb to the top of the breadcrumb stack
 * This is used when walking the resource directory
 */
void pefile_breadcrumb_push(
    struct pefile_crumbs **root,
    struct pefile_crumbs  *top)
{
    struct pefile_crumbs *bcnew = malloc(sizeof(*bcnew));
    memcpy(bcnew, top, sizeof(*top));
    bcnew->next = *root;
    *root = bcnew;
}

/* Pop a breadcrumb from the top of the breadcrumb stack
 * This is used when walking the resource directory
 */
void pefile_breadcrumb_pop(
    struct pefile_crumbs **root,
    struct pefile_crumbs  *ret)
{
    struct pefile_crumbs *top = *root;
    *root = top->next;
    memcpy(ret, top, sizeof(*ret));
    free(top);
}

