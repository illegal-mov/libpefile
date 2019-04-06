#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "errors.h"
#include "multiarch.h"
#include "reader.h"
#include "struct.h"
#include "utils.h"

static void read_import_desc_name(struct pefile *pe, struct import_table *idata, int diff, char *err_buf);
void (*pefile_error_handler)(int status, char *err_msg) = pefile_exit;

// macro'd 32 and 64 bit versions of the same function
/* Read hint and name of the imported function
 * Some functions might be imported by ordinal and will not have a hint or name
 */
PEFILE_READ_IMPORT_HINT_NAME(32, ) PEFILE_READ_IMPORT_HINT_NAME(64, l)

/* Build array of offsets to names of imported functions
 * Returns a pointer to the base of the new array
 */
PEFILE_READ_IMPORT_NAMES_TABLE(32) PEFILE_READ_IMPORT_NAMES_TABLE(64)

/* Build array of import descriptors
 * Returns the length of the new array
 */
PEFILE_READ_IMPORT_DIR(32) PEFILE_READ_IMPORT_DIR(64)

/* Read the exception directory
 */
PEFILE_READ_EXCEPTION_DIR(32) PEFILE_READ_EXCEPTION_DIR(64)

/* Read the TLS directory
 */
PEFILE_READ_TLS_DIR(32) PEFILE_READ_TLS_DIR(64)

/* Read the load config directory
 */
PEFILE_READ_LOAD_CONFIG_DIR(32) PEFILE_READ_LOAD_CONFIG_DIR(64)

/* Validate directory entry addresses and sizes
 * All directory entry offsets must be less than the file size
 */
static int is_all_de_in_file(
    struct pefile *pe,
    char          *err_buf)
{
    // get file size
    fseek(pe->file, 0, SEEK_END);
    long file_size = ftell(pe->file);
    for (int i=0; i < PEFILE_DATA_DIR_LEN; i++) {
        int index = pefile_get_section_of_dir(pe, &pe->nt.opt.ddir[i]);
        if (index != PEFILE_NO_SECTION) {
            int diff = pefile_fix_offset(pe->sctns, index);
            struct data_dir *dd = pe->nt.opt.ddir;
            /* ensure file offset to data directory entry
             * plus that entry's size is less than file size
             */
            if (dd[i].rva + dd[i].size - diff >= file_size) {
                snprintf(err_buf, PEFILE_ERRBUF_LEN, "%s %s",
                    pefile_dir_to_str(i), "is truncated");
                pefile_error_handler(PEFILE_GENERIC_ERR, err_buf);
                return 0;
            }
        }
    }
    return 1;
}

/* Read the DOS header
 */
static void read_dos_h(
    struct pefile *pe,
    char          *err_buf)
{
    fseek(pe->file, 0, SEEK_SET);
    fread(&pe->dos, sizeof(pe->dos), 1, pe->file);
    pefile_is_trunc(pe->file, "DOS header is", err_buf);

    if (strncmp(pe->dos.e_magic, "MZ", 2) != 0) {
        strcpy(err_buf, "Invalid DOS header magic");
        pefile_error_handler(PEFILE_BAD_SIG, err_buf);
    }
}

/* Read the Optional header
 */
static void read_optional_h(
    struct pefile *pe,
    char          *err_buf)
{
    // read up to but not including loader_flags
    // loader_flags marks start of some 32/64 bit fields
    fread(&pe->nt.opt, 1,
        offsetof(struct optional_common_h, loader_flags), pe->file);

    // read architecture specific fields
    if (pe->nt.opt.magic == PE_OH_32) {
        fread(&pe->nt.opt.opt32, sizeof(pe->nt.opt.opt32), 1, pe->file);
        assert(pe->nt.opt.base_address_32 % 0x10000 == 0);
    } else if (pe->nt.opt.magic == PE_OH_64) {
        fread(&pe->nt.opt.opt64, sizeof(pe->nt.opt.opt64), 1, pe->file);
        assert(pe->nt.opt.base_address_64 % 0x10000 == 0);
    } else {
        strcpy(err_buf, "Unknown optional header magic");
        pefile_error_handler(PEFILE_BAD_SIG, err_buf);
    }

    // read last two common fields and data directory
    fread(&pe->nt.opt.loader_flags, 1,
        sizeof(pe->nt.opt.loader_flags)            +
        sizeof(pe->nt.opt.number_of_rva_and_sizes) +
        sizeof(pe->nt.opt.ddir), pe->file);

    pefile_is_trunc(pe->file, "Optional header is", err_buf);

    /* assert facts about fields because Microsoft documentation said so */
    assert(pe->nt.opt.section_alignment >= pe->nt.opt.file_alignment);
    assert(pe->nt.opt.win32_version == 0);
    assert(pe->nt.opt.image_size % pe->nt.opt.section_alignment == 0);
    assert(pe->nt.opt.loader_flags == 0);
}

/* Read the NT header
 */
static void read_nt_h(
    struct pefile *pe,
    char          *err_buf)
{
    // read NT magic and file header
    fseek(pe->file, pe->dos.e_lfanew, SEEK_SET);
    fread(&pe->nt, offsetof(struct nt_h, opt), 1, pe->file);
    pefile_is_trunc(pe->file, "NT header is", err_buf);

    if (strncmp(pe->nt.signature, "PE", 2) != 0) {
        strcpy(err_buf, "Invalid NT header magic");
        pefile_error_handler(PEFILE_BAD_SIG, err_buf);
    }

    read_optional_h(pe, err_buf);
}

/* Read array of section headers located immediately after the optional header
 */
static void read_section_h(
    struct pefile *pe,
    char          *err_buf)
{
    uint16_t number_of_sections = pe->nt.file.number_of_sections;
    pe->sctns = pefile_malloc(
        sizeof(pe->sctns[0]) * number_of_sections,
        "section headers", err_buf);

    fread(pe->sctns, sizeof(pe->sctns[0]), number_of_sections, pe->file);
    pefile_is_trunc(pe->file, "Section headers are", err_buf);
}

/* Build array of ordinals for names
 * Returns a pointer to the base of the array
 */
static uint16_t* read_export_ordinal_table(
    struct pefile *pe,
    int            diff,
    char          *err_buf)
{
    uint32_t number_of_names = pe->xprt->nords_len;
    uint16_t *nords = pefile_malloc(
        sizeof(nords[0]) * number_of_names,
        "export name ordinals", err_buf);

    fseek(pe->file, pe->xprt->edir.ordinals_rva - diff, SEEK_SET);
    fread(nords, sizeof(nords[0]), number_of_names, pe->file);
    return nords;
}

/* Build array of functions exported by ordinal.
 * This type of export is a simple array of RVAs to
 * code on disk so the RVAs must be changed to file
 * offsets because they are merged into .text section.
 * Returns an array of structs of RVAs and file offsets to code.
 */
static struct export_func_ptr* read_export_address_table(
    struct pefile *pe,
    int            xprt_diff,
    char          *err_buf)
{
    uint32_t number_of_functions = pe->xprt->addrs_len;
    struct export_func_ptr *ords = pefile_malloc(
        sizeof(ords[0]) * number_of_functions,
        "export function ordinals", err_buf);

    // fread only one `ord` just to get its rva
    fseek(pe->file, pe->xprt->edir.functions_rva - xprt_diff, SEEK_SET);
    fread(&ords[0].code_rva, sizeof(ords[0].code_rva), 1, pe->file);

    // dirty hack to find `.text` section diff
    struct data_dir temp = {.rva=ords[0].code_rva, .size=1};
    int index = pefile_get_section_of_dir(pe, &temp);
    int code_diff = pefile_fix_offset(pe->sctns, index);

    // can now get true file offset to exported functions
    ords[0].code_apa = ords[0].code_rva - code_diff;
    for (uint32_t i=1; i < number_of_functions; i++) {
        fread(&ords[i].code_rva, sizeof(ords[0].code_rva), 1, pe->file);
        ords[i].code_apa = ords[i].code_rva - code_diff;
    }

    return ords;
}

/* Reads the name of the exported function.
 */
static void read_exported_func_name(
    struct pefile         *pe,
    struct export_by_name *ebn,
    int                    diff)
{
    long pos = ftell(pe->file);
    fseek(pe->file, ebn->name_rva - diff, SEEK_SET);
    fgets(ebn->name, PEFILE_NAME_FUNCTION_MAX_LEN, pe->file);
    fseek(pe->file, pos, SEEK_SET);
}

/* This is an array of RVAs to exported function names.
 * Read all array elements and use each element to offset to
 * file location where the function name is stored.
 * Returns the base address of the array of RVAs and names.
 */
static struct export_by_name* read_export_names_table(
    struct pefile *pe,
    int            diff,
    char          *err_buf)
{
    uint32_t number_of_names = pe->xprt->names_len;
    struct export_by_name *names = pefile_malloc(
        sizeof(names[0]) * number_of_names,
        "export function names", err_buf);

    fseek(pe->file, pe->xprt->edir.names_rva - diff, SEEK_SET);
    for (uint32_t i=0; i < number_of_names; i++) {
        // get RVA to function name
        fread(&names[i].name_rva, sizeof(names[i].name_rva), 1, pe->file);
        read_exported_func_name(pe, &names[i], diff);
    }

    return names;
}

/* Export directory is a single table with 3 pointers to different
 * pieces of export data. The export types are code, ordinal, and name.
 */
static void read_export_dir(
    struct pefile *pe,
    char          *err_buf)
{
    int index = pefile_get_section_of_dir(pe, &pe->nt.opt.ddir[PE_DE_EXPORT]);
    if (index == PEFILE_NO_SECTION)
        return;

    int diff = pefile_fix_offset(pe->sctns, index);

    pe->xprt = pefile_malloc(sizeof(*pe->xprt), "export directory", err_buf);
    fseek(pe->file, pe->nt.opt.ddir[PE_DE_EXPORT].rva - diff, SEEK_SET);
    fread(&pe->xprt->edir, sizeof(*pe->xprt), 1, pe->file);

    pe->xprt->addrs_len = pe->xprt->edir.number_of_functions;
    pe->xprt->nords_len = pe->xprt->edir.number_of_names;
    pe->xprt->names_len = pe->xprt->edir.number_of_names;

    pefile_is_trunc(pe->file, "Export directory is", err_buf);
    assert(pe->xprt->edir.characteristics == 0);
    pe->xprt->addrs = read_export_address_table(pe, diff, err_buf);
    pe->xprt->nords = read_export_ordinal_table(pe, diff, err_buf);
    pe->xprt->names = read_export_names_table(pe, diff, err_buf);
}

/* Read name of the module being imported from
 */
static void read_import_desc_name(
    struct pefile       *pe,
	struct import_table *idata,
	int                  diff,
	char                *err_buf)
{
    long pos = ftell(pe->file);
    fseek(pe->file, idata->metadata.name - diff, SEEK_SET);
    fgets(idata->name, PEFILE_NAME_MODULE_MAX_LEN, pe->file);
    pefile_is_trunc(pe->file, "An import descriptor is", err_buf);
    fseek(pe->file, pos, SEEK_SET);
}

/* Get the Windows wchar_t resource name
 * Windows wchar_t is 2 bytes while Linux wchar_t is 4 bytes
 */
static void read_resource_name(
    struct pefile        *pe,
	struct resource_node *rn,
	int                   rsrc_base,
	char                 *err_buf)
{
    long pos = ftell(pe->file);
    fseek(pe->file, rsrc_base + rn->entry.name_offset, SEEK_SET);
    fread(&rn->res_name.name_len, sizeof(rn->res_name.name_len), 1, pe->file);
    unsigned int name_len = rn->res_name.name_len;
    if (name_len >= PEFILE_NAME_RESOURCE_MAX_LEN) {
        strcpy(err_buf, "Resource name is too long");
        pefile_error_handler(PEFILE_LONG_RES_NAME, err_buf);
    }

    // size of wchar_t may be 4 bytes so I must
    // fread one 2-byte Windows wchar_t at a time
    // or else two Windows wchar_t may get shoved
    // into the same 4 byte space.
    for (unsigned int i=0; i < name_len; i++)
        fread(&rn->res_name.name[i], sizeof(uint16_t), 1, pe->file);

    // null terminate the string
    rn->res_name.name[name_len] = 0;
    fseek(pe->file, pos, SEEK_SET);
}

/* Read resource header which contains numberOfNameEntries and numberofIdEntries
 * Use total number of entries to read array of entries located immediately after the header
 */
static void read_resource_table(
    struct pefile         *pe,
	struct resource_table *rt,
	int                    rsrc_addr,
	char                  *err_buf)
{
    // read resource header
    fseek(pe->file, rsrc_addr, SEEK_SET);
    fread(&rt->header, sizeof(rt->header), 1, pe->file);

    // allocate memory for resource entries
    int number_of_entries = rt->header.number_of_named_entries + rt->header.number_of_id_entries;

    rt->nodes_len = number_of_entries;
    assert(number_of_entries > 0);
    rt->nodes = pefile_malloc(
        sizeof(rt->nodes[0]) * number_of_entries,
        "resource directory entries", err_buf);

    // read array of resource entries
    for (int i=0; i < number_of_entries; i++)
        fread(&rt->nodes[i].entry, sizeof(rt->nodes[0].entry), 1, pe->file);
}

/* Get the size and location of the actual resource data
 */
static void read_resource_metadata(
    struct pefile *pe,
	struct resource_node *rn,
	int rsrc_addr)
{
    // seek to and read resource metadata
    fseek(pe->file, rsrc_addr, SEEK_SET);
    fread(&rn->metadata, sizeof(rn->metadata), 1, pe->file);
    assert(rn->metadata.reserved == 0);
}

/* The resource directory is a tree structure with a variable number of nodes
 * per level. This function reads the resource table for each level of the
 * resource directory. Each resource entry is checked if it is a directory
 * and if it is, the current position in the resource directory is saved in
 * a linked list before entering the new resource table and applying
 * the algorithm to this new resource table. If the resource entry is not a
 * directory, it reads that entry's data and pops from the linked list to
 * return to the parent. The linked list is also popped from when the
 * `for` loop over the variable number of resource entries reaches the
 * last resource entry.
 */
static void read_resource_dir(
    struct pefile *pe,
	char          *err_buf)
{
    int index = pefile_get_section_of_dir(pe, &pe->nt.opt.ddir[PE_DE_RESOURCE]);
    if (index == PEFILE_NO_SECTION)
        return;

    int diff = pefile_fix_offset(pe->sctns, index);
    int rsrc_base = pe->nt.opt.ddir[PE_DE_RESOURCE].rva - diff;
    int rsrc_offset = 0;

    pe->rsrc = pefile_malloc(sizeof(*pe->rsrc),
        "resource table header", err_buf);
    struct pefile_crumbs *crms = NULL, current = {.res_table=pe->rsrc};

    do {
        read_resource_table(pe, current.res_table, rsrc_base + rsrc_offset, err_buf);
        current.array_len = current.res_table->nodes_len;

        for (current.index=0; current.index < current.array_len; current.index++) {
            struct resource_node *rn = &current.res_table->nodes[current.index];
            if (rn->entry.has_name_string)
                read_resource_name(pe, rn, rsrc_base, err_buf);

            if (rn->entry.is_directory) {
                // save crumb before entering next directory
                pefile_breadcrumb_push(&crms, &current);
                rn->table = pefile_malloc(sizeof(*rn->table),
                    "resource table header", err_buf);
                // set rsrc_offset for the upcoming call to `read_resource_table`
                rsrc_offset = rn->entry.directory_offset;
                current.res_table = rn->table;
                break;
            } else {
                read_resource_metadata(pe, rn, rsrc_base + rn->entry.data_offset);
                // return to parent directory
                pefile_breadcrumb_pop(&crms, &current);
            }

            // ensure pop when index iterator is done
            if (current.index == current.array_len - 1)
                pefile_breadcrumb_pop(&crms, &current);
        }
    // end of algorithm when crumb is at top level and index iterator is done
    } while (crms != NULL);

    pefile_is_trunc(pe->file, "Resource directory is", err_buf);
}

/* The certificate directory is an array of 8-byte headers each
 * concatenated with a variable number of bytes of certificate data
 */
static void read_certificate_dir(
    struct pefile *pe,
	char          *err_buf)
{
    int index = pefile_get_section_of_dir(pe, &pe->nt.opt.ddir[PE_DE_CERTIFICATE]);
    if (index == PEFILE_NO_SECTION)
        return;

    // start with enough memory allocated for 2 certificates
    uint32_t cd_max_len = 2; // ALERT! Arbitrary number
    pe->certs = pefile_malloc(sizeof(pe->certs[0]) * cd_max_len,
        "certificate directory", err_buf);

    // no `pefile_fix_offset` here because the certificate directory is weird like that
    fseek(pe->file, pe->nt.opt.ddir[PE_DE_CERTIFICATE].rva, SEEK_SET);
    uint32_t bytes_read = 0, cd_len = 0;
    uint32_t cert_dir_size = pe->nt.opt.ddir[PE_DE_CERTIFICATE].size;

    while (bytes_read < cert_dir_size) {
        // read certificate metadata which includes certicificate size
        fread(&pe->certs[cd_len].metadata, sizeof(pe->certs[0].metadata), 1, pe->file);
        uint32_t cert_size = pe->certs[cd_len].metadata.size;
        assert(cert_size <= cert_dir_size);

        // allocate memory for and read certificate bytes
        pe->certs[cd_len].data = pefile_malloc(cert_size,
            "certificate directory", err_buf);

        fread(pe->certs[cd_len].data, cert_size, 1, pe->file);

        // pad to align on 8-byte boundaries
        int alignment = (8 - (cert_size & 7)) & 7;
        fseek(pe->file, alignment, SEEK_CUR);
        bytes_read += cert_size;
        bytes_read += alignment;
        cd_len++;

        // unknown array length, so keep doubling memory when space runs out
        if (cd_len >= cd_max_len) {
            cd_max_len <<= 1;
            pe->certs = pefile_realloc(pe->certs,
                sizeof(pe->certs[0]) * cd_max_len,
                "certificate directory",
                err_buf);
        }
    }

    assert(bytes_read == cert_dir_size);
    pe->certs_len = cd_len;
    // no `is_trunc()` check here because certificates
    // may be located at the very end of the file
}

static void read_relocation_block(
    struct pefile      *pe,
	struct reloc_table *relocblock,
	char               *err_buf)
{
    // read relocation header to get size of block (header + all entries)
    fread(&relocblock->header, sizeof(relocblock->header), 1, pe->file);

    // read relocation entries
    uint32_t reloc_block_size = relocblock->header.size;
    assert(reloc_block_size - sizeof(relocblock->header) > 0);
    relocblock->entries = pefile_malloc(reloc_block_size
        - sizeof(relocblock->header), "relocation block", err_buf);
    fread(relocblock->entries, reloc_block_size
        - sizeof(relocblock->header), 1, pe->file);
    relocblock->entries_len = (reloc_block_size
        - sizeof(relocblock->header)) / sizeof(relocblock->entries[0]);
}

/* Relocation directory is a two-dimensional array
 */
static void read_relocation_dir(
    struct pefile *pe,
	char          *err_buf)
{
    int index = pefile_get_section_of_dir(pe, &pe->nt.opt.ddir[PE_DE_RELOCATION]);
    if (index == PEFILE_NO_SECTION)
        return;

    int diff = pefile_fix_offset(pe->sctns, index);
    fseek(pe->file, pe->nt.opt.ddir[PE_DE_RELOCATION].rva - diff, SEEK_SET);

    int bytes_read = 0, reloc_dir_size = pe->nt.opt.ddir[PE_DE_RELOCATION].size;

    // start with enough memory allocated for 32 blocks
    int blk_len = 0, blk_max_len = 32; // ALERT! Arbitrary number
    pe->relocs = pefile_malloc(sizeof(pe->relocs[0]) * blk_max_len,
        "relocation directory", err_buf);

    while (bytes_read < reloc_dir_size) {
        read_relocation_block(pe, &pe->relocs[blk_len], err_buf);
        bytes_read += pe->relocs[blk_len].header.size;
        blk_len++;
        // unknown array length, so keep doubling memory when space runs out
        if (blk_len >= blk_max_len) {
            blk_max_len <<= 1;
            pe->relocs = pefile_realloc(pe->relocs,
                sizeof(pe->relocs[0]) * blk_max_len,
                "relocation directory", err_buf);
        }
    }

    pefile_is_trunc(pe->file, "Relocation directory is", err_buf);
    pe->relocs_len = blk_len;
}

/* Read debug data pointed to by `debug_dir.apa`
 * The first 24 bytes of debug data are unknown, but an ASCII
 * string is present after the first 24 bytes.
 */
static void read_debug_data(
    struct pefile      *pe,
	struct debug_table *dbg_table,
	char               *err_buf)
{
    long pos = ftell(pe->file);
    fseek(pe->file, dbg_table->header.data_apa, SEEK_SET);
    fread(dbg_table->data.unknown, sizeof(dbg_table->data.unknown), 1, pe->file);
    fgets(dbg_table->data.pdb_path, PEFILE_PATH_MAX_LEN, pe->file);
    pefile_is_trunc(pe->file, "Debug data are", err_buf);
    fseek(pe->file, pos, SEEK_SET);
}

/* Debug directory is a variable length array of debug directory entry structs
 * Each debug directory entry is paired with a debug data struct
 */
static void read_debug_dir(
    struct pefile *pe,
	char          *err_buf)
{
    int index = pefile_get_section_of_dir(pe, &pe->nt.opt.ddir[PE_DE_DEBUG]);
    if (index == PEFILE_NO_SECTION)
        return;

    int diff = pefile_fix_offset(pe->sctns, index);
    fseek(pe->file, pe->nt.opt.ddir[PE_DE_DEBUG].rva - diff, SEEK_SET);
    int dbg_dir_size = pe->nt.opt.ddir[PE_DE_DEBUG].size;
    int dbgs_len = dbg_dir_size / sizeof(pe->dbgs[0].header);

    // use length of debug_directory to allocate enough memory for
    // all debug directory entries and all debug_data pointed to by
    // each debug directory entry
    pe->dbgs = pefile_malloc(dbgs_len * sizeof(*pe->dbgs),
        "debug directory", err_buf);
    for (int i=0; i < dbgs_len; i++) {
        fread(&pe->dbgs[i].header, sizeof(pe->dbgs[0].header), 1, pe->file);
        assert(pe->dbgs[i].header.characteristics == 0);
        read_debug_data(pe, &pe->dbgs[i], err_buf);
    }

    pefile_is_trunc(pe->file, "Debug directory is", err_buf);
    pe->dbgs_len = dbgs_len;
}

/*
static void read_globalptr_dir(
    struct pefile *pe,
	char          *err_buf)
{
    int index = pefile_get_section_of_dir(pe, &pe->nt.opt.ddir[PE_DE_GLOBALPTR]);
    if (index == PEFILE_NO_SECTION)
        return;
}

static void read_bound_import_dir(
    struct pefile *pe,
	char          *err_buf)
{
    int index = pefile_get_section_of_dir(pe, &pe->nt.opt.ddir[PE_DE_BOUND_IMPORT]);
    if (index == PEFILE_NO_SECTION)
        return;
}

static void read_iat_dir(
    struct pefile *pe,
	char          *err_buf)
{
    int index = pefile_get_section_of_dir(pe, &pe->nt.opt.ddir[PE_DE_IAT]);
    if (index == PEFILE_NO_SECTION)
        return;
}

static void read_delay_import_dir(
    struct pefile *pe,
	char          *err_buf)
{
    int index = pefile_get_section_of_dir(pe, &pe->nt.opt.ddir[PE_DE_DELAY_IMPORT]);
    if (index == PEFILE_NO_SECTION)
        return;
}

static void read_clr_dir(
    struct pefile *pe,
	char          *err_buf)
{
    int index = pefile_get_section_of_dir(pe, &pe->nt.opt.ddir[PE_DE_CLR]);
    if (index == PEFILE_NO_SECTION)
        return;
}
//*/

static void read_section_data(
    struct pefile *pe,
    char          *err_buf)
{
    read_section_h(pe, err_buf);
    is_all_de_in_file(pe, err_buf);

    if (pe->nt.opt.magic == PE_OH_32) {
        read_import_dir32(pe, err_buf);
        read_exception_dir32(pe, err_buf);
        read_tls_dir32(pe, err_buf);
        read_load_config_dir32(pe, err_buf);
    } else {
        read_import_dir64(pe, err_buf);
        read_exception_dir64(pe, err_buf);
        read_tls_dir64(pe, err_buf);
        read_load_config_dir64(pe, err_buf);
    }

    read_export_dir(pe, err_buf);
    read_resource_dir(pe, err_buf);
    read_certificate_dir(pe, err_buf);
    read_relocation_dir(pe, err_buf);
    read_debug_dir(pe, err_buf);
//  read_architecture_dir(pe, err_buf); // unused, always zero
//  read_globalptr_dir(pe, err_buf);    // TODO: find a file with a global pointer
//  read_bound_import_dir(pe, err_buf);  // TODO: find a file with bound imports
//  read_iat_dir(pe, err_buf);          // TODO: find documentation on this dir
//  read_delay_import_dir(pe, err_buf);  // TODO: find a file with delay imports
//  read_clr_dir(pe, err_buf);          // TODO: find a file with clr runtime
}

/* Initialize the PE file struct from a path to a suitable file on disk
 * Returns zero on success, non-zero on failure
 */
int pefile_init(struct pefile *pe, const char *path, void (*fp)(int, char*), char *err_buf)
{
    // change default error handler if one was provided
    if (fp != NULL)
        pefile_error_handler = fp;

    memset(pe, 0, sizeof(*pe));
    pe->file = fopen(path, "rb");
    if (pe->file == NULL) {
        strcpy(err_buf, "Error opening the file for reading");
        pefile_error_handler(PEFILE_GENERIC_ERR, err_buf);
    }

    read_dos_h(pe, err_buf);
    read_nt_h(pe, err_buf);
    read_section_data(pe, err_buf);
    return PEFILE_SUCCESS;
}

