#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "errors.h"
#include "utils.h"
#include "writer.h"

/* Write the DOS header
 */
static void writeDosH(
    struct pefile *pe)
{
    fseek(pe->file, 0, SEEK_SET);
    fwrite(&pe->dos, sizeof(pe->dos), 1, pe->file);
}

/* Write the Optional header
 */
static void writeOptionalH(
    struct pefile *pe)
{
    // write up to but not including loader_flags
    // loader_flags is first field after common 32/64 bit fields
    fwrite(&pe->nt.opt, 1,
        offsetof(struct optional_common_h, loader_flags), pe->file);

    // write architecture specific fields
    if (pe->nt.opt.magic == PE_OH_32) {
        fwrite(&pe->nt.opt.opt_32, sizeof(pe->nt.opt.opt_32), 1, pe->file);
        assert(pe->nt.opt.base_address_32 % 0x10000 == 0);
    } else if (pe->nt.opt.magic == PE_OH_64) {
        fwrite(&pe->nt.opt.opt_64, sizeof(pe->nt.opt.opt_64), 1, pe->file);
        assert(pe->nt.opt.base_address_64 % 0x10000 == 0);
    }

    // write last two common fields and data directory
    fwrite(&pe->nt.opt.loader_flags, 1,
        sizeof(pe->nt.opt.loader_flags)         +
        sizeof(pe->nt.opt.number_of_rva_and_sizes) +
        sizeof(pe->nt.opt.ddir), pe->file);

    assert(pe->nt.opt.section_alignment >= pe->nt.opt.file_alignment);
    assert(pe->nt.opt.win32_version == 0);
    assert(pe->nt.opt.image_size % pe->nt.opt.section_alignment == 0);
    assert(pe->nt.opt.loader_flags == 0);
}

/* Write the NT header
 */
static void writeNtH(
    struct pefile *pe)
{
    // write NT magic and file header
    fseek(pe->file, pe->dos.e_lfanew, SEEK_SET);
    fwrite(&pe->nt, offsetof(struct nt_h, opt), 1, pe->file);

    writeOptionalH(pe);
}

/* Write the PE file struct back to the file on disk
 * Returns zero on success, non-zero on failure
 */
int pefile_save(
    struct pefile *pe,
    const char    *path)
{
    if (pe->file != NULL)
        fclose(pe->file);

    pe->file = fopen(path, "r+b");
    if (pe->file == NULL) {
        pefile_error_handler(PEFILE_GENERIC_ERR, "Error opening the file for writing");
    }

    writeDosH(pe);
    writeNtH(pe);
    /* TODO: add everything else */
    return PEFILE_SUCCESS;
}

