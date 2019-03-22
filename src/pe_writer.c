#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pe_errors.h"
#include "pe_utils.h"
#include "pe_writer.h"

/* Write the DOS header
 */
static void writeDosH(struct pefile *pe)
{
    fseek(pe->file, 0, SEEK_SET);
    fwrite(&pe->dos, sizeof(pe->dos), 1, pe->file);
}

/* Write the Optional header
 */
static void writeOptionalH(struct pefile *pe)
{
    // write up to but not including loaderFlags
    // loaderFlags is first field after common 32/64 bit fields
    fwrite(&pe->nt.opt, 1,
        offsetof(struct optional_common_h, loaderFlags), pe->file);

    // write architecture specific fields
    if (pe->nt.opt.magic == PE_OH_32) {
        fwrite(&pe->nt.opt.opt32, sizeof(pe->nt.opt.opt32), 1, pe->file);
        assert(pe->nt.opt.imageBase32 % 0x10000 == 0);
    } else if (pe->nt.opt.magic == PE_OH_64) {
        fwrite(&pe->nt.opt.opt64, sizeof(pe->nt.opt.opt64), 1, pe->file);
        assert(pe->nt.opt.imageBase64 % 0x10000 == 0);
    }

    // write last two common fields and data directory
    fwrite(&pe->nt.opt.loaderFlags, 1,
        sizeof(pe->nt.opt.loaderFlags)         +
        sizeof(pe->nt.opt.numberOfRvaAndSizes) +
        sizeof(pe->nt.opt.ddir), pe->file);

    assert(pe->nt.opt.sectionAlignment >= pe->nt.opt.fileAlignment);
    assert(pe->nt.opt.win32VersionValue == 0);
    assert(pe->nt.opt.sizeOfImage % pe->nt.opt.sectionAlignment == 0);
    assert(pe->nt.opt.loaderFlags == 0);
}

/* Write the NT header
 */
static void writeNtH(struct pefile *pe)
{
    // write NT magic and file header
    fseek(pe->file, pe->dos.e_lfanew, SEEK_SET);
    fwrite(&pe->nt, offsetof(struct nt_h, opt), 1, pe->file);

    writeOptionalH(pe);
}

/* Write the PE file struct back to the file on disk
 * Returns zero on success, non-zero on failure
 */
int pefile_save(struct pefile *pe, const char *path)
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

