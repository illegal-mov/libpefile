#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "pe_errors.h"
#include "pe_multiarch.h"
#include "pe_reader.h"
#include "pe_struct.h"
#include "pe_utils.h"

static void readImportDescName(struct pefile *pe, struct import_table *idata, int diff, char *errBuf);
void (*pefile_error_handler)(int status, char *errMsg) = pefile_exit;

// macro'd 32 and 64 bit versions of the same function
/* Read hint and name of the imported function
 * Some functions might be imported by ordinal and will not have a hint or name
 */
PEFILE_READ_IMPORT_BY_NAME(32, ) PEFILE_READ_IMPORT_BY_NAME(64, l)

/* Build array of offsets to names of imported functions
 * Returns a pointer to the base of the new array
 */
PEFILE_READ_THUNK_DATA(32) PEFILE_READ_THUNK_DATA(64)

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
static int isAllDeInFile(struct pefile *pe, char *errBuf) {
    fseek(pe->file, 0, SEEK_END);
    long fSize = ftell(pe->file);
    for (int i=0; i < PEFILE_DATA_DIR_LEN; i++) {
        int index = getSectionOfDir(pe, &pe->nt.opt.ddir[i]);
        if (index != PEFILE_NO_SECTION) {
            int diff = fixOffset(pe->sctns, index);
            struct data_dir *dd = pe->nt.opt.ddir;
            if (dd[i].virtualAddress + dd[i].size - diff >= fSize) {
                snprintf(errBuf, PEFILE_ERRBUF_LEN, "%s %s",
                    pefile_dir_to_str(i), "is truncated");
                pefile_error_handler(PEFILE_GENERIC_ERR, errBuf);
                return 0;
            }
        }
    }
    return 1;
}

/* Read the DOS header
 */
static void readDosH(struct pefile *pe, char *errBuf)
{
    fseek(pe->file, 0, SEEK_SET);
    fread(&pe->dos, sizeof(pe->dos), 1, pe->file);
    pefile_isTrunc(pe->file, "DOS header is", errBuf);

    if (strncmp(pe->dos.e_magic, "MZ", 2) != 0) {
        strcpy(errBuf, "Invalid DOS header magic");
        pefile_error_handler(PEFILE_BAD_SIG, errBuf);
    }
}

/* Read the Optional header
 */
static void readOptionalH(struct pefile *pe, char *errBuf)
{
    // read up to but not including loaderFlags
    // loaderFlags is first field after common 32/64 bit fields
    fread(&pe->nt.opt, 1,
        offsetof(struct optional_common_h, loaderFlags), pe->file);

    // read architecture specific fields
    if (pe->nt.opt.magic == PE_OH_32) {
        fread(&pe->nt.opt.opt32, sizeof(pe->nt.opt.opt32), 1, pe->file);
        assert(pe->nt.opt.imageBase32 % 0x10000 == 0);
    } else if (pe->nt.opt.magic == PE_OH_64) {
        fread(&pe->nt.opt.opt64, sizeof(pe->nt.opt.opt64), 1, pe->file);
        assert(pe->nt.opt.imageBase64 % 0x10000 == 0);
    } else {
        strcpy(errBuf, "Unknown optional header magic");
        pefile_error_handler(PEFILE_BAD_SIG, errBuf);
    }

    // read last two common fields and data directory
    fread(&pe->nt.opt.loaderFlags, 1,
        sizeof(pe->nt.opt.loaderFlags)         +
        sizeof(pe->nt.opt.numberOfRvaAndSizes) +
        sizeof(pe->nt.opt.ddir), pe->file);

    assert(pe->nt.opt.sectionAlignment >= pe->nt.opt.fileAlignment);
    assert(pe->nt.opt.win32VersionValue == 0);
    assert(pe->nt.opt.sizeOfImage % pe->nt.opt.sectionAlignment == 0);
    assert(pe->nt.opt.loaderFlags == 0);

    pefile_isTrunc(pe->file, "Optional header is", errBuf);
}

/* Read the NT header
 */
static void readNtH(struct pefile *pe, char *errBuf)
{
    // read NT magic and file header
    fseek(pe->file, pe->dos.e_lfanew, SEEK_SET);
    fread(&pe->nt, offsetof(struct nt_h, opt), 1, pe->file);
    pefile_isTrunc(pe->file, "NT header is", errBuf);

    if (strncmp(pe->nt.signature, "PE", 2) != 0) {
        strcpy(errBuf, "Invalid NT header magic");
        pefile_error_handler(PEFILE_BAD_SIG, errBuf);
    }

    readOptionalH(pe, errBuf);
}

/* Read array of section headers located immediately after the optional header
 */
static void readSectionH(struct pefile *pe, char *errBuf)
{
    uint16_t nSect = pe->nt.file.numberOfSections;
    assert(nSect > 0);
    pe->sctns = pefile_malloc(sizeof(pe->sctns[0]) * nSect,
        "section headers",
        errBuf);
    fread(pe->sctns, sizeof(pe->sctns[0]), nSect, pe->file);
    pefile_isTrunc(pe->file, "Section headers are", errBuf);
}

/* Build array of ordinals for names
 * Returns a pointer to the base of the array or NULL on error
 */
static uint16_t* readExportByNameOrd(struct pefile *pe, int diff, char *errBuf)
{
    uint32_t nNames = pe->xprt->edir.numberOfNames;
    assert(nNames > 0);
    uint16_t *nords = pefile_malloc(sizeof(pe->xprt->nords[0]) * nNames,
        "export name ordinals",
        errBuf);
    fseek(pe->file, pe->xprt->edir.addressOfNameOrdinals - diff, SEEK_SET);
    fread(nords, sizeof(nords[0]), nNames, pe->file);
    return nords;
}

/* Build array of functions exported by ordinal
 */
static struct export_func_ptr* readExportedFunc(struct pefile *pe, int xprt_diff, char *errBuf)
{
    uint32_t nFuncs = pe->xprt->edir.numberOfFunctions;
    assert(nFuncs > 0);
    struct export_func_ptr *ords = pefile_malloc(sizeof(ords[0]) * nFuncs,
        "export function ordinals",
        errBuf);

    // read only one `ord` just to get its rva
    fseek(pe->file, pe->xprt->edir.addressOfFunctions - xprt_diff, SEEK_SET);
    fread(&ords[0].rva, sizeof(ords[0].rva), 1, pe->file);

    // dirty hack to find `.text` section diff
    struct data_dir temp = {.virtualAddress=ords[0].rva, .size=1};
    int index = getSectionOfDir(pe, &temp);
    int code_diff = fixOffset(pe->sctns, index);

    // can now get true file offset to exported functions
    ords[0].pointerToCode = ords[0].rva - code_diff;
    for (uint32_t i=1; i < nFuncs; i++) {
        fread(&ords[i].rva, sizeof(ords[0].rva), 1, pe->file);
        ords[i].pointerToCode = ords[i].rva - code_diff;
    }

    return ords;
}

/* Reads the name of the exported function
 */
static void readExportedFuncName(struct pefile *pe, struct export_by_name *ebn, int diff)
{
    long pos = ftell(pe->file);
    fseek(pe->file, ebn->rva - diff, SEEK_SET);
    fgets(ebn->name, PEFILE_FUNCTION_NAME_MAX_LEN, pe->file);
    fseek(pe->file, pos, SEEK_SET);
}

/* Build array of offsets to names of the exported functions
 */
static struct export_by_name* readExportByName(struct pefile *pe, int diff, char *errBuf)
{
    uint32_t nNames = pe->xprt->edir.numberOfNames;
    assert(nNames > 0);
    struct export_by_name *names = pefile_malloc(sizeof(names[0]) * nNames,
        "export function names",
        errBuf);
    fseek(pe->file, pe->xprt->edir.addressOfNames - diff, SEEK_SET);
    for (uint32_t i=0; i < nNames; i++) {
        fread(&names[i].rva, sizeof(names[i].rva), 1, pe->file);
        readExportedFuncName(pe, &names[i], diff);
    }

    return names;
}

/* Read export directory data
 * Build arrays of functions exported by name, ordinal, and name ordinal
 */
static void readExportDir(struct pefile *pe, char *errBuf)
{
    int index = getSectionOfDir(pe, &pe->nt.opt.ddir[PE_DE_EXPORT]);
    if (index == PEFILE_NO_SECTION)
        return;

    int diff = fixOffset(pe->sctns, index);

    pe->xprt = pefile_malloc(sizeof(*pe->xprt), "export directory", errBuf);
    fseek(pe->file, pe->nt.opt.ddir[PE_DE_EXPORT].virtualAddress - diff, SEEK_SET);
    fread(&pe->xprt->edir, sizeof(*pe->xprt), 1, pe->file);
    assert(pe->xprt->edir.characteristics == 0);
    pe->xprt->ords  = readExportedFunc(pe, diff, errBuf);
    pe->xprt->nords = readExportByNameOrd(pe, diff, errBuf);
    pe->xprt->names = readExportByName(pe, diff, errBuf);
    pefile_isTrunc(pe->file, "Export directory is", errBuf);
}

/* Read name of the module being imported from
 */
static void readImportDescName(struct pefile *pe, struct import_table *idata, int diff, char *errBuf)
{
    long pos = ftell(pe->file);
    fseek(pe->file, idata->mtdt.name - diff, SEEK_SET);
    fgets(idata->name, PEFILE_MODULE_NAME_MAX_LEN, pe->file);
    pefile_isTrunc(pe->file, "An import descriptor is", errBuf);
    fseek(pe->file, pos, SEEK_SET);
}

/* Get the Windows wchar_t resource name
 * Windows wchar_t is 2 bytes while Linux wchar_t is 4 bytes
 */
static void readResourceName(struct pefile *pe, struct resource_node *rn, int rsrcBase, char *errBuf)
{
    long pos = ftell(pe->file);
    fseek(pe->file, rsrcBase + rn->ent.nameOffset, SEEK_SET);
    fread(&rn->rname.len, sizeof(rn->rname.len), 1, pe->file);
    unsigned int nameLen = rn->rname.len;
    if (nameLen >= PEFILE_RESOURCE_NAME_MAX_LEN) {
        strcpy(errBuf, "Resource name is too long");
        pefile_error_handler(PEFILE_LONG_RES_NAME, errBuf);
    }

    // because fread with nmemb > 1 does not work (why?)
    for (unsigned int i=0; i < nameLen; i++)
        fread(&rn->rname.name[i], sizeof(uint16_t), 1, pe->file);

    // null terminate the string
    rn->rname.name[nameLen] = 0;
    fseek(pe->file, pos, SEEK_SET);
}

/* Read resource header which contains numberOfNameEntries and numberofIdEntries
 * Use total number of entries to read array of entries located immediately after the header
 */
static void readResourceTable(struct pefile *pe, struct resource_table *rt, int rsrcAddr, char *errBuf)
{
    // read resource header
    fseek(pe->file, rsrcAddr, SEEK_SET);
    fread(&rt->hdr, sizeof(rt->hdr), 1, pe->file);

    // allocate memory for resource entries
    int nEntries = rt->hdr.numberOfNamedEntries + rt->hdr.numberOfIdEntries;

    rt->branchesLen = nEntries;
    assert(nEntries > 0);
    rt->branches = pefile_malloc(sizeof(rt->branches[0]) * nEntries,
        "resource directory entries",
        errBuf);

    // read array of resource entries
    for (int i=0; i < nEntries; i++)
        fread(&rt->branches[i].ent, sizeof(rt->branches[0].ent), 1, pe->file);
}

/* Get the size and location of the actual resource data
 */
static void readResourceMetadata(struct pefile *pe, struct resource_node *rn, int rsrcAddr)
{
    // seek to and read resource metadata
    fseek(pe->file, rsrcAddr, SEEK_SET);
    fread(&rn->mtdt, sizeof(rn->mtdt), 1, pe->file);
    assert(rn->mtdt.reserved == 0);
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
static void readResourceDir(struct pefile *pe, char *errBuf)
{
    int index = getSectionOfDir(pe, &pe->nt.opt.ddir[PE_DE_RESOURCE]);
    if (index == PEFILE_NO_SECTION)
        return;

    int diff = fixOffset(pe->sctns, index);
    int rsrcBase = pe->nt.opt.ddir[PE_DE_RESOURCE].virtualAddress - diff;
    int rsrcOffset = 0;

    pe->rsrc = pefile_malloc(sizeof(*pe->rsrc), "resource table header", errBuf);
    struct pefile_crumbs *root = NULL;
    struct pefile_crumb crm = {.rt=pe->rsrc};

    do {
        readResourceTable(pe, crm.rt, rsrcBase + rsrcOffset, errBuf);
        crm.rryLn = crm.rt->branchesLen;

        for (crm.ndx=0; crm.ndx < crm.rryLn; crm.ndx++) {
            struct resource_node *rn = &crm.rt->branches[crm.ndx];
            if (rn->ent.nameIsString)
                readResourceName(pe, rn, rsrcBase, errBuf);

            if (rn->ent.dataIsDirectory) {
                // save crumb before entering next directory
                pefile_bc_push(&root, &crm);
                rn->tbl = pefile_malloc(sizeof(*crm.rt), "resource table header", errBuf);
                // set rsrcOffset for the upcoming call to `readResourceTable`
                rsrcOffset = rn->ent.offsetToDirectory;
                crm.rt = rn->tbl;
                break;
            } else {
                readResourceMetadata(pe, rn, rsrcBase + rn->ent.offsetToData);
                // return to parent directory
                pefile_bc_pop(&root, &crm);
            }

            // ensure pop when index iterator is done
            if (crm.ndx == crm.rryLn - 1)
                pefile_bc_pop(&root, &crm);
        }
    // end of algorithm when crumb is at top level and index iterator is done
    } while (root != NULL);

    pefile_isTrunc(pe->file, "Resource directory is", errBuf);
}

static void readCertificateDir(struct pefile *pe, char *errBuf)
{
    int index = getSectionOfDir(pe, &pe->nt.opt.ddir[PE_DE_CERTIFICATE]);
    if (index == PEFILE_NO_SECTION)
        return;

    int nBytesRead = 0, cd_len = 0, cd_maxLen = 2; // ALERT! Arbitrary number
    pe->certs = pefile_malloc(sizeof(pe->certs[0]) * cd_maxLen,
        "certificate directory",
        errBuf);

    fseek(pe->file, pe->nt.opt.ddir[PE_DE_CERTIFICATE].virtualAddress, SEEK_SET);
    int certDirSize = pe->nt.opt.ddir[PE_DE_CERTIFICATE].size;

    while (nBytesRead < certDirSize) {
        fread(&pe->certs[cd_len].mtdt, sizeof(pe->certs[0].mtdt), 1, pe->file);
        pe->certs[cd_len].data = pefile_malloc(pe->certs[cd_len].mtdt.size,
            "certificate directory",
            errBuf);

        fread(pe->certs[cd_len].data, pe->certs[cd_len].mtdt.size, 1, pe->file);

        // pad to align on 8-byte boundaries
        int alignment = (8 - (pe->certs[cd_len].mtdt.size & 7)) & 7;
        fseek(pe->file, alignment, SEEK_CUR);
        nBytesRead += pe->certs[cd_len].mtdt.size;
        nBytesRead += alignment;
        cd_len++;

        /* unknown array length, so keep doubling memory when space runs out */
        if (cd_len >= cd_maxLen) {
            cd_maxLen <<= 1;
            pe->certs = pefile_realloc(pe->certs,
                sizeof(pe->certs[0]) * cd_maxLen,
                "certificate directory",
                errBuf);
        }
    }

    assert(nBytesRead == certDirSize);
    pe->certsLen = cd_len;
    // no `isTrunc()` check here because certificates
    // may be located at the very end of the file
}

static void readRelocationBlock(struct pefile *pe, struct reloc_table *relocblock, char *errBuf)
{
    // read relocation header to get size of block (header + all entries)
    fread(&relocblock->header, sizeof(relocblock->header), 1, pe->file);

    // read relocation entries
    assert(relocblock->header.size - sizeof(relocblock->header) > 0);
    relocblock->entries = pefile_malloc(relocblock->header.size
        - sizeof(relocblock->header), "relocation block", errBuf);
    fread(relocblock->entries, relocblock->header.size
        - sizeof(relocblock->header), 1, pe->file);
    relocblock->entriesLen = (relocblock->header.size
        - sizeof(relocblock->header)) / sizeof(relocblock->entries[0]);
}

static void readRelocationDir(struct pefile *pe, char *errBuf)
{
    int index = getSectionOfDir(pe, &pe->nt.opt.ddir[PE_DE_RELOCATION]);
    if (index == PEFILE_NO_SECTION)
        return;

    int diff = fixOffset(pe->sctns, index);
    fseek(pe->file, pe->nt.opt.ddir[PE_DE_RELOCATION].virtualAddress - diff, SEEK_SET);

    int nBytesRead = 0, nBytesToRead = pe->nt.opt.ddir[PE_DE_RELOCATION].size;

    int blk_len = 0, blk_maxLen = 32; // ALERT! Arbitrary number
    pe->relocs = pefile_malloc(sizeof(pe->relocs[0]) * blk_maxLen,
        "relocation directory", errBuf);

    while (nBytesRead < nBytesToRead) {
        readRelocationBlock(pe, &pe->relocs[blk_len], errBuf);
        nBytesRead += pe->relocs[blk_len].header.size;
        blk_len++;
        /* unknown array length, so keep doubling memory when space runs out */
        if (blk_len >= blk_maxLen) {
            blk_maxLen <<= 1;
            pe->relocs = pefile_realloc(pe->relocs,
                sizeof(pe->relocs[0]) * blk_maxLen,
                "relocation directory", errBuf);
        }
    }

    pefile_isTrunc(pe->file, "Relocation directory is", errBuf);
    pe->relocsLen = blk_len;
}

static void readDebugDir(struct pefile *pe, char *errBuf)
{
    int index = getSectionOfDir(pe, &pe->nt.opt.ddir[PE_DE_DEBUG]);
    if (index == PEFILE_NO_SECTION)
        return;

    int diff = fixOffset(pe->sctns, index);
    fseek(pe->file, pe->nt.opt.ddir[PE_DE_DEBUG].virtualAddress - diff, SEEK_SET);
    int dbg_dir_size = pe->nt.opt.ddir[PE_DE_DEBUG].size;

    pe->dbgs = pefile_malloc(dbg_dir_size, "debug directory", errBuf);
    fread(pe->dbgs, dbg_dir_size, 1, pe->file);
    int dbgsLen = dbg_dir_size / sizeof(pe->dbgs[0]);
    for (int i=0; i < dbgsLen; i++)
        assert(pe->dbgs[0].characteristics == 0);

    pefile_isTrunc(pe->file, "Debug directory is", errBuf);
    pe->dbgsLen = dbgsLen;
}

/*
static void readGlobalptrDir(struct pefile *pe, char *errBuf)
{
    int index = getSectionOfDir(pe, &pe->nt.opt.ddir[PE_DE_GLOBALPTR]);
    if (index == PEFILE_NO_SECTION)
        return;
}

static void readBoundImportDir(struct pefile *pe, char *errBuf)
{
    int index = getSectionOfDir(pe, &pe->nt.opt.ddir[PE_DE_BOUND_IMPORT]);
    if (index == PEFILE_NO_SECTION)
        return;
}

static void readIatDir(struct pefile *pe, char *errBuf)
{
    int index = getSectionOfDir(pe, &pe->nt.opt.ddir[PE_DE_IAT]);
    if (index == PEFILE_NO_SECTION)
        return;
}

static void readDelayImportDir(struct pefile *pe, char *errBuf)
{
    int index = getSectionOfDir(pe, &pe->nt.opt.ddir[PE_DE_DELAY_IMPORT]);
    if (index == PEFILE_NO_SECTION)
        return;
}

static void readClrDir(struct pefile *pe, char *errBuf)
{
    int index = getSectionOfDir(pe, &pe->nt.opt.ddir[PE_DE_CLR]);
    if (index == PEFILE_NO_SECTION)
        return;
}
//*/

static void readSectionData(struct pefile *pe, char *errBuf)
{
    readSectionH(pe, errBuf);
    isAllDeInFile(pe, errBuf);

    if (pe->nt.opt.magic == PE_OH_32) {
        readImportDir32(pe, errBuf);
        readExceptionDir32(pe, errBuf);
        readTlsDir32(pe, errBuf);
        readLoadConfigDir32(pe, errBuf);
    } else {
        readImportDir64(pe, errBuf);
        readExceptionDir64(pe, errBuf);
        readTlsDir64(pe, errBuf);
        readLoadConfigDir64(pe, errBuf);
    }

    readExportDir(pe, errBuf);
    readResourceDir(pe, errBuf);
    readCertificateDir(pe, errBuf);
    readRelocationDir(pe, errBuf);
    readDebugDir(pe, errBuf);
//  readArchitectureDir(pe, errBuf); // unused, always zero
//  readGlobalptrDir(pe, errBuf);    // TODO: find a file with a global pointer
//  readBoundImportDir(pe, errBuf);  // TODO: find a file with bound imports
//  readIatDir(pe, errBuf);          // TODO: find documentation on this dir
//  readDelayImportDir(pe, errBuf);  // TODO: find a file with delay imports
//  readClrDir(pe, errBuf);          // TODO: find a file with clr runtime
}

/* Initialize the PE file struct from a path to a suitable file on disk
 * Returns zero on success, non-zero on failure
 */
int pefile_init(struct pefile *pe, const char *path, void (*fp)(int, char*), char *errBuf)
{
    // change default error handler if one was provided
    if (fp != NULL)
        pefile_error_handler = fp;

    memset(pe, 0, sizeof(*pe));
    pe->file = fopen(path, "rb");
    if (pe->file == NULL) {
        strcpy(errBuf, "Error opening the file for reading");
        pefile_error_handler(PEFILE_GENERIC_ERR, errBuf);
    }

    readDosH(pe, errBuf);
    readNtH(pe, errBuf);
    readSectionData(pe, errBuf);
    return PEFILE_SUCCESS;
}

