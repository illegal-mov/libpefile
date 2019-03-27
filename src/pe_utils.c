#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pe_errors.h"
#include "pe_utils.h"

/* Get index of the section a directory entry was merged into
 * Returns the index of the relevant section or PEFILE_NO_SECTION if not found
 */
int getSectionOfDir(struct pefile *pe, const struct data_dir *entry)
{
    if (entry->virtualAddress == 0 || entry->size == 0)
        return PEFILE_NO_SECTION; // -1

    int nSect = pe->nt.file.numberOfSections;
    for (int i=0; i < nSect; i++) {
        uint32_t va = pe->sctns[i].virtualAddress;
        uint32_t sz = pe->sctns[i].misc.virtualSize;
        if (va <= entry->virtualAddress &&
            entry->virtualAddress < va + sz)
            return i;
    }
    return PEFILE_NO_SECTION; // -1
}

/* Adjust offsets when a data directory entry is merged into some section
 * Returns the integer difference between the virtual address and raw address
 */
int fixOffset(const struct section_h *sctns, int sctn_ndx)
{
    assert(sctns[sctn_ndx].virtualAddress >=
           sctns[sctn_ndx].pointerToRawData);
    return sctns[sctn_ndx].virtualAddress -
           sctns[sctn_ndx].pointerToRawData;
}

char* pefile_dirToStr(int index)
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

void* pefile_realloc(void *buf, size_t size, const char *errMsg, char *errBuf)
{
    void *tmp = realloc(buf, size);
    if (tmp == NULL) {
        strcpy(errBuf, "Failed to resize memory for ");
        strncat(errBuf, errMsg, PEFILE_ERRBUF_LEN);
        pefile_error_handler(PEFILE_FAILED_ALLOC, errBuf);
    }
    return tmp;
}

void* pefile_malloc(size_t size, const char *errMsg, char *errBuf)
{
    void *tmp = malloc(size);
    if (tmp == NULL) {
        strcpy(errBuf, "Failed to allocate memory for ");
        strncat(errBuf, errMsg, PEFILE_ERRBUF_LEN);
        pefile_error_handler(PEFILE_FAILED_ALLOC, errBuf);
    }
    return tmp;
}

void pefile_isTrunc(FILE *f, const char *errMsg, char *errBuf)
{
    if (feof(f)) {
        strncpy(errBuf, errMsg, PEFILE_ERRBUF_LEN);
        strncat(errBuf, " truncated", PEFILE_ERRBUF_LEN);
        pefile_error_handler(PEFILE_IS_TRUNCATED, errBuf);
    }
}

void pefile_bcPush(struct pefile_crumbs **root, struct pefile_crumbs *temp)
{
    struct pefile_crumbs *bcnew = malloc(sizeof(*bcnew));
    memcpy(bcnew, temp, sizeof(*temp));
    bcnew->next = *root;
    *root = bcnew;
}

void pefile_bcPop(struct pefile_crumbs **root, struct pefile_crumbs *temp)
{
    struct pefile_crumbs *top = *root;
    *root = top->next;
    memcpy(temp, top, sizeof(*temp));
    free(top);
}

