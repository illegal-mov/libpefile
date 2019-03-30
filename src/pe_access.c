#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pe_access.h"
#include "pe_struct.h"
#include "pe_utils.h"
#include "pe_errors.h"

// internal resource iterator data for `getNextResource`
static struct pefile_crumbs *crms = NULL, current = {0};

struct resource_node* pefile_getResourceByName(struct resource_table *rsrc, const wchar_t *name)
{
    if (rsrc == NULL)
        return NULL;

    struct pefile_crumbs *crms = NULL, current = {.rt=rsrc};

    do {
        current.rryLn = current.rt->hdr.numberOfNamedEntries +
                        current.rt->hdr.numberOfIdEntries;
        for (current.ndx=0; current.ndx < current.rryLn; current.ndx++) {
            struct resource_node *rn = &current.rt->branches[current.ndx];
            if (rn->entry.nameIsString) {
                if (wcsncasecmp(rn->rname.name, name, PEFILE_RESOURCE_NAME_MAX_LEN) == 0) {
                    // clean up any left-over crumbs
                    while (crms != NULL) {
                        struct pefile_crumbs *temp = crms->next;
                        free(crms);
                        crms = temp;
                    }
                    return rn;
                }
            }

            if (rn->entry.dataIsDirectory) {
                pefile_bcPush(&crms, &current);
                current.rt = rn->tbl;
                break;
            } else {
                pefile_bcPop(&crms, &current);
            }

            if (current.ndx == current.rryLn - 1)
                pefile_bcPop(&crms, &current);
        }

    } while (crms != NULL);

    return NULL;
}

struct resource_table* pefile_initResourceWalker(struct resource_table *rsrc)
{
    if (rsrc == NULL)
        return NULL;

    current.rt = rsrc;
    return rsrc;
}

struct resource_table* pefile_getNextResourceDir()
{
    if (current.rt == NULL)
        return NULL;

    do {
        current.rryLn = current.rt->hdr.numberOfNamedEntries +
                        current.rt->hdr.numberOfIdEntries;
        for (current.ndx=0; current.ndx < current.rryLn; current.ndx++) {
            struct resource_node *rn = &current.rt->branches[current.ndx];
            if (rn->entry.dataIsDirectory) {
                pefile_bcPush(&crms, &current);
                current.rt = rn->tbl;
                return current.rt;
            } else {
                pefile_bcPop(&crms, &current);
            }

            if (current.ndx == current.rryLn - 1)
                pefile_bcPop(&crms, &current);
        }
    } while (crms != NULL);

    return NULL;
}

void pefile_dumpData(const struct pefile *pe, uint32_t fileOffset, uint32_t size, const char *path, char *errBuf)
{
    FILE *dump = fopen(path, "wb");
    if (dump == NULL) {
        strcpy(errBuf, "Failed to create the file");
        pefile_error_handler(PEFILE_GENERIC_ERR, errBuf);
    }

    fseek(pe->file, fileOffset, SEEK_SET);
    char buf[4096]; // ALERT! Arbitrary number
    // write resource data a chunk of `buf` at a time
    while (size > sizeof(buf)) {
        fread(buf, sizeof(buf), 1, pe->file);
        fwrite(buf, sizeof(buf), 1, dump);
        size -= sizeof(buf);
    }
    // write remaining bytes that partially fill `buf`
    fread(buf, size, 1, pe->file);
    fwrite(buf, size, 1, dump);
}

void pefile_dumpResourceData(const struct pefile *pe, const struct resource_metadata *rm, const char *path, char *errBuf)
{
    int diff = pefile_fixOffset(pe->sctns,
        pefile_getSectionOfDir(pe, &pe->nt.opt.ddir[PE_DE_RESOURCE]));

    pefile_dumpData(pe, rm->offsetToData - diff, rm->size, path, errBuf);
}

void pefile_dumpCertificateData(const struct cert_table *ct, const char *path, char *errBuf)
{
    FILE *dump = fopen(path, "wb");
    if (dump == NULL) {
        strcpy(errBuf, "Failed to create the file");
        pefile_error_handler(PEFILE_GENERIC_ERR, errBuf);
    }

    fwrite(ct->data, ct->mtdt.size, 1, dump);
}

