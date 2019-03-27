#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pe_access.h"
#include "pe_struct.h"
#include "pe_utils.h"
#include "pe_errors.h"

struct resource_node* getResourceByName(struct resource_table *rsrc, const wchar_t *name)
{
    if (rsrc == NULL)
        return NULL;

    struct pefile_crumbs *crms = NULL, current = {.rt=rsrc};

    do {
        current.rryLn = current.rt->hdr.numberOfNamedEntries +
                        current.rt->hdr.numberOfIdEntries;
        for (current.ndx=0; current.ndx < current.rryLn; current.ndx++) {
            struct resource_node *rn = &current.rt->branches[current.ndx];
            if (rn->ent.nameIsString) {
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

            if (rn->ent.dataIsDirectory) {
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

// TODO: flatten singletons
struct resource_table* getNextResourceDir(struct resource_table *rsrc)
{
    if (rsrc == NULL)
        return NULL;

    struct pefile_crumbs *crms = NULL, current = {.rt=rsrc};

    do {
        current.rryLn = current.rt->hdr.numberOfNamedEntries +
                        current.rt->hdr.numberOfIdEntries;
        for (current.ndx=0; current.ndx < current.rryLn; current.ndx++) {
            struct resource_node *rn = &current.rt->branches[current.ndx];
            if (rn->ent.dataIsDirectory) {
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
//*/

void dumpResourceData(struct pefile *pe, const struct resource_data *rd, const char *path, char *errBuf)
{
    FILE *dump = fopen(path, "wb");
    if (dump == NULL) {
        strcpy(errBuf, "Failed to create the file");
        pefile_error_handler(PEFILE_GENERIC_ERR, errBuf);
    }

    int diff = fixOffset(pe->sctns,
        getSectionOfDir(pe, &pe->nt.opt.ddir[PE_DE_RESOURCE]));

    fseek(pe->file, rd->offsetToData - diff, SEEK_SET);
    unsigned int size = rd->size;
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
