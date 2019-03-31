#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pe_free.h"
#include "pe_struct.h"
#include "pe_utils.h"

static void pefile_freeResourceDir(struct pefile *pe)
{
    struct pefile_crumbs *crms = NULL, current={.rt=pe->rsrc};

    do {
        current.rryLn = current.rt->hdr.numberOfNamedEntries +
                        current.rt->hdr.numberOfIdEntries;
        for (current.ndx=0; current.ndx < current.rryLn; current.ndx++) {
            struct resource_node *rn = &current.rt->branches[current.ndx];
            if (rn->entry.dataIsDirectory) {
                pefile_bcPush(&crms, &current);
                current.rt = rn->tbl;
                break;
            } else {
                free(current.rt);
                pefile_bcPop(&crms, &current);
            }

            if (current.ndx == current.rryLn - 1) {
                free(current.rt);
                pefile_bcPop(&crms, &current);
            }
        }

    } while (crms != NULL);
}

/* Free the memory used by the PE file struct
 */
void pefile_free(struct pefile *pe)
{
    free(pe->sctns);
    pe->sctns = NULL;

    // export dir
    if (pe->xprt != NULL) {
        free(pe->xprt->addrs);
        free(pe->xprt->nords);
        free(pe->xprt->names);
        free(pe->xprt);
        pe->xprt = NULL;
    }

    // import dir
    if (pe->mprts != NULL) {
        for (int i=0; i < pe->mprtsLen; i++) {
            free(pe->mprts[i].ils);
            i++;
        }
        free(pe->mprts);
        pe->mprts = NULL;
    }

    // resource dir
    if (pe->rsrc != NULL) {
        pefile_freeResourceDir(pe);
        free(pe->rsrc);
        pe->rsrc = NULL;
    }

    // exceptions dir
    if (pe->xcpts != NULL) {
        pe->xcpts = NULL;
    }

    // certificate dir
    if (pe->certs != NULL) {
        for (int i=0; i < pe->certsLen; i++)
            free(pe->certs[i].data);
        free(pe->certs);
        pe->certs = NULL;
    }

    // relocation dir
    if (pe->relocs != NULL) {
        for (int i=0; i < pe->relocsLen; i++)
            free(pe->relocs[i].entries);
        free(pe->relocs);
        pe->relocs = NULL;
    }

    // debug dir
    if (pe->dbgs != NULL) {
        free(pe->dbgs);
        pe->dbgs = NULL;
    }

    // architecture dir (unused, all zero)
//  if (pe->rchtr != NULL) {}

    // global pointer
    if (pe->gptr != NULL) { // TODO: find a file with a global pointer
        pe->gptr = NULL;
    }

    // tls dir
    if (pe->tlst32 != NULL) {
        free(pe->tlst32);
        pe->tlst32 = NULL;
    }

    // load config dir
    if (pe->ldcfg32 != NULL) {
        free(pe->ldcfg32);
        pe->ldcfg32 = NULL;
    }

    // bound import dir
    if (pe->bmprt != NULL) { // TODO: find a file with bound imports
        pe->bmprt = NULL;
    }

    // iat dir
    if (pe->iat != NULL) { // TODO: find documentation on this dir
        pe->iat = NULL;
    }

    // delay import dir
    if (pe->dmprt != NULL) { // TODO: find a file with delay imports
        pe->dmprt = NULL;
    }

    // clr runtime dir
    if (pe->clr != NULL) { // TODO: find a file with clr runtime
        pe->clr = NULL;
    }

    memset(pe, 0, sizeof(*pe));
}

