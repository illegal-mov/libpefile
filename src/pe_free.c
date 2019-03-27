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
            if (rn->ent.dataIsDirectory) {
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
    if (HAS_DIR(pe->xprt)) {
        free(pe->xprt->ords);
        free(pe->xprt->nords);
        free(pe->xprt->names);
        free(pe->xprt);
        pe->xprt = NULL;
    }

    // import dir
    if (HAS_DIR(pe->mprts)) {
        for (int i=0; i < pe->mprtsLen; i++) {
            free(pe->mprts[i].ofts);
            i++;
        }
        free(pe->mprts);
        pe->mprts = NULL;
    }

    // resource dir
    if (HAS_DIR(pe->rsrc)) {
        pefile_freeResourceDir(pe);
        free(pe->rsrc);
        pe->rsrc = NULL;
    }

    // exceptions dir
    if (HAS_DIR(pe->xcpts32)) {
        pe->xcpts32 = NULL;
    }

    // certificate dir
    if (HAS_DIR(pe->certs)) {
        for (int i=0; i < pe->certsLen; i++)
            free(pe->certs[i].data);
        free(pe->certs);
        pe->certs = NULL;
    }

    // relocation dir
    if (HAS_DIR(pe->relocs)) {
        for (int i=0; i < pe->relocsLen; i++)
            free(pe->relocs[i].entries);
        free(pe->relocs);
        pe->relocs = NULL;
    }

    // debug dir
    if (HAS_DIR(pe->dbgs)) {
        free(pe->dbgs);
        pe->dbgs = NULL;
    }

    // architecture dir (unused, all zero)
//  if (HAS_DIR(pe->rchtr)) {}

    // global pointer
    if (HAS_DIR(pe->gptr)) { // TODO: find a file with a global pointer
        pe->gptr = NULL;
    }

    // tls dir
    if (HAS_DIR(pe->tlst32)) {
        free(pe->tlst32);
        pe->tlst32 = NULL;
    }

    // load config dir
    if (HAS_DIR(pe->ldcfg32)) {
        free(pe->ldcfg32);
        pe->ldcfg32 = NULL;
    }

    // bound import dir
    if (HAS_DIR(pe->bmprt)) { // TODO: find a file with bound imports
        pe->bmprt = NULL;
    }

    // iat dir
    if (HAS_DIR(pe->iat)) { // TODO: find documentation on this dir
        pe->iat = NULL;
    }

    // delay import dir
    if (HAS_DIR(pe->dmprt)) { // TODO: find a file with delay imports
        pe->dmprt = NULL;
    }

    // clr runtime dir
    if (HAS_DIR(pe->clr)) { // TODO: find a file with clr runtime
        pe->clr = NULL;
    }

    memset(pe, 0, sizeof(*pe));
}

