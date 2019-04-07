#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "free.h"
#include "struct.h"
#include "utils.h"

static void pefile_freeResourceDir(struct pefile *pe)
{
    struct pefile_crumbs *crms = NULL, current={.res_table=pe->rsrc};

    do {
        current.array_len = current.res_table->header.number_of_named_entries +
                        current.res_table->header.number_of_id_entries;
        for (current.index=0; current.index < current.array_len; current.index++) {
            struct resource_node *rn = &current.res_table->nodes[current.index];
            if (rn->entry.is_directory) {
                pefile_breadcrumb_push(&crms, &current);
                current.res_table = rn->table;
                break;
            } else {
                free(current.res_table);
                pefile_breadcrumb_pop(&crms, &current);
            }

            if (current.index == current.array_len - 1) {
                free(current.res_table);
                pefile_breadcrumb_pop(&crms, &current);
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
        for (int i=0; i < pe->mprts_len; i++) {
            free(pe->mprts[i].lookups);
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
        for (int i=0; i < pe->certs_len; i++)
            free(pe->certs[i].data);
        free(pe->certs);
        pe->certs = NULL;
    }

    // relocation dir
    if (pe->relocs != NULL) {
        for (int i=0; i < pe->relocs_len; i++)
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
    if (pe->tlst != NULL) {
        free(pe->tlst->callbacks);
        free(pe->tlst);
        pe->tlst = NULL;
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

