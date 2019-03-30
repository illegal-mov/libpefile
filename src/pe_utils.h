#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include "pe_struct.h"

struct pefile_crumbs {
    int ndx;
    int rryLn;
    struct resource_table *rt;
    struct pefile_crumbs *next;
};

int pefile_getSectionOfDir(const struct pefile *pe, const struct data_dir *entry);
int pefile_fixOffset(const struct section_h *sctns, int sctn_indx);
char* pefile_dirToStr(int index);
void pefile_isTrunc(FILE *f, const char *errMsg, char *errBuf);
void* pefile_malloc(size_t size, const char *errMsg, char *errBuf);
void* pefile_realloc(void *buf, size_t size, const char *errMsg, char *errBuf);
void pefile_bcPush(struct pefile_crumbs **root, struct pefile_crumbs *temp);
void pefile_bcPop(struct pefile_crumbs **root, struct pefile_crumbs *temp);

#endif
