#ifndef PE_ACCESS_H
#define PE_ACCESS_H

#include <wchar.h>
#include "pe_struct.h"

struct resource_node* pefile_getResourceByName(struct resource_table *rsrc, const wchar_t *name);
struct resource_table* pefile_initResourceWalker(struct resource_table *rsrc);
struct resource_table* pefile_getNextResourceDir();
void pefile_dumpData(const struct pefile *pe, uint32_t fileOffset, uint32_t size, const char *path, char *errBuf);
void pefile_dumpResourceData(const struct pefile *pe, const struct resource_metadata *rm, const char *path, char *errBuf);
void pefile_dumpCertificateData(const struct cert_table *ct, const char *path, char *errBuf);

#endif
