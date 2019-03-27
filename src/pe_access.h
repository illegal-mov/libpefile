#ifndef PE_ACCESS_H
#define PE_ACCESS_H

#include <wchar.h>
#include "pe_struct.h"

struct resource_node* getResourceByName(struct resource_table *rsrc, const wchar_t *name);
struct resource_table* getNextResourceDir(struct resource_table *rsrc);
void dumpResourceData(struct pefile *pe, const struct resource_data *rd, const char *path, char *errBuf);

#endif
