#ifndef PE_READER_H
#define PE_READER_H

#include "pe_struct.h"

int pefile_init(struct pefile *pe, const char *path, void (*fp)(int, char*), char *errBuf);

#endif
