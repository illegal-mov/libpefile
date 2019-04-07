#ifndef PE_READER_H
#define PE_READER_H

#include "struct.h"

/* Load the pefile struct with data from the given PE file
 */
int pefile_init(
    struct pefile  *pe,
    const char     *path,
    void          (*fp)(int, char*),
    char           *err_buf);

#endif
