#ifndef PE_FREE_H
#define PE_FREE_H

#include "struct.h"

/* Free the memory used by pefile struct
 */
void pefile_free(struct pefile *pe);

#endif
