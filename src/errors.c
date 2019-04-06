#include <stdio.h>
#include <stdlib.h>
#include "errors.h"

/* Get a human-readable string for a PEFILE error
 */
char* pefile_err_to_str(
    int code)
{
    switch (code) {
        case PEFILE_SUCCESS:       return "Success";
        case PEFILE_GENERIC_ERR:   return "An unknown error occurred";
        case PEFILE_FAILED_ALLOC:  return "Failed to allocate memory";
        case PEFILE_IS_TRUNCATED:  return "File data is truncated";
        case PEFILE_BAD_SIG:       return "Incorrect signature bytes";
        case PEFILE_LONG_RES_NAME: return "Resource name is too long";
        default:                   return "<UNKNOWN_CODE>";
    }
}

/* Default error handler function
 */
void pefile_exit(
    int   status,
    char *err_msg)
{
    fprintf(stderr, "%s\n", err_msg);
    exit(status);
}

