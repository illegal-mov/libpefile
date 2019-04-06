#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wctype.h>
#include "errors.h"
#include "utils.h"

/* Get index of the section a directory entry was merged into
 * Returns the index of the relevant section or PEFILE_NO_SECTION if not found
 */
int pefile_get_section_of_dir(
    const struct pefile   *pe,
    const struct data_dir *entry)
{
    if (entry->rva == 0 || entry->size == 0)
        return PEFILE_NO_SECTION; // -1

    int num_sections = pe->nt.file.number_of_sections;
    for (int i=0; i < num_sections; i++) {
        uint32_t va = pe->sctns[i].data_rva;
        uint32_t sz = pe->sctns[i].size_in_memory;
        if (va <= entry->rva &&
            entry->rva < va + sz)
            return i;
    }
    return PEFILE_NO_SECTION; // -1
}

/* Adjust offsets when a data directory entry is merged into some section
 * Returns the integer difference between the virtual address and raw address
 */
int pefile_fix_offset(
    const struct section_h *sctns,
    int                     section_index)
{
    assert(sctns[section_index].data_rva >=
           sctns[section_index].data_apa);
    return sctns[section_index].data_rva -
           sctns[section_index].data_apa;
}

/* Get directory name from index
 */
char* pefile_dir_to_str(
    int index)
{
    switch (index) {
        case PE_DE_EXPORT:       return "Export directory";
        case PE_DE_IMPORT:       return "Import directory";
        case PE_DE_RESOURCE:     return "Resource directory";
        case PE_DE_EXCEPTION:    return "Exception directory";
        case PE_DE_CERTIFICATE:  return "Certificate directory";
        case PE_DE_RELOCATION:   return "Relocation directory";
        case PE_DE_DEBUG:        return "Debug directory";
        case PE_DE_ARCHITECTURE: return "Architecture directory";
        case PE_DE_GLOBALPTR:    return "Global pointer directory";
        case PE_DE_TLS:          return "TLS directory";
        case PE_DE_LOAD_CONFIG:  return "Load config directory";
        case PE_DE_BOUND_IMPORT: return "Bound import directory";
        case PE_DE_IAT:          return "IAT directory";
        case PE_DE_DELAY_IMPORT: return "Delay import directory";
        case PE_DE_CLR:          return "CLR directory";
        default:                 return "<UNKNOWN_DIRECTORY>";
    }
}

/* Resize allocated memory
 * Calls error handler if allocation fails
 */
void* pefile_realloc(
    void       *buf,
    size_t      size,
    const char *err_msg,
    char       *err_buf)
{
    void *tmp = realloc(buf, size);
    if (tmp == NULL) {
        strcpy(err_buf, "Failed to resize memory for ");
        strncat(err_buf, err_msg, PEFILE_ERRBUF_LEN);
        pefile_error_handler(PEFILE_FAILED_ALLOC, err_buf);
    }
    return tmp;
}

/* Allocate memory
 * Calls error handler if allocation fails
 */
void* pefile_malloc(
    size_t      size,
    const char *err_msg,
    char       *err_buf)
{
    void *tmp = malloc(size);
    if (tmp == NULL) {
        strcpy(err_buf, "Failed to allocate memory for ");
        strncat(err_buf, err_msg, PEFILE_ERRBUF_LEN);
        pefile_error_handler(PEFILE_FAILED_ALLOC, err_buf);
    }
    return tmp;
}

/* Call error handler function if EOF was reached
 */
void pefile_is_trunc(
    FILE       *fp,
    const char *err_msg,
    char       *err_buf)
{
    if (feof(fp)) {
        strncpy(err_buf, err_msg, PEFILE_ERRBUF_LEN);
        strncat(err_buf, " truncated", PEFILE_ERRBUF_LEN);
        pefile_error_handler(PEFILE_IS_TRUNCATED, err_buf);
    }
}

/* Push a breadcrumb on top of the breadcrumb stack
 * This is used when walking the resource directory
 */
void pefile_breadcrumb_push(
    struct pefile_crumbs **root,
    struct pefile_crumbs  *temp)
{
    struct pefile_crumbs *bcnew = malloc(sizeof(*bcnew));
    memcpy(bcnew, temp, sizeof(*temp));
    bcnew->next = *root;
    *root = bcnew;
}

/* Pop a breadcrumb from the top of the breadcrumb stack
 * This is used when walking the resource directory
 */
void pefile_breadcrumb_pop(
    struct pefile_crumbs **root,
    struct pefile_crumbs  *temp)
{
    struct pefile_crumbs *top = *root;
    *root = top->next;
    memcpy(temp, top, sizeof(*temp));
    free(top);
}

