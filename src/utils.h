#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include "struct.h"

struct pefile_crumbs {
    int index;
    int array_len;
    struct resource_table *res_table;
    struct pefile_crumbs *next;
};

/* Get index of the section a directory entry was merged into.
 * Returns the index of the relevant section or PEFILE_NO_SECTION if not found.
 */
int pefile_get_section_of_dir(
    const struct pefile   *pe,
    const struct data_dir *entry);

/* Adjust offsets when a data directory entry is merged into some section.
 * Returns the integer difference between the virtual address and raw address.
 */
int pefile_get_rva_to_apa_diff(
    const struct section_h *sctns,
    int                     section_index);

/* Get directory name from index
 */
char* pefile_dir_to_str(
    int index);

/* Call error handler function if EOF was reached
 */
void pefile_is_trunc(
    FILE       *fp,
    const char *err_msg,
    char       *err_buf);

/* Allocate memory
 * Calls error handler if allocation fails
 */
void* pefile_malloc(
    size_t      size,
    const char *err_msg,
    char       *err_buf);

/* Resize allocated memory
 * Calls error handler if allocation fails
 */
void* pefile_realloc(
    void       *buf,
    size_t      size,
    const char *err_msg,
    char       *err_buf);

/* Push a breadcrumb on top of the breadcrumb stack
 * This is used when walking the resource directory
 */
void pefile_breadcrumb_push(
    struct pefile_crumbs **root,
    struct pefile_crumbs  *temp);

/* Pop a breadcrumb from the top of the breadcrumb stack
 * This is used when walking the resource directory
 */
void pefile_breadcrumb_pop(
    struct pefile_crumbs **root,
    struct pefile_crumbs  *temp);

#endif
