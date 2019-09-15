#ifndef PE_ACCESS_H
#define PE_ACCESS_H

#include <wchar.h>
#include "struct.h"

/* Returns 1 if the file is 32 bit, else 0
 */
int pefile_is_32_bit(const struct pefile *pe);

/* Returns 1 if the file is 64 bit, else 0
 */
int pefile_is_64_bit(const struct pefile *pe);

/* Returns 1 if the IS_DLL bit is set, else 0
 */
int pefile_is_dll(const struct pefile *pe);

/* Get a pointer to a resource node that has the given name.
 * Returns NULL if no resource node is found.
 */
struct resource_node* pefile_get_resource_by_name(
    struct resource_table *rsrc,
    const wchar_t *name);

/* Initialize or reset the data used to
 * traverse the resource directory.
 */
struct resource_table* pefile_init_resource_walker(
    struct resource_table *rsrc);

/* After initializing the data used to traverse
 * the resource directory, repeatedly call this
 * function to get the next resource directory.
 * Returns NULL after reaching the end.
 */
struct resource_table* pefile_get_next_resource_dir();

/* Get the current depth of the resource walker's position
 * by counting the length of the crumbs list which is just
 * the number of parent directories.
 */
int pefile_get_resource_walker_depth();

/* Generic data dump function
 */
void pefile_dump_data(
    const struct pefile *pe,
    uint32_t             file_offset,
    uint32_t             size,
    const char          *file_path,
    char                *err_buf);

/* Write a resource data entry to a separate file
 */
void pefile_dump_resource_data(
    const struct pefile            *pe,
    const struct resource_metadata *rm,
    const char                     *file_path,
    char                           *err_buf);

/* Write an embedded certificate to a separate file
 */
void pefile_dump_certificate_data(
    const struct cert_table *ct,
    const char              *file_path,
    char                    *err_buf);

#endif
