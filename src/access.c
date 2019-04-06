#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wctype.h>
#include "access.h"
#include "struct.h"
#include "utils.h"
#include "errors.h"

// internal resource iterator data for `getNextResource`
static struct pefile_crumbs *crms = NULL, current = {0};

/* Get a pointer to a resource node that has the given name.
 * Returns NULL if no resource node is found.
 */
struct resource_node* pefile_get_resource_by_name(
    struct resource_table *rsrc,
    const wchar_t         *name)
{
    if (rsrc == NULL)
        return NULL;

    struct pefile_crumbs *crms = NULL, current = {.res_table=rsrc};

    do {
        current.array_len = current.res_table->header.number_of_named_entries +
                        current.res_table->header.number_of_id_entries;
        for (current.index=0; current.index < current.array_len; current.index++) {
            struct resource_node *rn = &current.res_table->nodes[current.index];
            if (rn->entry.has_name_string) {

                // make a lower case copy
                wchar_t *resname = rn->res_name.name;
                wchar_t lwrRes[PEFILE_NAME_RESOURCE_MAX_LEN] = {0};
                wchar_t lwres_name[PEFILE_NAME_RESOURCE_MAX_LEN] = {0};
                for (int i=0; resname[i] != 0; i++) {
                    lwrRes[i] = towlower(resname[i]);
                    lwres_name[i] = towlower(name[i]);
                }

                // find case-insensitive match
                if (wcsncmp(lwrRes, lwres_name, PEFILE_NAME_RESOURCE_MAX_LEN) == 0) {
                    // clean up any left-over crumbs
                    while (crms != NULL) {
                        struct pefile_crumbs *temp = crms->next;
                        free(crms);
                        crms = temp;
                    }
                    return rn;
                }
            }

            if (rn->entry.is_directory) {
                pefile_breadcrumb_push(&crms, &current);
                current.res_table = rn->table;
                break;
            } else {
                pefile_breadcrumb_pop(&crms, &current);
            }

            if (current.index == current.array_len - 1)
                pefile_breadcrumb_pop(&crms, &current);
        }

    } while (crms != NULL);

    return NULL;
}

/* Initialize or reset the data used to
 * traverse the resource directory.
 */
struct resource_table* pefile_init_resource_walker(
    struct resource_table *rsrc)
{
    if (rsrc == NULL)
        return NULL;

    // free any pre-existing crumbs
    while (crms != NULL) {
        struct pefile_crumbs *temp = crms->next;
        free(crms);
        crms = temp;
    }

    memset(&current, 0, sizeof(current));
    current.res_table = rsrc;
    return rsrc;
}

/* After initializing the data used to traverse
 * the resource directory, repeatedly call this
 * function to get the next resource directory.
 * Returns NULL after reaching the end.
 */
struct resource_table* pefile_get_next_resource_dir()
{
    if (current.res_table == NULL)
        return NULL;

    do {
        current.array_len = current.res_table->header.number_of_named_entries +
                        current.res_table->header.number_of_id_entries;
        for (current.index=0; current.index < current.array_len; current.index++) {
            struct resource_node *rn = &current.res_table->nodes[current.index];
            if (rn->entry.is_directory) {
                pefile_breadcrumb_push(&crms, &current);
                current.res_table = rn->table;
                return current.res_table;
            } else {
                pefile_breadcrumb_pop(&crms, &current);
            }

            if (current.index == current.array_len - 1)
                pefile_breadcrumb_pop(&crms, &current);
        }
    } while (crms != NULL);

    return NULL;
}

/* Generic data dump function
 */
void pefile_dump_data(
    const struct pefile *pe,
    uint32_t             file_offset,
    uint32_t             size,
    const char          *file_path,
    char                *err_buf)
{
    FILE *dump = fopen(file_path, "wb");
    if (dump == NULL) {
        strcpy(err_buf, "Failed to create the file");
        pefile_error_handler(PEFILE_GENERIC_ERR, err_buf);
    }

    fseek(pe->file, file_offset, SEEK_SET);
    char buf[4096]; // ALERT! Arbitrary number
    // write resource data a chunk of `buf` at a time
    while (size > sizeof(buf)) {
        fread(buf, sizeof(buf), 1, pe->file);
        fwrite(buf, sizeof(buf), 1, dump);
        size -= sizeof(buf);
    }
    // write remaining bytes that partially fill `buf`
    fread(buf, size, 1, pe->file);
    fwrite(buf, size, 1, dump);
}

/* Write a resource data entry to a separate file
 */
void pefile_dump_resource_data(
    const struct pefile            *pe,
    const struct resource_metadata *rm,
    const char                     *file_path,
    char                           *err_buf)
{
    int diff = pefile_fix_offset(pe->sctns,
        pefile_get_section_of_dir(pe, &pe->nt.opt.ddir[PE_DE_RESOURCE]));

    pefile_dump_data(pe, rm->data_offset - diff, rm->size, file_path, err_buf);
}

/* Write an embedded certificate to a separate file
 */
void pefile_dump_certificate_data(
    const struct cert_table *ct,
    const char              *file_path,
    char                    *err_buf)
{
    FILE *dump = fopen(file_path, "wb");
    if (dump == NULL) {
        strcpy(err_buf, "Failed to create the file");
        pefile_error_handler(PEFILE_GENERIC_ERR, err_buf);
    }

    fwrite(ct->data, ct->metadata.size, 1, dump);
}

