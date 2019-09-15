#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wctype.h>
#include "access.h"
#include "struct.h"
#include "utils.h"
#include "errors.h"

// internal resource iterator data for `getNextResource`
static struct pefile_crumbs *s_crms = NULL, s_current = {0};

/* Returns 1 if the file is 32 bit, else 0
 */
int pefile_is_32_bit(const struct pefile *pe)
{
    return pe->nt.opt.magic == PE_OH_32;
}

/* Returns 1 if the file is 64 bit, else 0
 */
int pefile_is_64_bit(const struct pefile *pe)
{
    return pe->nt.opt.magic == PE_OH_64;
}

/* Returns 1 if the IS_DLL bit is set, else 0
 */
int pefile_is_dll(const struct pefile *pe)
{
    return (pe->nt.file.characteristics & PE_FC_IS_DLL) != 0;
}

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

                // make lower case copies of both resource name and function argument
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
    while (s_crms != NULL) {
        struct pefile_crumbs *temp = s_crms->next;
        free(s_crms);
        s_crms = temp;
    }

    memset(&s_current, 0, sizeof(s_current));
    s_current.res_table = rsrc;
    return rsrc;
}

/* After initializing the data used to traverse
 * the resource directory, repeatedly call this
 * function to get the next resource directory.
 * Returns NULL after reaching the end.
 */
struct resource_table* pefile_get_next_resource_dir()
{
    if (s_current.res_table == NULL)
        return NULL;

    do {
        s_current.array_len = s_current.res_table->header.number_of_named_entries +
                              s_current.res_table->header.number_of_id_entries;
        for (s_current.index=0; s_current.index < s_current.array_len; s_current.index++) {
            struct resource_node *rn = &s_current.res_table->nodes[s_current.index];
            if (rn->entry.is_directory) {
                pefile_breadcrumb_push(&s_crms, &s_current);
                s_current.res_table = rn->table;
                return s_current.res_table;
            } else {
                pefile_breadcrumb_pop(&s_crms, &s_current);
            }

            if (s_current.index == s_current.array_len - 1) {
                pefile_breadcrumb_pop(&s_crms, &s_current);
            }
        }
    } while (s_crms != NULL);

    return NULL;
}

/* Get the current depth of the resource walker's position
 * by counting the length of the crumbs list which is just
 * the number of parent directories.
 */
int pefile_get_resource_walker_depth()
{
    int depth = 0;
    struct pefile_crumbs *iter = s_crms;
    for (; iter != NULL; iter = iter->next, depth++);
    return depth;
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

    // write resource data a chunk of `buf` at a time
    char buf[4096]; // ALERT! Arbitrary number
    while (size > sizeof(buf)) {
        fread(buf, 1, sizeof(buf), pe->file);
        fwrite(buf, 1, sizeof(buf), dump);
        size -= sizeof(buf);
    }

    // write remaining bytes that partially fill `buf`
    fread(buf, 1, size, pe->file);
    fwrite(buf, 1, size, dump);
    fflush(dump); // force immediate write
}

/* Write a resource data entry to a separate file
 */
void pefile_dump_resource_data(
    const struct pefile            *pe,
    const struct resource_metadata *rm,
    const char                     *file_path,
    char                           *err_buf)
{
    int diff = pefile_get_rva_to_apa_diff(pe->sctns,
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

