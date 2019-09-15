#include <string.h>

#include "../include/libpefile.h"
#include "dumping.h"
#include "help.h"

int dump_resource(const struct pefile *cpe, char *args[])
{
    if (cpe->rsrc == NULL) {
        fprintf(stderr, "No resource data\n");
        return 1;
    }

    // read variable number of resource directory indices
    int i=0, indices[8] = {0};
    // array indices are >= 0, so use negative value to indicate end of list
    memset(indices, -1, sizeof(indices));
    while (args[i+2] != NULL
    && i < (int)(sizeof(indices)/sizeof(indices[0]))
    && sscanf(args[i+2], "%d", &indices[i]) == 1) {
        i++;
    }

    // ensure terminated by -1
    indices[(sizeof(indices)/sizeof(indices[0]))-1] = -1;

    // use user input resource indices to walk resource dir
    struct resource_table *rt = cpe->rsrc;
    struct resource_metadata *rm = NULL;
    for (int j=0; indices[j] != -1; j++) {
        // return if index out of range
        if (!(0 <= indices[j] && indices[j] < (int)rt->nodes_len)) {
            fprintf(stderr, "Resource index out of range.\n"
                    "Index must be between 0 and %u\n", rt->nodes_len - 1);
            return 1;
        }

        // if entry is directory, enter it, and repeat loop
        if (rt->nodes[indices[j]].entry.is_directory) {
            rt = rt->nodes[indices[j]].table;
            continue;
        } else {
            // otherwise, it is file data and we're done
            rm = &rt->nodes[indices[j]].metadata;
            break;
        }
    }

    // found resource data && filename was given
    if (rm != NULL && args[i+2] != NULL && args[i+2][0] != 0) {
        char msg[32] = {0};
        pefile_dump_resource_data(cpe, rm, args[i+2], msg);
        return 0;
    }

    usage_do_dump();
    return 1;
}

int dump_certificate(const struct pefile *cpe, char *args[])
{
    if (cpe->certs == NULL) {
        fprintf(stderr, "No certificate data\n");
        return 1;
    }

    if (args[2] == NULL
    || args[3]    == NULL
    || args[3][0] == 0) {
        usage_do_dump();
        return 1;
    }

    int cert_index = -1;
    if (sscanf(args[2], "%d", &cert_index) != 1) {
        fprintf(stderr, "No certificate selected\n");
        printf("Usage: `dump certificate #`\n");
        return 1;
    }

    printf("cert_index = %d\n", cert_index);

    // verify index is in range
    if (!(0 <= cert_index && cert_index < (int)cpe->certs_len)) {
        fprintf(stderr, "Certificate index out of range.\n"
            "Index must be between 0 and %u\n", cpe->certs_len - 1);
        return 1;
    }

    char msg[32] = {0};
    pefile_dump_certificate_data(&cpe->certs[cert_index], args[3], msg);

    return 0;
}

void do_dump(const struct pefile *cpe, char *args[])
{
    if (args[1] == NULL || args[1][0] == 0) {
        usage_do_dump();
        return;
    }

    int status = 0;
    switch (args[1][0]) {
        case 'r':
            status = dump_resource(cpe, args);
            break;
        case 'c':
            status = dump_certificate(cpe, args);
            break;
        default : fprintf(stderr, "Unknown option '%s'\n", args[1]);
    }

    if (status != 0) {
        fprintf(stderr, "Dump failed\n");
        return;
    }
}

