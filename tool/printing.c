#include <string.h>

#include "../include/libpefile.h"
#include "help.h"
#include "printing.h"

void print_dos(const struct pefile *cpe)
{
    int index = 0;
    // ljust(40) && print max 2 chars
    printf("%-40s%.2s\n",   pefile_field_name_dos(index++), cpe->dos.e_magic);
    printf("%-40s0x%04x\n", pefile_field_name_dos(index++), cpe->dos.e_cblp);
    printf("%-40s0x%04x\n", pefile_field_name_dos(index++), cpe->dos.e_cp);
    printf("%-40s0x%04x\n", pefile_field_name_dos(index++), cpe->dos.e_crlc);
    printf("%-40s0x%04x\n", pefile_field_name_dos(index++), cpe->dos.e_cparhdr);
    printf("%-40s0x%04x\n", pefile_field_name_dos(index++), cpe->dos.e_minalloc);
    printf("%-40s0x%04x\n", pefile_field_name_dos(index++), cpe->dos.e_maxalloc);
    printf("%-40s0x%04x\n", pefile_field_name_dos(index++), cpe->dos.e_ss);
    printf("%-40s0x%04x\n", pefile_field_name_dos(index++), cpe->dos.e_sp);
    printf("%-40s0x%04x\n", pefile_field_name_dos(index++), cpe->dos.e_csum);
    printf("%-40s0x%04x\n", pefile_field_name_dos(index++), cpe->dos.e_ip);
    printf("%-40s0x%04x\n", pefile_field_name_dos(index++), cpe->dos.e_cs);
    printf("%-40s0x%04x\n", pefile_field_name_dos(index++), cpe->dos.e_lfarlc);
    printf("%-40s0x%04x\n", pefile_field_name_dos(index++), cpe->dos.e_ovno);
    printf("%-40s0x%04x\n", pefile_field_name_dos(index++), cpe->dos.e_res[0]);
    printf("%-40s0x%04x\n", pefile_field_name_dos(index++), cpe->dos.e_oemid);
    printf("%-40s0x%04x\n", pefile_field_name_dos(index++), cpe->dos.e_oeminfo);
    printf("%-40s0x%04x\n", pefile_field_name_dos(index++), cpe->dos.e_res2[0]);
    printf("%-40s0x%04x\n", pefile_field_name_dos(index++), cpe->dos.e_lfanew);
}

void print_file(const struct pefile *cpe, char *args[])
{
    int index = 0;
    // The command looked something like "[p]rint file [c]haracteristics"
    if (args[2] != NULL && args[2][0] == 'c') {
        for (; index < PEFILE_FC_NUM_FIELDS; index++) {
            int bit = cpe->nt.file.characteristics & (1 << index);
            if (bit != 0)
                printf("%-40s0x%08x\n", pefile_characteristics_name_file(bit), bit);
        }
    } else {
        printf("%-40s0x%04x\n", pefile_field_name_file(index++), cpe->nt.file.machine);
        printf("%-40s0x%04x\n", pefile_field_name_file(index++), cpe->nt.file.number_of_sections);
        printf("%-40s0x%08x\n", pefile_field_name_file(index++), cpe->nt.file.timestamp);
        printf("%-40s0x%08x\n", pefile_field_name_file(index++), cpe->nt.file.symbol_table_apa);
        printf("%-40s0x%08x\n", pefile_field_name_file(index++), cpe->nt.file.number_of_symbols);
        printf("%-40s0x%04x\n", pefile_field_name_file(index++), cpe->nt.file.optional_header_size);
        printf("%-40s0x%04x\n", pefile_field_name_file(index++), cpe->nt.file.characteristics);
    }
}

void print_optional(const struct pefile *cpe, char *args[])
{
    int index = 0;
    // The command looked something like [p]rint optional [c]haracteristics
    if (args[2] != NULL && args[2][0] == 'c') {
        for (; index < PEFILE_OC_NUM_FIELDS; index++) {
            int bit = cpe->nt.opt.dll_characteristics & (1 << index);
            if (bit != 0)
                printf("%-40s0x%04x\n", pefile_characteristics_name_optional(bit), bit);
        }
    // The command looked something like [p]rint optional [d]atadir
    } else if (args[2] != NULL && args[2][0] == 'd') {
        for (int i=0; i < PEFILE_DATA_DIR_LEN; i++)
            printf("%s\n\tRVA: %08x\n\tSIZE: %08x\n\n", pefile_dir_to_str(i), cpe->nt.opt.ddir[i].rva, cpe->nt.opt.ddir[i].size);
    } else {
        int is64 = pefile_is_64_bit(cpe);
        printf("%-40s0x%04x\n", pefile_field_name_optional(index++), cpe->nt.opt.magic);
        printf("%-40s0x%02x\n", pefile_field_name_optional(index++), cpe->nt.opt.linker_version_major);
        printf("%-40s0x%02x\n", pefile_field_name_optional(index++), cpe->nt.opt.linker_version_minor);
        printf("%-40s0x%08x\n", pefile_field_name_optional(index++), cpe->nt.opt.code_size);
        printf("%-40s0x%08x\n", pefile_field_name_optional(index++), cpe->nt.opt.initialized_data_size);
        printf("%-40s0x%08x\n", pefile_field_name_optional(index++), cpe->nt.opt.uninitialized_data_size);
        printf("%-40s0x%08x\n", pefile_field_name_optional(index++), cpe->nt.opt.entry_point_rva);
        printf("%-40s0x%08x\n", pefile_field_name_optional(index++), cpe->nt.opt.code_base_rva);
        printf("%-40s0x%08x\n", pefile_field_name_optional(index++), (is64) ? 0 : cpe->nt.opt.data_base_rva);

        printf("%-40s", pefile_field_name_optional(index++));
        (is64) ? printf("0x%016lx\n", cpe->nt.opt.base_address_64) : printf("0x%08x\n", cpe->nt.opt.base_address_32);

        printf("%-40s0x%08x\n", pefile_field_name_optional(index++), cpe->nt.opt.section_alignment);
        printf("%-40s0x%08x\n", pefile_field_name_optional(index++), cpe->nt.opt.file_alignment);
        printf("%-40s0x%04x\n", pefile_field_name_optional(index++), cpe->nt.opt.operating_system_version_major);
        printf("%-40s0x%04x\n", pefile_field_name_optional(index++), cpe->nt.opt.operating_system_version_minor);
        printf("%-40s0x%04x\n", pefile_field_name_optional(index++), cpe->nt.opt.image_version_major);
        printf("%-40s0x%04x\n", pefile_field_name_optional(index++), cpe->nt.opt.image_version_minor);
        printf("%-40s0x%04x\n", pefile_field_name_optional(index++), cpe->nt.opt.subsystem_version_major);
        printf("%-40s0x%04x\n", pefile_field_name_optional(index++), cpe->nt.opt.subsystem_version_minor);
        printf("%-40s0x%08x\n", pefile_field_name_optional(index++), cpe->nt.opt.win32_version);
        printf("%-40s0x%08x\n", pefile_field_name_optional(index++), cpe->nt.opt.image_size);
        printf("%-40s0x%08x\n", pefile_field_name_optional(index++), cpe->nt.opt.headers_size);
        printf("%-40s0x%08x\n", pefile_field_name_optional(index++), cpe->nt.opt.checksum);
        printf("%-40s0x%04x\n", pefile_field_name_optional(index++), cpe->nt.opt.subsystem);
        printf("%-40s0x%04x\n", pefile_field_name_optional(index++), cpe->nt.opt.dll_characteristics);

        printf("%-40s", pefile_field_name_optional(index++));
        (is64) ? printf("0x%016lx\n", cpe->nt.opt.opt_64.stack_reserve_size) : printf("0x%08x\n", cpe->nt.opt.opt_32.stack_reserve_size);

        printf("%-40s", pefile_field_name_optional(index++));
        (is64) ? printf("0x%016lx\n", cpe->nt.opt.opt_64.stack_commit_size) : printf("0x%08x\n", cpe->nt.opt.opt_32.stack_commit_size);

        printf("%-40s", pefile_field_name_optional(index++));
        (is64) ? printf("0x%016lx\n", cpe->nt.opt.opt_64.heap_reserve_size) : printf("0x%08x\n", cpe->nt.opt.opt_32.heap_reserve_size);

        printf("%-40s", pefile_field_name_optional(index++));
        (is64) ? printf("0x%016lx\n", cpe->nt.opt.opt_64.heap_commit_size) : printf("0x%08x\n", cpe->nt.opt.opt_32.heap_commit_size);

        printf("%-40s0x%08x\n", pefile_field_name_optional(index++), cpe->nt.opt.loader_flags);
        printf("%-40s0x%08x\n", pefile_field_name_optional(index++), cpe->nt.opt.number_of_rva_and_sizes);
    }
}

void print_section(const struct pefile *cpe, char *args[])
{
    unsigned int param=0;
    if (args[2] == NULL || sscanf(args[2], "%u", &param) != 1)
        return;

    if (param >= cpe->nt.file.number_of_sections) {
        fprintf(stderr, "Section index out of range.\n"
                "Index must be between 0 and %u\n",
                cpe->nt.file.number_of_sections - 1);
        return;
    }

    int index = 0;
    // The command looked something like [p]rint section # [c]haracteristics
    if (args[3] != NULL && args[3][0] == 'c') {
        int charact = cpe->sctns[param].characteristics & ~PEFILE_SC_ALIGN_NYBBLE;
        for (; index < PEFILE_SC_NUM_FIELDS; index++) {
            int bit = charact & (1 << index);
            if (bit != 0)
                printf("%-40s%08x\n", pefile_characteristics_name_section(bit), bit);
        }
        int alignment = cpe->sctns[param].characteristics & PEFILE_SC_ALIGN_NYBBLE;
        printf("%-40s%08x\n", pefile_characteristics_alignment_name_section(alignment), alignment);
    } else {
        printf("%-40s%.*s\n",   pefile_field_name_section(index++), PEFILE_NAME_SECTION_MAX_LEN, cpe->sctns[param].name);
        printf("%-40s0x%08x\n", pefile_field_name_section(index++), cpe->sctns[param].size_in_memory);
        printf("%-40s0x%08x\n", pefile_field_name_section(index++), cpe->sctns[param].data_rva);
        printf("%-40s0x%08x\n", pefile_field_name_section(index++), cpe->sctns[param].size_on_disk);
        printf("%-40s0x%08x\n", pefile_field_name_section(index++), cpe->sctns[param].data_apa);
        printf("%-40s0x%08x\n", pefile_field_name_section(index++), cpe->sctns[param].relocations_apa);
        printf("%-40s0x%08x\n", pefile_field_name_section(index++), cpe->sctns[param].linenumbers_apa);
        printf("%-40s0x%04x\n", pefile_field_name_section(index++), cpe->sctns[param].number_of_relocations);
        printf("%-40s0x%04x\n", pefile_field_name_section(index++), cpe->sctns[param].number_of_linenumbers);
        printf("%-40s0x%08x\n", pefile_field_name_section(index++), cpe->sctns[param].characteristics);
    }
}

void print_export(const struct pefile *cpe)
{
    if (cpe->xprt == NULL)
        return;

    puts("\tORDS | CODE | NORDS | NAMES | NAME");
    for (unsigned int i=0; i < cpe->xprt->addrs_len; i++) {
        printf("\t%08x | %08x | %04x | %08x | %s\n",
            cpe->xprt->addrs[i].code_rva,
            cpe->xprt->addrs[i].code_apa,
            cpe->xprt->nords[i],
            cpe->xprt->names[i].name_rva,
            cpe->xprt->names[i].name);
    }
}

void print_import(const struct pefile *cpe)
{
    if (cpe->mprts == NULL)
        return;

    for (unsigned int i=0; i < cpe->mprts_len; i++) {
        for (unsigned int j=0; j < cpe->mprts[i].lookups_len; j++) {
            printf("%s!%s\n",
                cpe->mprts[i].name,
                cpe->mprts[i].lookups[j].function_name.name);
        }
    }
}

void print_resource(const struct pefile *cpe)
{
    if (cpe->rsrc == NULL)
        return;

    struct pefile_crumbs *crms = NULL, current = {.res_table=cpe->rsrc};

    do {
        current.array_len = current.res_table->nodes_len;

        for (current.index=0; current.index < current.array_len; current.index++) {
            struct resource_node *rn = &current.res_table->nodes[current.index];

            int list_len = 0; // TODO: use pefile_get_resource_walker_depth();
            struct pefile_crumbs *iter = crms;
            for (; iter != NULL; iter = iter->next, list_len++);

            for (int i=0; i < list_len+1; i++)
                printf("    ");

            printf("Entry %02d :  Name:   %08x ", current.index, rn->entry.name);

            if (rn->entry.has_name_string)
                printf("%.*ls", rn->res_name.name_len, rn->res_name.name);

            printf("\n");

            for (int i=0; i < list_len+4; i++)
                printf("    ");

            printf("Offset: %08x\n", rn->entry.data_offset);

            for (int i=0; i < list_len+4; i++)
                printf("    ");

            if (!rn->entry.is_directory) {
                printf("Size:   %08x\n", rn->metadata.size);
                for (int i=0; i < list_len; i++)
                    printf("    ");
            }

            printf("\n");

            if (rn->entry.is_directory) {
                // save crumb before entering next directory
                pefile_breadcrumb_push(&crms, &current);
                current.res_table = rn->table;
                break;
            } else {
                // return to parent directory
                pefile_breadcrumb_pop(&crms, &current);
            }

            // ensure pop when index iterator is done
            if (current.index == current.array_len - 1)
                pefile_breadcrumb_pop(&crms, &current);
        }
    // end of algorithm when crumb is at top level and index iterator is done
    } while (crms != NULL);
}

void print_exception(const struct pefile *cpe)
{
    if (cpe->xcpts == NULL)
        return;

    if (pefile_is_64_bit(cpe)) {
        puts("SET | END | FILE_OFFSET");
        for (unsigned int i=0; i < cpe->xcpts_len; i++) {
            printf("0x%08x | 0x%08x | 0x%08x\n",
                cpe->xcpts[i].entry64.start_rva,
                cpe->xcpts[i].entry64.end_rva,
                cpe->xcpts[i].function.code_apa);
        }
    } else {
        puts("SET | END | UNWIND");
        for (unsigned int i=0; i < cpe->xcpts_len; i++) {
            printf("0x%08x | 0x%08x | 0x%08x\n",
                cpe->xcpts[i].entry32.start_rva,
                cpe->xcpts[i].entry32.end_rva,
                cpe->xcpts[i].function.code_apa);
        }
    }
}

void print_certificate(const struct pefile *cpe)
{
    if (cpe->certs == NULL)
        return;

    puts("TYPE       | VERSION    | SIZE");
    for (unsigned int i=0; i < cpe->certs_len; i++) {
        printf("0x%08x | 0x%08x | 0x%08x\n",
            cpe->certs[i].metadata.type,
            cpe->certs[i].metadata.version,
            cpe->certs[i].metadata.size);
    }

}

void print_relocation(const struct pefile *cpe)
{
    if (cpe->relocs == NULL)
        return;

    for (unsigned int i=0; i < cpe->relocs_len; i++) {
        printf("RVA: 0x%08x | Size: 0x%08x\n", cpe->relocs[i].header.rva, cpe->relocs[i].header.size);
        struct reloc_table *prt = &cpe->relocs[i];
        for (unsigned int j=0; j < prt->entries_len; j++) {
            printf("\tType: 0x%01x | Offset: 0x%03x\n", prt->entries[j].type, prt->entries[j].offset);
        }
        printf("\n");
    }
}

void print_debug(const struct pefile *cpe)
{
    if (cpe->dbgs == NULL)
        return;

    for (unsigned int i=0; i < cpe->dbgs_len; i++) {
        int index = 0;
        printf("%-40s%08x\n", pefile_field_name_debug_dir(index++), cpe->dbgs[i].header.characteristics);
        printf("%-40s%08x\n", pefile_field_name_debug_dir(index++), cpe->dbgs[i].header.timestamp);
        printf("%-40s%04x\n", pefile_field_name_debug_dir(index++), cpe->dbgs[i].header.version_major);
        printf("%-40s%04x\n", pefile_field_name_debug_dir(index++), cpe->dbgs[i].header.version_minor);
        printf("%-40s%08x\n", pefile_field_name_debug_dir(index++), cpe->dbgs[i].header.type);
        printf("%-40s%08x\n", pefile_field_name_debug_dir(index++), cpe->dbgs[i].header.data_size);
        printf("%-40s%08x\n", pefile_field_name_debug_dir(index++), cpe->dbgs[i].header.data_rva);
        printf("%-40s%08x\n", pefile_field_name_debug_dir(index++), cpe->dbgs[i].header.data_apa);
        printf("%-40s%.*s\n", "PDB Path", PEFILE_PATH_MAX_LEN, cpe->dbgs[i].data.pdb_path);
    }
}

/*
void print_globalptr(const struct pefile *cpe)
{
}
*/

void print_tls(const struct pefile *cpe)
{
    if (cpe->tlst == NULL)
        return;

    printf("start\t= 0x%08x\nend\t= 0x%08x\nindex\t= 0x%08x\ncllbcks\t= 0x%08x\n\n",
        cpe->tlst->tlst32.data_start_ava,
        cpe->tlst->tlst32.data_end_ava,
        cpe->tlst->tlst32.index_ava,
        cpe->tlst->tlst32.callbacks_ava);
    for (unsigned int i=0; i < cpe->tlst->callbacks_len; i++) {
        printf("0x%04x | 0x%04x\n", cpe->tlst->callbacks[i].code_ava, cpe->tlst->callbacks[i].code_apa);
    }
}

void print_loadconfig(const struct pefile *cpe)
{
    if (cpe->ldcfg32 == NULL)
        return;

    int is64 = pefile_is_64_bit(cpe);
    struct load_config_32 *ldcfg32 = cpe->ldcfg32;
    struct load_config_64 *ldcfg64 = cpe->ldcfg64;

    int index = 0;
    printf("%-40s0x%08x\n", pefile_field_name_loadconfig_dir(index++), ldcfg32->characteristics);
    printf("%-40s0x%08x\n", pefile_field_name_loadconfig_dir(index++), ldcfg32->timestamp);
    printf("%-40s0x%04x\n", pefile_field_name_loadconfig_dir(index++), ldcfg32->version_major);
    printf("%-40s0x%04x\n", pefile_field_name_loadconfig_dir(index++), ldcfg32->version_minor);
    printf("%-40s0x%08x\n", pefile_field_name_loadconfig_dir(index++), ldcfg32->global_flags_clear);
    printf("%-40s0x%08x\n", pefile_field_name_loadconfig_dir(index++), ldcfg32->global_flags_set);
    printf("%-40s0x%08x\n", pefile_field_name_loadconfig_dir(index++), ldcfg32->critical_section_default_timeout);

    printf("%-40s", pefile_field_name_loadconfig_dir(index++));
    (is64) ? printf("0x%016lx\n", ldcfg64->de_commit_free_block_threshold) : printf("0x%08x\n", ldcfg32->de_commit_free_block_threshold);

    printf("%-40s", pefile_field_name_loadconfig_dir(index++));
    (is64) ? printf("0x%016lx\n", ldcfg64->de_commit_total_free_threshold) : printf("0x%08x\n", ldcfg32->de_commit_total_free_threshold);

    printf("%-40s", pefile_field_name_loadconfig_dir(index++));
    (is64) ? printf("0x%016lx\n", ldcfg64->lock_prefix_table) : printf("0x%08x\n", ldcfg32->lock_prefix_table);

    printf("%-40s", pefile_field_name_loadconfig_dir(index++));
    (is64) ? printf("0x%016lx\n", ldcfg64->maximum_allocation_size) : printf("0x%08x\n", ldcfg32->maximum_allocation_size);

    printf("%-40s", pefile_field_name_loadconfig_dir(index++));
    (is64) ? printf("0x%016lx\n", ldcfg64->virtual_memory_threshold) : printf("0x%08x\n", ldcfg32->virtual_memory_threshold);

    printf("%-40s", pefile_field_name_loadconfig_dir(index++));
    (is64) ? printf("0x%016lx\n", ldcfg64->process_affinity_mask) : printf("0x%08x\n", ldcfg32->process_affinity_mask);

    printf("%-40s", pefile_field_name_loadconfig_dir(index++));
    (is64) ? printf("0x%08x\n", cpe->ldcfg64->process_heap_flags) : printf("0x%08x\n", cpe->ldcfg32->process_heap_flags);

    printf("%-40s", pefile_field_name_loadconfig_dir(index++));
    (is64) ? printf("0x%04x\n", cpe->ldcfg64->csd_version) : printf("0x%04x\n", cpe->ldcfg32->csd_version);

    printf("%-40s", pefile_field_name_loadconfig_dir(index++));
    (is64) ? printf("0x%04x\n", cpe->ldcfg64->reserved) : printf("0x%04x\n", cpe->ldcfg32->reserved);

    printf("%-40s", pefile_field_name_loadconfig_dir(index++));
    (is64) ? printf("0x%016lx\n", ldcfg64->edit_list) : printf("0x%08x\n", ldcfg32->edit_list);

    printf("%-40s", pefile_field_name_loadconfig_dir(index++));
    (is64) ? printf("0x%016lx\n", ldcfg64->security_cookie) : printf("0x%08x\n", ldcfg32->security_cookie);

    printf("%-40s", pefile_field_name_loadconfig_dir(index++));
    (is64) ? printf("0x%016lx\n", ldcfg64->se_handler_table) : printf("0x%08x\n", ldcfg32->se_handler_table);

    printf("%-40s", pefile_field_name_loadconfig_dir(index++));
    (is64) ? printf("0x%016lx\n", ldcfg64->se_handler_count) : printf("0x%08x\n", ldcfg32->se_handler_count);

    printf("%-40s", pefile_field_name_loadconfig_dir(index++));
    (is64) ? printf("0x%016lx\n", ldcfg64->guard_cf_check_function_pointer) : printf("0x%08x\n", ldcfg32->guard_cf_check_function_pointer);

    printf("%-40s", pefile_field_name_loadconfig_dir(index++));
    (is64) ? printf("0x%016lx\n", ldcfg64->guard_cf_dispatch_function_pointer) : printf("0x%08x\n", ldcfg32->guard_cf_dispatch_function_pointer);

    printf("%-40s", pefile_field_name_loadconfig_dir(index++));
    (is64) ? printf("0x%016lx\n", ldcfg64->guard_cf_function_table) : printf("0x%08x\n", ldcfg32->guard_cf_function_table);

    printf("%-40s", pefile_field_name_loadconfig_dir(index++));
    (is64) ? printf("0x%016lx\n", ldcfg64->guard_cf_function_count) : printf("0x%08x\n", ldcfg32->guard_cf_function_count);

    printf("%-40s", pefile_field_name_loadconfig_dir(index++));
    (is64) ? printf("0x%08x\n", cpe->ldcfg64->guard_flags) : printf("0x%08x\n", cpe->ldcfg32->guard_flags);

    printf("%-40s0x", pefile_field_name_loadconfig_dir(index++));
    for (unsigned long i=0; i < sizeof(ldcfg32->code_integrity) / sizeof(ldcfg32->code_integrity[0]); i++)
        printf("%02x", cpe->ldcfg32->code_integrity[i]);
    printf("\n");

    printf("%-40s", pefile_field_name_loadconfig_dir(index++));
    (is64) ? printf("0x%016lx\n", ldcfg64->guard_address_taken_iat_entry_table) : printf("0x%08x\n", ldcfg32->guard_address_taken_iat_entry_table);

    printf("%-40s", pefile_field_name_loadconfig_dir(index++));
    (is64) ? printf("0x%016lx\n", ldcfg64->guard_address_taken_iat_entry_count) : printf("0x%08x\n", ldcfg32->guard_address_taken_iat_entry_count);

    printf("%-40s", pefile_field_name_loadconfig_dir(index++));
    (is64) ? printf("0x%016lx\n", ldcfg64->guard_long_jump_target_table) : printf("0x%08x\n", ldcfg32->guard_long_jump_target_table);

    printf("%-40s", pefile_field_name_loadconfig_dir(index++));
    (is64) ? printf("0x%016lx\n", ldcfg64->guard_long_jump_target_count) : printf("0x%08x\n", ldcfg32->guard_long_jump_target_count);
}

/*
void print_boundimport(const struct pefile *cpe)
{
}

void print_iat(const struct pefile *cpe)
{
}

void print_delayimport(const struct pefile *cpe)
{
}

void print_clr(const struct pefile *cpe)
{
}
*/

void do_print(const struct pefile *cpe, char *args[])
{
    if      (args[1] == NULL || args[1][0]   == 0) usage_do_print();
//  /* (32|64)-Bit; Is DLL; Has Exports;  */
//  else if (strcmp(args[1], "summary"     ) == 0) print_summary(cpe);
    else if (strcmp(args[1], "dos"         ) == 0) print_dos(cpe);
    else if (strcmp(args[1], "file"        ) == 0) print_file(cpe, args);
    else if (strcmp(args[1], "optional"    ) == 0) print_optional(cpe, args);
    else if (strcmp(args[1], "section"     ) == 0) print_section(cpe, args);
    else if (strcmp(args[1], "export"      ) == 0) print_export(cpe);
    else if (strcmp(args[1], "import"      ) == 0) print_import(cpe);
    else if (strcmp(args[1], "resource"    ) == 0) print_resource(cpe);
    else if (strcmp(args[1], "exception"   ) == 0) print_exception(cpe);
    else if (strcmp(args[1], "certificate" ) == 0) print_certificate(cpe);
    else if (strcmp(args[1], "relocation"  ) == 0) print_relocation(cpe);
    else if (strcmp(args[1], "debug"       ) == 0) print_debug(cpe);
//  else if (strcmp(args[1], "architecture") == 0) print_architecture(cpe);
//  else if (strcmp(args[1], "globalptr"   ) == 0) print_globalptr(cpe);
    else if (strcmp(args[1], "tls"         ) == 0) print_tls(cpe);
    else if (strcmp(args[1], "loadconfig"  ) == 0) print_loadconfig(cpe);
//  else if (strcmp(args[1], "boundimport" ) == 0) print_boundimport(cpe);
//  else if (strcmp(args[1], "iat"         ) == 0) print_iat(cpe);
//  else if (strcmp(args[1], "delayimport" ) == 0) print_delayimport(cpe);
//  else if (strcmp(args[1], "clr"         ) == 0) print_clr(cpe);
    else                                           fprintf(stderr, "Invalid choice: '%s'\n", args[1]);
}

