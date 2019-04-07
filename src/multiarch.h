#ifndef PE_MULTIARCH_H
#define PE_MULTIARCH_H

/* Read hint and name of the imported function.
 * Some functions might be imported by ordinal
 * and will not have a hint or name.
 */
#define PEFILE_READ_IMPORT_HINT_NAME(BITS, FMT)                            \
static void read_import_hint_name_##BITS(                                  \
    struct pefile        *pe,                                              \
	struct import_lookup *il,                                              \
	int                   rva_to_apa_diff,                                 \
	char                 *err_buf)                                         \
{                                                                          \
    /* imports by ordinal have no name, so make this string instead */     \
    if (il->metadata##BITS.is_ordinal) {                                   \
        il->function_name.hint = 0;                                        \
        snprintf(il->function_name.name,                                   \
            PEFILE_NAME_FUNCTION_MAX_LEN,                                  \
            "Ordinal: %.*"#FMT"x", BITS / 4,                               \
            /* %lx does not play nice with bit fields,                     \
             * so do this crazy bitwise junk instead.                      \
             * Cast -1 to an unsigned int to get all 0xF,                  \
             * then shift right to unset top bit                           \
             */                                                            \
            il->metadata##BITS.rva & (uint##BITS##_t)-1 >> 1);             \
        return;                                                            \
    }                                                                      \
    /* save file pointer position, seek to and read hint,                  \
     * fgets name, restore file pointer pos                                \
     */                                                                    \
    long pos = ftell(pe->file);                                            \
    fseek(pe->file, il->metadata##BITS.rva - rva_to_apa_diff, SEEK_SET);   \
    fread(&il->function_name.hint,                                         \
        sizeof(il->function_name.hint), 1, pe->file);                      \
    fgets(il->function_name.name, PEFILE_NAME_FUNCTION_MAX_LEN, pe->file); \
    pefile_is_trunc(pe->file, "An import lookup is", err_buf);             \
    fseek(pe->file, pos, SEEK_SET);                                        \
}

/* Build array of offsets to names of imported functions
 * Returns a pointer to the base of the new array
 */
#define PEFILE_READ_IMPORT_NAMES_TABLE(BITS)                                         \
static struct import_lookup* read_import_names_table_##BITS(                         \
    struct pefile *pe,                                                               \
	int            idt_index,                                                        \
	int            rva_to_apa_diff,                                                  \
	char          *err_buf)                                                          \
{                                                                                    \
    long pos = ftell(pe->file);                                                      \
    int lookups_len = 0, lookups_max_len = 8; /* ALERT! Arbitrary number */          \
    struct import_lookup *lookups = pefile_malloc(                                   \
        sizeof(lookups[0]) * lookups_max_len,                                        \
        "import lookup", err_buf);                                                   \
    fseek(pe->file,                                                                  \
        pe->mprts[idt_index].metadata.import_names_table_rva - rva_to_apa_diff,      \
        SEEK_SET);                                                                   \
    fread(&lookups[lookups_len].metadata##BITS,                                      \
        sizeof(lookups[0].metadata##BITS), 1, pe->file);                             \
    /* thunk data are stored as a null-terminated array */                           \
    struct thunk_data_##BITS null = {0};                                             \
    while (memcmp(&lookups[lookups_len].metadata##BITS, &null, sizeof(null)) != 0) { \
        read_import_hint_name_##BITS(pe,                                             \
            &lookups[lookups_len], rva_to_apa_diff, err_buf);                        \
        lookups_len++;                                                               \
        /* unknown array length, so double memory when space runs out */             \
        if (lookups_len >= lookups_max_len) {                                        \
            lookups_max_len <<= 1;                                                   \
            lookups = pefile_realloc(lookups,                                        \
            sizeof(lookups[0]) * lookups_max_len, "import lookup", err_buf);         \
        }                                                                            \
        fread(&lookups[lookups_len].metadata##BITS,                                  \
            sizeof(lookups->metadata##BITS), 1, pe->file);                           \
    }                                                                                \
                                                                                     \
    pefile_is_trunc(pe->file, "an import lookup is", err_buf);                       \
    pe->mprts[idt_index].lookups_len = lookups_len;                                  \
    fseek(pe->file, pos, SEEK_SET);                                                  \
    return lookups;                                                                  \
}

/* Import directory is a variable length array of import descriptors whose
 * length is equal to the number of modules being imported from
 */
#define PEFILE_READ_IMPORT_DIR(BITS)                                                             \
static void read_import_dir_##BITS(                                                              \
    struct pefile *pe,                                                                           \
	char          *err_buf)                                                                      \
{                                                                                                \
    int index = pefile_get_section_of_dir(pe, &pe->nt.opt.ddir[PE_DE_IMPORT]);                   \
    if (index == PEFILE_NO_SECTION)                                                              \
        return;                                                                                  \
                                                                                                 \
    int rva_to_apa_diff = pefile_get_rva_to_apa_diff(pe->sctns, index);                          \
    int idt_len = 0, idt_max_len = 4; /* ALERT! Arbitrary number */                              \
    pe->mprts = pefile_malloc(sizeof(pe->mprts[0]) * idt_max_len,                                \
        "import directory", err_buf);                                                            \
    fseek(pe->file, pe->nt.opt.ddir[PE_DE_IMPORT].rva -                                          \
        rva_to_apa_diff, SEEK_SET);                                                              \
    fread(&pe->mprts[idt_len].metadata,                                                          \
        sizeof(pe->mprts->metadata), 1, pe->file);                                               \
    /* import descriptors are stored as a null-terminated array */                               \
    struct import_desc null = {0};                                                               \
    while (memcmp(&pe->mprts[idt_len].metadata, &null, sizeof(null)) != 0) {                     \
        read_import_desc_name(pe, &pe->mprts[idt_len], rva_to_apa_diff, err_buf);                \
        /* read array of data about the functions imported from this module */                   \
        pe->mprts[idt_len].lookups = read_import_names_table_##BITS(pe,                          \
            idt_len, rva_to_apa_diff, err_buf);                                                  \
        idt_len++;                                                                               \
        /* unknown array length, so double memory when space runs out */                         \
        if (idt_len >= idt_max_len) {                                                            \
            idt_max_len <<= 1;                                                                   \
            pe->mprts = pefile_realloc(pe->mprts,                                                \
                sizeof(pe->mprts[0]) * idt_max_len,                                              \
                "import directory", err_buf);                                                    \
        }                                                                                        \
        fread(&pe->mprts[idt_len].metadata,                                                      \
            sizeof(pe->mprts->metadata), 1, pe->file);                                           \
    }                                                                                            \
                                                                                                 \
    pefile_is_trunc(pe->file, "Import directory is", err_buf);                                   \
    pe->mprts_len = idt_len;                                                                     \
}

/* Find absolute physical address to
 * array of callback function pointers
 */
#define PEFILE_GET_TLS_CALLBACKS_APA(BITS)                              \
static uint##BITS##_t get_tls_callbacks_apa_##BITS(                     \
    struct pefile *pe,                                                  \
    uint##BITS##_t file_base_address)                                   \
{                                                                       \
    uint##BITS##_t callbacks_rva = pe->tlst->tlst##BITS.callbacks_ava - \
        file_base_address;                                              \
    struct data_dir temp = {.rva=callbacks_rva, .size=1};               \
    int index = pefile_get_section_of_dir(pe, &temp);                   \
    int code_diff = pefile_get_rva_to_apa_diff(pe->sctns, index);       \
    return callbacks_rva - code_diff;                                   \
}

/* Read array of absolute virtual addresses to callback functions.
 * Returns the length of the array.
 */
#define PEFILE_READ_TLS_CALLBACKS(BITS)                                     \
static int read_tls_callbacks_##BITS(                                       \
    struct pefile            *pe,                                           \
    struct callback_func_ptr *cllbcks,                                      \
    int                       ava_to_apa_diff,                              \
    int                       callbacks_max_len,                            \
    char                     *err_buf)                                      \
{                                                                           \
    int callbacks_len = 0;                                                  \
    while (cllbcks[callbacks_len].code_ava != 0) {                          \
        callbacks_len++;                                                    \
        /* unknown array length, so double memory when space runs out */    \
        if (callbacks_len >= callbacks_max_len) {                           \
            callbacks_max_len <<= 1;                                        \
            cllbcks = pefile_realloc(cllbcks,                               \
                sizeof(cllbcks[0]) * callbacks_max_len,                     \
                "TLS callbacks", err_buf);                                  \
        }                                                                   \
        fread(&cllbcks[callbacks_len].code_ava,                             \
            sizeof(cllbcks[0].code_ava), 1, pe->file);                      \
        cllbcks[callbacks_len].code_apa = cllbcks[callbacks_len].code_ava - \
            ava_to_apa_diff;                                                \
    }                                                                       \
    return callbacks_len;                                                   \
}

/* TLS directory is a single 32 bit or 64 bit TLS structure with
 * a pointer to a variable length of array of absolute virtual
 * addresses to callback functions.
 */
#define PEFILE_READ_TLS_DIR(BITS, FMT)                                      \
static void read_tls_dir_##BITS(                                            \
    struct pefile *pe,                                                      \
	char          *err_buf)                                                 \
{                                                                           \
    int index = pefile_get_section_of_dir(pe, &pe->nt.opt.ddir[PE_DE_TLS]); \
    if (index == PEFILE_NO_SECTION)                                         \
        return;                                                             \
                                                                            \
    int rva_to_apa_diff = pefile_get_rva_to_apa_diff(pe->sctns, index);     \
    fseek(pe->file, pe->nt.opt.ddir[PE_DE_TLS].rva -                        \
        rva_to_apa_diff, SEEK_SET);                                         \
    pe->tlst = pefile_malloc(sizeof(*pe->tlst), "TLS directory", err_buf);  \
    fread(&pe->tlst->tlst##BITS,                                            \
        sizeof(pe->tlst->tlst##BITS), 1, pe->file);                         \
                                                                            \
    uint##BITS##_t file_base_address = pe->nt.opt.base_address_##BITS;      \
    uint##BITS##_t callbacks_apa = get_tls_callbacks_apa_##BITS(pe,         \
        file_base_address);                                                 \
    fseek(pe->file, callbacks_apa, SEEK_SET);                               \
                                                                            \
    int callbacks_max_len = 4; /* ALERT! Arbitrary number */                \
    struct callback_func_ptr *cllbcks = pefile_malloc(                      \
        sizeof(cllbcks[0]) * callbacks_max_len,                             \
        "TLS callbacks", err_buf);                                          \
                                                                            \
    /* fread only one entry just to get its ava */                          \
    fread(&cllbcks[0].code_ava,                                             \
        sizeof(cllbcks[0].code_ava), 1, pe->file);                          \
                                                                            \
    uint##BITS##_t code_rva = cllbcks[0].code_ava - file_base_address;      \
    struct data_dir temp = {.rva=code_rva, .size=1};                        \
    index = pefile_get_section_of_dir(pe, &temp);                           \
    int ava_to_apa_diff = pefile_get_rva_to_apa_diff(pe->sctns, index) +    \
        file_base_address;                                                  \
                                                                            \
    cllbcks[0].code_apa = cllbcks[0].code_ava - ava_to_apa_diff;            \
                                                                            \
    pe->tlst->callbacks_len = read_tls_callbacks_##BITS(                    \
        pe, cllbcks, ava_to_apa_diff, callbacks_max_len, err_buf);          \
    pe->tlst->callbacks = cllbcks;                                          \
    pefile_is_trunc(pe->file, "TLS directory is", err_buf);                 \
}

/* Load config directory is a single 32 bit
 * or 64 bit load config structure
 */
#define PEFILE_READ_LOAD_CONFIG_DIR(BITS)                                     \
static void read_load_config_dir_##BITS(                                      \
    struct pefile *pe,                                                        \
	char          *err_buf)                                                   \
{                                                                             \
    int index = pefile_get_section_of_dir(pe,                                 \
        &pe->nt.opt.ddir[PE_DE_LOAD_CONFIG]);                                 \
    if (index == PEFILE_NO_SECTION)                                           \
        return;                                                               \
                                                                              \
    int rva_to_apa_diff = pefile_get_rva_to_apa_diff(pe->sctns, index);       \
    fseek(pe->file, pe->nt.opt.ddir[PE_DE_LOAD_CONFIG].rva -                  \
        rva_to_apa_diff, SEEK_SET);                                           \
    pe->ldcfg##BITS = pefile_malloc(sizeof(*pe->ldcfg##BITS),                 \
        "Load config directory", err_buf);                                    \
    fread(pe->ldcfg##BITS,                                                    \
        sizeof(*pe->ldcfg##BITS), 1, pe->file);                               \
    /* according to documentation, this field must always be zero */          \
    assert(pe->ldcfg##BITS->reserved == 0);                                   \
    pefile_is_trunc(pe->file, "Load config directory is", err_buf);           \
}

/* Exception directory is a variable length array
 * of 32 bit or 64 bit function table entries
 */
#define PEFILE_READ_EXCEPTION_DIR(BITS)                                 \
static void read_exception_dir_##BITS(                                  \
    struct pefile *pe,                                                  \
	char          *err_buf)                                             \
{                                                                       \
    int index = pefile_get_section_of_dir(pe,                           \
        &pe->nt.opt.ddir[PE_DE_EXCEPTION]);                             \
    if (index == PEFILE_NO_SECTION)                                     \
        return;                                                         \
                                                                        \
    int rva_to_apa_diff = pefile_get_rva_to_apa_diff(pe->sctns, index); \
    fseek(pe->file, pe->nt.opt.ddir[PE_DE_EXCEPTION].rva -              \
        rva_to_apa_diff, SEEK_SET);                                     \
    int xcpt_dir_size = pe->nt.opt.ddir[PE_DE_EXCEPTION].size;          \
    int xcpts_len = xcpt_dir_size / sizeof(pe->xcpts[0].entry##BITS);   \
                                                                        \
    struct exception_table *xcpts = pefile_malloc(                      \
        xcpts_len * sizeof(xcpts[0]),                                   \
        "debug directory", err_buf);                                    \
                                                                        \
    /* fread only one entry just to get its rva */                      \
    fread(&xcpts[0].entry##BITS,                                        \
        sizeof(xcpts[0].entry##BITS), 1, pe->file);                     \
                                                                        \
    /* dirty hack to find `.text` section rva_to_apa_diff */            \
    struct data_dir temp = {                                            \
        .rva=xcpts[0].entry##BITS.start_rva,                            \
        .size=1};                                                       \
    index = pefile_get_section_of_dir(pe, &temp);                       \
    rva_to_apa_diff = pefile_get_rva_to_apa_diff(pe->sctns, index);     \
                                                                        \
    /* can now get true file offset to exception handler function */    \
    uint32_t begin_addr = xcpts[0].entry##BITS.start_rva;               \
    xcpts[0].function.code_apa = begin_addr - rva_to_apa_diff;          \
    xcpts[0].function.code_size = xcpts[0].entry##BITS.end_rva -        \
        begin_addr;                                                     \
                                                                        \
    for (int i=1; i < xcpts_len; i++) {                                 \
        fread(&xcpts[i].entry##BITS,                                    \
            sizeof(xcpts[0].entry##BITS), 1, pe->file);                 \
        begin_addr = xcpts[i].entry##BITS.start_rva;                    \
        xcpts[i].function.code_apa = begin_addr - rva_to_apa_diff;      \
        xcpts[i].function.code_size = xcpts[i].entry##BITS.end_rva -    \
            begin_addr;                                                 \
    }                                                                   \
                                                                        \
    pefile_is_trunc(pe->file, "Exception directory is", err_buf);       \
    pe->xcpts = xcpts;                                                  \
    pe->xcpts_len = xcpts_len;                                          \
}

#endif
