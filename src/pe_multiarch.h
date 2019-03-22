#ifndef PE_MULTIARCH_H
#define PE_MULTIARCH_H

/* Read hint and name of the imported function
 * Some functions might be imported by ordinal and will not have a hint or name
 */
#define PEFILE_READ_IMPORT_BY_NAME(BITS, TYPE, FMT)                                                         \
static void readImportByName##BITS(struct pefile *pe, struct thunk_data_entry *oft, int diff, char *errBuf) \
{                                                                                                           \
    /* imports by ordinal have no name, so produce this string instead */                                   \
    if (oft->mtdt##BITS.isOrd) {                                                                            \
        oft->ibn.hint = 0;                                                                                  \
        snprintf(oft->ibn.name, PEFILE_FUNCTION_NAME_MAX_LEN,                                               \
            "Ordinal: %.*"#FMT"x", BITS / 4,                                                                \
            oft->mtdt##BITS.addressOfData & (TYPE)-1 >> 1);                                                 \
        return;                                                                                             \
    }                                                                                                       \
    /* save file pointer position, seek to and read hint, fgets name, restore file pointer pos */           \
    long pos = ftell(pe->file);                                                                             \
    fseek(pe->file, oft->mtdt##BITS.addressOfData - diff, SEEK_SET);                                        \
    fread(&oft->ibn.hint, sizeof(oft->ibn.hint), 1, pe->file);                                              \
    fgets(oft->ibn.name, PEFILE_FUNCTION_NAME_MAX_LEN, pe->file);                                           \
    pefile_isTrunc(pe->file, "A thunk data entry is", errBuf);                                              \
    fseek(pe->file, pos, SEEK_SET);                                                                         \
}

/* Build array of offsets to names of imported functions
 * Returns a pointer to the base of the new array
 */
#define PEFILE_READ_THUNK_DATA(BITS)                                                                          \
static struct thunk_data_entry* readThunkData##BITS(struct pefile *pe, int idt_index, int diff, char *errBuf) \
{                                                                                                             \
    long pos = ftell(pe->file);                                                                               \
    int oft_len = 0, oft_maxLen = 8; /* ALERT! Arbitrary number */                                            \
    struct thunk_data_entry *tda = pefile_malloc(sizeof(tda[0]) * oft_maxLen,                                 \
        "thunk data", errBuf);                                                                                \
    fseek(pe->file, pe->mprts[idt_index].mtdt.originalFirstThunk - diff, SEEK_SET);                           \
    fread(&tda[oft_len].mtdt##BITS, sizeof(tda[0].mtdt##BITS), 1, pe->file);                                  \
    /* thunk data are stored as a null-terminated array */                                                    \
    struct thunk_data_##BITS null = {0};                                                                      \
    while (memcmp(&tda[oft_len].mtdt##BITS, &null, sizeof(null)) != 0) {                                      \
        readImportByName##BITS(pe, &tda[oft_len], diff, errBuf);                                              \
        oft_len++;                                                                                            \
        /* unknown array length, so keep doubling memory when space runs out */                               \
        if (oft_len >= oft_maxLen) {                                                                          \
            oft_maxLen <<= 1;                                                                                 \
            tda = pefile_realloc(tda, sizeof(tda[0]) * oft_maxLen, "thunk data", errBuf);                     \
        }                                                                                                     \
        fread(&tda[oft_len].mtdt##BITS, sizeof(tda->mtdt##BITS), 1, pe->file);                                \
    }                                                                                                         \
                                                                                                              \
    pefile_isTrunc(pe->file, "Thunk data are", errBuf);                                                       \
    pe->mprts[idt_index].oftsLen = oft_len;                                                                   \
    fseek(pe->file, pos, SEEK_SET);                                                                           \
    return tda;                                                                                               \
}

/* Build array of import descriptors
 * Returns the length of the new array
 */
#define PEFILE_READ_IMPORT_DIR(BITS)                                                \
static int readImportDir##BITS(struct pefile *pe, char *errBuf)                     \
{                                                                                   \
    int index = getSectionOfDir(pe, &pe->nt.opt.ddir[PE_DE_IMPORT]);                \
    if (index == PEFILE_NO_SECTION)                                                 \
        return 0;                                                                   \
                                                                                    \
    int idt_len = 0, idt_maxLen = 4; /* ALERT! Arbitrary number */                  \
    pe->mprts = pefile_malloc(sizeof(pe->mprts[0]) * idt_maxLen,                    \
        "import directory", errBuf);                                                \
    int diff = fixOffset(pe->sctns, index);                                         \
    fseek(pe->file, pe->nt.opt.ddir[PE_DE_IMPORT].virtualAddress - diff, SEEK_SET); \
    fread(&pe->mprts[idt_len].mtdt, sizeof(pe->mprts->mtdt), 1, pe->file);          \
    /* import descriptors are stored as a null-terminated array */                  \
    struct import_desc null = {0};                                                  \
    while (memcmp(&pe->mprts[idt_len].mtdt, &null, sizeof(null)) != 0) {            \
        readImportDescName(pe, &pe->mprts[idt_len], diff, errBuf);                  \
        pe->mprts[idt_len].ofts = readThunkData##BITS(pe, idt_len, diff, errBuf);   \
        idt_len++;                                                                  \
        /* unknown array length, so keep doubling memory when space runs out */     \
        if (idt_len >= idt_maxLen) {                                                \
            idt_maxLen <<= 1;                                                       \
            pe->mprts = pefile_realloc(pe->mprts,                                   \
                sizeof(pe->mprts[0]) * idt_maxLen,                                  \
                "import directory", errBuf);                                        \
        }                                                                           \
        fread(&pe->mprts[idt_len].mtdt, sizeof(pe->mprts->mtdt), 1, pe->file);      \
    }                                                                               \
                                                                                    \
    pefile_isTrunc(pe->file, "Import directory is", errBuf);                        \
    pe->mprtsLen = idt_len;                                                         \
    return idt_len;                                                                 \
}

/* Read the TLS directory
 */
#define PEFILE_READ_TLS_DIR(BITS)                                                     \
static void readTlsDir##BITS(struct pefile *pe, char *errBuf)                         \
{                                                                                     \
    int index = getSectionOfDir(pe, &pe->nt.opt.ddir[PE_DE_TLS]);                     \
    if (index == PEFILE_NO_SECTION)                                                   \
        return;                                                                       \
                                                                                      \
    int diff = fixOffset(pe->sctns, index);                                           \
    fseek(pe->file, pe->nt.opt.ddir[PE_DE_TLS].virtualAddress - diff, SEEK_SET);      \
    pe->tlst##BITS = pefile_malloc(sizeof(*pe->tlst##BITS), "TLS directory", errBuf); \
    fread(pe->tlst##BITS, sizeof(*pe->tlst##BITS), 1, pe->file);                      \
    pefile_isTrunc(pe->file, "TLS directory is", errBuf);                             \
}

/* Read the load config directory
 */
#define PEFILE_READ_LOAD_CONFIG_DIR(BITS)                                                       \
static void readLoadConfigDir##BITS(struct pefile *pe, char *errBuf)                            \
{                                                                                               \
    int index = getSectionOfDir(pe, &pe->nt.opt.ddir[PE_DE_LOAD_CONFIG]);                       \
    if (index == PEFILE_NO_SECTION)                                                             \
        return;                                                                                 \
                                                                                                \
    int diff = fixOffset(pe->sctns, index);                                                     \
    fseek(pe->file, pe->nt.opt.ddir[PE_DE_LOAD_CONFIG].virtualAddress - diff, SEEK_SET);        \
    pe->ldcfg##BITS = pefile_malloc(sizeof(*pe->ldcfg##BITS), "Load config directory", errBuf); \
    fread(pe->ldcfg##BITS, sizeof(*pe->ldcfg##BITS), 1, pe->file);                              \
    /* according to documentation, this field must always be zero */                            \
    assert(pe->ldcfg##BITS->reserved == 0);                                                     \
    pefile_isTrunc(pe->file, "Load config directory is", errBuf);                               \
}

/* Read the exception directory
 */
#define PEFILE_READ_EXCEPTION_DIR(BITS)                                                \
static void readExceptionDir##BITS(struct pefile *pe, char *errBuf)                    \
{                                                                                      \
    int index = getSectionOfDir(pe, &pe->nt.opt.ddir[PE_DE_EXCEPTION]);                \
    if (index == PEFILE_NO_SECTION)                                                    \
        return;                                                                        \
                                                                                       \
    int diff = fixOffset(pe->sctns, index);                                            \
    fseek(pe->file, pe->nt.opt.ddir[PE_DE_EXCEPTION].virtualAddress - diff, SEEK_SET); \
    int xcpt_dir_size = pe->nt.opt.ddir[PE_DE_EXCEPTION].size;                         \
                                                                                       \
    pe->xcpts##BITS = pefile_malloc(xcpt_dir_size, "debug directory", errBuf);         \
    fread(pe->xcpts##BITS, xcpt_dir_size, 1, pe->file);                                \
                                                                                       \
    pefile_isTrunc(pe->file, "Exception directory is", errBuf);                        \
    pe->xcptsLen = xcpt_dir_size / sizeof(pe->xcpts##BITS[0]);                         \
}

#endif
