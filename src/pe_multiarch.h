#ifndef PE_MULTIARCH_H
#define PE_MULTIARCH_H

/* Read hint and name of the imported function
 * Some functions might be imported by ordinal and will not have a hint or name
 */
#define PEFILE_READ_IMPORT_HINT_NAME(BITS, FMT)                                                           \
static void readImportHintName##BITS(struct pefile *pe, struct import_lookup *il, int diff, char *errBuf) \
{                                                                                                         \
    /* imports by ordinal have no name, so produce this string instead */                                 \
    if (il->mtdt##BITS.isOrd) {                                                                           \
        il->ibn.hint = 0;                                                                                 \
        snprintf(il->ibn.name, PEFILE_NAME_FUNCTION_MAX_LEN,                                              \
            "Ordinal: %.*"#FMT"x", BITS / 4,                                                              \
            /* %lx does not play nice with bit fields, so do this crazy bitwise junk instead.             \
             * cast -1 to an unsigned int to get all 0xF, then shift right to unset top bit               \
             */                                                                                           \
            il->mtdt##BITS.addressOfData & (uint##BITS##_t)-1 >> 1);                                      \
        return;                                                                                           \
    }                                                                                                     \
    /* save file pointer position, seek to and read hint, fgets name, restore file pointer pos */         \
    long pos = ftell(pe->file);                                                                           \
    fseek(pe->file, il->mtdt##BITS.addressOfData - diff, SEEK_SET);                                       \
    fread(&il->ibn.hint, sizeof(il->ibn.hint), 1, pe->file);                                              \
    fgets(il->ibn.name, PEFILE_NAME_FUNCTION_MAX_LEN, pe->file);                                          \
    pefile_isTrunc(pe->file, "An import lookup is", errBuf);                                              \
    fseek(pe->file, pos, SEEK_SET);                                                                       \
}

/* Build array of offsets to names of imported functions
 * Returns a pointer to the base of the new array
 */
#define PEFILE_READ_IMPORT_NAMES_TABLE(BITS)                                                                     \
static struct import_lookup* readImportNamesTable##BITS(struct pefile *pe, int idtIndex, int diff, char *errBuf) \
{                                                                                                                \
    long pos = ftell(pe->file);                                                                                  \
    int ilsLen = 0, ilsMaxLen = 8; /* ALERT! Arbitrary number */                                                 \
    struct import_lookup *ils = pefile_malloc(sizeof(ils[0]) * ilsMaxLen,                                        \
        "import lookup", errBuf);                                                                                \
    fseek(pe->file, pe->mprts[idtIndex].mtdt.addressOfInt - diff, SEEK_SET);                                     \
    fread(&ils[ilsLen].mtdt##BITS, sizeof(ils[0].mtdt##BITS), 1, pe->file);                                      \
    /* thunk data are stored as a null-terminated array */                                                       \
    struct thunk_data_##BITS null = {0};                                                                         \
    while (memcmp(&ils[ilsLen].mtdt##BITS, &null, sizeof(null)) != 0) {                                          \
        readImportHintName##BITS(pe, &ils[ilsLen], diff, errBuf);                                                \
        ilsLen++;                                                                                                \
        /* unknown array length, so keep doubling memory when space runs out */                                  \
        if (ilsLen >= ilsMaxLen) {                                                                               \
            ilsMaxLen <<= 1;                                                                                     \
            ils = pefile_realloc(ils, sizeof(ils[0]) * ilsMaxLen, "import lookup", errBuf);                      \
        }                                                                                                        \
        fread(&ils[ilsLen].mtdt##BITS, sizeof(ils->mtdt##BITS), 1, pe->file);                                    \
    }                                                                                                            \
                                                                                                                 \
    pefile_isTrunc(pe->file, "An import lookup is", errBuf);                                                     \
    pe->mprts[idtIndex].ilsLen = ilsLen;                                                                         \
    fseek(pe->file, pos, SEEK_SET);                                                                              \
    return ils;                                                                                                  \
}

/* Import directory is a variable length array of import descriptors whose
 * length is equal to the number of modules being imported from
 */
#define PEFILE_READ_IMPORT_DIR(BITS)                                                  \
static void readImportDir##BITS(struct pefile *pe, char *errBuf)                      \
{                                                                                     \
    int index = pefile_getSectionOfDir(pe, &pe->nt.opt.ddir[PE_DE_IMPORT]);           \
    if (index == PEFILE_NO_SECTION)                                                   \
        return;                                                                       \
                                                                                      \
    int diff = pefile_fixOffset(pe->sctns, index);                                    \
    int idtLen = 0, idtMaxLen = 4; /* ALERT! Arbitrary number */                      \
    pe->mprts = pefile_malloc(sizeof(pe->mprts[0]) * idtMaxLen,                       \
        "import directory", errBuf);                                                  \
    fseek(pe->file, pe->nt.opt.ddir[PE_DE_IMPORT].virtualAddress - diff, SEEK_SET);   \
    fread(&pe->mprts[idtLen].mtdt, sizeof(pe->mprts->mtdt), 1, pe->file);             \
    /* import descriptors are stored as a null-terminated array */                    \
    struct import_desc null = {0};                                                    \
    while (memcmp(&pe->mprts[idtLen].mtdt, &null, sizeof(null)) != 0) {               \
        readImportDescName(pe, &pe->mprts[idtLen], diff, errBuf);                     \
        /* read array of data about the functions imported from this module */        \
        pe->mprts[idtLen].ils = readImportNamesTable##BITS(pe, idtLen, diff, errBuf); \
        idtLen++;                                                                     \
        /* unknown array length, so keep doubling memory when space runs out */       \
        if (idtLen >= idtMaxLen) {                                                    \
            idtMaxLen <<= 1;                                                          \
            pe->mprts = pefile_realloc(pe->mprts,                                     \
                sizeof(pe->mprts[0]) * idtMaxLen,                                     \
                "import directory", errBuf);                                          \
        }                                                                             \
        fread(&pe->mprts[idtLen].mtdt, sizeof(pe->mprts->mtdt), 1, pe->file);         \
    }                                                                                 \
                                                                                      \
    pefile_isTrunc(pe->file, "Import directory is", errBuf);                          \
    pe->mprtsLen = idtLen;                                                            \
}

/* TLS directory is a single 32 bit or 64 bit TLS structure
 */
#define PEFILE_READ_TLS_DIR(BITS)                                                     \
static void readTlsDir##BITS(struct pefile *pe, char *errBuf)                         \
{                                                                                     \
    int index = pefile_getSectionOfDir(pe, &pe->nt.opt.ddir[PE_DE_TLS]);              \
    if (index == PEFILE_NO_SECTION)                                                   \
        return;                                                                       \
                                                                                      \
    int diff = pefile_fixOffset(pe->sctns, index);                                    \
    fseek(pe->file, pe->nt.opt.ddir[PE_DE_TLS].virtualAddress - diff, SEEK_SET);      \
    pe->tlst##BITS = pefile_malloc(sizeof(*pe->tlst##BITS), "TLS directory", errBuf); \
    fread(pe->tlst##BITS, sizeof(*pe->tlst##BITS), 1, pe->file);                      \
    pefile_isTrunc(pe->file, "TLS directory is", errBuf);                             \
}

/* Load config directory is a single 32 bit
 * or 64 bit load config structure
 */
#define PEFILE_READ_LOAD_CONFIG_DIR(BITS)                                                \
static void readLoadConfigDir##BITS(struct pefile *pe, char *errBuf)                     \
{                                                                                        \
    int index = pefile_getSectionOfDir(pe, &pe->nt.opt.ddir[PE_DE_LOAD_CONFIG]);         \
    if (index == PEFILE_NO_SECTION)                                                      \
        return;                                                                          \
                                                                                         \
    int diff = pefile_fixOffset(pe->sctns, index);                                       \
    fseek(pe->file, pe->nt.opt.ddir[PE_DE_LOAD_CONFIG].virtualAddress - diff, SEEK_SET); \
    pe->ldcfg##BITS = pefile_malloc(sizeof(*pe->ldcfg##BITS),                            \
        "Load config directory", errBuf);                                                \
    fread(pe->ldcfg##BITS, sizeof(*pe->ldcfg##BITS), 1, pe->file);                       \
    /* according to documentation, this field must always be zero */                     \
    assert(pe->ldcfg##BITS->reserved == 0);                                              \
    pefile_isTrunc(pe->file, "Load config directory is", errBuf);                        \
}

/* Exception directory is a variable length array
 * of 32 bit or 64 bit function table entries
 */
#define PEFILE_READ_EXCEPTION_DIR(BITS)                                                  \
static void readExceptionDir##BITS(struct pefile *pe, char *errBuf)                      \
{                                                                                        \
    int index = pefile_getSectionOfDir(pe, &pe->nt.opt.ddir[PE_DE_EXCEPTION]);           \
    if (index == PEFILE_NO_SECTION)                                                      \
        return;                                                                          \
                                                                                         \
    int diff = pefile_fixOffset(pe->sctns, index);                                       \
    fseek(pe->file, pe->nt.opt.ddir[PE_DE_EXCEPTION].virtualAddress - diff, SEEK_SET);   \
    int xcptDirSize = pe->nt.opt.ddir[PE_DE_EXCEPTION].size;                             \
    int xcptsLen = xcptDirSize / sizeof(pe->xcpts[0].entry##BITS);                       \
                                                                                         \
    pe->xcpts = pefile_malloc(xcptsLen * sizeof(pe->xcpts[0]),                           \
        "debug directory", errBuf);                                                      \
                                                                                         \
    /* fread only one entry just to get its rva */                                       \
    fread(&pe->xcpts[0].entry##BITS, sizeof(pe->xcpts[0].entry##BITS), 1, pe->file);     \
                                                                                         \
    /* dirty hack to find `.text` section diff */                                        \
    struct data_dir temp = {                                                             \
        .virtualAddress=pe->xcpts[0].entry##BITS.beginAddress,                           \
        .size=1};                                                                        \
    index = pefile_getSectionOfDir(pe, &temp);                                           \
    int codeDiff = pefile_fixOffset(pe->sctns, index);                                   \
                                                                                         \
    /* can now get true file offset to exception handler function */                     \
    uint32_t beginAddr = pe->xcpts[0].entry##BITS.beginAddress;                          \
    pe->xcpts[0].func.beginPointer = beginAddr - codeDiff;                               \
    pe->xcpts[0].func.size = pe->xcpts[0].entry##BITS.endAddress - beginAddr;            \
                                                                                         \
    for (int i=1; i < xcptsLen; i++) {                                                   \
        fread(&pe->xcpts[i].entry##BITS, sizeof(pe->xcpts[0].entry##BITS), 1, pe->file); \
        beginAddr = pe->xcpts[i].entry##BITS.beginAddress;                               \
        pe->xcpts[i].func.beginPointer = beginAddr - codeDiff;                           \
        pe->xcpts[i].func.size = pe->xcpts[i].entry##BITS.endAddress - beginAddr;        \
    }                                                                                    \
                                                                                         \
    pefile_isTrunc(pe->file, "Exception directory is", errBuf);                          \
    pe->xcptsLen = xcptsLen;                                                             \
}

#endif
