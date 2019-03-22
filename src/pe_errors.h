#ifndef PE_ERRORS_H
#define PE_ERRORS_H

#define PEFILE_ERRBUF_LEN 256

enum pefile_errs {
    PEFILE_NO_SECTION=-1,
    PEFILE_SUCCESS,
    PEFILE_GENERIC_ERR,
    PEFILE_FAILED_ALLOC,
    PEFILE_IS_TRUNCATED,
    PEFILE_BAD_SIG,
    PEFILE_LONG_RES_NAME,
};

char* pefile_err_to_str(int code);
void pefile_exit(int status, char *errMsg);
void (*pefile_error_handler)(int status, char *errMsg);

#endif
