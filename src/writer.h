#ifndef PE_WRITER_H
#define PE_WRITER_H

/* Write modifications to pefile struct back to disk
 */
int pefile_save(
    struct pefile *pe,
    const char    *path);

#endif
