#ifndef PRINTING_H
#define PRINTING_H

void print_dos(const struct pefile *cpe);
void print_file(const struct pefile *cpe, char *args[]);
void print_optional(const struct pefile *cpe, char *args[]);
void print_section(const struct pefile *cpe, char *args[]);
void print_export(const struct pefile *cpe);
void print_import(const struct pefile *cpe);
void print_resource(const struct pefile *cpe);
void print_exception(const struct pefile *cpe);
void print_certificate(const struct pefile *cpe);
void print_relocation(const struct pefile *cpe);
void print_debug(const struct pefile *cpe);
void print_globalptr(const struct pefile *cpe);
void print_tls(const struct pefile *cpe);
void print_loadconfig(const struct pefile *cpe);
void print_boundimport(const struct pefile *cpe);
void print_iat(const struct pefile *cpe);
void print_delayimport(const struct pefile *cpe);
void print_clr(const struct pefile *cpe);
void do_print(const struct pefile *cpe, char *args[]);

#endif
