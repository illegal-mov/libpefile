#ifndef DUMPING_H
#define DUMPING_H

int dump_resource(const struct pefile *cpe, char *args[]);
int dump_certificate(const struct pefile *cpe, char *args[]);
void do_dump(const struct pefile *cpe, char *args[]);

#endif
