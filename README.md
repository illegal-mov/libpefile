# libpefile
A simple library to parse headers and directories in PE files

## Examples

### Initialization

Before you can analyze a PE file, you must initialize the relevant data structure with a call to `pefile_init`

```
#include "./include/libpefile.h"

char err_buf[PEFILE_ERRBUF_LEN];
struct pefile pe;
pefile_init(&pe, "FILE.exe", NULL, err_buf);
```

**Parameters**

1. Pointer to a `struct pefile`
2. Path of the PE file to open
3. Optional pointer to an error handler function with signature `void (*fp)(int err_code, char *err_msg)`
4. Pointer to char array to hold an error message

### Printing Tables

All the following examples assume the sample code under "Initialization" has been used.

### Exports

Exports are functions a DLL may make available to clients.

```
puts("ORDS | CODE | NORDS | NAMES | NAME");
for (int i=0; i < pe.xprt->addrs_len; i++) {
    printf("%08x | %08x | %04x | %08x | %s\n",
        pe.xprt->addrs[i].code_rva,
        pe.xprt->addrs[i].code_apa,
        pe.xprt->nords[i],
        pe.xprt->names[i].name_rva,
        pe.xprt->names[i].name);
}
```

### Imports

Imports are functions included in a program via a DLL.

```
```

---

### Dumping Data

```
```

