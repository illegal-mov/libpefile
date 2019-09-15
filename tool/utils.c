#include <ctype.h>
#include <string.h>

#include "utils.h"

void str_lower(char *str)
{
    for (size_t i=0; str[i] != 0; i++)
        str[i] = tolower(str[i]);
}

char* strip_whitespace(char *str)
{
    /* lstrip */
    while (isspace(*str))
        str++;

    if (*str == 0)
        return str;

    /* rstrip */
    size_t last_printable=0, i=0;
    while (str[i]) {
        if (!isspace(str[i]))
            last_printable = i;
        i++;
    }
    str[++last_printable] = 0;

    return str;
}

