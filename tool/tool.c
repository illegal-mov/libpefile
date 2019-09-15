#include <stdlib.h>
#include <string.h>

#include "../include/libpefile.h"
#include "dumping.h"
#include "help.h"
#include "printing.h"
#include "utils.h"

#define MAX_WORDS 8

void str_lower(char *str);
char* strip_whitespace(char *str);

void process_command(const struct pefile *cpe)
{
    while (1) {
        printf("\n > ");
        char cmd_buf[64] = {0};
        if (fgets(cmd_buf, sizeof(cmd_buf), stdin) == NULL)
            exit(0);

        if (strlen(cmd_buf) >= sizeof(cmd_buf)-1) {
            fprintf(stderr, "Command string is too long\n");
            // clear stdin
            int tmp;
            while ((tmp = getchar()) != '\n');
            continue;
        }

        // clean up user input
        str_lower(cmd_buf);
        char *cmd = strip_whitespace(cmd_buf);

        if (*cmd == 0)
            continue;

        // parse input string into array of words
        int i=0;
        char *args[MAX_WORDS] = {0};
        if ((args[i++] = strtok(cmd, " ")) != NULL) {
            while ((args[i++] = strtok(NULL, " ")) && i < MAX_WORDS);
        }
        args[MAX_WORDS-1] = NULL;

        // check user's command
        switch (args[0][0]) {
            case 'd':
                do_dump(cpe, args);
                break;
            case 'e':
                exit(0);
                break;
            case 'h':
                do_help(args);
                break;
            case 'p':
                do_print(cpe, args);
                break;
            case 'q':
                exit(0);
                break;
            default:
                fprintf(stderr, "Unknown option '%s'\n", args[0]);
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc <= 1)
        usage(argv[0]);

    char err_buf[PEFILE_ERRBUF_LEN];
    struct pefile cpe;
    pefile_init(&cpe, argv[1], NULL, err_buf);

    intro_msg();
    process_command(&cpe);

    return 0;
}

