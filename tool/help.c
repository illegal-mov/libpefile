#include <stdio.h>
#include <stdlib.h>

#include "help.h"

void intro_msg()
{
    puts("==INTERACTIVE PE PARSER TOOL==");
    puts("Help            - View the help menu");
    puts("Exit|Quit       - Close the program\n");
    puts("Use \"Help <COMMAND>\" for more detailed info on a command");
}

void usage(const char *argv0)
{
    printf("Usage: %s BINARY\n", argv0);
    exit(0);
}

void usage_do_print()
{
    puts("Usage: `print <HEADER> [<ARGS>]`\n");
    puts("<HEADER> is one of the following:");
    puts("\tdos");
    puts("\tfile");
    puts("\toptional");
    puts("\tsection <NUM>");
    puts("\texport");
    puts("\timport");
    puts("\tresource");
    puts("\texception");
    puts("\tcertificate");
    puts("\trelocation");
    puts("\tdebug");
    puts("\tglobalptr");
    puts("\ttls");
    puts("\tloadconfig");
    puts("\tboundimport");
    puts("\tiat");
    puts("\tdelayimport");
    puts("\tclr");
}

void usage_do_dump()
{
    puts("Usage: `dump <OBJECT> <FILE>`\n");
}

void do_help(char *args[])
{
    if (args[1] == NULL || args[1][0] == 0) {
        puts("Help  <COMMAND>       - View a help menu");
        puts("Print <HEADER>        - Print the named header");
        //puts("Dump  <OBJECT> <FILE> - Dump the object to file");
        puts("Exit|Quit             - Close the program\n");
        return;
    }

    switch (args[1][0]) {
        case 'p':
            usage_do_print();
            break;
        case 'd':
            usage_do_dump();
            break;
    }
}

