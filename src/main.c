#include "lab.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef TEST
#define main main_exclude
#endif



int main(int argc, char **argv)
{
    if (argc == 1) {
        printf("Usage: myapp info <address>/<prefix>\n"
               "       myapp split <network>/<prefix> <count>\n"
               "       myapp lookup <table-file> <address>...\n");
        return 0;
    }

    /* Task 4.1: info */
    if (strcmp(argv[1], "info") == 0) {
        if (argc != 3) {
            fprintf(stderr,
                    "myapp: info requires exactly one CIDR argument\n");
            return 1;
        }

        cidr_t block;
        if (!cidr_parse(argv[2], &block)) {
            fprintf(stderr, "myapp: invalid CIDR address: %s\n", argv[2]);
            return 1;
        }

        char address[IP_STR_LEN];
        char mask[IP_STR_LEN];
        char network[IP_STR_LEN];
        char broadcast[IP_STR_LEN];
        char first[IP_STR_LEN];
        char last[IP_STR_LEN];

        ip_format(block.addr, address);
        ip_format(cidr_mask(block.prefix), mask);
        ip_format(cidr_network(block), network);
        ip_format(cidr_broadcast(block), broadcast);
        ip_format(cidr_first_host(block), first);
        ip_format(cidr_last_host(block), last);

        printf("address    %s\n", address);
        printf("prefix     /%u\n", (unsigned)block.prefix);
        printf("netmask    %s\n", mask);
        printf("network    %s\n", network);
        printf("broadcast  %s\n", broadcast);
        printf("first host %s\n", first);
        printf("last host  %s\n", last);
        printf("hosts      %" PRIu64 "\n", cidr_host_count(block));

        return 0;
    }

    /* Task 4.2: split */
    if (strcmp(argv[1], "split") == 0) {
        if (argc != 4) {
            fprintf(stderr,
                    "myapp: split requires a CIDR argument and a count\n");
            return 1;
        }

        cidr_t block;
        if (!cidr_parse(argv[2], &block)) {
            fprintf(stderr, "myapp: invalid CIDR address: %s\n", argv[2]);
            return 1;
        }

        if (!cidr_is_network(block)) {
            fprintf(stderr, "myapp: split address is not a network: %s\n",
                    argv[2]);
            return 1;
        }

        /* Parse count as a positive decimal integer. */
        const char *count_text = argv[3];
        if (*count_text == '\0') {
            fprintf(stderr, "myapp: invalid subnet count: %s\n", argv[3]);
            return 1;
        }

        for (const char *p = count_text; *p != '\0'; ++p) {
            if (*p < '0' || *p > '9') {
                fprintf(stderr, "myapp: invalid subnet count: %s\n",
                        argv[3]);
                return 1;
            }
        }

        errno = 0;
        char *end = NULL;
        unsigned long parsed_count = strtoul(count_text, &end, 10);

        if (errno == ERANGE || end == count_text || *end != '\0' ||
            parsed_count == 0 || parsed_count > UINT32_MAX) {
            fprintf(stderr, "myapp: invalid subnet count: %s\n", argv[3]);
            return 1;
        }

        uint32_t count = (uint32_t)parsed_count;

        /* A valid count must be a power of two. */
        if ((count & (count - 1)) != 0) {
            fprintf(stderr,
                    "myapp: subnet count must be a power of two\n");
            return 1;
        }

        /* Check that the resulting prefix does not exceed 32. */
        uint32_t extra_prefix = 0;
        for (uint32_t n = count; n > 1; n >>= 1) {
            ++extra_prefix;
        }

        if ((uint32_t)block.prefix + extra_prefix > 32) {
            fprintf(stderr,
                    "myapp: split would require a prefix longer than 32\n");
            return 1;
        }

        for (uint32_t i = 0; i < count; ++i) {
            cidr_t subnet;

            if (!cidr_subnet(block, count, i, &subnet)) {
                fprintf(stderr,
                        "myapp: unable to calculate subnet %" PRIu32 "\n",
                        i);
                return 1;
            }

            char formatted[CIDR_STR_LEN];
            cidr_format(subnet, formatted);
            printf("%s\n", formatted);
        }

        return 0;
    }

    /* Task 4.3: lookup */
    if (strcmp(argv[1], "lookup") == 0) {
        if (argc < 4) {
            fprintf(stderr,
                    "myapp: lookup requires a table file and at least one address\n");
            return 1;
        }

        const char *filename = argv[2];
        FILE *in = fopen(filename, "r");

        if (in == NULL) {
            fprintf(stderr, "myapp: cannot open %s: %s\n",
                    filename, strerror(errno));
            return 2;
        }

        fwd_table_t *table = table_create();
        if (table == NULL) {
            fprintf(stderr, "myapp: cannot allocate forwarding table\n");
            fclose(in);
            return 2;
        }

        size_t bad_line = 0;

        if (!table_load(table, in, &bad_line)) {
            if (bad_line != 0) {
                fprintf(stderr, "myapp: %s:%zu: not a valid route\n",
                        filename, bad_line);
            } else {
                fprintf(stderr, "myapp: could not read table file %s\n",
                        filename);
            }

            table_destroy(table);
            fclose(in);
            return 2;
        }

        if (fclose(in) != 0) {
            fprintf(stderr, "myapp: could not close table file %s: %s\n",
                    filename, strerror(errno));
            table_destroy(table);
            return 2;
        }

        int malformed = 0;
        int unreachable = 0;

        for (int i = 3; i < argc; ++i) {
            uint32_t addr;

            if (!ip_parse(argv[i], &addr)) {
                fprintf(stderr, "myapp: invalid address: %s\n", argv[i]);
                malformed = 1;
                continue;
            }

            const route_t *route = table_lookup(table, addr);

            if (route == NULL) {
                printf("%s unreachable\n", argv[i]);
                unreachable = 1;
                continue;
            }

            if (route->gateway != 0) {
                char gateway[IP_STR_LEN];
                ip_format(route->gateway, gateway);

                printf("%s via %s dev %s\n",
                       argv[i], gateway, route->dev);
            } else {
                printf("%s dev %s\n", argv[i], route->dev);
            }
        }

        table_destroy(table);

        if (malformed) {
            return 1;
        }

        if (unreachable) {
            return 3;
        }

        return 0;
    }

    fprintf(stderr, "myapp: unknown command: %s\n", argv[1]);
    printf("Usage: myapp info <address>/<prefix>\n"
           "       myapp split <network>/<prefix> <count>\n"
           "       myapp lookup <table-file> <address>...\n");

    return 1;
}