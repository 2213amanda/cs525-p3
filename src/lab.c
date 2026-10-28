#define _POSIX_C_SOURCE 200809L

#include "lab.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

struct fwd_table {
    route_t *routes;
    size_t count;
    size_t capacity;
};

#ifdef TEST
void table_test_set_full_capacity(fwd_table_t *table, size_t capacity)
{
    if (table != NULL) {
        table->capacity = capacity;
        table->count = capacity;
    }
}
#endif

bool ip_parse(const char *text, uint32_t *addr)
{
    uint32_t result = 0;
    const char *p;

    if (text == NULL || addr == NULL) {
        return false;
    }

    p = text;

    for (int octet_index = 0; octet_index < 4; octet_index++) {
        unsigned int octet = 0;
        int digits = 0;

        /* Each octet must begin with a decimal digit. */
        if (*p < '0' || *p > '9') {
            return false;
        }

        /* Reject leading zeros, except for the octet "0". */
        if (*p == '0' && p[1] >= '0' && p[1] <= '9') {
            return false;
        }

        /* Parse the octet and reject values greater than 255. */
        while (*p >= '0' && *p <= '9') {
            octet = octet * 10 + (unsigned int)(*p - '0');
            digits++;

            if (octet > 255) {
                return false;
            }

            p++;
        }

        result = (result << 8) | octet;

        if (octet_index < 3) {
            /* The first three octets must end with a period. */
            if (*p != '.') {
                return false;
            }

            p++;
        } else {
            /* No characters may follow the fourth octet. */
            if (*p != '\0') {
                return false;
            }
        }
    }

    *addr = result;
    return true;
}

void ip_format(uint32_t addr, char out[IP_STR_LEN])
{
    if (out == NULL) {
        return;
    }

    snprintf(out, IP_STR_LEN, "%u.%u.%u.%u",
             (unsigned int)((addr >> 24) & 0xFF),
             (unsigned int)((addr >> 16) & 0xFF),
             (unsigned int)((addr >> 8) & 0xFF),
             (unsigned int)(addr & 0xFF));
}

bool cidr_parse(const char *text, cidr_t *block)
{
    uint32_t addr;
    uint32_t prefix = 0;
    const char *slash;
    const char *p;
    cidr_t result;

    if (text == NULL || block == NULL) {
        return false;
    }

    /* Find the slash separating the address and prefix. */
    slash = strchr(text, '/');

    if (slash == NULL) {
        return false;
    }

    /* Reject a second slash. */
    if (strchr(slash + 1, '/') != NULL) {
        return false;
    }

    /*
     * Copy the address portion into a temporary buffer.
     * A dotted quad can contain at most 15 characters.
     */
    size_t addr_len = (size_t)(slash - text);

    if (addr_len == 0 || addr_len >= IP_STR_LEN) {
        return false;
    }

    char addr_text[IP_STR_LEN];
    memcpy(addr_text, text, addr_len);
    addr_text[addr_len] = '\0';

    if (!ip_parse(addr_text, &addr)) {
        return false;
    }

    /* The prefix is required and must start with a digit. */
    p = slash + 1;

    if (*p < '0' || *p > '9') {
        return false;
    }

    /* Reject leading zeros, such as /024. */
    if (*p == '0' && p[1] != '\0') {
        return false;
    }

    /* Parse the prefix, which must be between 0 and 32. */
    while (*p >= '0' && *p <= '9') {
        prefix = prefix * 10 + (uint32_t)(*p - '0');

        if (prefix > 32) {
            return false;
        }

        p++;
    }

    /* Reject trailing characters or whitespace. */
    if (*p != '\0') {
        return false;
    }

    result.addr = addr;
    result.prefix = (uint8_t)prefix;

    /* Modify the output only after successful parsing. */
    *block = result;
    return true;
}

void cidr_format(cidr_t block, char out[CIDR_STR_LEN])
{
    if (out == NULL) {
        return;
    }

    if (block.prefix > 32) {
        block.prefix = 32;
    }

    char addr_text[IP_STR_LEN];
    ip_format(block.addr, addr_text);

    snprintf(out, CIDR_STR_LEN, "%s/%u",
             addr_text, (unsigned int)block.prefix);
}

uint32_t cidr_mask(uint8_t prefix)
{
    if (prefix > 32) {
        prefix = 32;
    }

    if (prefix == 0) {
        return 0;
    }

    return UINT32_MAX << (32 - prefix);
}

uint32_t cidr_network(cidr_t block)
{
    return block.addr & cidr_mask(block.prefix);
}

uint32_t cidr_broadcast(cidr_t block)
{
    return cidr_network(block) | ~cidr_mask(block.prefix);
}

uint32_t cidr_first_host(cidr_t block)
{
    uint32_t network = cidr_network(block);

    if (block.prefix >= 31) {
        return network;
    }

    return network + 1;
}

uint32_t cidr_last_host(cidr_t block)
{
    uint32_t broadcast = cidr_broadcast(block);

    if (block.prefix >= 31) {
        return broadcast;
    }

    return broadcast - 1;
}

uint64_t cidr_host_count(cidr_t block)
{
    uint8_t prefix = block.prefix;

    if (prefix > 32) {
        prefix = 32;
    }

    if (prefix == 32) {
        return 1;
    }

    if (prefix == 31) {
        return 2;
    }

    return (UINT64_C(1) << (32 - prefix)) - 2;
}

bool cidr_contains(cidr_t block, uint32_t addr)
{
    return (addr & cidr_mask(block.prefix)) ==
           cidr_network(block);
}

bool cidr_is_network(cidr_t block)
{
    return block.addr == cidr_network(block);
}

bool cidr_subnet(cidr_t block, uint32_t n, uint32_t i, cidr_t *out)
{
    uint32_t added_bits = 0;
    uint32_t temp;
    uint32_t new_prefix;
    uint64_t subnet_size;
    cidr_t result;

    if (out == NULL) {
        return false;
    }

    if (!cidr_is_network(block)) {
        return false;
    }

    if (n == 0 || (n & (n - 1)) != 0) {
        return false;
    }

    if (i >= n) {
        return false;
    }

    /* Count the bits needed to represent n equal-sized subnets. */
    temp = n;

    while (temp > 1) {
        temp >>= 1;
        added_bits++;
    }

    new_prefix = (uint32_t)block.prefix + added_bits;

    if (new_prefix > 32) {
        return false;
    }

    result.prefix = (uint8_t)new_prefix;

    /* Calculate each subnet's size without 32-bit overflow. */
    subnet_size = UINT64_C(1) << (32 - new_prefix);

    result.addr = block.addr + (uint32_t)((uint64_t)i * subnet_size);

    *out = result;
    return true;
}

bool route_parse(const char *line, route_t *route)
{
    char dest_text[CIDR_STR_LEN];
    char gateway_text[IP_STR_LEN];
    char dev_text[DEV_NAME_LEN];
    char extra;
    cidr_t dest;
    uint32_t gateway;
    route_t result;

    if (line == NULL || route == NULL) {
        return false;
    }

    /*
     * Read exactly three fields. A fourth non-whitespace field
     * makes the line invalid.
     */
    if (sscanf(line, " %18s %15s %15s %c",
               dest_text, gateway_text, dev_text, &extra) != 3) {
        return false;
    }

    /* Parse destination. */
    if (strcmp(dest_text, "default") == 0) {
        dest.addr = 0;
        dest.prefix = 0;
    } else {
        if (!cidr_parse(dest_text, &dest)) {
            return false;
        }

        /* Destinations must be network addresses. */
        if (!cidr_is_network(dest)) {
            return false;
        }
    }

    /* Parse gateway. */
    if (strcmp(gateway_text, "direct") == 0) {
        gateway = 0;
    } else {
        if (!ip_parse(gateway_text, &gateway)) {
            return false;
        }
    }

    /* Build the result locally to leave *route unchanged on failure. */
    result.dest = dest;
    result.gateway = gateway;
    strcpy(result.dev, dev_text);

    *route = result;
    return true;
}

fwd_table_t *table_create(void)
{
    fwd_table_t *table = malloc(sizeof(*table));

    // GCOVR_EXCL_START
    if (table == NULL) {
        return NULL;
    }
    // GCOVR_EXCL_STOP

    table->routes = NULL;
    table->count = 0;
    table->capacity = 0;

    return table;
}

void table_destroy(fwd_table_t *table)
{
    if (table == NULL) {
        return;
    }

    free(table->routes);
    free(table);
}

size_t table_count(const fwd_table_t *table)
{
    if (table == NULL) {
        return 0;
    }

    return table->count;
}

bool table_add(fwd_table_t *table, const route_t *route)
{
    if (table == NULL || route == NULL) {
        return false;
    }

    /* Validate the destination prefix and network address. */
    if (route->dest.prefix > 32 || !cidr_is_network(route->dest)) {
        return false;
    }

    /* Calculate the new capacity if the table is full. */
    size_t new_capacity = 0;

    if (table->count == table->capacity) {
        if (table->capacity == 0) {
            new_capacity = 4;
        } else {
            if (table->capacity > SIZE_MAX / 2) {
                return false;
            }

            new_capacity = table->capacity * 2;

            if (new_capacity > SIZE_MAX / sizeof(*table->routes)) {
                return false;
            }
        }
    }

    /* Reject duplicate destination networks. */
    for (size_t i = 0; i < table->count; i++) {
        if (table->routes[i].dest.addr == route->dest.addr &&
            table->routes[i].dest.prefix == route->dest.prefix) {
            return false;
        }
    }

    /* Grow the route array if necessary. */
    if (table->count == table->capacity) {
        route_t *new_routes = realloc(
            table->routes,
            new_capacity * sizeof(*table->routes)
        );

        //GCOVR_EXCL_START
        if (new_routes == NULL) {
            return false;
        }
        //GCOVR_EXCL_STOP

        table->routes = new_routes;
        table->capacity = new_capacity;
    }

    /* Add the route. */
    table->routes[table->count] = *route;
    table->count++;

    return true;
}

bool table_load(fwd_table_t *table, FILE *in, size_t *bad_line)
{
    char *line = NULL;
    size_t line_capacity = 0;
    size_t line_number = 0;
    ssize_t length;
    bool success = true;

    if (bad_line != NULL) {
        *bad_line = 0;
    }

    if (table == NULL || in == NULL) {
        return false;
    }

    while ((length = getline(&line, &line_capacity, in)) != -1) {
        char *comment;
        char *p;
        route_t route;

        (void)length;
        line_number++;

        /* Remove comments. */
        comment = strchr(line, '#');
        if (comment != NULL) {
            *comment = '\0';
        }

        /* Skip whitespace-only lines. */
        p = line;
        while (isspace((unsigned char)*p)) {
            p++;
        }

        if (*p == '\0') {
            continue;
        }

        /* Parse and add the route. */
        if (!route_parse(p, &route) ||
            !table_add(table, &route)) {
            if (bad_line != NULL) {
                *bad_line = line_number;
            }

            success = false;
            break;
        }
    }

    /* A read error is also a failure. */
    // GCOVR_EXCL_START
    if (ferror(in)) {
        success = false;

        if (bad_line != NULL) {
            *bad_line = 0;
        }
    }
    // GCOVR_EXCL_STOP

    free(line);
    return success;
}

const route_t *table_lookup(const fwd_table_t *table, uint32_t dest)
{
    const route_t *best = NULL;
    uint8_t best_prefix = 0;
    size_t i;

    if (table == NULL) {
        return NULL;
    }

    for (i = 0; i < table->count; i++) {
        const route_t *route = &table->routes[i];

        if (!cidr_contains(route->dest, dest)) {
            continue;
        }

        if (best == NULL || route->dest.prefix > best_prefix) {
            best = route;
            best_prefix = route->dest.prefix;
        }
    }

    return best;
}


