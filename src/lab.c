#include "lab.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
