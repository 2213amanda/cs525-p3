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
