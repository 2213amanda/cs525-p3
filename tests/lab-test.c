#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "harness/unity.h"
#include "../src/lab.h"

#ifdef TEST
void table_test_set_full_capacity(fwd_table_t *table, size_t capacity);
#endif

void setUp(void) {
  printf("Setting up tests...\n");
}

void tearDown(void) {
  printf("Tearing down tests...\n");
}

// ip_parse tests

void test_ip_parse_null_text(void)
{
    uint32_t addr = 0x12345678;

    TEST_ASSERT_FALSE(ip_parse(NULL, &addr));
    TEST_ASSERT_EQUAL_HEX32(0x12345678, addr);
}

void test_ip_parse_null_addr(void)
{
    TEST_ASSERT_FALSE(ip_parse("192.168.1.10", NULL));
}

void test_ip_parse_empty_string(void)
{
    uint32_t addr = 0;

    TEST_ASSERT_FALSE(ip_parse("", &addr));
}

void test_ip_parse_first_character_not_digit(void)
{
    uint32_t addr = 0;

    TEST_ASSERT_FALSE(ip_parse("a.1.2.3", &addr));
    TEST_ASSERT_FALSE(ip_parse("+1.2.3.4", &addr));
    TEST_ASSERT_FALSE(ip_parse("-1.2.3.4", &addr));
}

void test_ip_parse_leading_zero(void)
{
    uint32_t addr = 0;

    /* Leading-zero condition is true. */
    TEST_ASSERT_FALSE(ip_parse("01.2.3.4", &addr));

    /* Leading-zero condition is false for a single zero. */
    TEST_ASSERT_TRUE(ip_parse("0.2.3.4", &addr));
    TEST_ASSERT_EQUAL_HEX32(0x00020304, addr);
}

void test_ip_parse_octet_exceeds_255(void)
{
    uint32_t addr = 0;

    /* Overflow check becomes true while parsing the first octet. */
    TEST_ASSERT_FALSE(ip_parse("256.1.1.1", &addr));

    /* Overflow check becomes true in a later octet. */
    TEST_ASSERT_FALSE(ip_parse("1.2.300.4", &addr));

    /* Boundary values do not trigger the overflow check. */
    TEST_ASSERT_TRUE(ip_parse("255.255.255.255", &addr));
    TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, addr);
}

void test_ip_parse_missing_octet(void)
{
    uint32_t addr = 0;

    /* Initial digit check fails for the second octet. */
    TEST_ASSERT_FALSE(ip_parse("1..2.3", &addr));

    /* Initial digit check fails for the fourth octet. */
    TEST_ASSERT_FALSE(ip_parse("1.2.3.", &addr));
}

void test_ip_parse_missing_period(void)
{
    uint32_t addr = 0;

    /* The expected period is missing after the first octet. */
    TEST_ASSERT_FALSE(ip_parse("1x.2.3.4", &addr));

    /* The expected period is missing after the second octet. */
    TEST_ASSERT_FALSE(ip_parse("1.2x.3.4", &addr));
}

void test_ip_parse_extra_period(void)
{
    uint32_t addr = 0;

    /* Extra period after the fourth octet. */
    TEST_ASSERT_FALSE(ip_parse("1.2.3.4.5", &addr));
}

void test_ip_parse_trailing_characters(void)
{
    uint32_t addr = 0;

    /* Final null-terminator check fails. */
    TEST_ASSERT_FALSE(ip_parse("1.2.3.4x", &addr));
    TEST_ASSERT_FALSE(ip_parse("1.2.3.4 ", &addr));
    TEST_ASSERT_FALSE(ip_parse("1.2.3.4/24", &addr));
}

void test_ip_parse_valid_address(void)
{
    uint32_t addr = 0;

    TEST_ASSERT_TRUE(ip_parse("192.168.1.10", &addr));
    TEST_ASSERT_EQUAL_HEX32(0xC0A8010A, addr);
}

void test_ip_parse_output_unchanged_on_failure(void)
{
    uint32_t addr = 0x12345678;

    TEST_ASSERT_FALSE(ip_parse("256.1.1.1", &addr));
    TEST_ASSERT_EQUAL_HEX32(0x12345678, addr);

    TEST_ASSERT_FALSE(ip_parse("1.2.3", &addr));
    TEST_ASSERT_EQUAL_HEX32(0x12345678, addr);
}

// ip_format tests

void test_ip_format_null_output(void)
{
    /*
     * Covers the true branch:
     * if (out == NULL)
     */
    ip_format(0xC0A8010A, NULL);
}

void test_ip_format_zero_address(void)
{
    char out[IP_STR_LEN];

    /*
     * Covers the false branch of out == NULL.
     */
    ip_format(0x00000000, out);

    TEST_ASSERT_EQUAL_STRING("0.0.0.0", out);
}

void test_ip_format_broadcast_address(void)
{
    char out[IP_STR_LEN];

    ip_format(0xFFFFFFFF, out);

    TEST_ASSERT_EQUAL_STRING("255.255.255.255", out);
}

void test_ip_format_typical_address(void)
{
    char out[IP_STR_LEN];

    ip_format(0xC0A8010A, out);

    TEST_ASSERT_EQUAL_STRING("192.168.1.10", out);
}

void test_ip_format_single_digit_octets(void)
{
    char out[IP_STR_LEN];

    ip_format(0x01020304, out);

    TEST_ASSERT_EQUAL_STRING("1.2.3.4", out);
}

void test_ip_format_mixed_octet_sizes(void)
{
    char out[IP_STR_LEN];

    ip_format(0x0A00FF01, out);

    TEST_ASSERT_EQUAL_STRING("10.0.255.1", out);
}

// cidr_parse tests

void test_cidr_parse_null_text(void)
{
    cidr_t block = {0x12345678, 12};
    cidr_t original = block;

    TEST_ASSERT_FALSE(cidr_parse(NULL, &block));
    TEST_ASSERT_EQUAL_HEX32(original.addr, block.addr);
    TEST_ASSERT_EQUAL_UINT8(original.prefix, block.prefix);
}

void test_cidr_parse_null_block(void)
{
    TEST_ASSERT_FALSE(cidr_parse("192.168.1.0/24", NULL));
}

/* Slash validation. */

void test_cidr_parse_missing_slash(void)
{
    cidr_t block = {0};

    TEST_ASSERT_FALSE(cidr_parse("192.168.1.0", &block));
}

void test_cidr_parse_multiple_slashes(void)
{
    cidr_t block = {0};

    TEST_ASSERT_FALSE(cidr_parse("192.168.1.0/24/25", &block));
}

/* Address substring length validation. */

void test_cidr_parse_empty_address(void)
{
    cidr_t block = {0};

    /* addr_len == 0 */
    TEST_ASSERT_FALSE(cidr_parse("/24", &block));
}

void test_cidr_parse_address_too_long(void)
{
    cidr_t block = {0};

    /* addr_len >= IP_STR_LEN */
    TEST_ASSERT_FALSE(cidr_parse("1234567890123456/24", &block));
}

/* Address parsing. */

void test_cidr_parse_invalid_address(void)
{
    cidr_t block = {0};

    /* The embedded ip_parse() call returns false. */
    TEST_ASSERT_FALSE(cidr_parse("256.1.1.1/24", &block));
    TEST_ASSERT_FALSE(cidr_parse("1.2.3/24", &block));
}

void test_cidr_parse_valid_address(void)
{
    cidr_t block = {0};

    /* The embedded ip_parse() call returns true. */
    TEST_ASSERT_TRUE(cidr_parse("192.168.1.0/24", &block));
    TEST_ASSERT_EQUAL_HEX32(0xC0A80100, block.addr);
    TEST_ASSERT_EQUAL_UINT8(24, block.prefix);
}

/* Prefix initial-character validation. */

void test_cidr_parse_prefix_not_digit(void)
{
    cidr_t block = {0};

    TEST_ASSERT_FALSE(cidr_parse("192.168.1.0/x", &block));
    TEST_ASSERT_FALSE(cidr_parse("192.168.1.0/-1", &block));
    TEST_ASSERT_FALSE(cidr_parse("192.168.1.0/", &block));
}

/* Leading-zero validation. */

void test_cidr_parse_prefix_leading_zero(void)
{
    cidr_t block = {0};

    /* *p == '0' and p[1] != '\0': true */
    TEST_ASSERT_FALSE(cidr_parse("192.168.1.0/024", &block));

    /* *p == '0' and p[1] != '\0': false */
    TEST_ASSERT_TRUE(cidr_parse("192.168.1.0/0", &block));

    /* *p == '0': false */
    TEST_ASSERT_TRUE(cidr_parse("192.168.1.0/24", &block));
}

/* Prefix digit loop and range validation. */

void test_cidr_parse_prefix_over_32(void)
{
    cidr_t block = {0};

    /* prefix > 32 becomes true. */
    TEST_ASSERT_FALSE(cidr_parse("192.168.1.0/33", &block));
    TEST_ASSERT_FALSE(cidr_parse("192.168.1.0/99", &block));
}

void test_cidr_parse_prefix_loop_multiple_digits(void)
{
    cidr_t block = {0};

    /*
     * The digit loop iterates multiple times, then stops at '\0'.
     * The prefix remains within range.
     */
    TEST_ASSERT_TRUE(cidr_parse("192.168.1.0/32", &block));
    TEST_ASSERT_EQUAL_UINT8(32, block.prefix);
}

void test_cidr_parse_prefix_zero(void)
{
    cidr_t block = {0};

    /*
     * Exercises a single-digit prefix of zero.
     * The digit loop stops immediately after consuming '0'.
     */
    TEST_ASSERT_TRUE(cidr_parse("0.0.0.0/0", &block));
    TEST_ASSERT_EQUAL_UINT8(0, block.prefix);
}

/* Trailing-character validation. */

void test_cidr_parse_trailing_characters(void)
{
    cidr_t block = {0};

    /* *p != '\0' becomes true. */
    TEST_ASSERT_FALSE(cidr_parse("192.168.1.0/24x", &block));
    TEST_ASSERT_FALSE(cidr_parse("192.168.1.0/24 ", &block));
    TEST_ASSERT_FALSE(cidr_parse("192.168.1.0/24.0", &block));
}

void test_cidr_parse_no_trailing_characters(void)
{
    cidr_t block = {0};

    /* *p != '\0' becomes false. */
    TEST_ASSERT_TRUE(cidr_parse("10.0.0.1/8", &block));
    TEST_ASSERT_EQUAL_HEX32(0x0A000001, block.addr);
    TEST_ASSERT_EQUAL_UINT8(8, block.prefix);
}

/* Output must remain unchanged on failure. */

void test_cidr_parse_output_unchanged_on_failure(void)
{
    cidr_t block = {0x12345678, 12};

    TEST_ASSERT_FALSE(cidr_parse("192.168.1.0/33", &block));
    TEST_ASSERT_EQUAL_HEX32(0x12345678, block.addr);
    TEST_ASSERT_EQUAL_UINT8(12, block.prefix);

    TEST_ASSERT_FALSE(cidr_parse("192.168.1.0/024", &block));
    TEST_ASSERT_EQUAL_HEX32(0x12345678, block.addr);
    TEST_ASSERT_EQUAL_UINT8(12, block.prefix);
}

/* Host bits are permitted in parsed CIDR addresses. */

void test_cidr_parse_host_bits_set(void)
{
    cidr_t block = {0};

    TEST_ASSERT_TRUE(cidr_parse("132.178.227.11/25", &block));
    TEST_ASSERT_EQUAL_HEX32(0x84B2E30B, block.addr);
    TEST_ASSERT_EQUAL_UINT8(25, block.prefix);
}

//cidr_format tests

void test_cidr_format_null_output(void)
{
    cidr_t block = {0xC0A8010A, 24};

    /* Covers out == NULL: true branch. */
    cidr_format(block, NULL);
}

void test_cidr_format_prefix_within_range(void)
{
    char out[CIDR_STR_LEN];
    cidr_t block = {0xC0A8010A, 24};

    /* Covers block.prefix > 32: false branch. */
    cidr_format(block, out);

    TEST_ASSERT_EQUAL_STRING("192.168.1.10/24", out);
}

void test_cidr_format_prefix_zero(void)
{
    char out[CIDR_STR_LEN];
    cidr_t block = {0x00000000, 0};

    cidr_format(block, out);

    TEST_ASSERT_EQUAL_STRING("0.0.0.0/0", out);
}

void test_cidr_format_prefix_32(void)
{
    char out[CIDR_STR_LEN];
    cidr_t block = {0xFFFFFFFF, 32};

    cidr_format(block, out);

    TEST_ASSERT_EQUAL_STRING("255.255.255.255/32", out);
}

void test_cidr_format_prefix_above_32(void)
{
    char out[CIDR_STR_LEN];
    cidr_t block = {0xC0A8010A, 33};

    /* Covers block.prefix > 32: true branch. */
    cidr_format(block, out);

    TEST_ASSERT_EQUAL_STRING("192.168.1.10/32", out);
}

void test_cidr_format_large_prefix_clamped_to_32(void)
{
    char out[CIDR_STR_LEN];
    cidr_t block = {0x0A000001, 255};

    cidr_format(block, out);

    TEST_ASSERT_EQUAL_STRING("10.0.0.1/32", out);
}

void test_cidr_format_preserves_host_bits(void)
{
    char out[CIDR_STR_LEN];
    cidr_t block = {0x84B2E30B, 25};

    /* Formatting must not change the stored address to the network address. */
    cidr_format(block, out);

    TEST_ASSERT_EQUAL_STRING("132.178.227.11/25", out);
}

//cidr_mask tests

void test_cidr_mask_prefix_zero(void)
{
    /* Covers prefix == 0: true branch. */
    TEST_ASSERT_EQUAL_HEX32(0x00000000, cidr_mask(0));
}

void test_cidr_mask_prefix_one(void)
{
    /* Covers prefix > 32: false, prefix == 0: false. */
    TEST_ASSERT_EQUAL_HEX32(0x80000000, cidr_mask(1));
}

void test_cidr_mask_prefix_eight(void)
{
    TEST_ASSERT_EQUAL_HEX32(0xFF000000, cidr_mask(8));
}

void test_cidr_mask_prefix_sixteen(void)
{
    TEST_ASSERT_EQUAL_HEX32(0xFFFF0000, cidr_mask(16));
}

void test_cidr_mask_prefix_twenty_four(void)
{
    TEST_ASSERT_EQUAL_HEX32(0xFFFFFF00, cidr_mask(24));
}

void test_cidr_mask_prefix_thirty_one(void)
{
    TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFE, cidr_mask(31));
}

void test_cidr_mask_prefix_thirty_two(void)
{
    /* Covers prefix == 0: false and the maximum valid prefix. */
    TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, cidr_mask(32));
}

void test_cidr_mask_prefix_above_thirty_two(void)
{
    /* Covers prefix > 32: true branch. */
    TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, cidr_mask(33));
    TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, cidr_mask(255));
}

//cidr_network tests

void test_cidr_network_typical_subnet(void)
{
    cidr_t block = {0xC0A80164, 24}; /* 192.168.1.100/24 */

    TEST_ASSERT_EQUAL_HEX32(0xC0A80100, cidr_network(block));
}

void test_cidr_network_prefix_zero(void)
{
    cidr_t block = {0xC0A80164, 0};

    TEST_ASSERT_EQUAL_HEX32(0x00000000, cidr_network(block));
}

void test_cidr_network_prefix_thirty_two(void)
{
    cidr_t block = {0xC0A80164, 32};

    TEST_ASSERT_EQUAL_HEX32(0xC0A80164, cidr_network(block));
}

void test_cidr_network_host_bits_already_zero(void)
{
    cidr_t block = {0xC0A80100, 24};

    TEST_ASSERT_EQUAL_HEX32(0xC0A80100, cidr_network(block));
}


// cidr_broadcast tests

void test_cidr_broadcast_typical_subnet(void)
{
    cidr_t block = {0xC0A80164, 24}; /* 192.168.1.100/24 */

    TEST_ASSERT_EQUAL_HEX32(0xC0A801FF, cidr_broadcast(block));
}

void test_cidr_broadcast_prefix_zero(void)
{
    cidr_t block = {0xC0A80164, 0};

    TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, cidr_broadcast(block));
}

void test_cidr_broadcast_prefix_thirty_two(void)
{
    cidr_t block = {0xC0A80164, 32};

    TEST_ASSERT_EQUAL_HEX32(0xC0A80164, cidr_broadcast(block));
}

void test_cidr_broadcast_prefix_thirty_one(void)
{
    cidr_t block = {0xC0A80164, 31};

    TEST_ASSERT_EQUAL_HEX32(0xC0A80165, cidr_broadcast(block));
}


// cidr_first_host tests

void test_cidr_first_host_typical_subnet(void)
{
    cidr_t block = {0xC0A80164, 24};

    /* Network is 192.168.1.0; first usable host is .1. */
    TEST_ASSERT_EQUAL_HEX32(0xC0A80101, cidr_first_host(block));
}

void test_cidr_first_host_prefix_zero(void)
{
    cidr_t block = {0xC0A80164, 0};

    /* /0 uses the ordinary network + 1 branch. */
    TEST_ASSERT_EQUAL_HEX32(0x00000001, cidr_first_host(block));
}

void test_cidr_first_host_prefix_thirty_one(void)
{
    cidr_t block = {0xC0A80164, 31};

    /* /31: both addresses are usable. */
    TEST_ASSERT_EQUAL_HEX32(0xC0A80164, cidr_first_host(block));
}

void test_cidr_first_host_prefix_thirty_two(void)
{
    cidr_t block = {0xC0A80164, 32};

    /* /32: the single address is the first host. */
    TEST_ASSERT_EQUAL_HEX32(0xC0A80164, cidr_first_host(block));
}


// cidr_last_host tests

void test_cidr_last_host_typical_subnet(void)
{
    cidr_t block = {0xC0A80164, 24};

    /* Broadcast is 192.168.1.255; last usable host is .254. */
    TEST_ASSERT_EQUAL_HEX32(0xC0A801FE, cidr_last_host(block));
}

void test_cidr_last_host_prefix_zero(void)
{
    cidr_t block = {0xC0A80164, 0};

    /* /0 uses the ordinary broadcast - 1 branch. */
    TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFE, cidr_last_host(block));
}

void test_cidr_last_host_prefix_thirty_one(void)
{
    cidr_t block = {0xC0A80164, 31};

    /* /31: the broadcast address is also usable. */
    TEST_ASSERT_EQUAL_HEX32(0xC0A80165, cidr_last_host(block));
}

void test_cidr_last_host_prefix_thirty_two(void)
{
    cidr_t block = {0xC0A80164, 32};

    /* /32: the single address is the last host. */
    TEST_ASSERT_EQUAL_HEX32(0xC0A80164, cidr_last_host(block));
}

// cidr_host_count tests

/* prefix > 32: false; prefix == 32: false; prefix == 31: false */
void test_cidr_host_count_prefix_zero(void)
{
    cidr_t block = {0x00000000, 0};

    /* 2^32 addresses, minus network and broadcast. */
    TEST_ASSERT_EQUAL_UINT64(4294967294ULL,
                             cidr_host_count(block));
}

/* Ordinary subnet: exercises the general calculation. */
void test_cidr_host_count_prefix_twenty_four(void)
{
    cidr_t block = {0xC0A80100, 24};

    TEST_ASSERT_EQUAL_UINT64(254, cidr_host_count(block));
}

/* prefix == 31: true */
void test_cidr_host_count_prefix_thirty_one(void)
{
    cidr_t block = {0xC0A80100, 31};

    TEST_ASSERT_EQUAL_UINT64(2, cidr_host_count(block));
}

/* prefix == 32: true */
void test_cidr_host_count_prefix_thirty_two(void)
{
    cidr_t block = {0xC0A80101, 32};

    TEST_ASSERT_EQUAL_UINT64(1, cidr_host_count(block));
}

/* prefix > 32: true; clamped to 32, then prefix == 32: true */
void test_cidr_host_count_prefix_above_thirty_two(void)
{
    cidr_t block = {0xC0A80101, 33};

    TEST_ASSERT_EQUAL_UINT64(1, cidr_host_count(block));
}

/* Also test the largest possible uint8_t prefix value. */
void test_cidr_host_count_prefix_maximum(void)
{
    cidr_t block = {0xC0A80101, 255};

    TEST_ASSERT_EQUAL_UINT64(1, cidr_host_count(block));
}

// cidr_contains tests

/* Address is inside the subnet. */
void test_cidr_contains_address_inside_subnet(void)
{
    cidr_t block = {0xC0A80164, 24}; /* 192.168.1.100/24 */

    TEST_ASSERT_TRUE(cidr_contains(block, 0xC0A80101));
}

/* Address equals the network address. */
void test_cidr_contains_network_address(void)
{
    cidr_t block = {0xC0A80100, 24};

    TEST_ASSERT_TRUE(cidr_contains(block, 0xC0A80100));
}

/* Address equals the broadcast address. */
void test_cidr_contains_broadcast_address(void)
{
    cidr_t block = {0xC0A80100, 24};

    TEST_ASSERT_TRUE(cidr_contains(block, 0xC0A801FF));
}

/* Address is outside the subnet: comparison evaluates false. */
void test_cidr_contains_address_outside_subnet(void)
{
    cidr_t block = {0xC0A80100, 24};

    TEST_ASSERT_FALSE(cidr_contains(block, 0xC0A80201));
}

/* /0 contains every IPv4 address. */
void test_cidr_contains_prefix_zero(void)
{
    cidr_t block = {0xC0A80100, 0};

    TEST_ASSERT_TRUE(cidr_contains(block, 0xFFFFFFFF));
}

/* /32 contains only its one exact address. */
void test_cidr_contains_prefix_thirty_two(void)
{
    cidr_t block = {0xC0A80101, 32};

    TEST_ASSERT_TRUE(cidr_contains(block, 0xC0A80101));
    TEST_ASSERT_FALSE(cidr_contains(block, 0xC0A80102));
}

// cidr_is_network tests

/* Address already equals the network address. */
void test_cidr_is_network_true(void)
{
    cidr_t block = {0xC0A80100, 24}; /* 192.168.1.0/24 */

    TEST_ASSERT_TRUE(cidr_is_network(block));
}

/* Host bits are set, so this is not a network address. */
void test_cidr_is_network_false(void)
{
    cidr_t block = {0xC0A80164, 24}; /* 192.168.1.100/24 */

    TEST_ASSERT_FALSE(cidr_is_network(block));
}

/* Every address is aligned for a /0 network. */
void test_cidr_is_network_prefix_zero(void)
{
    cidr_t block = {0x00000000, 0};

    TEST_ASSERT_TRUE(cidr_is_network(block));
}

void test_cidr_is_network_prefix_zero_with_host_bits(void)
{
    cidr_t block = {0xC0A80164, 0};

    TEST_ASSERT_FALSE(cidr_is_network(block));
}

/* Every address is a valid /32 network. */
void test_cidr_is_network_prefix_thirty_two(void)
{
    cidr_t block = {0xC0A80164, 32};

    TEST_ASSERT_TRUE(cidr_is_network(block));
}

/* /31 network address must have its lowest bit clear. */
void test_cidr_is_network_prefix_thirty_one_true(void)
{
    cidr_t block = {0xC0A80164, 31};

    TEST_ASSERT_TRUE(cidr_is_network(block));
}

void test_cidr_is_network_prefix_thirty_one_false(void)
{
    cidr_t block = {0xC0A80165, 31};

    TEST_ASSERT_FALSE(cidr_is_network(block));
}

// cidr_subnet tests

/* out == NULL: true */
void test_cidr_subnet_null_output(void)
{
    cidr_t block = {0xC0A80000, 16};

    TEST_ASSERT_FALSE(cidr_subnet(block, 4, 0, NULL));
}

/* Input address has host bits set: network validation fails. */
void test_cidr_subnet_input_not_network(void)
{
    cidr_t block = {0xC0A80101, 24};
    cidr_t out = {0x12345678, 12};
    cidr_t original = out;

    TEST_ASSERT_FALSE(cidr_subnet(block, 4, 0, &out));
    TEST_ASSERT_EQUAL_HEX32(original.addr, out.addr);
    TEST_ASSERT_EQUAL_UINT8(original.prefix, out.prefix);
}

/* n == 0: true */
void test_cidr_subnet_zero_count(void)
{
    cidr_t block = {0xC0A80000, 16};
    cidr_t out = {0x12345678, 12};

    TEST_ASSERT_FALSE(cidr_subnet(block, 0, 0, &out));
    TEST_ASSERT_EQUAL_HEX32(0x12345678, out.addr);
    TEST_ASSERT_EQUAL_UINT8(12, out.prefix);
}

/* n != 0, but n is not a power of two. */
void test_cidr_subnet_count_not_power_of_two(void)
{
    cidr_t block = {0xC0A80000, 16};
    cidr_t out = {0x12345678, 12};

    TEST_ASSERT_FALSE(cidr_subnet(block, 3, 0, &out));
    TEST_ASSERT_EQUAL_HEX32(0x12345678, out.addr);
    TEST_ASSERT_EQUAL_UINT8(12, out.prefix);
}

/* n is a power of two, but i >= n. */
void test_cidr_subnet_index_out_of_range(void)
{
    cidr_t block = {0xC0A80000, 16};
    cidr_t out = {0x12345678, 12};

    TEST_ASSERT_FALSE(cidr_subnet(block, 4, 4, &out));
    TEST_ASSERT_EQUAL_HEX32(0x12345678, out.addr);
    TEST_ASSERT_EQUAL_UINT8(12, out.prefix);
}

/* new_prefix > 32: true */
void test_cidr_subnet_prefix_overflow(void)
{
    cidr_t block = {0xC0A80100, 31};
    cidr_t out = {0x12345678, 12};

    /* Splitting a /31 into two subnets would require /32;
       n=4 requires two extra bits, producing /33. */
    TEST_ASSERT_FALSE(cidr_subnet(block, 4, 0, &out));
    TEST_ASSERT_EQUAL_HEX32(0x12345678, out.addr);
    TEST_ASSERT_EQUAL_UINT8(12, out.prefix);
}

/* Successful case with n == 1: loop body never executes. */
void test_cidr_subnet_one_subnet(void)
{
    cidr_t block = {0xC0A80000, 16};
    cidr_t out = {0, 0};

    TEST_ASSERT_TRUE(cidr_subnet(block, 1, 0, &out));
    TEST_ASSERT_EQUAL_HEX32(0xC0A80000, out.addr);
    TEST_ASSERT_EQUAL_UINT8(16, out.prefix);
}

/* Successful case with n > 1: loop body executes. */
void test_cidr_subnet_four_subnets(void)
{
    cidr_t block = {0xC0A80000, 16};
    cidr_t out = {0, 0};

    TEST_ASSERT_TRUE(cidr_subnet(block, 4, 0, &out));
    TEST_ASSERT_EQUAL_HEX32(0xC0A80000, out.addr);
    TEST_ASSERT_EQUAL_UINT8(18, out.prefix);
}

/* Verify subnet index affects the address correctly. */
void test_cidr_subnet_nonzero_index(void)
{
    cidr_t block = {0xC0A80000, 16};
    cidr_t out = {0, 0};

    TEST_ASSERT_TRUE(cidr_subnet(block, 4, 2, &out));
    TEST_ASSERT_EQUAL_HEX32(0xC0A80000 + 2 * 16384, out.addr);
    TEST_ASSERT_EQUAL_UINT8(18, out.prefix);
}

/* Largest valid subnet count for a /30: four /32 subnets. */
void test_cidr_subnet_prefix_thirty_two(void)
{
    cidr_t block = {0xC0A80100, 30};
    cidr_t out = {0, 0};

    TEST_ASSERT_TRUE(cidr_subnet(block, 4, 3, &out));
    TEST_ASSERT_EQUAL_HEX32(0xC0A80103, out.addr);
    TEST_ASSERT_EQUAL_UINT8(32, out.prefix);
}

/* new_prefix == 32: false branch of new_prefix > 32. */
void test_cidr_subnet_exact_prefix_limit(void)
{
    cidr_t block = {0xC0A80100, 31};
    cidr_t out = {0, 0};

    TEST_ASSERT_TRUE(cidr_subnet(block, 2, 1, &out));
    TEST_ASSERT_EQUAL_HEX32(0xC0A80101, out.addr);
    TEST_ASSERT_EQUAL_UINT8(32, out.prefix);
}

// route_parse tests

/* Helper: initialize output to sentinel values. */
static void init_route_sentinel(route_t *route)
{
    route->dest.addr = UINT32_C(0x12345678);
    route->dest.prefix = 17;
    route->gateway = UINT32_C(0xABCDEF01);
    memset(route->dev, 'X', sizeof(route->dev));
}

/* Helper: verify that failed parsing leaves output unchanged. */
static void assert_route_unchanged(const route_t *route)
{
    TEST_ASSERT_EQUAL_UINT32(UINT32_C(0x12345678),
                             route->dest.addr);
    TEST_ASSERT_EQUAL_UINT8(17, route->dest.prefix);
    TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xABCDEF01),
                             route->gateway);

    for (size_t i = 0; i < DEV_NAME_LEN; i++) {
        TEST_ASSERT_EQUAL_INT('X', route->dev[i]);
    }
}

/* NULL arguments. */
void test_route_parse_null_line(void)
{
    route_t route;
    init_route_sentinel(&route);

    TEST_ASSERT_FALSE(route_parse(NULL, &route));
    assert_route_unchanged(&route);
}

void test_route_parse_null_output(void)
{
    TEST_ASSERT_FALSE(route_parse("default direct eth0", NULL));
}

void test_route_parse_both_null(void)
{
    TEST_ASSERT_FALSE(route_parse(NULL, NULL));
}

/* Invalid field counts. */
void test_route_parse_empty_line(void)
{
    route_t route;
    init_route_sentinel(&route);

    TEST_ASSERT_FALSE(route_parse("", &route));
    assert_route_unchanged(&route);
}

void test_route_parse_whitespace_only(void)
{
    route_t route;
    init_route_sentinel(&route);

    TEST_ASSERT_FALSE(route_parse(" \t \n", &route));
    assert_route_unchanged(&route);
}

void test_route_parse_missing_gateway_and_device(void)
{
    route_t route;
    init_route_sentinel(&route);

    TEST_ASSERT_FALSE(route_parse("10.0.0.0/8", &route));
    assert_route_unchanged(&route);
}

void test_route_parse_missing_device(void)
{
    route_t route;
    init_route_sentinel(&route);

    TEST_ASSERT_FALSE(
        route_parse("10.0.0.0/8 10.1.0.1", &route)
    );
    assert_route_unchanged(&route);
}

void test_route_parse_extra_field(void)
{
    route_t route;
    init_route_sentinel(&route);

    TEST_ASSERT_FALSE(
        route_parse("default direct eth0 extra", &route)
    );
    assert_route_unchanged(&route);
}

/* Destination parsing. */
void test_route_parse_default_destination(void)
{
    route_t route;

    TEST_ASSERT_TRUE(
        route_parse("default 132.178.227.1 eno1", &route)
    );

    TEST_ASSERT_EQUAL_UINT32(0, route.dest.addr);
    TEST_ASSERT_EQUAL_UINT8(0, route.dest.prefix);
    TEST_ASSERT_EQUAL_UINT32(UINT32_C(0x84B2E301),
                             route.gateway);
    TEST_ASSERT_EQUAL_STRING("eno1", route.dev);
}

void test_route_parse_valid_cidr_destination(void)
{
    route_t route;

    TEST_ASSERT_TRUE(
        route_parse("10.1.2.0/24 direct eth2", &route)
    );

    TEST_ASSERT_EQUAL_UINT32(UINT32_C(0x0A010200),
                             route.dest.addr);
    TEST_ASSERT_EQUAL_UINT8(24, route.dest.prefix);
    TEST_ASSERT_EQUAL_UINT32(0, route.gateway);
    TEST_ASSERT_EQUAL_STRING("eth2", route.dev);
}

void test_route_parse_invalid_cidr_destination(void)
{
    route_t route;
    init_route_sentinel(&route);

    TEST_ASSERT_FALSE(
        route_parse("10.0.0.0/33 direct eth0", &route)
    );
    assert_route_unchanged(&route);
}

void test_route_parse_destination_with_host_bits_set(void)
{
    route_t route;
    init_route_sentinel(&route);

    TEST_ASSERT_FALSE(
        route_parse("10.0.0.1/24 direct eth0", &route)
    );
    assert_route_unchanged(&route);
}

/* Gateway parsing. */
void test_route_parse_direct_gateway(void)
{
    route_t route;

    TEST_ASSERT_TRUE(
        route_parse("192.168.0.0/16 direct eth1", &route)
    );

    TEST_ASSERT_EQUAL_UINT32(0, route.gateway);
    TEST_ASSERT_EQUAL_STRING("eth1", route.dev);
}

void test_route_parse_valid_ip_gateway(void)
{
    route_t route;

    TEST_ASSERT_TRUE(
        route_parse("10.0.0.0/8 10.1.0.1 eth1", &route)
    );

    TEST_ASSERT_EQUAL_UINT32(UINT32_C(0x0A010001),
                             route.gateway);
    TEST_ASSERT_EQUAL_STRING("eth1", route.dev);
}

void test_route_parse_invalid_gateway(void)
{
    route_t route;
    init_route_sentinel(&route);

    TEST_ASSERT_FALSE(
        route_parse("10.0.0.0/8 300.1.1.1 eth0", &route)
    );
    assert_route_unchanged(&route);
}

/* Device validation. */
void test_route_parse_empty_device_missing_field(void)
{
    route_t route;
    init_route_sentinel(&route);

    TEST_ASSERT_FALSE(
        route_parse("10.0.0.0/8 direct", &route)
    );
    assert_route_unchanged(&route);
}

void test_route_parse_device_too_long(void)
{
    route_t route;
    init_route_sentinel(&route);

    TEST_ASSERT_FALSE(
        route_parse(
            "10.0.0.0/8 direct abcdefghijklmnop",
            &route
        )
    );
    assert_route_unchanged(&route);
}

/* Whitespace handling. */
void test_route_parse_leading_and_trailing_whitespace(void)
{
    route_t route;

    TEST_ASSERT_TRUE(
        route_parse(
            " \t10.0.0.0/8\t direct   eth1 \n",
            &route
        )
    );

    TEST_ASSERT_EQUAL_UINT32(UINT32_C(0x0A000000),
                             route.dest.addr);
    TEST_ASSERT_EQUAL_UINT8(8, route.dest.prefix);
    TEST_ASSERT_EQUAL_UINT32(0, route.gateway);
    TEST_ASSERT_EQUAL_STRING("eth1", route.dev);
}

// table_create tests

void test_table_create_success(void)
{
    fwd_table_t *table = table_create();

    TEST_ASSERT_NOT_NULL(table);

    /* A newly created table should be empty. */
    TEST_ASSERT_EQUAL_UINT(0, table_count(table));

    table_destroy(table);
}

//table_destroy tests

void test_table_destroy_null(void)
{
    /* NULL should be accepted and do nothing. */
    table_destroy(NULL);
}

void test_table_destroy_empty_table(void)
{
    fwd_table_t *table = table_create();

    TEST_ASSERT_NOT_NULL(table);

    /* Destroy a valid table with no routes. */
    table_destroy(table);
}

//table_count tests

void test_table_count_null(void)
{
    TEST_ASSERT_EQUAL_UINT(0, table_count(NULL));
}

void test_table_count_empty_table(void)
{
    fwd_table_t *table = table_create();

    TEST_ASSERT_NOT_NULL(table);

    TEST_ASSERT_EQUAL_UINT(0, table_count(table));

    table_destroy(table);
}

void test_table_count_after_adding_route(void)
{
    fwd_table_t *table = table_create();
    route_t route;

    TEST_ASSERT_NOT_NULL(table);

    TEST_ASSERT_TRUE(
        route_parse("10.0.0.0/8 direct eth0", &route)
    );

    TEST_ASSERT_TRUE(table_add(table, &route));
    TEST_ASSERT_EQUAL_UINT(1, table_count(table));

    table_destroy(table);
}

// table_add tests

void test_table_add_null_table(void)
{
    route_t route;

    TEST_ASSERT_TRUE(
        route_parse("10.0.0.0/8 direct eth0", &route)
    );

    TEST_ASSERT_FALSE(table_add(NULL, &route));
}

void test_table_add_null_route(void)
{
    fwd_table_t *table = table_create();

    TEST_ASSERT_NOT_NULL(table);
    TEST_ASSERT_FALSE(table_add(table, NULL));
    TEST_ASSERT_EQUAL_UINT(0, table_count(table));

    table_destroy(table);
}

void test_table_add_both_null(void)
{
    TEST_ASSERT_FALSE(table_add(NULL, NULL));
}

void test_table_add_destination_with_host_bits(void)
{
    fwd_table_t *table = table_create();
    route_t route = {
        .dest = { .addr = UINT32_C(0x0A000001), .prefix = 24 },
        .gateway = 0,
        .dev = "eth0"
    };

    TEST_ASSERT_NOT_NULL(table);

    /* 10.0.0.1/24 is not a network address. */
    TEST_ASSERT_FALSE(table_add(table, &route));
    TEST_ASSERT_EQUAL_UINT(0, table_count(table));

    table_destroy(table);
}

void test_table_add_invalid_prefix_network(void)
{
    fwd_table_t *table = table_create();
    route_t route = {
        .dest = { .addr = UINT32_C(0x0A000000), .prefix = 33 },
        .gateway = 0,
        .dev = "eth0"
    };

    TEST_ASSERT_NOT_NULL(table);

    /* A prefix greater than 32 cannot represent a valid network. */
    TEST_ASSERT_FALSE(table_add(table, &route));
    TEST_ASSERT_EQUAL_UINT(0, table_count(table));

    table_destroy(table);
}

void test_table_add_first_route(void)
{
    fwd_table_t *table = table_create();
    route_t route;

    TEST_ASSERT_NOT_NULL(table);
    TEST_ASSERT_TRUE(
        route_parse("10.0.0.0/8 direct eth0", &route)
    );

    /* Exercises the initial capacity == 0 path. */
    TEST_ASSERT_TRUE(table_add(table, &route));
    TEST_ASSERT_EQUAL_UINT(1, table_count(table));

    table_destroy(table);
}

void test_table_add_duplicate_route(void)
{
    fwd_table_t *table = table_create();
    route_t first;
    route_t duplicate;

    TEST_ASSERT_NOT_NULL(table);

    TEST_ASSERT_TRUE(
        route_parse("10.0.0.0/8 direct eth0", &first)
    );
    TEST_ASSERT_TRUE(
        route_parse("10.0.0.0/8 10.1.0.1 eth1", &duplicate)
    );

    TEST_ASSERT_TRUE(table_add(table, &first));

    /* Same destination and prefix, despite different gateway/device. */
    TEST_ASSERT_FALSE(table_add(table, &duplicate));
    TEST_ASSERT_EQUAL_UINT(1, table_count(table));

    table_destroy(table);
}

void test_table_add_different_prefix_same_address(void)
{
    fwd_table_t *table = table_create();
    route_t first;
    route_t second;

    TEST_ASSERT_NOT_NULL(table);

    TEST_ASSERT_TRUE(
        route_parse("10.0.0.0/8 direct eth0", &first)
    );
    TEST_ASSERT_TRUE(
        route_parse("10.0.0.0/16 direct eth1", &second)
    );

    TEST_ASSERT_TRUE(table_add(table, &first));
    TEST_ASSERT_TRUE(table_add(table, &second));
    TEST_ASSERT_EQUAL_UINT(2, table_count(table));

    table_destroy(table);
}

void test_table_add_multiple_routes_within_capacity(void)
{
    fwd_table_t *table = table_create();
    route_t route;

    TEST_ASSERT_NOT_NULL(table);

    TEST_ASSERT_TRUE(
        route_parse("10.0.0.0/8 direct eth0", &route)
    );
    TEST_ASSERT_TRUE(table_add(table, &route));

    TEST_ASSERT_TRUE(
        route_parse("11.0.0.0/8 direct eth0", &route)
    );
    TEST_ASSERT_TRUE(table_add(table, &route));

    TEST_ASSERT_TRUE(
        route_parse("12.0.0.0/8 direct eth0", &route)
    );
    TEST_ASSERT_TRUE(table_add(table, &route));

    TEST_ASSERT_EQUAL_UINT(3, table_count(table));

    table_destroy(table);
}

void test_table_add_grows_full_table(void)
{
    fwd_table_t *table = table_create();
    route_t route;

    TEST_ASSERT_NOT_NULL(table);

    /*
     * The implementation starts with capacity 4.
     * Add four routes to fill the initial allocation.
     */
    TEST_ASSERT_TRUE(
        route_parse("10.0.0.0/8 direct eth0", &route)
    );
    TEST_ASSERT_TRUE(table_add(table, &route));

    TEST_ASSERT_TRUE(
        route_parse("11.0.0.0/8 direct eth0", &route)
    );
    TEST_ASSERT_TRUE(table_add(table, &route));

    TEST_ASSERT_TRUE(
        route_parse("12.0.0.0/8 direct eth0", &route)
    );
    TEST_ASSERT_TRUE(table_add(table, &route));

    TEST_ASSERT_TRUE(
        route_parse("13.0.0.0/8 direct eth0", &route)
    );
    TEST_ASSERT_TRUE(table_add(table, &route));

    TEST_ASSERT_EQUAL_UINT(4, table_count(table));

    /* The fifth route exercises the capacity-doubling path. */
    TEST_ASSERT_TRUE(
        route_parse("14.0.0.0/8 direct eth0", &route)
    );
    TEST_ASSERT_TRUE(table_add(table, &route));

    TEST_ASSERT_EQUAL_UINT(5, table_count(table));

    table_destroy(table);
}

void test_table_add_capacity_doubling_overflow(void)
{
    fwd_table_t *table = table_create();
    TEST_ASSERT_NOT_NULL(table);

    route_t route = {0};
    route.dest.addr = UINT32_C(0x0A000000);
    route.dest.prefix = 8;
    route.gateway = UINT32_C(0xC0000201);
    strcpy(route.dev, "eth0");

    table_test_set_full_capacity(table, SIZE_MAX / 2 + 1);

    TEST_ASSERT_FALSE(table_add(table, &route));

    table_destroy(table);
}

void test_table_add_allocation_size_overflow(void)
{
    fwd_table_t *table = table_create();
    TEST_ASSERT_NOT_NULL(table);

    route_t route = {0};
    route.dest.addr = UINT32_C(0x0A000000);
    route.dest.prefix = 8;
    route.gateway = UINT32_C(0xC0000201);
    strcpy(route.dev, "eth0");

    size_t capacity = SIZE_MAX / (2 * sizeof(route_t)) + 1;

    TEST_ASSERT_TRUE(capacity <= SIZE_MAX / 2);

    table_test_set_full_capacity(table, capacity);

    TEST_ASSERT_FALSE(table_add(table, &route));

    table_destroy(table);
}


// table_load tests

static FILE *make_input_file(const char *contents)
{
    FILE *in = tmpfile();

    if (in == NULL) {
        return NULL;
    }

    if (fputs(contents, in) == EOF) {
        fclose(in);
        return NULL;
    }

    rewind(in);
    return in;
}

void test_table_load_null_table(void)
{
    FILE *in = make_input_file("");
    size_t bad_line = 99;

    TEST_ASSERT_NOT_NULL(in);

    TEST_ASSERT_FALSE(table_load(NULL, in, &bad_line));
    TEST_ASSERT_EQUAL_UINT(0, bad_line);

    fclose(in);
}

void test_table_load_null_file(void)
{
    fwd_table_t *table = table_create();
    size_t bad_line = 99;

    TEST_ASSERT_NOT_NULL(table);

    TEST_ASSERT_FALSE(table_load(table, NULL, &bad_line));
    TEST_ASSERT_EQUAL_UINT(0, bad_line);
    TEST_ASSERT_EQUAL_UINT(0, table_count(table));

    table_destroy(table);
}

void test_table_load_both_null(void)
{
    size_t bad_line = 99;

    TEST_ASSERT_FALSE(table_load(NULL, NULL, &bad_line));
    TEST_ASSERT_EQUAL_UINT(0, bad_line);
}

void test_table_load_bad_line_pointer_null(void)
{
    FILE *in = make_input_file("10.0.0.0/8 direct eth0\n");
    fwd_table_t *table = table_create();

    TEST_ASSERT_NOT_NULL(in);
    TEST_ASSERT_NOT_NULL(table);

    TEST_ASSERT_TRUE(table_load(table, in, NULL));
    TEST_ASSERT_EQUAL_UINT(1, table_count(table));

    fclose(in);
    table_destroy(table);
}

void test_table_load_empty_file(void)
{
    FILE *in = make_input_file("");
    fwd_table_t *table = table_create();
    size_t bad_line = 99;

    TEST_ASSERT_NOT_NULL(in);
    TEST_ASSERT_NOT_NULL(table);

    TEST_ASSERT_TRUE(table_load(table, in, &bad_line));
    TEST_ASSERT_EQUAL_UINT(0, bad_line);
    TEST_ASSERT_EQUAL_UINT(0, table_count(table));

    fclose(in);
    table_destroy(table);
}

void test_table_load_valid_route(void)
{
    FILE *in = make_input_file(
        "10.0.0.0/8 direct eth0\n"
    );
    fwd_table_t *table = table_create();
    size_t bad_line = 99;

    TEST_ASSERT_NOT_NULL(in);
    TEST_ASSERT_NOT_NULL(table);

    TEST_ASSERT_TRUE(table_load(table, in, &bad_line));
    TEST_ASSERT_EQUAL_UINT(0, bad_line);
    TEST_ASSERT_EQUAL_UINT(1, table_count(table));

    fclose(in);
    table_destroy(table);
}

void test_table_load_multiple_valid_routes(void)
{
    FILE *in = make_input_file(
        "default 132.178.227.1 eno1\n"
        "10.0.0.0/8 10.1.0.1 eth1\n"
        "10.1.0.0/16 direct eth1\n"
    );
    fwd_table_t *table = table_create();
    size_t bad_line = 99;

    TEST_ASSERT_NOT_NULL(in);
    TEST_ASSERT_NOT_NULL(table);

    TEST_ASSERT_TRUE(table_load(table, in, &bad_line));
    TEST_ASSERT_EQUAL_UINT(0, bad_line);
    TEST_ASSERT_EQUAL_UINT(3, table_count(table));

    fclose(in);
    table_destroy(table);
}

void test_table_load_comments_and_blank_lines(void)
{
    FILE *in = make_input_file(
        "# full-line comment\n"
        "\n"
        "   \t  \n"
        "10.0.0.0/8 direct eth0 # inline comment\n"
        "   # indented comment\n"
        "11.0.0.0/8 direct eth1\n"
    );
    fwd_table_t *table = table_create();
    size_t bad_line = 99;

    TEST_ASSERT_NOT_NULL(in);
    TEST_ASSERT_NOT_NULL(table);

    TEST_ASSERT_TRUE(table_load(table, in, &bad_line));
    TEST_ASSERT_EQUAL_UINT(0, bad_line);
    TEST_ASSERT_EQUAL_UINT(2, table_count(table));

    fclose(in);
    table_destroy(table);
}

void test_table_load_leading_and_trailing_whitespace(void)
{
    FILE *in = make_input_file(
        " \t10.0.0.0/8   direct\teth0   \n"
    );
    fwd_table_t *table = table_create();
    size_t bad_line = 99;

    TEST_ASSERT_NOT_NULL(in);
    TEST_ASSERT_NOT_NULL(table);

    TEST_ASSERT_TRUE(table_load(table, in, &bad_line));
    TEST_ASSERT_EQUAL_UINT(0, bad_line);
    TEST_ASSERT_EQUAL_UINT(1, table_count(table));

    fclose(in);
    table_destroy(table);
}

void test_table_load_invalid_route_reports_line(void)
{
    FILE *in = make_input_file(
        "# line 1\n"
        "10.0.0.0/8 direct eth0\n"
        "\n"
        "10.1.0.1/24 direct eth1\n"
        "11.0.0.0/8 direct eth2\n"
    );
    fwd_table_t *table = table_create();
    size_t bad_line = 99;

    TEST_ASSERT_NOT_NULL(in);
    TEST_ASSERT_NOT_NULL(table);

    TEST_ASSERT_FALSE(table_load(table, in, &bad_line));

    /* The invalid route is on physical line 4. */
    TEST_ASSERT_EQUAL_UINT(4, bad_line);

    /* The valid route before the error remains loaded. */
    TEST_ASSERT_EQUAL_UINT(1, table_count(table));

    fclose(in);
    table_destroy(table);
}

void test_table_load_duplicate_route_reports_line(void)
{
    FILE *in = make_input_file(
        "10.0.0.0/8 direct eth0\n"
        "11.0.0.0/8 direct eth1\n"
        "10.0.0.0/8 10.1.0.1 eth2\n"
    );
    fwd_table_t *table = table_create();
    size_t bad_line = 99;

    TEST_ASSERT_NOT_NULL(in);
    TEST_ASSERT_NOT_NULL(table);

    TEST_ASSERT_FALSE(table_load(table, in, &bad_line));
    TEST_ASSERT_EQUAL_UINT(3, bad_line);

    /* Both earlier routes remain; the duplicate was rejected. */
    TEST_ASSERT_EQUAL_UINT(2, table_count(table));

    fclose(in);
    table_destroy(table);
}

void test_table_load_invalid_gateway_reports_line(void)
{
    FILE *in = make_input_file(
        "10.0.0.0/8 direct eth0\n"
        "11.0.0.0/8 300.1.1.1 eth1\n"
    );
    fwd_table_t *table = table_create();
    size_t bad_line = 99;

    TEST_ASSERT_NOT_NULL(in);
    TEST_ASSERT_NOT_NULL(table);

    TEST_ASSERT_FALSE(table_load(table, in, &bad_line));
    TEST_ASSERT_EQUAL_UINT(2, bad_line);
    TEST_ASSERT_EQUAL_UINT(1, table_count(table));

    fclose(in);
    table_destroy(table);
}

void test_table_load_bad_line_reset_on_success(void)
{
    FILE *in = make_input_file(
        "10.0.0.0/8 direct eth0\n"
    );
    fwd_table_t *table = table_create();
    size_t bad_line = 123;

    TEST_ASSERT_NOT_NULL(in);
    TEST_ASSERT_NOT_NULL(table);

    TEST_ASSERT_TRUE(table_load(table, in, &bad_line));
    TEST_ASSERT_EQUAL_UINT(0, bad_line);

    fclose(in);
    table_destroy(table);
}

void test_table_load_failure_resets_bad_line_for_null_arguments(void)
{
    size_t bad_line = 123;

    TEST_ASSERT_FALSE(table_load(NULL, NULL, &bad_line));
    TEST_ASSERT_EQUAL_UINT(0, bad_line);
}

// table_lookup tests 

void test_table_lookup_null_table(void)
{
    uint32_t dest = UINT32_C(0x0A000001);

    TEST_ASSERT_NULL(table_lookup(NULL, dest));
}

void test_table_lookup_empty_table(void)
{
    fwd_table_t *table = table_create();
    TEST_ASSERT_NOT_NULL(table);

    TEST_ASSERT_NULL(table_lookup(table, UINT32_C(0x0A000001)));

    table_destroy(table);
}

void test_table_lookup_no_matching_route(void)
{
    fwd_table_t *table = table_create();
    TEST_ASSERT_NOT_NULL(table);

    route_t route;
    TEST_ASSERT_TRUE(route_parse("10.0.0.0/8 192.0.2.1 eth0", &route));
    TEST_ASSERT_TRUE(table_add(table, &route));

    /* 11.0.0.1 is outside 10.0.0.0/8. */
    TEST_ASSERT_NULL(table_lookup(table, UINT32_C(0x0B000001)));

    table_destroy(table);
}

void test_table_lookup_exact_prefix_match(void)
{
    fwd_table_t *table = table_create();
    TEST_ASSERT_NOT_NULL(table);

    route_t route;
    TEST_ASSERT_TRUE(route_parse("192.168.1.0/24 192.0.2.1 eth0", &route));
    TEST_ASSERT_TRUE(table_add(table, &route));

    const route_t *found =
        table_lookup(table, UINT32_C(0xC0A80164)); /* 192.168.1.100 */

    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xC0A80100), found->dest.addr);
    TEST_ASSERT_EQUAL_UINT8(24, found->dest.prefix);
    TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xC0000201), found->gateway);

    table_destroy(table);
}

void test_table_lookup_longest_prefix_match(void)
{
    fwd_table_t *table = table_create();
    TEST_ASSERT_NOT_NULL(table);

    route_t broad;
    route_t narrow;

    TEST_ASSERT_TRUE(route_parse("10.0.0.0/8 192.0.2.1 eth0", &broad));
    TEST_ASSERT_TRUE(route_parse("10.1.0.0/16 192.0.2.2 eth1", &narrow));

    TEST_ASSERT_TRUE(table_add(table, &broad));
    TEST_ASSERT_TRUE(table_add(table, &narrow));

    const route_t *found =
        table_lookup(table, UINT32_C(0x0A010203)); /* 10.1.2.3 */

    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_UINT32(UINT32_C(0x0A010000), found->dest.addr);
    TEST_ASSERT_EQUAL_UINT8(16, found->dest.prefix);
    TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xC0000202), found->gateway);

    table_destroy(table);
}

void test_table_lookup_longest_prefix_independent_of_insertion_order(void)
{
    fwd_table_t *table = table_create();
    TEST_ASSERT_NOT_NULL(table);

    route_t narrow;
    route_t broad;

    TEST_ASSERT_TRUE(route_parse("10.1.0.0/16 192.0.2.2 eth1", &narrow));
    TEST_ASSERT_TRUE(route_parse("10.0.0.0/8 192.0.2.1 eth0", &broad));

    /* Insert the more-specific route first. */
    TEST_ASSERT_TRUE(table_add(table, &narrow));
    TEST_ASSERT_TRUE(table_add(table, &broad));

    const route_t *found =
        table_lookup(table, UINT32_C(0x0A010203));

    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_UINT8(16, found->dest.prefix);
    TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xC0000202), found->gateway);

    table_destroy(table);
}

void test_table_lookup_default_route(void)
{
    fwd_table_t *table = table_create();
    TEST_ASSERT_NOT_NULL(table);

    route_t route;
    TEST_ASSERT_TRUE(route_parse("default 192.0.2.1 eth0", &route));
    TEST_ASSERT_TRUE(table_add(table, &route));

    const route_t *found =
        table_lookup(table, UINT32_C(0xCB007109)); /* 203.0.113.9 */

    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_UINT8(0, found->dest.prefix);
    TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xC0000201), found->gateway);

    table_destroy(table);
}

void test_table_lookup_prefers_specific_route_over_default(void)
{
    fwd_table_t *table = table_create();
    TEST_ASSERT_NOT_NULL(table);

    route_t default_route;
    route_t specific_route;

    TEST_ASSERT_TRUE(route_parse("default 192.0.2.1 eth0", &default_route));
    TEST_ASSERT_TRUE(route_parse("203.0.113.0/24 192.0.2.2 eth1", &specific_route));

    TEST_ASSERT_TRUE(table_add(table, &default_route));
    TEST_ASSERT_TRUE(table_add(table, &specific_route));

    const route_t *found =
        table_lookup(table, UINT32_C(0xCB007109)); /* 203.0.113.9 */

    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_UINT8(24, found->dest.prefix);
    TEST_ASSERT_EQUAL_UINT32(UINT32_C(0xC0000202), found->gateway);

    table_destroy(table);
}

void test_table_lookup_route_for_network_address(void)
{
    fwd_table_t *table = table_create();
    TEST_ASSERT_NOT_NULL(table);

    route_t route;
    TEST_ASSERT_TRUE(route_parse("172.16.0.0/12 192.0.2.1 eth0", &route));
    TEST_ASSERT_TRUE(table_add(table, &route));

    /* Query the network address itself. */
    const route_t *found =
        table_lookup(table, UINT32_C(0xAC100000)); /* 172.16.0.0 */

    TEST_ASSERT_NOT_NULL(found);
    TEST_ASSERT_EQUAL_UINT8(12, found->dest.prefix);

    table_destroy(table);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_ip_parse_null_text);
    RUN_TEST(test_ip_parse_null_addr);
    RUN_TEST(test_ip_parse_empty_string);
    RUN_TEST(test_ip_parse_first_character_not_digit);
    RUN_TEST(test_ip_parse_leading_zero);
    RUN_TEST(test_ip_parse_octet_exceeds_255);
    RUN_TEST(test_ip_parse_missing_octet);
    RUN_TEST(test_ip_parse_missing_period);
    RUN_TEST(test_ip_parse_extra_period);
    RUN_TEST(test_ip_parse_trailing_characters);
    RUN_TEST(test_ip_parse_valid_address);
    RUN_TEST(test_ip_parse_output_unchanged_on_failure);
    RUN_TEST(test_ip_format_null_output);
    RUN_TEST(test_ip_format_zero_address);
    RUN_TEST(test_ip_format_broadcast_address);
    RUN_TEST(test_ip_format_typical_address);
    RUN_TEST(test_ip_format_single_digit_octets);
    RUN_TEST(test_ip_format_mixed_octet_sizes);
    RUN_TEST(test_cidr_parse_null_text);
    RUN_TEST(test_cidr_parse_null_block);
    RUN_TEST(test_cidr_parse_missing_slash);
    RUN_TEST(test_cidr_parse_multiple_slashes);
    RUN_TEST(test_cidr_parse_empty_address);
    RUN_TEST(test_cidr_parse_address_too_long);
    RUN_TEST(test_cidr_parse_invalid_address);
    RUN_TEST(test_cidr_parse_valid_address);
    RUN_TEST(test_cidr_parse_prefix_not_digit);
    RUN_TEST(test_cidr_parse_prefix_leading_zero);
    RUN_TEST(test_cidr_parse_prefix_over_32);
    RUN_TEST(test_cidr_parse_prefix_loop_multiple_digits);
    RUN_TEST(test_cidr_parse_prefix_zero);
    RUN_TEST(test_cidr_parse_trailing_characters);
    RUN_TEST(test_cidr_parse_no_trailing_characters);
    RUN_TEST(test_cidr_parse_output_unchanged_on_failure);
    RUN_TEST(test_cidr_parse_host_bits_set);
    RUN_TEST(test_cidr_format_null_output);
    RUN_TEST(test_cidr_format_prefix_within_range);
    RUN_TEST(test_cidr_format_prefix_zero);
    RUN_TEST(test_cidr_format_prefix_32);
    RUN_TEST(test_cidr_format_prefix_above_32);
    RUN_TEST(test_cidr_format_large_prefix_clamped_to_32);
    RUN_TEST(test_cidr_format_preserves_host_bits);
    RUN_TEST(test_cidr_mask_prefix_zero);
    RUN_TEST(test_cidr_mask_prefix_one);
    RUN_TEST(test_cidr_mask_prefix_eight);
    RUN_TEST(test_cidr_mask_prefix_sixteen);
    RUN_TEST(test_cidr_mask_prefix_twenty_four);
    RUN_TEST(test_cidr_mask_prefix_thirty_one);
    RUN_TEST(test_cidr_mask_prefix_thirty_two);
    RUN_TEST(test_cidr_mask_prefix_above_thirty_two);
    RUN_TEST(test_cidr_network_typical_subnet);
    RUN_TEST(test_cidr_network_prefix_zero);
    RUN_TEST(test_cidr_network_prefix_thirty_two);
    RUN_TEST(test_cidr_network_host_bits_already_zero);
    RUN_TEST(test_cidr_broadcast_typical_subnet);
    RUN_TEST(test_cidr_broadcast_prefix_zero);
    RUN_TEST(test_cidr_broadcast_prefix_thirty_two);
    RUN_TEST(test_cidr_broadcast_prefix_thirty_one);
    RUN_TEST(test_cidr_first_host_typical_subnet);
    RUN_TEST(test_cidr_first_host_prefix_zero);
    RUN_TEST(test_cidr_first_host_prefix_thirty_one);
    RUN_TEST(test_cidr_first_host_prefix_thirty_two);
    RUN_TEST(test_cidr_last_host_typical_subnet);
    RUN_TEST(test_cidr_last_host_prefix_zero);
    RUN_TEST(test_cidr_last_host_prefix_thirty_one);
    RUN_TEST(test_cidr_last_host_prefix_thirty_two);
    RUN_TEST(test_cidr_host_count_prefix_zero);
    RUN_TEST(test_cidr_host_count_prefix_twenty_four);
    RUN_TEST(test_cidr_host_count_prefix_thirty_one);
    RUN_TEST(test_cidr_host_count_prefix_thirty_two);
    RUN_TEST(test_cidr_host_count_prefix_above_thirty_two);
    RUN_TEST(test_cidr_host_count_prefix_maximum);
    RUN_TEST(test_cidr_contains_address_inside_subnet);
    RUN_TEST(test_cidr_contains_network_address);
    RUN_TEST(test_cidr_contains_broadcast_address);
    RUN_TEST(test_cidr_contains_address_outside_subnet);
    RUN_TEST(test_cidr_contains_prefix_zero);
    RUN_TEST(test_cidr_contains_prefix_thirty_two);
    RUN_TEST(test_cidr_is_network_true);
    RUN_TEST(test_cidr_is_network_false);
    RUN_TEST(test_cidr_is_network_prefix_zero);
    RUN_TEST(test_cidr_is_network_prefix_zero_with_host_bits);
    RUN_TEST(test_cidr_is_network_prefix_thirty_two);
    RUN_TEST(test_cidr_is_network_prefix_thirty_one_true);
    RUN_TEST(test_cidr_is_network_prefix_thirty_one_false);
    RUN_TEST(test_cidr_subnet_null_output);
    RUN_TEST(test_cidr_subnet_input_not_network);
    RUN_TEST(test_cidr_subnet_zero_count);
    RUN_TEST(test_cidr_subnet_count_not_power_of_two);
    RUN_TEST(test_cidr_subnet_index_out_of_range);
    RUN_TEST(test_cidr_subnet_prefix_overflow);
    RUN_TEST(test_cidr_subnet_one_subnet);
    RUN_TEST(test_cidr_subnet_four_subnets);
    RUN_TEST(test_cidr_subnet_nonzero_index);
    RUN_TEST(test_cidr_subnet_prefix_thirty_two);
    RUN_TEST(test_cidr_subnet_exact_prefix_limit);
    RUN_TEST(test_route_parse_null_line);
    RUN_TEST(test_route_parse_null_output);
    RUN_TEST(test_route_parse_both_null);
    RUN_TEST(test_route_parse_empty_line);
    RUN_TEST(test_route_parse_whitespace_only);
    RUN_TEST(test_route_parse_missing_gateway_and_device);
    RUN_TEST(test_route_parse_missing_device);
    RUN_TEST(test_route_parse_extra_field);
    RUN_TEST(test_route_parse_default_destination);
    RUN_TEST(test_route_parse_valid_cidr_destination);
    RUN_TEST(test_route_parse_invalid_cidr_destination);
    RUN_TEST(test_route_parse_destination_with_host_bits_set);
    RUN_TEST(test_route_parse_direct_gateway);
    RUN_TEST(test_route_parse_valid_ip_gateway);
    RUN_TEST(test_route_parse_invalid_gateway);
    RUN_TEST(test_route_parse_empty_device_missing_field);
    RUN_TEST(test_route_parse_device_too_long);
    RUN_TEST(test_route_parse_leading_and_trailing_whitespace);
    RUN_TEST(test_table_create_success);
    RUN_TEST(test_table_destroy_null);
    RUN_TEST(test_table_destroy_empty_table);
    RUN_TEST(test_table_count_null);
    RUN_TEST(test_table_count_empty_table);
    RUN_TEST(test_table_count_after_adding_route);
    RUN_TEST(test_table_add_null_table);
    RUN_TEST(test_table_add_null_route);
    RUN_TEST(test_table_add_both_null);
    RUN_TEST(test_table_add_destination_with_host_bits);
    RUN_TEST(test_table_add_invalid_prefix_network);
    RUN_TEST(test_table_add_first_route);
    RUN_TEST(test_table_add_duplicate_route);
    RUN_TEST(test_table_add_different_prefix_same_address);
    RUN_TEST(test_table_add_multiple_routes_within_capacity);
    RUN_TEST(test_table_add_grows_full_table);
    RUN_TEST(test_table_add_capacity_doubling_overflow);
    RUN_TEST(test_table_add_allocation_size_overflow);
    RUN_TEST(test_table_load_null_table);
    RUN_TEST(test_table_load_null_file);
    RUN_TEST(test_table_load_both_null);
    RUN_TEST(test_table_load_bad_line_pointer_null);
    RUN_TEST(test_table_load_empty_file);
    RUN_TEST(test_table_load_valid_route);
    RUN_TEST(test_table_load_multiple_valid_routes);
    RUN_TEST(test_table_load_comments_and_blank_lines);
    RUN_TEST(test_table_load_leading_and_trailing_whitespace);
    RUN_TEST(test_table_load_invalid_route_reports_line);
    RUN_TEST(test_table_load_duplicate_route_reports_line);
    RUN_TEST(test_table_load_invalid_gateway_reports_line);
    RUN_TEST(test_table_load_bad_line_reset_on_success);
    RUN_TEST(test_table_load_failure_resets_bad_line_for_null_arguments);
    RUN_TEST(test_table_lookup_null_table);
    RUN_TEST(test_table_lookup_empty_table);
    RUN_TEST(test_table_lookup_no_matching_route);
    RUN_TEST(test_table_lookup_exact_prefix_match);
    RUN_TEST(test_table_lookup_longest_prefix_match);
    RUN_TEST(test_table_lookup_longest_prefix_independent_of_insertion_order);
    RUN_TEST(test_table_lookup_default_route);
    RUN_TEST(test_table_lookup_prefers_specific_route_over_default);
    RUN_TEST(test_table_lookup_route_for_network_address);
  return UNITY_END();
}
