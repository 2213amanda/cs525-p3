#include <stdlib.h>
#include <stdio.h>
#include "harness/unity.h"
#include "../src/lab.h"


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
  return UNITY_END();
}
