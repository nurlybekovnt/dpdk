#include <stdio.h>
#include <rte_hash.h>
#include <rte_errno.h>
#include <rte_hash_crc.h>
#include <rte_jhash.h>
#include <rte_ip.h>
#include <rte_log.h>

#define IPV6_ADDR_LEN 16

struct ipv6_5tuple
{
    uint8_t ip_dst[IPV6_ADDR_LEN];
    uint8_t ip_src[IPV6_ADDR_LEN];
    uint16_t port_dst;
    uint16_t port_src;
    uint8_t proto;
} __rte_packed;

static inline uint16_t
get_short_sig(const uint32_t hash)
{
    return hash >> 16;
}

static inline uint32_t
get_prim_bucket_index(const uint32_t hash)
{
    return hash & 127;
}

static inline uint32_t
get_alt_bucket_index(uint32_t cur_bkt_idx, uint16_t sig)
{
    return (cur_bkt_idx ^ sig) & 127;
}

void print_data(void *data, uint32_t data_len);

void print_data(void *data, uint32_t data_len)
{
    for (uint32_t i = 0; i < data_len; i++)
    {
        printf("%x", ((uint8_t *)data)[i]);
    }
    printf("\r\n");
}

/*int main(int argc __rte_unused, char **argv __rte_unused)
{
    int i = 0;

    for (uint16_t port_dst = 0; port_dst < 65535; port_dst++)
    {
        for (uint16_t port_src = 0; port_src < 65535; port_src++)
        {
            struct ipv6_5tuple key = {
                .ip_dst = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
                .ip_src = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
                .port_dst = port_dst,
                .port_src = port_src,
                .proto = 0x06,
            };
            uint32_t sig = rte_hash_crc(&key, sizeof(struct ipv6_5tuple), 0);
            uint16_t short_sig = get_short_sig(sig);
            uint32_t prim_bucket_idx = get_prim_bucket_index(sig);
            uint32_t sec_bucket_idx = get_alt_bucket_index(prim_bucket_idx, short_sig);
            if (prim_bucket_idx == 0 && sec_bucket_idx == 6)
            {
                print_data(&key, sizeof(struct ipv6_5tuple));
                printf("port_dst: %d, port_src: %d, sig: %x, short_sig: %x, prim_bucket_idx: %d, sec_bucket_idx: %d\r\n", key.port_dst, key.port_src, sig, short_sig, prim_bucket_idx, sec_bucket_idx);
                i++;
                if (i == 17)
                {
                    return 0;
                }
            }
        }
    }
    return 0;
}

struct ipv6_5tuple keys[] = {
    {
        .ip_dst = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
        .ip_src = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
        .port_dst = 0,
        .port_src = 4230,
        .proto = 0x06,
    },
    {
        .ip_dst = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
        .ip_src = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
        .port_dst = 0,
        .port_src = 14626,
        .proto = 0x06,
    },
    {
        .ip_dst = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
        .ip_src = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
        .port_dst = 0,
        .port_src = 20427,
        .proto = 0x06,
    },
    {
        .ip_dst = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
        .ip_src = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
        .port_dst = 0,
        .port_src = 26223,
        .proto = 0x06,
    },
    {
        .ip_dst = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
        .ip_src = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
        .port_dst = 1,
        .port_src = 35845,
        .proto = 0x06,
    },
    {
        .ip_dst = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
        .ip_src = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
        .port_dst = 1,
        .port_src = 42401,
        .proto = 0x06,
    },
    {
        .ip_dst = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
        .ip_src = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
        .port_dst = 1,
        .port_src = 54088,
        .proto = 0x06,
    },
    {
        .ip_dst = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
        .ip_src = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
        .port_dst = 1,
        .port_src = 64236,
        .proto = 0x06,
    },
    {
        .ip_dst = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
        .ip_src = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
        .port_dst = 2,
        .port_src = 36850,
        .proto = 0x06,
    },
    {
        .ip_dst = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
        .ip_src = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
        .port_dst = 2,
        .port_src = 42582,
        .proto = 0x06,
    },
    {
        .ip_dst = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
        .ip_src = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
        .port_dst = 2,
        .port_src = 53439,
        .proto = 0x06,
    },
    {
        .ip_dst = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
        .ip_src = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
        .port_dst = 2,
        .port_src = 63771,
        .proto = 0x06,
    },
    {
        .ip_dst = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
        .ip_src = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
        .port_dst = 3,
        .port_src = 4977,
        .proto = 0x06,
    },
    {
        .ip_dst = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
        .ip_src = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
        .port_dst = 3,
        .port_src = 15061,
        .proto = 0x06,
    },
    {
        .ip_dst = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
        .ip_src = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
        .port_dst = 3,
        .port_src = 19516,
        .proto = 0x06,
    },
    {
        .ip_dst = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
        .ip_src = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
        .port_dst = 3,
        .port_src = 26008,
        .proto = 0x06,
    },
    {
        .ip_dst = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
        .ip_src = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
        .port_dst = 4,
        .port_src = 4903,
        .proto = 0x06,
    },
};

int main(int argc __rte_unused, char **argv __rte_unused)
{
    int diag = rte_eal_init(argc, argv);
    if (diag < 0)
    {
        rte_exit(EXIT_FAILURE, "Cannot init EAL: %s\n\n", rte_strerror(rte_errno));
    }

    printf("\r\n\r\n");

    struct rte_hash_parameters hash_params = {
        .name = "flow_table",
        .entries = 1024,
        .key_len = sizeof(struct ipv6_5tuple),
        .socket_id = -1,
    };
    struct rte_hash *tbl = rte_hash_create(&hash_params);
    if (tbl == NULL)
    {
        rte_exit(EXIT_FAILURE, "hash create failed: %s(%d)\r\n", rte_strerror(rte_errno), rte_errno);
    }

    int N = sizeof(keys) / sizeof(struct ipv6_5tuple);
    for (int i = 0; i < N; i++)
    {
        int data = i + 100;
        int ret = rte_hash_add_key_data(tbl, &keys[i], (void *)(intptr_t)data);
        rte_print_hash_buckets(tbl);
        if (ret < 0)
        {
            rte_exit(EXIT_FAILURE, "hash add failed: %s(%d)\r\n", rte_strerror(rte_errno), rte_errno);
        }
        printf("data added: %d\r\n\r\n", data);
    }

    for (int i = 0; i < N; i++)
    {
        void *data = NULL;
        int ret = rte_hash_lookup_data(tbl, &keys[i], &data);
        if (ret < 0)
        {
            rte_exit(EXIT_FAILURE, "hash lookup failed: %s(%d)\r\n", rte_strerror(rte_errno), rte_errno);
        }
        printf("i: %d, data: %p\r\n", i, data);
    }

    return 0;
}
*/

/*
struct ipv6_5tuple keys[] = {
    {
        .ip_dst = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
        .ip_src = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
        .port_dst = 0x12,
        .port_src = 0x34,
        .proto = 0x06,
    },
    {
        .ip_dst = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
        .ip_src = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
        .port_dst = 0x56,
        .port_src = 0x78,
        .proto = 0x06,
    },
    {
        .ip_dst = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
        .ip_src = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
        .port_dst = 0x9a,
        .port_src = 0xbc,
        .proto = 0x06,
    },
    {
        .ip_dst = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
        .ip_src = {0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x08, 0x00, 0x27, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
        .port_dst = 0xde,
        .port_src = 0xf0,
        .proto = 0x06,
    },
};

int main(int argc __rte_unused, char **argv __rte_unused)
{
    int diag = rte_eal_init(argc, argv);
    if (diag < 0)
    {
        rte_exit(EXIT_FAILURE, "Cannot init EAL: %s\n\n", rte_strerror(rte_errno));
    }

    printf("\r\n\r\n");

    struct rte_hash_parameters hash_params = {
        .name = "flow_table",
        .entries = 1024,
        .key_len = sizeof(struct ipv6_5tuple),
        .socket_id = -1,
        .extra_flag = RTE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL,
    };
    struct rte_hash *tbl = rte_hash_create(&hash_params);
    if (tbl == NULL)
    {
        rte_exit(EXIT_FAILURE, "hash create failed: %s(%d)\r\n", rte_strerror(rte_errno), rte_errno);
    }

    int N = sizeof(keys) / sizeof(struct ipv6_5tuple);
    for (int i = 0; i < N; i++)
    {
        int ret = rte_hash_add_key(tbl, &keys[i]);
        if (ret < 0)
        {
            rte_exit(EXIT_FAILURE, "hash add failed: %s(%d)\r\n", rte_strerror(rte_errno), rte_errno);
        }
        printf("#%d added ret: %d\r\n", i, ret);
    }

    printf("\r\n");

    for (int i = 0; i < N; i++)
    {
        int ret = rte_hash_lookup(tbl, &keys[i]);
        if (ret < 0)
        {
            rte_exit(EXIT_FAILURE, "hash lookup failed: %s(%d)\r\n", rte_strerror(rte_errno), rte_errno);
        }
        printf("#%d lookup ret: %d\r\n", i, ret);
    }

    printf("\r\n");

    int ret = rte_hash_free_key_with_position(tbl, 1);
    if (ret < 0)
    {
        rte_exit(EXIT_FAILURE, "hash free failed: %s(%d)\r\n", rte_strerror(rte_errno), rte_errno);
    }
    /ret = rte_hash_del_key(tbl, &keys[1]);
    if (ret < 0)
    {
        rte_exit(EXIT_FAILURE, "hash del failed: %s(%d)\r\n", rte_strerror(rte_errno), rte_errno);
    }*

    for (int i = 0; i < N; i++)
    {
        int ret = rte_hash_lookup(tbl, &keys[i]);
        printf("#%d lookup after free ret: %d\r\n", i, ret);
    }
    
    return 0;
}*/

/*
 * 5-tuple key type.
 * Should be packed to avoid holes with potentially
 * undefined content in the middle.
 */
struct flow_key {
	uint32_t ip_src;
	uint32_t ip_dst;
	uint16_t port_src;
	uint16_t port_dst;
	uint32_t proto;
} __rte_packed;


RTE_LOG_REGISTER(hash_logtype_test, test.hash, INFO);

/*
 * Print out result of unit test hash operation.
 */
static void print_key_info(const char *msg, const struct flow_key *key,
								int32_t pos)
{
	const uint8_t *p = (const uint8_t *)key;
	unsigned int i;

	rte_log(RTE_LOG_DEBUG, hash_logtype_test, "%s key:0x", msg);
	for (i = 0; i < sizeof(struct flow_key); i++)
		rte_log(RTE_LOG_DEBUG, hash_logtype_test, "%02X", p[i]);
	rte_log(RTE_LOG_DEBUG, hash_logtype_test, " @ pos %d\n", pos);
}

/* Keys used by unit test functions */
static struct flow_key keys[5] = { {
	.ip_src = RTE_IPV4(0x03, 0x02, 0x01, 0x00),
	.ip_dst = RTE_IPV4(0x07, 0x06, 0x05, 0x04),
	.port_src = 0x0908,
	.port_dst = 0x0b0a,
	.proto = 0x0c,
}, {
	.ip_src = RTE_IPV4(0x13, 0x12, 0x11, 0x10),
	.ip_dst = RTE_IPV4(0x17, 0x16, 0x15, 0x14),
	.port_src = 0x1918,
	.port_dst = 0x1b1a,
	.proto = 0x1c,
}, {
	.ip_src = RTE_IPV4(0x23, 0x22, 0x21, 0x20),
	.ip_dst = RTE_IPV4(0x27, 0x26, 0x25, 0x24),
	.port_src = 0x2928,
	.port_dst = 0x2b2a,
	.proto = 0x2c,
}, {
	.ip_src = RTE_IPV4(0x33, 0x32, 0x31, 0x30),
	.ip_dst = RTE_IPV4(0x37, 0x36, 0x35, 0x34),
	.port_src = 0x3938,
	.port_dst = 0x3b3a,
	.proto = 0x3c,
}, {
	.ip_src = RTE_IPV4(0x43, 0x42, 0x41, 0x40),
	.ip_dst = RTE_IPV4(0x47, 0x46, 0x45, 0x44),
	.port_src = 0x4948,
	.port_dst = 0x4b4a,
	.proto = 0x4c,
} };


/*
 * Check condition and return an error if true. Assumes that "handle" is the
 * name of the hash structure pointer to be freed.
 */
#define RETURN_IF_ERROR(cond, str, ...) do {				\
	if (cond) {							\
		printf("ERROR line %d: " str "\n", __LINE__, ##__VA_ARGS__); \
		if (handle) rte_hash_free(handle);			\
		return -1;						\
	}								\
} while(0)


/* Parameters used for hash table in unit test functions. Name set later. */
static struct rte_hash_parameters ut_params = {
	.entries = 64,
	.key_len = sizeof(struct flow_key),
	.hash_func = rte_jhash,
	.hash_func_init_val = 0,
	.socket_id = 0,
};

int main(int argc __rte_unused, char **argv __rte_unused)
{
    int diag = rte_eal_init(argc, argv);
    if (diag < 0)
    {
        rte_exit(EXIT_FAILURE, "Cannot init EAL: %s\n\n", rte_strerror(rte_errno));
    }

    printf("\r\n\r\n");

    struct rte_hash *handle;
	int pos0, expectedPos0, delPos0, result;

	ut_params.name = "test2";
	ut_params.extra_flag = RTE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL;
	handle = rte_hash_create(&ut_params);
	RETURN_IF_ERROR(handle == NULL, "hash creation failed");
	ut_params.extra_flag = 0;

	pos0 = rte_hash_del_key(handle, &keys[0]);
	print_key_info("Del", &keys[0], pos0);
	RETURN_IF_ERROR(pos0 != -ENOENT,
			"fail: found non-existent key (pos0=%d)", pos0);

	pos0 = rte_hash_add_key(handle, &keys[0]);
	print_key_info("Add", &keys[0], pos0);
	RETURN_IF_ERROR(pos0 < 0, "failed to add key (pos0=%d)", pos0);
	expectedPos0 = pos0;

	pos0 = rte_hash_lookup(handle, &keys[0]);
	print_key_info("Lkp", &keys[0], pos0);
	RETURN_IF_ERROR(pos0 != expectedPos0,
			"failed to find key (pos0=%d)", pos0);

	pos0 = rte_hash_add_key(handle, &keys[0]);
	print_key_info("Add", &keys[0], pos0);
	RETURN_IF_ERROR(pos0 != expectedPos0,
			"failed to re-add key (pos0=%d)", pos0);

	pos0 = rte_hash_lookup(handle, &keys[0]);
	print_key_info("Lkp", &keys[0], pos0);
	RETURN_IF_ERROR(pos0 != expectedPos0,
			"failed to find key (pos0=%d)", pos0);

	delPos0 = rte_hash_del_key(handle, &keys[0]);
	print_key_info("Del", &keys[0], delPos0);
	RETURN_IF_ERROR(delPos0 != expectedPos0,
			"failed to delete key (pos0=%d)", delPos0);

	pos0 = rte_hash_del_key(handle, &keys[0]);
	print_key_info("Del", &keys[0], pos0);
	RETURN_IF_ERROR(pos0 != -ENOENT,
			"fail: deleted already deleted key (pos0=%d)", pos0);

	pos0 = rte_hash_lookup(handle, &keys[0]);
	print_key_info("Lkp", &keys[0], pos0);
	RETURN_IF_ERROR(pos0 != -ENOENT,
			"fail: found key after deleting! (pos0=%d)", pos0);

	result = rte_hash_free_key_with_position(handle, delPos0);
	print_key_info("Free", &keys[0], delPos0);
	RETURN_IF_ERROR(result != 0,
			"failed to free key (pos1=%d)", delPos0);

	pos0 = rte_hash_lookup(handle, &keys[0]);
	print_key_info("Lkp", &keys[0], pos0);
	RETURN_IF_ERROR(pos0 != -ENOENT,
			"fail: found key after deleting! (pos0=%d)", pos0);

	rte_hash_free(handle);
	return 0;
}