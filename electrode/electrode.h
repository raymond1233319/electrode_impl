#ifndef _ELECTRODE_H
#define _ELECTRODE_H
#include <linux/if_ether.h>

#define ELECTRODE_PORT 3939
#define CLUSTER_SIZE 3
#define REPLICA_MAX_NUM 100
#define NONFRAG_MAGIC 0x20050318
#define FRAG_MAGIC 0x20101010
#define MAGIC_LEN sizeof(__u32)
#define MAXIMUM_TYPE_LEN 40
#define MINIMUM_TYPE_LEN 10
#define ELECTRODE_DATA_LEN 12
#define BROADCAST_SIGN_BIT (1 << 31)
#define QUORUM_SIZE ((CLUSTER_SIZE + 1) >> 1)
#define QUORUM_ARRAY_LENGTH (2 << 10)
#define MAX_DATA_LEN 64
#define FAST_ACK 100
#define WRITE_BUFFER 101
#define PREPARE_TYPE_LEN 33
#define PREPAREOK_TYPE_LEN 35
#define EBPFOK_TYPE_LEN 19

#define validate_paxos_packet(start, end, eth, ip, udp, type_str, extra)                           \
    ({                                                                                             \
        int __valid = 0;                                                                           \
        char *__cursor = (char *)(start);                                                          \
        void *__end = (void *)(end);                                                               \
        do {                                                                                       \
            if (__cursor + sizeof(struct ethhdr) > __end)                                          \
                break;                                                                             \
            (eth) = (struct ethhdr *)__cursor;                                                     \
            __cursor += sizeof(struct ethhdr);                                                     \
            if (__cursor + sizeof(struct iphdr) > __end)                                           \
                break;                                                                             \
            (ip) = (struct iphdr *)__cursor;                                                       \
            __u32 __ihl = (ip)->ihl * 4;                                                           \
            if (__ihl < sizeof(struct iphdr))                                                      \
                break;                                                                             \
            if (__cursor + __ihl > __end)                                                          \
                break;                                                                             \
            if ((ip)->protocol != IPPROTO_UDP)                                                     \
                break;                                                                             \
            __cursor += __ihl;                                                                     \
            if (__cursor + sizeof(struct udphdr) > __end)                                          \
                break;                                                                             \
            (udp) = (struct udphdr *)__cursor;                                                     \
            __cursor += sizeof(struct udphdr);                                                     \
            if ((udp)->dest != htons(ELECTRODE_PORT))                                              \
                break;                                                                             \
            if (__cursor + MAGIC_LEN > __end)                                                      \
                break;                                                                             \
            if (__cursor[0] != 0x18 || __cursor[1] != 0x03 || __cursor[2] != 0x05 ||               \
                __cursor[3] != 0x20)                                                               \
                break;                                                                             \
            __cursor += MAGIC_LEN;                                                                 \
            if (__cursor + sizeof(__u64) > __end)                                                  \
                break;                                                                             \
            __u64 __type_len = *(__u64 *)__cursor;                                                 \
            __cursor += sizeof(__u64);                                                             \
            if (__type_len >= MAXIMUM_TYPE_LEN)                                                    \
                break;                                                                             \
            if (__cursor + __type_len > __end)                                                     \
                break;                                                                             \
            if (__cursor + MINIMUM_TYPE_LEN >= __end)                                              \
                break;                                                                             \
            (type_str) = __cursor;                                                                 \
            __cursor += __type_len;                                                                \
            if (__cursor + ELECTRODE_DATA_LEN > __end)                                             \
                break;                                                                             \
            (extra) = (struct electrode_data *)__cursor;                                           \
            __valid = 1;                                                                           \
        } while (0);                                                                               \
        __valid;                                                                                   \
    })

enum ReplicaStatus { STATUS_NORMAL, STATUS_VIEW_CHANGE, STATUS_RECOVERING };

enum {
    PREPARE_MESSAGE,
    PREPAREOK_MESSAGE,
};

struct peer_config {
    __u32 addr;
    __u16 port;
    char eth[ETH_ALEN];
};

#endif