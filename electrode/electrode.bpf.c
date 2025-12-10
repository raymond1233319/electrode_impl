#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include "linux/tools/lib/bpf/bpf_helpers.h"
#include "electrode.h"

struct control_state
{
	enum ReplicaStatus state;
	int myIdx, leaderIdx;
	__u64 view, lastOp;
};

struct electrode_data
{
	__u32 view_flags;
	__u32 seq;
	__u32 aux_field;
};

struct quorum_entry
{
	__u32 view, seq, bitset, quorum_reached;
};

struct bpf_map_def SEC("maps") xdp_progs_map = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") peer_config_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct peer_config),
	.max_entries = REPLICA_MAX_NUM,
};

struct bpf_map_def SEC("maps") control_state_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct control_state),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") quorum_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct quorum_entry),
	.max_entries = QUORUM_ARRAY_LENGTH,
};

struct bpf_map_def SEC("maps") ring_buffer_map = {
	.type = BPF_MAP_TYPE_RINGBUF,
	.max_entries = 1 << 20,
};

// helper functions
static inline int compute_message_type(char *type_str, void *data_end)
{
	if (type_str + PREPARE_TYPE_LEN < data_end && type_str[19] == 'P' &&
		type_str[20] == 'r' && type_str[21] == 'e' && type_str[22] == 'p' &&
		type_str[23] == 'a' && type_str[24] == 'r' && type_str[25] == 'e' && type_str[26] == 'M')
	{
		return PREPARE_MESSAGE;
	}
	else if (type_str + PREPAREOK_TYPE_LEN < data_end && type_str[19] == 'P' &&
			 type_str[20] == 'r' && type_str[21] == 'e' && type_str[22] == 'p' &&
			 type_str[23] == 'a' && type_str[24] == 'r' && type_str[25] == 'e' &&
			 type_str[26] == 'O' && type_str[27] == 'K')
	{
		return PREPAREOK_MESSAGE;
	}
	else if (type_str + EBPFOK_TYPE_LEN < data_end && type_str[13] == 'E' &&
			 type_str[14] == 'b' && type_str[15] == 'p' && type_str[16] == 'f')
	{
		return PREPAREOK_MESSAGE;
	}
	return -1;
}

static inline __u16 compute_ip_checksum(struct iphdr *ip)
{
	__u32 csum = 0;
	__u16 *next_ip_u16 = (__u16 *)ip;

	ip->check = 0;
#pragma clang loop unroll(full)
	for (int i = 0; i < (sizeof(*ip) >> 1); i++)
	{
		csum += *next_ip_u16++;
	}

	return ~((csum & 0xffff) + (csum >> 16));
}

static inline int handle_ACK(struct electrode_data *extra, struct udphdr *udp, char *type_str, void *data_end)
{
	__u32 msg_view = extra->view_flags;
	__u32 msg_seq = extra->seq;
	__u32 msg_replica_idx = extra->aux_field;

	// Compute index into quorum array
	__u32 idx = msg_seq % QUORUM_ARRAY_LENGTH;
	struct quorum_entry *entry = bpf_map_lookup_elem(&quorum_map, &idx);
	if (!entry)
		return XDP_PASS; // if map lookup fails, do nothing special

	// Only count towards quorum if entry matches the same (view,opnum)
	if (entry->view != msg_view || entry->seq != msg_seq)
		return XDP_PASS;

	// Set bit for this replica index in the bitset and compute popcount
	entry->bitset |= 1 << msg_replica_idx; // bitmap per replica id

	// If not at quorum yet, drop to prune noise early
	__u32 quorum_num = __builtin_popcount(entry->bitset);
	if (quorum_num == QUORUM_SIZE - 1)
	{
		entry->quorum_reached = 1; // mark that we've reached quorum
		__u32 zero = 0;
		struct control_state *control_state = bpf_map_lookup_elem(&control_state_map, &zero);
		if (!control_state)
			return XDP_PASS;
		// update lastOp to the highest seen so far
		if (control_state->lastOp < msg_seq)
			control_state->lastOp = msg_seq;
		if (type_str + PREPAREOK_TYPE_LEN < data_end)
			type_str[26] = 'o'; // change "PrepareOK" to "PrepareoK" to indicate quorum reached
		udp->check = 0;
		return XDP_PASS;
	}
	else
		return XDP_DROP;
}

static inline int handle_preparation(struct electrode_data *extra)
{
	__u64 msg_view = extra->view_flags;
	__u64 msg_seq = extra->seq;
	__u64 msg_batchStart = extra->aux_field;

	// Fetch shared context frames: msg_lastOp scratch and control state
	__u32 zero = 0;
	struct control_state *control_state = bpf_map_lookup_elem(&control_state_map, &zero);
	if (!control_state)
		return XDP_PASS;

	// Only operate in NORMAL state; otherwise, conservative handling
	if (control_state->state != STATUS_NORMAL)
		return XDP_PASS;
	// Drop stale messages
	if (msg_view < control_state->view || msg_seq <= control_state->lastOp)
		return XDP_DROP;
	// Newer view: let user space handle view change complexities
	if (msg_view > control_state->view)
		return XDP_PASS;
	// If there's a gap before batchStart, punt to user space for buffering logic
	if (msg_batchStart > control_state->lastOp + 1)
		return XDP_PASS;

	// Record new lastOp in shared scratch and control
	control_state->lastOp = msg_seq;

	return WRITE_BUFFER; // copy payload for user space
}

static inline int write_buffer(void *data, void *data_end)
{
	// points to .proto message.
	char *payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) +
					MAGIC_LEN + sizeof(__u64) + PREPARE_TYPE_LEN + ELECTRODE_DATA_LEN;
	char *payload_tail = payload + MAX_DATA_LEN;
	if (payload >= data_end)
		return XDP_PASS;
	if (payload_tail > data_end)
		return XDP_PASS;

	// Allocate ring buffer record for the payload slice; mirrors kernel->user offload
	char *slot = bpf_ringbuf_reserve(&ring_buffer_map, MAX_DATA_LEN, 0);
	if (!slot)
		return XDP_PASS;

	// Copy byte-by-byte with bounds checks to satisfy verifier
	for (int i = 0; i < MAX_DATA_LEN; ++i)
	{
		char *cursor = payload + i + 1;
		if (cursor <= data_end)
			slot[i] = cursor[-1];
	}

	// Submit to user space; it will read and process asynchronously
	bpf_ringbuf_submit(slot, 0);
	return FAST_ACK;
}

SEC("classifier")
int tc_broadcast(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = NULL;
	struct iphdr *ip = NULL;
	struct udphdr *udp = NULL;
	char *type_str = NULL;
	struct electrode_data *extra = NULL;

	int ok = validate_paxos_packet(data, data_end, eth, ip, udp, type_str, extra);
	if (!ok)
	{
		return TC_ACT_OK;
	}

	// Only handle PrepareMessage for ring broadcast; others pass through
	int msg_type = compute_message_type(type_str, data_end);
	if (msg_type != PREPARE_MESSAGE)
		return TC_ACT_OK;

	__u32 msg_view = extra->view_flags;
	__u32 msg_seq = extra->seq;
	__u32 is_broadcast = msg_view & BROADCAST_SIGN_BIT; // top bit marks broadcast
	msg_view ^= is_broadcast;							// clear flag bit

	// reset quorum tracking window (view/opnum/bitset) if changed
	__u32 idx = msg_seq % QUORUM_ARRAY_LENGTH;
	struct quorum_entry *entry = bpf_map_lookup_elem(&quorum_map, &idx);
	if (entry && entry->quorum_reached && (entry->view != msg_view || entry->seq != msg_seq))
	{
		entry->view = msg_view;
		entry->seq = msg_seq;
		entry->bitset = 0; // reset bitset for new message
	}

	// If not marked for broadcast, let it pass without cloning
	if (!is_broadcast)
		return TC_ACT_OK;

	// Load control state to know leader index and compute ring next hop
	struct control_state *control_state = bpf_map_lookup_elem(&control_state_map, &(__u32){0});
	if (!control_state)
		return TC_ACT_OK;

	char id = (type_str[1] == 'p') ? !control_state->leaderIdx : type_str[0];
	char nxt = id + 1;

	if (nxt == control_state->leaderIdx)
		nxt++;

	type_str[0] = nxt;
	if (type_str[1] == 'p')
		type_str[1] = 'P';

	if (nxt < CLUSTER_SIZE)
		bpf_clone_redirect(skb, skb->ifindex, 0);

	// Revalidate as bpf_clone_redirect may change the underlying packet buffer.
	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;
	ok = validate_paxos_packet(data, data_end, eth, ip, udp, type_str, extra);
	if (!ok)
		return TC_ACT_SHOT;

	// Ensure it have correct view
	extra->view_flags = msg_view;
	extra->seq = msg_seq;
	type_str[0] = 's', type_str[1] = 'p';
	struct peer_config *replicaInfo = bpf_map_lookup_elem(&peer_config_map, &id);
	if (!replicaInfo)
		return TC_ACT_SHOT;
	udp->dest = replicaInfo->port;
	udp->check = 0;
	ip->daddr = replicaInfo->addr;
	ip->check = compute_ip_checksum(ip);
	memcpy(eth->h_dest, replicaInfo->eth, ETH_ALEN);

	return TC_ACT_OK;
}

SEC("xdp")
int xdp_dispatcher(struct xdp_md *ctx)
{

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = NULL;
	struct iphdr *ip = NULL;
	struct udphdr *udp = NULL;
	char *type_str = NULL;
	struct electrode_data *extra = NULL;

	int ok = validate_paxos_packet(data, data_end, eth, ip, udp, type_str, extra);
	if (!ok)
		return XDP_PASS;

	int msg_type = compute_message_type(type_str, data_end);

#ifdef FAST_REPLY
	if (msg_type == PREPARE_MESSAGE)
	{
		int status = handle_preparation(extra);
		if (status == WRITE_BUFFER)
		{
			int wb_status;
			wb_status = write_buffer(data, data_end);
			if (wb_status == FAST_ACK)
				bpf_tail_call(ctx, &xdp_progs_map, 0);
			else
				return wb_status;
		}
		else
			return status;
	}
#endif

#ifdef WAIT_ON_QUORUM
	if (msg_type == PREPAREOK_MESSAGE)
	{
		return handle_ACK(extra, udp, type_str, data_end);
	}

#endif

	return XDP_PASS;
}

SEC("xdp")
int fast_ACK(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = NULL;
	struct iphdr *ip = NULL;
	struct udphdr *udp = NULL;
	char *payload = NULL;
	struct electrode_data *extra = NULL;

	int ok = validate_paxos_packet(data, data_end, eth, ip, udp, payload, extra);
	if (!ok)
		return TC_ACT_OK;

	__u32 zero = 0;
	__u64 msg_lastOp = (__u64)extra->seq;
	struct control_state *control_state = bpf_map_lookup_elem(&control_state_map, &zero);
	if (!control_state)
		return XDP_PASS;

	struct peer_config *leaderInfo =
		bpf_map_lookup_elem(&peer_config_map, &control_state->leaderIdx);
	if (!leaderInfo)
		return XDP_PASS;

	char *cursor = payload;
	char *limit = cursor + EBPFOK_TYPE_LEN + ELECTRODE_DATA_LEN +
				  sizeof(__u64) * 3 + sizeof(__u32);
	if (limit > (char *)data_end)
		return XDP_PASS;

	cursor[13] = 'E';
	cursor[14] = 'b';
	cursor[15] = 'p';
	cursor[16] = 'f';
	cursor[17] = 'O';
	cursor[18] = 'K';

	cursor += EBPFOK_TYPE_LEN;

	__u32 *electrode_data_extra = (__u32 *)cursor;
	electrode_data_extra[0] = control_state->view;
	electrode_data_extra[1] = (__u32)msg_lastOp;
	electrode_data_extra[2] = control_state->myIdx;
	cursor += ELECTRODE_DATA_LEN;

	__u64 *nested = (__u64 *)cursor;
	nested[0] = sizeof(__u64) * 2 + sizeof(__u32);
	nested[1] = control_state->view;
	nested[2] = msg_lastOp;
	cursor += sizeof(__u64) * 3;

	*(__u32 *)cursor = control_state->myIdx;
	cursor += sizeof(__u32);

	udp->source = udp->dest;
	udp->dest = leaderInfo->port;
	__u16 udp_len = cursor - (char *)udp;
	udp->len = htons(udp_len);

	ip->tot_len = htons(udp_len + sizeof(struct iphdr));
	ip->saddr = ip->daddr;
	ip->daddr = leaderInfo->addr;
	ip->check = compute_ip_checksum(ip);

	unsigned char tmp_mac[ETH_ALEN];
	memcpy(tmp_mac, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

	bpf_xdp_adjust_tail(ctx, (void *)cursor - data_end);
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";