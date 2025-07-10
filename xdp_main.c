#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define NUM_CPUS 16
#define VLAN_HDR_SZ 4
#define ETH_P_8021AD 0x88A8

struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__type(key, __u32);
	__type(value, struct bpf_cpumap_val);
	__uint(max_entries, 256);
} cpu_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 32);
} dev_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, unsigned char[ETH_ALEN]);
	__uint(max_entries, 32);
} redirect_map SEC(".maps");

SEC("xdp.frags")
int xdp_main(struct xdp_md *ctx)
{
	return bpf_redirect_map(&cpu_map, bpf_get_prandom_u32() % NUM_CPUS, 0);
}

SEC("xdp.frags/cpumap")
int xdp_cpumap(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	if (data + sizeof(struct ethhdr) + VLAN_HDR_SZ > data_end) {
		bpf_printk("pass");
		return XDP_PASS;
	}

	// safely get the target we are redirecting to
	int index = 0, zero = 0;
	__u32 *index_ptr = bpf_map_lookup_elem(&dev_map, &zero);
	if (index_ptr) {
		index = *index_ptr;
	}

	// do redirect
	long status = bpf_redirect(index, 0);
	if (status != XDP_REDIRECT) {
		bpf_printk("failed to redirect");
		return XDP_PASS;
	}

	// get dst mac
	__u8 *new_dst_mac = bpf_map_lookup_elem(&redirect_map, &zero);
	if (!new_dst_mac) {
		bpf_printk("failed to get dst mac");
		return XDP_PASS;
	}

	// Check if we are not using VLAN
	struct ethhdr *eth_frame = data;
	if (eth_frame->h_proto != bpf_htons(ETH_P_8021Q) &&
	    eth_frame->h_proto != bpf_htons(ETH_P_8021AD)) {
		return XDP_REDIRECT;
	}

	// Otherwise strip VLAN header and re-write mac
	unsigned char orig_mac[ETH_ALEN];
	for (int i = 0; i < ETH_ALEN; i++) {
		orig_mac[i] = ((unsigned char *)data)[ETH_ALEN + i];
	}
	__builtin_memcpy(data + VLAN_HDR_SZ, new_dst_mac, ETH_ALEN);
	__builtin_memcpy(data + VLAN_HDR_SZ + ETH_ALEN, orig_mac, ETH_ALEN);
	bpf_xdp_adjust_head(ctx, VLAN_HDR_SZ);

	return XDP_REDIRECT;
}

char _license[] SEC("license") = "GPL";