#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_devmap(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;

	if (data + sizeof(struct ethhdr) > data_end) {
		return XDP_ABORTED;
	}

	bpf_printk("->xdp_devmap size %d ingress %d cpu %d",data_end - data, ctx->ingress_ifindex, bpf_get_smp_processor_id());
	bpf_printk(
		"->src %02x:%02x:%02x:%02x:%02x:%02x dest %02x:%02x:%02x:%02x:%02x:%02x",
		eth->h_source[0], eth->h_source[1], eth->h_source[2],
		eth->h_source[3], eth->h_source[4], eth->h_source[5],
		eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3],
		eth->h_dest[4], eth->h_dest[5]);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";