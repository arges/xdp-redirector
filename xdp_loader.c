#include <stdio.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <unistd.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <netinet/ether.h>

#define NUM_CPUS 16

struct xdp_test {
	struct bpf_object *obj_main;
	struct bpf_object *obj_devmap;
	struct bpf_program *prog_main;
	struct bpf_program *prog_cpumap;
	struct bpf_program *prog_devmap;
	struct bpf_map *cpu_map;
	struct bpf_map *dev_map;
	struct bpf_map *redirect_map;
	__u8 dst_mac[ETH_ALEN];
};

int cleanup(char *message, struct xdp_test *test, int ret)
{
	if (message) {
		fprintf(stderr, "%s\n", message);
	}
	if (!test) {
		return ret;
	}
	if (test->prog_devmap) {
		bpf_program__unload(test->prog_devmap);
	}
	if (test->prog_cpumap) {
		bpf_program__unload(test->prog_cpumap);
	}
	if (test->prog_main) {
		bpf_program__unload(test->prog_main);
	}
	if (test->obj_devmap) {
		bpf_object__close(test->obj_devmap);
	}
	if (test->obj_main) {
		bpf_object__close(test->obj_main);
	}
	return ret;
}

int parse_mac(char *input_string, __u8 output_bytes[ETH_ALEN])

{
	if (sscanf(input_string, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
	           &output_bytes[0], &output_bytes[1], &output_bytes[2],
	           &output_bytes[3], &output_bytes[4], &output_bytes[5]) != 6) {
		return -1;
	}
	return 0;
}


int main(int argc, char **argv)
{
	struct xdp_test obj;

	if (argc != 4) {
		printf(
			"usage: %s <source device> <target device> <orig mac> <new mac>\n",
			argv[0]);
		return -1;
	}

	// get interface indicied
	int source_ifindex = if_nametoindex(argv[1]);
	if (source_ifindex == 0) {
		return cleanup(
			"Error: could not find source network interface.", &obj,
			1);
	}
	int target_ifindex = if_nametoindex(argv[2]);
	if (target_ifindex == 0) {
		return cleanup(
			"Error: could not find target network interface.", &obj,
			1);
	}

	// get mac addresses
	if (parse_mac(argv[3], obj.dst_mac)) {
		return cleanup("Error: invalid new dst mac address.", &obj, 1);
	}

	// load xdp_main program
	obj.obj_main = bpf_object__open_file("xdp_main.o", NULL);
	if (!obj.obj_main) {
		return cleanup("Error: could not load xdp object file.", &obj,
		               1);
	}
	if (bpf_object__load(obj.obj_main)) {
		return cleanup("Error: could not load bpf object.", &obj, 1);
	}
	obj.prog_main = bpf_object__find_program_by_name(
		obj.obj_main, "xdp_main");
	if (!obj.prog_main) {
		return cleanup("Error: could not find xdp name.", &obj, 1);
	}

	// setup secondary cpumap program
	obj.prog_cpumap = bpf_object__find_program_by_name(obj.obj_main, "xdp_cpumap");
	if (!obj.prog_cpumap) {
		return cleanup("Error: could not find xdp name.", &obj, 1);
	}

	// get cpumap from obj
	obj.cpu_map = bpf_object__find_map_by_name(obj.obj_main, "cpu_map");
	if (!obj.cpu_map) {
		return cleanup("Error: could not find map.", &obj, 1);
	}
	int cpu_map_fd = bpf_map__fd(obj.cpu_map);
	struct bpf_cpumap_val val = {
		.qsize = 64,
		.bpf_prog.id = bpf_program__fd(obj.prog_cpumap),
	};

	// update map to point at secondary program
	for (int i = 0; i < NUM_CPUS; i++) {
		__u32 cpu_id = i;
		if (bpf_map_update_elem(cpu_map_fd, &cpu_id, &val, BPF_ANY)) {
			return cleanup("Error: could not update map.", &obj, 1);
		}
	}

	// set up third program
	obj.obj_devmap = bpf_object__open_file("xdp_devmap.o", NULL);
	if (!obj.obj_devmap) {
		return cleanup("Error: could not load xdp devmap object file.",
		               &obj, 1);
	}
	if (bpf_object__load(obj.obj_devmap)) {
		return cleanup("Error: could not load devmap bpf object.", &obj,
		               1);
	}

	obj.prog_devmap = bpf_object__find_program_by_name(
		obj.obj_devmap, "xdp_devmap");
	if (!obj.prog_devmap) {
		return cleanup("Error: could not find xdp name.", &obj, 1);
	}

	// get devmap from obj
	obj.dev_map = bpf_object__find_map_by_name(obj.obj_main, "dev_map");
	if (!obj.dev_map) {
		return cleanup("Error: could not find devmap.", &obj, 1);
	}

	// update map to point at target interface
	int dev_map_fd = bpf_map__fd(obj.dev_map);
	int dev_index = 0;
	if (bpf_map_update_elem(dev_map_fd, &dev_index, &target_ifindex, 0)) {
		return cleanup("Error: could not update dev map.", &obj, 1);
	}

	// setup redirect map
	obj.redirect_map = bpf_object__find_map_by_name(
		obj.obj_main, "redirect_map");
	if (!obj.redirect_map) {
		return cleanup("Error: could not find redirect_map.", &obj, 1);
	}
	int redirect_map_fd = bpf_map__fd(obj.redirect_map);
	int zero = 0;
	if (bpf_map_update_elem(redirect_map_fd, &zero, &obj.dst_mac, 0)) {
		return cleanup("Error: could not update mac map.", &obj, 1);
	}

	// ensure modes are the same
	if (bpf_xdp_attach(target_ifindex, bpf_program__fd(obj.prog_devmap), XDP_FLAGS_DRV_MODE, NULL)) {
		return cleanup("Error: could not attach xdp program to target.",
			       &obj, 1);
	}
	if (bpf_xdp_attach(source_ifindex, bpf_program__fd(obj.prog_main), XDP_FLAGS_DRV_MODE, NULL)) {
		return cleanup("Error: could not attach xdp program to source.",
			       &obj, 1);
	}

	// wait until char pressed then clean up
	printf("Attached XDP program %s source %s target %s.\n",
	       bpf_program__name(obj.prog_main), argv[1], argv[2]);
	printf("source_ifindex %d target_ifindex %d\n", source_ifindex,
	       target_ifindex);
	printf("obj %p main %p cpumap %p map %p\n", obj.obj_main, obj.prog_main,
	       obj.prog_cpumap, obj.cpu_map);
	printf("Press enter to exit...\n");
	getchar(); // Wait for user input to keep the program attached
	return cleanup(NULL, &obj, 0);
}