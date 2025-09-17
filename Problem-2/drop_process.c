#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/in.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, char[16]);
    __type(value, __u16);
} proc_port SEC(".maps");

SEC("cgroup/connect4")

int drop_other_ports(struct bpf_sock_addr *ctx) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    __u16 dport = ctx->user_port;

    bpf_printk("proc=%s port=%d\n", comm, dport);

    __u16 *allowed = bpf_map_lookup_elem(&proc_port, comm);
    if (allowed && *allowed == dport) {
        bpf_printk("ALLOW %s:%d\n", comm, dport);
        return 1;
    }

    bpf_printk("DROP %s:%d\n", comm, dport);
    return 0;
}

char _license[] SEC("license") = "GPL";