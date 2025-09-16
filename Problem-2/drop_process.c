#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/in.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>

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
    __u16 *allowed_port = bpf_map_lookup_elem(&proc_port, &comm);
    if (allowed_port)
    {
        if (ctx->user_port == *allowed_port)
        {
            return 1;
        }
        else
        {
            return 0;
        }
    }
    return 1;
}