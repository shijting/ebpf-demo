// generated by command: bpftool btf dump file /sys/kernel/btf/vmlinux format c
// > vmlinux.h
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>
#include <sys/cdefs.h>

char __license[] SEC("license") = "Dual MIT/GPL";

char log_fmt_timeout[] = "timeout: %lld %lld";

#define SECOND (1000 * 1000 * 1000)

typedef enum status {
  FILE_PROTECT_ENABLED,
  FILE_PROTECT_TICK,
  FILE_PROTECT_MAX,
} file_protect_state;

typedef struct check_ctx {
  struct dentry *dentry;
  __u64 need_to_be_checked;
  __u64 return_value;
  __u64 root_inode;
} check_ctx;

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, FILE_PROTECT_MAX);
  __type(key, file_protect_state);
  __type(value, __u64);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} states SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, unsigned long);
  __type(value, __u8);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} roots SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024 * 1024);
  __type(key, unsigned long);
  __type(value, __u64);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} banned_access SEC(".maps");

#define MAX_PATH_FRAGEMENTS 256

static __u64 check_file_need_protection(struct bpf_map *map,
                                        unsigned long *inode, __u8 *enabled,
                                        check_ctx *ctx) {
  if (!*enabled) {
    return 0;
  }

  struct dentry *dentry = ctx->dentry;
  int count_down = MAX_PATH_FRAGEMENTS;

  // enumerate from the leaf to root
  while (count_down-- > 0 && dentry != NULL) {
    if (dentry->d_inode->i_ino == *inode) {
      ctx->root_inode = dentry->d_inode->i_ino;
      ctx->need_to_be_checked = 1;
      return 1;
    }
  }

  return 0;
}

static __u64 check_service_status(struct bpf_map *map, file_protect_state *kind,
                                  __u64 *state, check_ctx *data) {
  __u64 now;
  switch (*kind) {
  case FILE_PROTECT_ENABLED:
    if (!*state) {
      data->need_to_be_checked = 0;
      data->return_value = 0;
      return 1; // early return to improve performance. return 1 means to stop
                // iteration.
    }
    break;
  case FILE_PROTECT_TICK:
    now = bpf_ktime_get_ns();
    // now - last > 3 seconds
    // but 3 * SECOND will overflow
    if ((now - *state) / 3 > SECOND) {
      data->return_value = EPERM;
      bpf_trace_printk(log_fmt_timeout, sizeof(log_fmt_timeout), now, *state);
    }
    break;
  case FILE_PROTECT_MAX: // this branch just tell clang to not complaint about
                         // FILE_PROTECT_MAX
    // noop
    break;
    // default: // TAKE CARE!!!! default branch disable enum branch checking.
    //     // noop
    //     break;
  }

  return 0;
}

SEC("lsm/file_open")
int BPF_PROG(check_file_open, struct file *file, int ret) {
  if (ret != 0)
    return ret;

  __u64 counter_init_val = 1;
  __u64 *counter;

  check_ctx data = {
      .dentry = file->f_path.dentry,
      .need_to_be_checked = 0,
      .return_value = 0,
  };

  bpf_for_each_map_elem(&roots, check_file_need_protection, &data, 0);

  if (!data.need_to_be_checked) {
    return 0;
  }

  data.need_to_be_checked = 1;
  bpf_for_each_map_elem(&states, check_service_status, &data, 0);

  if (!data.need_to_be_checked) {
    return 0;
  }

  if (data.return_value != 0) {
    counter = bpf_map_lookup_elem(&banned_access, &data.root_inode);
    if (counter == NULL)
      bpf_map_update_elem(&banned_access, &data.root_inode, &counter_init_val,
                          BPF_ANY);
    else
      __sync_fetch_and_add(counter, 1);
  }

  return data.return_value;
}