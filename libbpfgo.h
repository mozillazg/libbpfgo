#ifndef __LIBBPF_GO_H__
#define __LIBBPF_GO_H__

#ifdef __powerpc64__
#define __SANE_USERSPACE_TYPES__ 1
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

int libbpf_print_fn(enum libbpf_print_level level, // libbpf print level
                    const char *format,            // format used for the msg
                    va_list args) {                // args used by format

  if (level != LIBBPF_WARN)
    return 0;

  int ret;
  char str[300];
  va_list check;

  va_copy(check, args);
  ret = vsnprintf(str, sizeof(str), format, check);
  va_end(check);

  if (ret <= 0) {
    goto done;
  }

  // BUG: https:/github.com/aquasecurity/tracee/issues/1676
  if (strstr(str, "Exclusivity flag on") != NULL) {
    return 0;
  }

  // BUG: https://github.com/aquasecurity/tracee/issues/2446
  if (strstr(str, "failed to create kprobe") != NULL) {
    if (strstr(str, "trace_check_map_func_compatibility") != NULL)
      return 0;
  }

  // AttachCgroupLegacy() will first try AttachCgroup() and it might fail. This
  // is not an error and is the best way of probing for eBPF cgroup attachment
  // link existence.
  if (strstr(str, "cgroup") != NULL) {
    if (strstr(str, "Invalid argument") != NULL)
      return 0;
  }

done:
  return vfprintf(stderr, format, args);
}

void set_print_fn() { libbpf_set_print(libbpf_print_fn); }

extern void perfCallback(void *ctx, int cpu, void *data, __u32 size);
extern void perfLostCallback(void *ctx, int cpu, __u64 cnt);
extern int ringbufferCallback(void *ctx, void *data, size_t size);

struct ring_buffer *init_ring_buf(int map_fd, uintptr_t ctx) {
  struct ring_buffer *rb = NULL;

  rb = ring_buffer__new(map_fd, ringbufferCallback, (void *)ctx, NULL);
  if (!rb) {
    int saved_errno = errno;
    fprintf(stderr, "Failed to initialize ring buffer: %s\n", strerror(errno));
    errno = saved_errno;
    return NULL;
  }

  return rb;
}

struct perf_buffer *init_perf_buf(int map_fd, int page_cnt, uintptr_t ctx) {
  struct perf_buffer_opts pb_opts = {};
  struct perf_buffer *pb = NULL;

  pb_opts.sz = sizeof(struct perf_buffer_opts);

  pb = perf_buffer__new(map_fd, page_cnt, perfCallback, perfLostCallback,
                        (void *)ctx, &pb_opts);
  if (!pb) {
    int saved_errno = errno;
    fprintf(stderr, "Failed to initialize perf buffer: %s\n", strerror(errno));
    errno = saved_errno;
    return NULL;
  }

  return pb;
}

void get_internal_map_init_value(struct bpf_map *map, void *value) {
  size_t psize;
  const void *data;
  data = bpf_map__initial_value(map, &psize);
  memcpy(value, data, psize);
}

int bpf_prog_attach_cgroup_legacy(
    int prog_fd,   // eBPF program file descriptor
    int target_fd, // cgroup directory file descriptor
    int type)      // BPF_CGROUP_INET_{INGRESS,EGRESS}, ...
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.target_fd = target_fd;
  attr.attach_bpf_fd = prog_fd;
  attr.attach_type = type;
  attr.attach_flags = BPF_F_ALLOW_MULTI; // or BPF_F_ALLOW_OVERRIDE

  return syscall(__NR_bpf, BPF_PROG_ATTACH, &attr, sizeof(attr));
}

int bpf_prog_detach_cgroup_legacy(
    int prog_fd,   // eBPF program file descriptor
    int target_fd, // cgroup directory file descriptor
    int type)      // BPF_CGROUP_INET_{INGRESS,EGRESS}, ...
{
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.target_fd = target_fd;
  attr.attach_bpf_fd = prog_fd;
  attr.attach_type = type;

  return syscall(__NR_bpf, BPF_PROG_DETACH, &attr, sizeof(attr));
}

// https://lore.kernel.org/all/20220824233117.1312810-2-haoluo@google.com/
#ifndef bpf_cgroup_iter_order
enum bpf_cgroup_iter_order {
  BPF_ITER_ORDER_UNSPEC = 0,
  BPF_ITER_SELF_ONLY,        /* process only a single object. */
  BPF_ITER_DESCENDANTS_PRE,  /* walk descendants in pre-order. */
  BPF_ITER_DESCENDANTS_POST, /* walk descendants in post-order. */
  BPF_ITER_ANCESTORS_UP,     /* walk ancestors upward. */
};
#define BPF_ITER_LINK_INFO_NO_CGROUP
#endif

// https://lore.kernel.org/bpf/20220926184957.208194-2-kuifeng@fb.com/
#ifndef bpf_iter_task_type
#define BPF_ITER_LINK_INFO_NO_TASK
#endif

struct bpf_link *bpf_prog_attach_iter(struct bpf_program *prog, __u32 map_fd,
                                      enum bpf_cgroup_iter_order order,
                                      __u32 cgroup_fd, __u64 cgroup_id,
                                      __u32 tid, __u32 pid, __u32 pid_fd) {
  DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
  union bpf_iter_link_info linfo;
  memset(&linfo, 0, sizeof(linfo));
  linfo.map.map_fd = map_fd;
#ifndef BPF_ITER_LINK_INFO_NO_CGROUP
  linfo.cgroup.order = order;
  linfo.cgroup.cgroup_fd = cgroup_fd;
  linfo.cgroup.cgroup_id = cgroup_id;
#endif
#ifndef BPF_ITER_LINK_INFO_NO_TASK
  linfo.task.tid = tid;
  linfo.task.pid = pid;
  linfo.task.pid_fd = pid_fd;
#endif
  opts.link_info = &linfo;
  opts.link_info_len = sizeof(linfo);

  return bpf_program__attach_iter(prog, &opts);
}

struct bpf_object *open_bpf_object(char *btf_file_path, char *kconfig_path,
                                   char *bpf_obj_name, const void *obj_buf,
                                   size_t obj_buf_size) {
  struct bpf_object_open_opts opts = {};
  opts.btf_custom_path = btf_file_path;
  opts.kconfig = kconfig_path;
  opts.object_name = bpf_obj_name;
  opts.sz = sizeof(opts);

  struct bpf_object *obj = bpf_object__open_mem(obj_buf, obj_buf_size, &opts);
  if (obj == NULL) {
    int saved_errno = errno;
    fprintf(stderr, "Failed to open bpf object: %s\n", strerror(errno));
    errno = saved_errno;
    return NULL;
  }

  return obj;
}

#endif
