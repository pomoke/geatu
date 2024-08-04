// BPF indirects are terrible.
#define INDIRECT(value, target) \
    bpf_core_read(&value, sizeof(value), (void *)(target))


#define INDIRECT_OR_BAIL(value, target) \
    int _read_ret = bpf_core_read(&value, sizeof(value), (void *)(target)) \
    if (_read_ret != 0) goto end;

#define FALLTHROUGH() if (ret) return ret;
