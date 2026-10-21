/* Explicit canary modification response. No userspace PID signalling.
 * pidfs TGID identity is shared by threads and independent of PID namespaces.
 * A bounded HASH never evicts a live response to admit another process. */
struct response_state {
    struct bpf_spin_lock lock;
    u32 reserved;
    u64 epoch;
    u64 deadline_boot_ns;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, SECMON_RESPONSE_CAPACITY);
    __type(key, u64);
    __type(value, struct response_state);
} responses SEC(".maps");
struct response_observation { u64 epoch; u64 deadline_boot_ns; };

static __always_inline struct file_policy_value *response_config(void *policy)
{
    if (!policy) return 0;
    struct file_key key = { .major = SECMON_RESPONSE_KEY_MAJOR };
    return bpf_map_lookup_elem(policy, &key);
}
static __always_inline int active_response(void *policy, struct response_observation *out)
{
    struct file_policy_value *config = response_config(policy);
    if (!config || !config->response_epoch) return 0;
    u64 epoch = config->response_epoch;
    u64 identity = process_inode(bpf_get_current_task_btf());
    if (!identity) return 0;
    struct response_state *state = bpf_map_lookup_elem(&responses, &identity);
    if (!state) return 0;
    u64 now = bpf_ktime_get_boot_ns();
    bpf_spin_lock(&state->lock);
    out->epoch = state->epoch;
    out->deadline_boot_ns = state->deadline_boot_ns;
    bpf_spin_unlock(&state->lock);
    if (out->epoch == epoch && now < out->deadline_boot_ns) return 1;
    out->epoch = out->deadline_boot_ns = 0;
    return 0;
}
/* Return audit flags. Triggering denial remains independent of allocation/logs. */
static __always_inline u32 start_response(void *policy, struct response_observation *out)
{
    struct file_policy_value *config = response_config(policy);
    if (!config || !config->response_epoch || !config->response_duration_ns) goto failed;
    u64 epoch = config->response_epoch, duration = config->response_duration_ns;
    u64 identity = process_inode(bpf_get_current_task_btf());
    if (!identity) goto failed;
    struct response_state *state = bpf_map_lookup_elem(&responses, &identity);
    if (!state) {
        struct response_state empty = {};
        bpf_map_update_elem(&responses, &identity, &empty, BPF_NOEXIST);
        state = bpf_map_lookup_elem(&responses, &identity);
        if (!state) goto failed;
    }
    u64 now = bpf_ktime_get_boot_ns();
    u32 started = 0;
    bpf_spin_lock(&state->lock);
    /* Concurrent hits never extend the current lease. Older in-flight policy
     * snapshots cannot overwrite a response from a newer epoch. */
    if (state->epoch < epoch || (state->epoch == epoch && now >= state->deadline_boot_ns)) {
        state->epoch = epoch;
        state->deadline_boot_ns = now + duration;
        started = 1;
    }
    out->epoch = state->epoch;
    out->deadline_boot_ns = state->deadline_boot_ns;
    bpf_spin_unlock(&state->lock);
    if (started) count_stat(SECMON_RESPONSE_STARTS);
    return SECMON_CANARY_HIT | (started ? SECMON_RESPONSE_STARTED : 0);
failed:
    count_stat(SECMON_RESPONSE_FAILURES);
    return SECMON_CANARY_HIT | SECMON_RESPONSE_FAILED;
}
static __always_inline int guard_response_task(u32 operation)
{
    struct response_observation response = {};
    if (!active_response(active_file_policy(), &response)) return 0;
    count_stat(SECMON_RESPONSE_DENIALS);
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { count_stat(SECMON_DROPPED); return -13; }
    __builtin_memset(e, 0, sizeof(*e));
    e->version = SECMON_ABI_VERSION;
    e->size = sizeof(*e);
    e->kind = SECMON_RESPONSE_DENIED_EVENT;
    e->operation = operation;
    e->flags = SECMON_RESPONSE_BLOCKED;
    e->response_epoch = response.epoch;
    e->response_deadline_boot_ns = response.deadline_boot_ns;
    e->timestamp_ns = bpf_ktime_get_ns();
    struct task_struct *task = bpf_get_current_task_btf();
    e->start_ns = BPF_CORE_READ(task, start_boottime);
    e->process_inode = process_inode(task);
    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32; e->tid = (u32)id;
    e->caller_uid = BPF_CORE_READ(task, cred, uid.val);
    e->caller_euid = BPF_CORE_READ(task, cred, euid.val);
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return -13;
}
SEC("lsm/task_alloc")
int BPF_PROG(guard_response_fork, struct task_struct *task, unsigned long clone_flags, int ret)
{
    return ret ? ret : guard_response_task(SECMON_OP_TASK_CREATE);
}
