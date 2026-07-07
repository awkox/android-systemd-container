#include "asc.h"

/**
 * seccomp_apply_minimal()
 *
 * 阻止直接控制宿主机内核的提权攻击向量 (内核模块加载，kexec)。
 * 无论运行在何种模式，它都会被应用到容器。
 */
int seccomp_apply_minimal(const int privileged_mask) {
  if (privileged_mask & PRIV_NOSEC)
    return 0;

  static struct sock_filter filter[78];
  int curr = 0;

  /* 1. 验证运行架构 */
  filter[curr++] = (struct sock_filter)BPF_STMT(
      BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
#ifdef __aarch64__
  filter[curr++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                AUDIT_ARCH_AARCH64, 1, 0);
#elifdef __x86_64__
  filter[curr++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                AUDIT_ARCH_X86_64, 1, 0);
#elifdef __arm__
  filter[curr++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                AUDIT_ARCH_ARM, 1, 0);
#elifdef __i386__
  filter[curr++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                AUDIT_ARCH_I386, 1, 0);
#endif
  filter[curr++] =
      (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);

  /* 2. 载入 syscall 调用号 */
  filter[curr++] = (struct sock_filter)BPF_STMT(
      BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));

#ifdef __x86_64__
  /* 3. 阻塞 x32 ABI 兼容层 */
  filter[curr++] =
      (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 0, 1);
  filter[curr++] =
      (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
#endif

  if (!(privileged_mask & PRIV_NOSEC)) {
    /* 4. 阻止内核模块加载 */
    filter[curr++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                  __NR_init_module, 0, 1);
    filter[curr++] =
        (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    filter[curr++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                  __NR_finit_module, 0, 1);
    filter[curr++] =
        (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    filter[curr++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                  __NR_delete_module, 0, 1);
    filter[curr++] =
        (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);

    /* 5. 阻止 kexec 热重启内核 */
    filter[curr++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                  __NR_kexec_load, 0, 1);
    filter[curr++] =
        (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
#ifdef __NR_kexec_file_load
    filter[curr++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                  __NR_kexec_file_load, 0, 1);
    filter[curr++] =
        (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
#endif

#ifdef __NR_clone3
    /* 6. 阻塞 clone3 (防穿透) */
    filter[curr++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                  __NR_clone3, 0, 1);
    filter[curr++] = (struct sock_filter)BPF_STMT(
        BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA));
#endif

    /* 7. unshare(CLONE_NEWUSER) */
    filter[curr++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                  __NR_unshare, 0, 4);
    filter[curr++] = (struct sock_filter)BPF_STMT(
        BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0]));
    filter[curr++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K,
                                                  0x10000000, 0, 1);
    filter[curr++] = (struct sock_filter)BPF_STMT(
        BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
    filter[curr++] = (struct sock_filter)BPF_STMT(
        BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));

    /* 8. clone(CLONE_NEWUSER) */
    filter[curr++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                  __NR_clone, 0, 3);
    filter[curr++] = (struct sock_filter)BPF_STMT(
        BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0]));
    filter[curr++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K,
                                                  0x10000000, 0, 1);
    filter[curr++] = (struct sock_filter)BPF_STMT(
        BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));

     /*
      * 9. CVE-2026-31431 ("Copy Fail") - 缓解漏洞的强制性第二层。
      */
    filter[curr++] = (struct sock_filter)BPF_STMT(
        BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
    filter[curr++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                  __NR_socket, 0, 4);
    filter[curr++] = (struct sock_filter)BPF_STMT(
        BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0]));
    filter[curr++] =
        (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_ALG, 0, 1);
    filter[curr++] = (struct sock_filter)BPF_STMT(
        BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
    filter[curr++] = (struct sock_filter)BPF_STMT(
        BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));

    /*
     * 10. 阻止宿主机时钟修改
     */
#ifdef __NR_settimeofday
    filter[curr++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                  __NR_settimeofday, 0, 1);
    filter[curr++] = (struct sock_filter)BPF_STMT(
        BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
#endif
#ifdef __NR_adjtimex
    filter[curr++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                  __NR_adjtimex, 0, 1);
    filter[curr++] = (struct sock_filter)BPF_STMT(
        BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
#endif
#ifdef __NR_clock_settime
    filter[curr++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                  __NR_clock_settime, 0, 1);
    filter[curr++] = (struct sock_filter)BPF_STMT(
        BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
#endif
#ifdef __NR_clock_adjtime
    filter[curr++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                  __NR_clock_adjtime, 0, 1);
    filter[curr++] = (struct sock_filter)BPF_STMT(
        BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
#endif
#ifdef __NR_clock_settime64
    filter[curr++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                  __NR_clock_settime64, 0, 1);
    filter[curr++] = (struct sock_filter)BPF_STMT(
        BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
#endif

    /* 10b. 阻止内核日志的越权读取 */
#ifdef __NR_syslog
    filter[curr++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                  __NR_syslog, 0, 1);
    filter[curr++] = (struct sock_filter)BPF_STMT(
        BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
#endif
  }

  filter[curr++] =
      (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

  struct sock_fprog prog = {
      .len = (unsigned short)curr,
      .filter = filter,
  };

  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
    log_warn("[SEC] 无法应用基础的 Seccomp 内核隔离机制: %s",
             strerror(errno));
    return -1;
  }
  return 0;
}

/**
 * android_seccomp_setup()
 *
 * 为 Android 兼容性应用的一层附加隔离。
 */
int android_seccomp_setup(const bool block_nested_ns, const int privileged_mask) {
  if (privileged_mask & PRIV_NOSEC)
    return 0;
  int major = 0, minor = 0;
  get_kernel_version(&major, &minor);

  constexpr uint32_t ns_mask = 0x7E020000;

  if (!block_nested_ns && major >= 5)
    return 0;

  const struct sock_filter filter_base[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
#ifdef __aarch64__
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
#elifdef __x86_64__
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
#elifdef __arm__
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_ARM, 1, 0),
#elifdef __i386__
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_I386, 1, 0),
#endif
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
  };

  const struct sock_filter filter_keyring[] = {
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_keyctl, 0, 1),
      BPF_STMT(BPF_RET | BPF_K,
               SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA))};

  const struct sock_filter filter_ns[] = {
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_unshare, 1, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 3),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
               offsetof(struct seccomp_data, args[0])),
      BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, ns_mask, 0, 1),
      BPF_STMT(BPF_RET | BPF_K,
               SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))};

  const struct sock_filter filter_allow[] = {
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
  };

  int filter_len = sizeof(filter_base) / sizeof(struct sock_filter);
  if (major < 5)
    filter_len += sizeof(filter_keyring) / sizeof(struct sock_filter);
  if (block_nested_ns)
    filter_len += sizeof(filter_ns) / sizeof(struct sock_filter);
  filter_len += sizeof(filter_allow) / sizeof(struct sock_filter);

  auto_free struct sock_filter *final_filter =
      static_cast<struct sock_filter *>(malloc(filter_len * sizeof(struct sock_filter)));
  if (!final_filter)
    return -1;

  int curr = 0;
  memcpy(final_filter + curr, filter_base, sizeof(filter_base));
  curr += sizeof(filter_base) / sizeof(struct sock_filter);

  if (major < 5) {
    memcpy(final_filter + curr, filter_keyring, sizeof(filter_keyring));
    curr += sizeof(filter_keyring) / sizeof(struct sock_filter);
  }

  if (block_nested_ns) {
    log_info(
        "[SEC] 激活 --block-nested-namespaces: 已强制拦截后续的命名空间系统调用。");
    memcpy(final_filter + curr, filter_ns, sizeof(filter_ns));
    curr += sizeof(filter_ns) / sizeof(struct sock_filter);
  }

  memcpy(final_filter + curr, filter_allow, sizeof(filter_allow));

  struct sock_fprog prog = {
      .len = (unsigned short)filter_len,
      .filter = final_filter,
  };

  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
    log_warn("由于未知错误无法应用 Android 附加 Seccomp 滤网: %s", strerror(errno));
    return -1;
  }

  return 0;
}