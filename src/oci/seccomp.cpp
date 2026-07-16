#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cerrno>
#include <vector>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include "oci/seccomp.h"
#include "utils/log.h"
#include "utils/system.h"
#include "common.h"

namespace {

class BpfBuilder {
public:
    std::vector<sock_filter> filter;

    void stmt(uint16_t code, uint32_t k) {
        filter.push_back(BPF_STMT(code, k));
    }

    void jump(uint16_t code, uint32_t k, uint8_t jt, uint8_t jf) {
        filter.push_back(BPF_JUMP(code, k, jt, jf));
    }

    void deny_syscall(uint32_t nr, uint32_t ret = SECCOMP_RET_KILL_PROCESS) {
        jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1);
        stmt(BPF_RET | BPF_K, ret);
    }

    void validate_arch() {
        stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
#ifdef __aarch64__
        jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0);
#elifdef __x86_64__
        jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);
#else
#error "Unsupported architecture"
#endif
        stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    }

    void load_syscall_nr() {
        stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
    }

    int apply() {
        sock_fprog prog = {
            .len = static_cast<unsigned short>(filter.size()),
            .filter = filter.data(),
        };
        return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
    }
};

} // namespace

/**
 * seccomp_apply_minimal()
 *
 * 阻止直接控制宿主机内核的提权攻击向量 (内核模块加载，kexec)。
 * 无论运行在何种模式，它都会被应用到容器。
 */
int seccomp_apply_minimal(const int privileged_mask) {
  if (privileged_mask & PRIV_NOSEC)
    return 0;

  BpfBuilder bpf;

  /* 1. 验证运行架构 */
  bpf.validate_arch();

  /* 2. 载入 syscall 调用号 */
  bpf.load_syscall_nr();

#ifdef __x86_64__
  /* 3. 阻塞 x32 ABI 兼容层 */
  bpf.jump(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 0, 1);
  bpf.stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
#endif

  /* 4. 阻止内核模块加载 */
  bpf.deny_syscall(SYS_init_module);
  bpf.deny_syscall(SYS_finit_module);
  bpf.deny_syscall(SYS_delete_module);

  /* 5. 阻止 kexec 热重启内核 */
  bpf.deny_syscall(SYS_kexec_load);
  bpf.deny_syscall(SYS_kexec_file_load);

  /*
   * 6. 阻止宿主机时钟修改
   */
  bpf.deny_syscall(SYS_settimeofday, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
  bpf.deny_syscall(SYS_adjtimex, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
  bpf.deny_syscall(SYS_clock_settime, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
  bpf.deny_syscall(SYS_clock_adjtime, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));

  /* 7. 阻止内核日志的越权读取 */
  bpf.deny_syscall(SYS_syslog, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));

  bpf.stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

  if (bpf.apply() < 0) {
    log_error("[SEC] 无法应用基础的 Seccomp 内核隔离机制: %s", strerror(errno));
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
  get_kernel_version(major, minor);

  constexpr uint32_t ns_mask = 0x7E020000;

  if (!block_nested_ns && major >= 5)
    return 0;

  BpfBuilder bpf;

  bpf.validate_arch();
  bpf.load_syscall_nr();

  if (major < 5) {
    bpf.deny_syscall(SYS_keyctl, SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA));
  }

  if (block_nested_ns) {
    log_info("[SEC] 激活 block-nested-namespaces: 已强制拦截后续的命名空间系统调用。");
    bpf.jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_unshare, 1, 0);
    bpf.jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone, 0, 3);
    bpf.stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0]));
    bpf.jump(BPF_JMP | BPF_JSET | BPF_K, ns_mask, 0, 1);
    bpf.stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
  }

  bpf.stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

  if (bpf.apply() < 0) {
    log_error("由于未知错误无法应用 Android 附加 Seccomp 滤网: %s", strerror(errno));
    return -1;
  }

  return 0;
}