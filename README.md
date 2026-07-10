**!!!!使用本项目时请务必确保程序不会被意外结束，若意外结束请手动清理资源或重启系统!!!**

### 1. 主控制流与指令分发 (Main Entry & Dispatch)

该流程描述了 `main.cpp` 的执行逻辑，包含权限检查、配置加载以及对 Daemon（守护进程）的代理转发逻辑。

```mermaid
graph TD
    A[main 函数入口] --> B{参数解析 & 校验}
    B --> C{是否为 help 命令?}
    C -- 是 --> D[打印帮助 print_usage]
    C -- 否 --> E{getuid() == 0 ?}
    E -- 否 --> F[拒绝运行: 需 Root 权限]
    E -- 是 --> G[解析容器名及 Config 路径]
    G --> H[config_load 加载配置]
    
    H --> I{NO_PROXY 环境变量?}
    I -- 未设置 --> J[client_run 尝试代理给 Daemon]
    J --> K{socket() & connect() 成功?}
    K -- 是 --> L[通过 epoll 收发数据, 远端执行] --> Z[退出]
    K -- 否: ECONNREFUSED/ENOENT --> M[回退到直接本地执行]
    I -- 已设置 --> M
    
    M --> N{指令分发}
    N -- start --> O[check_requirements_hw 检查内核特性]
    O --> P[cgroup_host_bootstrap 初始化 Cgroup]
    P --> Q((子流程: start_rootfs))
    
    N -- stop --> R[stop_rootfs 发送 SIGRTMIN+3 / SIGKILL]
    
    N -- info --> S[show_info 显示容器状态]
    
    N -- daemon --> T[daemon_run 启动守护进程监听]
    
    Q --> Z
    R --> Z
    S --> Z
    T --> Z
```

#### 代码步骤作用：
*   **权限校验 (`getuid`)**：容器的挂载、命名空间隔离等底层操作强依赖 Linux Root 权限。
*   **配置加载 (`config_load`)**：从配置文件读取内存限制、CPU 配额、特权掩码、镜像路径等。
*   **Daemon 代理 (`client_run`)**：通过 `AF_UNIX` Socket 将命令行参数转发给后台运行的守护进程，实现状态的统一管理，如果守护进程未启动，则回退为当前进程直接执行。

---

### 2. 容器启动控制层 (Container Start)

此流程对应 `container_start.cpp` 中的 `start_rootfs` 函数，负责准备挂载点资源、创建终端并孵化监控进程。

```mermaid
graph TD
    A((开始 start_rootfs)) --> B[acquire_external_lock: open+fcntl 获取文件锁]
    B --> C{检查 existing_pid}
    C -- 运行中 --> D[报错并退出]
    C -- 未运行 --> E{指定了 rootfs 镜像?}
    E -- 是 --> F[mount_rootfs_img: ioctl LOOP_CTL_GET_FREE & mount]
    E -- 否 --> G
    F --> G[检查 Init 二进制可执行权限 access]
    G --> H{开启 volatile_mode?}
    H -- 是 --> I[setup_volatile_overlay: 挂载 OverlayFS]
    H -- 否 --> J
    I --> J[generate_uuid: 从 /dev/urandom 生成]
    J --> K[terminal_create: ioctl TIOCGPTPEER 申请 PTY]
    K --> L[pipe() 创建 PID 同步管道]
    L --> M[monitor_pid = fork()]
    
    M -- "Child (PID=0)" --> N((子流程: monitor_run))
    M -- "Parent (PID>0)" --> O[read() 从管道接收容器 Init PID]
    
    O --> P{前台运行 foreground?}
    P -- 是 --> Q[console_monitor_loop: epoll 监听 PTY 及 STDIN]
    P -- 否 --> R[循环检测 /proc/$PID/root/run/asc 引导标记]
    
    Q --> S[cleanup_container_resources 资源清理 umount/rmdir]
    R --> S
```

#### 代码步骤作用：
*   **资源加锁 (`fcntl`)**：防止并发执行多个 `start` 或 `stop` 破坏同一个容器的文件系统。
*   **挂载镜像 (`mount_rootfs_img`)**：若是文件镜像，通过 `/dev/loop-control` 寻找空闲 loop 设备挂载，探测 ext4/btrfs。
*   **创建 PTY (`asc_openpty`)**：利用 `TIOCGPTPEER` 分配伪终端（Master/Slave），为容器内的终端交互提供宿主机接管通道。
*   **Fork Monitor (`fork`)**：父进程留在宿主机通过管道等待子进程（监控器）回传最终容器进程的 PID，随后进入控制台循环或后台监控。

---

### 3. 监控与命名空间隔离层 (Monitor & Intermediate Process)

对应 `monitor.cpp` 中的 `monitor_run`，该模块是容器的“保姆”，处理重启循环并构建第一层命名空间隔离。

```mermaid
graph TD
    A((开始 monitor_run)) --> B[setsid() 脱离原会话]
    B --> C[配置屏蔽 SIGINT/SIGTERM 等信号]
    C --> D[oom_protect: 写 /proc/self/oom_score_adj=-1000]
    D --> E[cgroup_apply_limits: 应用 memory/cpu/pids 限制]
    
    E --> F{重入循环: reboot_loop}
    F --> G[mid_pid = fork()]
    
    G -- "Child (PID=0)" --> H[中间进程: 负责隔离与引导]
    H --> I[unshare: CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC 等]
    I --> J[init_pid = fork()]
    
    J -- "Child (PID=0)" --> K((子流程: internal_boot))
    J -- "Parent (PID>0)" --> L[将 init_pid 通过管道发给宿主机]
    L --> M[waitpid 阻塞等待 init_pid 退出]
    M --> N[将 init_pid 退出码通过 _exit 返回]
    
    G -- "Parent (PID>0)" --> O[Monitor 进程]
    O --> P[获取 ns_inode: stat /proc/.../ns/pid]
    P --> Q[epoll/signalfd 每 500ms 探测 mid_pid 状态]
    Q --> R[virtualize_update: 覆盖刷新 /proc/meminfo 等虚拟化信息]
    R --> S{mid_pid 退出?}
    S -- 未退出 --> Q
    S -- 退出 --> T{退出码 == REBOOT_EXIT?}
    
    T -- 是 --> U[配置重载, 状态重置, 返回 reboot_loop] --> F
    T -- 否 --> V[cleanup_container_resources 执行彻底的系统清理]
    V --> W[_exit 退出]
```

#### 代码步骤作用：
*   **命名空间建立 (`unshare`)**：中间进程调用 `unshare` 建立 PID、UTS、IPC，甚至 Network、Cgroup 的隔离（根据配置）。
*   **二次 Fork (`fork`)**：中间进程 `unshare(CLONE_NEWPID)` 后，它自己并不在新的 PID 命名空间内，只有它 `fork` 出的子进程（即 `init_pid`）才会成为新 PID 命名空间内的 PID 1。
*   **资源虚拟化轮询 (`virtualize_update`)**：在宿主机端每半秒计算一次容器 CPU/内存的真实消耗，就地覆盖（`write_inplace`）容器内的 `/run/asc/vproc/*` 文件，以骗过 `htop` 等工具。

---

### 4. 容器内部引导层 (Container Internal Boot)

对应 `init.cpp` 中的 `internal_boot`，这是在容器内以 PID 1 运行的最终初始化过程，涉及最敏感的文件系统和权限操作。

```mermaid
graph TD
    A((开始 internal_boot)) --> B[unshare: CLONE_NEWNS 挂载命名空间隔离]
    B --> C[mount: MS_REC | MS_SLAVE/PRIVATE 隔离挂载传播]
    C --> D[mount: MS_BIND 自身绑定 rootfs]
    D --> E[chdir: 进入 rootfs 路径]
    
    E --> F[预创建目录: .old_root, proc, sys, run, tmp]
    F --> G[setup_dev: 挂载 tmpfs 到 /dev, mknod 创建基础设备节点]
    G --> H[mount: 挂载 proc, sysfs]
    H --> I[setup_cgroups: 挂载 cgroup2/tmpfs 到 /sys/fs/cgroup]
    I --> J[mount: 挂载 tmpfs 到 /run, /tmp]
    J --> K[mount: MS_BIND 绑定 Console PTY 到 /dev/console]
    
    K --> L{当前根在 RAMFS 吗?}
    L -- 是 --> M[MS_MOVE + chroot 回退机制切换根]
    L -- 否 --> N[syscall: SYS_pivot_root 切换根文件系统]
    
    M --> O
    N --> O[chdir /]
    
    O --> P[setup_devpts: 挂载 /dev/pts, 链接 /dev/ptmx]
    P --> Q[apply_jail_mask: 通过 bind mount ro 屏蔽敏感 /proc 和 /sys 接口]
    Q --> R[virtualize_init: 生成 meminfo, cpuinfo 并 bind mount 覆盖]
    R --> S[sethostname 重置主机名]
    S --> T[umount2: 卸载并删除 /.old_root]
    
    T --> U[clearenv & 设置初始环境变量]
    U --> V[seccomp_apply_minimal: prctl 配置 BPF 拦截器禁止 kexec/模块加载]
    V --> W[apply_capability_hardening: prctl PR_CAPBSET_DROP 丢弃危险 Caps]
    
    W --> X[terminal_make_controlling: TIOCSCTTY 设置当前控制台]
    X --> Y[dup2: 重定向 stdin/stdout/stderr 到 /dev/console]
    
    Y --> Z[execve: 执行 /sbin/init 移交控制权]
```

#### 代码步骤作用：
*   **挂载传播隔离 (`mount MS_SLAVE`)**：防止容器内部的 mount 操作泄露到宿主机。
*   **切换根目录 (`pivot_root`)**：Linux 中实现容器最核心的系统调用，将当前的 rootfs 切换为我们准备好的镜像目录，并将旧的宿主机根目录挂载到 `/.old_root`。
*   **监狱级掩码 (`apply_jail_mask`)**：将 `/proc/sys`、`/proc/sysrq-trigger`、`/sys/firmware` 等危险路径以 `MS_BIND | MS_RDONLY` 挂载，或者用 `/dev/null` 甚至自定义 `mkfifo` 管道（如针对 `kmsg` 防止 CPU 死循环）屏蔽，阻断容器向宿主机逃逸的通道。
*   **权限降维 (`seccomp` & `capabilities`)**：
    *   `seccomp`: 使用 `BPF` (Berkeley Packet Filter) 配置内核系统调用拦截，禁用 `init_module`, `kexec_load` 等操作宿主机内核的系统调用。
    *   `capabilities`: 调用 `prctl(PR_CAPBSET_DROP)` 丢弃 `CAP_SYS_MODULE`、`CAP_SYS_RAWIO` 等，限制 root 用户的破坏力。
*   **移交控制权 (`execve`)**：用容器自身的 `init` 程序（如 Systemd 或自定义脚本）完全替换当前进程的内存镜像，此时项目代码生命周期结束，容器内应用正式开始接管。