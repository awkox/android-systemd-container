# AGENTS.md

## 必须遵守的规范

### 项目以简洁实用为核心目标

### 始终使用中文回答

所有回复、注释、解释必须使用中文。

### 新功能实现前必须审查

在实现任何新功能之前，必须先搜索代码库确认是否已有相同实现。
避免重复造轮子，优先复用现有代码。

### 单一职责原则

所有代码必须遵守单一职责。
如果发现某一功能的实现代码内在做明显不符合职责的行为，应将其提取出来

### 遵守关注点分离原则

### 注释规范

所有注释禁止使用"==="、"----"这类没有任何作用的符号进行美化

## 构建与运行

```bash
cmake -S . -B build      # 配置 (生成 build/generated/version.h)
cmake --build build       # 编译
./build/asc help          # 运行
```

单一二进制文件 `asc`，静态链接 (`-static`)，目标平台为 aarch64 Linux / Android。除 `libutil` 外无外部依赖。

大部分命令需要 root 权限 (`getuid() == 0`)。

## 语言与代码风格

C++23 with GNU extensions (`-std=gnu++23`)。编译器：GCC（CI 使用 `ubuntu-24.04-arm` 上的 `g++`）。

广泛使用的可选模式：`src/include/cleanup.h` 中的 `[[gnu::cleanup]]` RAII 宏 — `auto_free`、`auto_fclose`、`auto_close`、`auto_closedir`。新增资源类型应遵循此模式。

强制开启的警告：`-Wall -Wextra -Wshadow -Wunused`。

注释和 CI 步骤名称为中文。

## 源码布局

```
src/
├── main.cpp           # CLI 入口与调度
├── fs_mount.cpp       # 文件系统挂载/卸载
├── core/              # 容器生命周期、守护进程 IPC、init、monitor、配置
├── oci/               # 能力集、cgroups、seccomp、命名空间监狱
├── platform/          # loop 设备、PTY、netlink、/proc|/sys|/dev
├── utils/             # fileio、logger、process、string、uuid、system、workspace、firmware
└── include/           # 所有头文件；asc.h 是聚合引用
```

CMakeLists.txt 是编译哪些 `.cpp` 文件的唯一权威来源。

## CI

`ci.yml` 在 push 时触发：配置、构建、创建 GitHub Release。`rootfs.yml` 仅手动触发，用于构建 Debian rootfs 构件。

## 无 Lint / 格式化 / 测试

无测试框架、无 linter、无格式化工具。CMakeLists.txt 中的 clang-tidy 行已被注释。编译本身即为类型检查。
