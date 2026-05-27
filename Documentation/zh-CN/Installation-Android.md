<!--
title: Android 安装指南
section: Basics
order: 1
desc: Droidspaces 的 Android 分步安装指南。Root 你的设备、安装 APK、设置后端，并通过零终端命令运行 Linux 容器。
keywords: install, droidspaces, android, rooted, container, apk, atomic, backend, sparse, image, linux
-->

# Android 安装指南

Droidspaces 在 Android 上旨在提供"零终端"体验。从首次安装到运行完整的 Linux 发行版，一切都通过直观的 Android 应用完成。

## 前提条件

1. **已 Root 的设备**，使用[此处](../../README_CN.md#rooting-requirements)列出的受支持的 Root 方案
2. **兼容的内核**，已启用 Droidspaces 支持（请参阅[内核配置指南](./Kernel-Configuration.md)）

## 第 1 步：安装应用

1. 从[最新发布版本](https://github.com/ravindu644/Droidspaces-OSS/releases/latest)下载 **Droidspaces APK**。
2. 在你的设备上安装 APK。
3. **授予 Root 权限**并打开应用。

## 第 2 步：自动后端设置

首次启动时，Droidspaces 会执行后端系统的**原子安装**：
- 它会检测你的设备架构（`aarch64`、`armhf` 等）。
- 它将 `droidspaces` 和 `busybox` 二进制文件解压到 `/data/local/Droidspaces/bin`。
- 它执行原子移动操作，确保即使旧版本当前正在运行，二进制文件也能正确安装。
- 它验证校验和以确保零损坏。

## 第 3 步：设置你的第一个容器

你无需手动解压 rootfs 文件。应用会处理一切：

1. **下载 rootfs tarball**：我们推荐使用我们的[官方 rootfs tarball](https://github.com/ravindu644/Droidspaces-rootfs-builder/releases/latest)——这些是**专门为 Android 优化过的**——或官方的 [Linux Containers 镜像](https://images.linuxcontainers.org/images/)。
2. **打开容器选项卡**：点击底部导航栏中的中间图标。
3. **添加容器**：点击右下角的 **"+"** 按钮。
4. **选择你的 Tarball**：选择下载的 `.tar.xz` 或 `.tar.gz` 文件。
5. **配置向导**：
   - **名称**：为你的容器起一个友好的名称。
   - **功能**：根据需要切换硬件加速、IPv6、网络隔离、Android 存储集成等。
   - **容器类型**：我们推荐使用**稀疏镜像**，以便在 Android 的 f2fs 存储上获得更好的性能和稳定性，同时避免奇怪的 SELinux/Keyring 问题。
6. **安装**：应用将解压 tarball 并自动应用**解压后修复**（DNS、屏蔽无用/危险的服务以及安全 Udev）。

## 验证与设置

你可以随时验证系统状态：
1. 前往**设置**（齿轮图标）-> **需求**。
2. 点击**检查需求**。这会在内部运行完整的 `droidspaces check` 套件。
3. **内核配置**：如果你是一位内核开发者，你可以找到一���可复制的 `droidspaces.config` defconfig 片段，类似于[此页面](./Kernel-Configuration.md#required-kernel-configuration)，以确保你的内核与 Droidspaces 完全兼容。

## 下一步

- [Android 应用使用指南](./Usage-Android-App.md)：了解管理详情。
- [GPU 加速指南](./GPU-Acceleration.md)：启用硬件加速的桌面环境。
- [Linux CLI 指南](./Linux-CLI.md)：提供专家级命令行访问。
