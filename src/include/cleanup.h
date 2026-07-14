#ifndef ASC_CLEANUP_H
#define ASC_CLEANUP_H

#include <cstdio>
#include <cstdlib>

#include <dirent.h>
#include <unistd.h>

extern "C" {

/*
 * 清理属性辅助工具（类似 RAII 的自动资源管理）
 *
 * 接受 const void* 可以完美兼容 C 和 C++ 的任何指针类型，
 * 同时解决了 const 变量传递时丢失 const 限定符的警告。
 */

[[maybe_unused]] static void cfclose(const void *p) {
    FILE **f = (FILE **)p;
    if (f && *f) {
        fclose(*f);
    }
}

[[maybe_unused]] static void cclose(const void *p) {
    const int *fd = (const int *)p;
    if (fd && *fd >= 0) {
        close(*fd);
    }
}

}

#define _cleanup_(x)  [[gnu::cleanup(x)]]
#define auto_fclose   _cleanup_(cfclose)
#define auto_close    _cleanup_(cclose)

#endif // ASC_CLEANUP_H