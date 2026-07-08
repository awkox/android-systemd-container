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

[[maybe_unused]] static void cfree(const void *p) {
    void **pp = (void **)p;
    if (pp && *pp) {
        free(*pp);
        *pp = nullptr;
    }
}

[[maybe_unused]] static void cfclose(const void *p) {
    FILE **f = (FILE **)p;
    if (f && *f) {
        fclose(*f);
        *f = nullptr;
    }
}

[[maybe_unused]] static void cclose(const void *p) {
    const int *fd = (const int *)p;
    if (fd && *fd >= 0) {
        close(*fd);
    }
}

[[maybe_unused]] static void cclosedir(const void *p) {
    DIR **d = (DIR **)p;
    if (d && *d) {
        closedir(*d);
        *d = nullptr;
    }
}

}

#define _cleanup_(x)  [[gnu::cleanup(x)]]
#define auto_free     _cleanup_(cfree)
#define auto_fclose   _cleanup_(cfclose)
#define auto_close    _cleanup_(cclose)
#define auto_closedir _cleanup_(cclosedir)

#endif // ASC_CLEANUP_H