// #ifndef ASC_UTILS_LOG_H
// #define ASC_UTILS_LOG_H

// [[gnu::format(printf, 3, 4)]]
// void log_internal(const char *prefix, bool is_err, const char *fmt, ...);

// #define log_info(fmt, ...) log_internal("+", false, fmt __VA_OPT__(,) __VA_ARGS__)
// #define log_warn(fmt, ...) log_internal("!", true, fmt __VA_OPT__(,) __VA_ARGS__)
// #define log_error(fmt, ...) log_internal("-", true, fmt __VA_OPT__(,) __VA_ARGS__)

// #endif

#ifndef ASC_UTILS_LOG_H
#define ASC_UTILS_LOG_H

#include <cstdio>
#include <format>
#include <string_view>
#include <utility>
#include <print>

template <typename... Args>
inline void log_internal(const char* prefix, bool is_err, 
                         std::format_string<Args...> fmt, Args&&... args) {
    FILE* out = is_err ? stderr : stdout;
    
    // 直接一次性格式化并打印输出，不需要中间的 buffer，底层自动做最高效的处理
    std::print(out, "[{}] {}\r\n", prefix, std::format(fmt, std::forward<Args>(args)...));
    fflush(out);
}

// 用内联模板函数取代原先的 #define 宏
template <typename... Args>
inline void log_info(std::format_string<Args...> fmt, Args&&... args) {
    log_internal("+", false, fmt, std::forward<Args>(args)...);
}

template <typename... Args>
inline void log_warn(std::format_string<Args...> fmt, Args&&... args) {
    log_internal("!", true, fmt, std::forward<Args>(args)...);
}

template <typename... Args>
inline void log_error(std::format_string<Args...> fmt, Args&&... args) {
    log_internal("-", true, fmt, std::forward<Args>(args)...);
}

#endif