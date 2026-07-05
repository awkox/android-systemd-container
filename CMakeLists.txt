cmake_minimum_required(VERSION 3.28)

project(asc
	VERSION 1.0.0
	DESCRIPTION "Android Systemd Container"
	HOMEPAGE_URL "https://github.com/awkox/android-systemd-container"
	LANGUAGES C CXX)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)
# set(CMAKE_C_CLANG_TIDY clang-tidy)
# set(CMAKE_CXX_CLANG_TIDY clang-tidy)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/include/version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/version.h"
    @ONLY
)

add_executable(asc
	src/main.c
	src/utils.c
	src/fs_mount.c
	src/core/state.c
	src/core/init.c
	src/core/config.c
	src/core/container.c
	src/core/monitor.c
	src/core/daemon.c
	src/core/check.c
	src/utils/string.c
	src/utils/fileio.c
	src/utils/logger.c
	src/utils/workspace.c
	src/utils/process.c
	src/oci/jail.c
	src/oci/seccomp.c
	src/oci/cgroup.c
	src/oci/caps.c
	src/platform/blockdev.c
	src/platform/devices.c
	src/platform/pty.c
	src/platform/console.c
	src/platform/netlink.c
	src/platform/virtual.c
)
target_include_directories(asc PRIVATE 
    "${CMAKE_CURRENT_SOURCE_DIR}/src/include"
    "${CMAKE_CURRENT_BINARY_DIR}/generated"
)
target_link_libraries(asc PRIVATE
	util
)
target_compile_options(asc PRIVATE
	-ffunction-sections
	-fdata-sections
	-O3
	-Wall
	-Wextra
	-Wshadow
	-Wunused
)
target_link_options(asc PRIVATE
	-Wl,--gc-sections
	-Wl,-s
	-static
)

# LTO检查
include(CheckIPOSupported)
check_ipo_supported(RESULT lto_supported LANGUAGES C CXX)
if(lto_supported)
	set_target_properties(asc PROPERTIES
		INTERPROCEDURAL_OPTIMIZATION TRUE
	)
endif()