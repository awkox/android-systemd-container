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
	src/main.cpp
	src/fs_mount.cpp

	# Core - container lifecycle
	src/core/config.cpp
	src/core/container_start.cpp
	src/core/container_stop.cpp
	src/core/init.cpp
	src/core/monitor.cpp
	src/core/state.cpp
	src/core/check.cpp

	# Core - daemon
	src/core/daemon_protocol.cpp
	src/core/daemon_server.cpp
	src/core/daemon_client.cpp

	# OCI - security & resource control
	src/oci/caps.cpp
	src/oci/cgroup.cpp
	src/oci/jail.cpp
	src/oci/seccomp.cpp

	# Platform - system interaction
	src/platform/blockdev.cpp
	src/platform/console.cpp
	src/platform/devices.cpp
	src/platform/netlink.cpp
	src/platform/pty.cpp

	# Utils - helpers
	src/utils/fileio.cpp
	src/utils/logger.cpp
	src/utils/process.cpp
	src/utils/string.cpp
	src/utils/workspace.cpp
	src/utils/system.cpp
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
