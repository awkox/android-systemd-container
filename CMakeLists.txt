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

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/include/version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/version.h"
    @ONLY
)

add_executable(asc
	src/main.c
	src/utils.c
	src/seccomp.c
	src/mount.c
	src/cgroup.c
	src/terminal.c
	src/console.c
	src/pid.c
	src/boot.c
	src/config.c
	src/container.c
	src/monitor.c
	src/hardware.c
	src/netlink.c
	src/daemon.c
	src/check.c
	src/virtualize.c
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
	-Wall
	-Wextra
	-Wshadow
	-Wunused
)
target_link_options(asc PRIVATE
	-Wl,--gc-sections
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