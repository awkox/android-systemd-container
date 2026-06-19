cmake_minimum_required(VERSION 3.28)

project("Android Systemd Container"
	VERSION 1.0.0
	DESCRIPTION ""
	LANGUAGES C CXX)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

find_package(Threads REQUIRED)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/include/version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/version.h"
    @ONLY
)

add_executable(asc
	src/main.c
	src/utils.c
	src/android/android.c
	src/seccomp.c
	src/mount.c
	src/cgroup.c
	src/net/network.c
	src/terminal.c
	src/console.c
	src/pid.c
	src/boot.c
	src/config.c
	src/container.c
	src/monitor.c
	src/environment.c
	src/documentation.c
	src/hardware.c
	src/net/iptables.c
	src/net/netlink.c
	src/net/dhcp.c
	src/daemon.c
	src/check.c
	src/android/x11.c
	src/android/virgl.c
	src/android/pulseaudio.c
	src/virtualize.c
)
target_include_directories(asc PRIVATE 
    "${CMAKE_CURRENT_SOURCE_DIR}/src/include"
    "${CMAKE_CURRENT_BINARY_DIR}/generated"
)
target_link_libraries(asc PRIVATE
	util
	Threads::Threads
)
target_compile_options(asc PRIVATE
	-ffunction-sections
	-fdata-sections
	-Wall
	-Wextra
	-Wshadow
)
target_link_options(asc PRIVATE
	-Wl,--gc-sections
	-static
)

option(ENABLE_SOCKETD_BACKEND "Enable socketd backend" ON)
if (ENABLE_SOCKETD_BACKEND)
	target_compile_definitions(asc PRIVATE
		DS_ENABLE_SOCKETD_BACKEND=1
	)
	target_sources(asc PRIVATE
		src/socketd_bridge.c
	)
endif()

# LTO检查
include(CheckIPOSupported)
check_ipo_supported(RESULT lto_supported LANGUAGES C CXX)
if(lto_supported)
	set_target_properties(asc PROPERTIES
		INTERPROCEDURAL_OPTIMIZATION TRUE
	)
endif()