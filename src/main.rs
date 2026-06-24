//! CLI 入口点 —— 对应原 main.c。

use std::path::Path;

use asc::check::{check_requirements_detailed, check_requirements_hw};
use asc::config::{config_load, config_load_by_name};
use asc::constants;
use asc::types::{Config, PRIV_NOSEC};
use asc::utils::{
    get_kernel_version, multi_stop, parse_and_validate_names, print_privileged_warning,
    reject_container_name, resolve_argv_paths, set_log_container_name,
    show_container_usage,
};
use asc::{log_error, log_warn};

use asc::cgroup::cgroup_host_bootstrap;
use asc::pid::{
    count_running_containers, ensure_runtime, generate_container_name,
    is_container_running, scan_containers, show_containers,
};
use asc::container::{restart_rootfs, show_info, start_rootfs, stop_rootfs};

fn print_usage() {
    println!(
        "Usage: {} [options] <command>\n\nCommands: start stop restart usage info pid show scan check mode help daemon",
        asc::constants::PROJECT_NAME
    );
}

fn validate_kernel_version() -> i32 {
    match get_kernel_version() {
        Ok((major, minor)) => {
            if major < constants::MIN_KERNEL_MAJOR
                || (major == constants::MIN_KERNEL_MAJOR && minor < constants::MIN_KERNEL_MINOR)
            { log_error!("Kernel too old"); return -1; }
            0
        }
        Err(_) => { log_error!("Failed to detect kernel version."); -1 }
    }
}

fn validate_configuration_cli(cfg: &Config) -> i32 {
    let mut errors = 0;
    if cfg.container_name.is_empty() { log_error!("Container name is mandatory (--name)."); errors += 1; }
    else if reject_container_name(&cfg.container_name).is_err() { errors += 1; }
    if cfg.rootfs_img_path.as_os_str().is_empty() { log_error!("No rootfs image specified."); errors += 1; }
    else if !Path::new(&cfg.rootfs_img_path).exists() {
        log_error!("Rootfs image not found: '{}'", cfg.rootfs_img_path.display()); errors += 1;
    }
    if errors > 0 { -1 } else { 0 }
}

fn auto_resolve_container_name(cfg: &mut Config) -> i32 {
    if !cfg.container_name.is_empty() { return 0; }
    let (count, first_name) = count_running_containers();
    let count = if count == 0 { scan_containers(); count_running_containers().0 } else { count };
    let (count, first_name) = if count == 0 { (count, first_name) } else { count_running_containers() };
    if count == 0 { log_error!("No containers are currently running."); return -1; }
    if count > 1 { log_error!("Multiple containers running."); show_containers(cfg); return -1; }
    if let Some(n) = first_name { cfg.container_name = n; }
    0
}

pub fn main_inner(args: Vec<String>) -> i32 {
    let mut cfg = Config {
        prog_name: args[0].clone(),
        ..Default::default()
    };

    let _resolved = resolve_argv_paths(&args);
    let args: Vec<&str> = args.iter().skip(1).map(|s| s.as_str()).collect();

    let mut discovered_cmd: Option<String> = None;
    let mut raw_names = String::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        match arg {
            "-n" | "--name" => {
                i += 1;
                if i < args.len() {
                    let _ = parse_and_validate_names(args[i]);
                    raw_names = args[i].to_string();
                    cfg.container_name = args[i].to_string();
                }
            }
            "-C" | "--conf" => {
                i += 1;
                if i < args.len() { cfg.config_file = args[i].into(); cfg.config_file_specified = true; }
            }
            "-f" | "--foreground" => cfg.foreground = true,
            "--format" => cfg.format_output = true,
            "--help" => { print_usage(); return 0; }
            a if !a.starts_with('-') && discovered_cmd.is_none() => discovered_cmd = Some(a.to_string()),
            _ => {}
        }
        i += 1;
    }

    let cmd = match discovered_cmd { Some(c) => c, None => { log_error!("Missing command"); return 1; } };
    if cmd == "help" { print_usage(); return 0; }
    if cmd == "mode" {
        println!("{}", if asc::daemon::daemon_probe() { "daemon" } else { "direct" });
        return 0;
    }
    if cmd == "check" { check_requirements_detailed(); return 0; }

    // Daemon 代理：除了 daemon 本身和上面几个不需要 root 的命令，
    // 其余命令都先乐观地尝试代理给后台 daemon 进程执行；daemon 不可达
    // （client_run 返回 -2）才回退到本地直接执行。
    // 对应 C 版 main.c 里的 `client_run()` 调用——这条路径此前在 Rust
    // 重写里完全缺失，导致 daemon 这套 IPC 子系统从未被真正用上。
    let is_daemon_cmd = cmd == "daemon";
    if !is_daemon_cmd && std::env::var("NO_PROXY").is_err() {
        let proxy_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let proxy_ret = asc::daemon::client_run(&proxy_args);
        if proxy_ret != -2 {
            return proxy_ret;
        }
        // -2: daemon 不可达，落回下面的本地直接执行路径。
    }

    if unsafe { libc::getuid() != 0 } { log_error!("Root privileges required for '{}'", cmd); return 1; }

    let is_stateful = matches!(cmd.as_str(), "stop" | "restart" | "pid" | "info" | "usage");

    if !cfg.config_file.as_os_str().is_empty() {
        let cp = cfg.config_file.to_string_lossy().to_string();
        if config_load(&cp, &mut cfg).is_err() { log_error!("Failed to load config"); return 1; }
    }
    if is_stateful && cfg.container_name.is_empty() && auto_resolve_container_name(&mut cfg) < 0 { return 1; }
    if !cfg.container_name.is_empty() && cfg.config_file.as_os_str().is_empty() {
        let name = cfg.container_name.clone();
    if config_load_by_name(&name, &mut cfg).is_err() && is_stateful {
        scan_containers(); config_load_by_name(&name, &mut cfg).ok();
    }
    }

    set_log_container_name(&cfg.container_name);
    ensure_runtime().ok();

    match cmd.as_str() {
        "show" => show_containers(&cfg),
        "scan" => { scan_containers(); 0 }
        "start" => {
            if raw_names.contains(',') {
                log_error!("start does not support multiple containers.");
                return 1;
            }
            if validate_configuration_cli(&cfg) < 0 || validate_kernel_version() < 0 { return 1; }
            if check_requirements_hw(cfg.hw_access).is_err() { return 1; }
            print_privileged_warning(cfg.privileged_mask);
            if cfg.privileged_mask & PRIV_NOSEC != 0 && cfg.block_nested_ns { log_warn!("noseccomp: nested-ns block is NO-OP"); }
            cgroup_host_bootstrap(cfg.force_cgroupv1);
            if cfg.container_name.is_empty() { cfg.container_name = generate_container_name(&cfg.rootfs_img_path.to_string_lossy()); }
            start_rootfs(&mut cfg)
        }
        "stop" => {
            if raw_names.contains(',') {
                match multi_stop(&raw_names) { Ok(()) => 0, Err(_) => 1 }
            } else {
                stop_rootfs(&mut cfg, false)
            }
        }
        "restart" => {
            if raw_names.contains(',') {
                log_error!("restart does not support multiple containers.");
                return 1;
            }
            if check_requirements_hw(cfg.hw_access).is_err() { return 1; }
            print_privileged_warning(cfg.privileged_mask);
            cgroup_host_bootstrap(cfg.force_cgroupv1);
            restart_rootfs(&mut cfg)
        }
        "pid" => match is_container_running(&cfg) {
            Ok(pid) => { println!("{}", pid); 0 }
            Err(_) => { println!("NONE"); 1 }
        },
        "info" => show_info(&cfg, false),
        "usage" => show_container_usage(&cfg).map(|_| 0).unwrap_or(-1),
        "daemon" => asc::daemon::daemon_run(cfg.foreground),
        _ => { log_error!("Unknown command: '{}'", cmd); 1 }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rc = main_inner(args);
    std::process::exit(rc);
}
