use crate::utils::output;
use anyhow::Result;
use clap::Subcommand;
use sysinfo::System;
use strum::{Display, EnumIter};

#[derive(Subcommand, Clone, EnumIter, Display)]
pub enum SystemCommands {
    /// 显示系统信息
    Info,
    /// 显示运行中的进程
    Processes {
        /// 显示的进程数量
        #[arg(short, long, default_value = "10")]
        limit: usize,
    },
    /// 显示内存使用情况
    Memory,
    /// 显示磁盘使用情况
    Disk,
}

pub async fn handle_system_command(command: SystemCommands) -> Result<()> {
    match command {
        SystemCommands::Info => {
            show_system_info().await?;
        }
        SystemCommands::Processes { limit } => {
            show_processes(limit).await?;
        }
        SystemCommands::Memory => {
            show_memory_usage().await?;
        }
        SystemCommands::Disk => {
            show_disk_usage().await?;
        }
    }
    Ok(())
}

async fn show_system_info() -> Result<()> {
    output::print_header("ℹ️ System Information");

    let mut sys = System::new_all();
    sys.refresh_all();

    output::print_normal(&format!("System: {}", System::name().unwrap_or("Unknown".to_string())));
    output::print_normal(&format!("Kernel Version: {}", System::kernel_version().unwrap_or("Unknown".to_string())));
    output::print_normal(&format!("OS Version: {}", os_info::get().version()));
    output::print_normal(&format!("Host Name: {}", System::host_name().unwrap_or("Unknown".to_string())));
    output::print_normal(&format!("CPU Cores: {}", sys.cpus().len()));

    let uptime = System::uptime();
    let days = uptime / 86400;
    let hours = (uptime % 86400) / 3600;
    let minutes = (uptime % 3600) / 60;
    output::print_normal(&format!("Uptime: {} days, {} hours, {} minutes", days, hours, minutes));

    Ok(())
}

async fn show_processes(limit: usize) -> Result<()> {
    output::print_header(&format!("🔍 Top {} Processes", limit));

    let mut sys = System::new_all();
    sys.refresh_all();

    let mut processes: Vec<_> = sys.processes().iter().collect();
    processes.sort_by(|a, b| b.1.cpu_usage().partial_cmp(&a.1.cpu_usage()).unwrap_or(std::cmp::Ordering::Equal));

    output::print_normal("PID  | CPU% | Memory% | Name");
    output::print_normal("-----|------|---------|------");

    for (pid, process) in processes.iter().take(limit) {
        let cpu_usage = process.cpu_usage();
        let memory = process.memory();
        let total_memory = sys.total_memory();
        let memory_percent = (memory as f64 / total_memory as f64) * 100.0;

        output::print_normal(&format!(
            "{:5} | {:4.1} | {:7.1} | {}",
            pid,
            cpu_usage,
            memory_percent,
            process.name()
        ));
    }

    Ok(())
}

async fn show_memory_usage() -> Result<()> {
    output::print_header("💾 Memory Usage");

    let mut sys = System::new_all();
    sys.refresh_all();

    let total_memory = sys.total_memory();
    let used_memory = sys.used_memory();
    let free_memory = sys.free_memory();
    let available_memory = sys.available_memory();

    let total_swap = sys.total_swap();
    let used_swap = sys.used_swap();

    output::print_normal(&format!("Total Memory: {}", format_bytes(total_memory)));
    output::print_normal(&format!("Used Memory:  {}", format_bytes(used_memory)));
    output::print_normal(&format!("Free Memory:  {}", format_bytes(free_memory)));
    output::print_normal(&format!("Available:    {}", format_bytes(available_memory)));

    if total_swap > 0 {
        output::print_normal("");
        output::print_normal(&format!("Total Swap: {}", format_bytes(total_swap)));
        output::print_normal(&format!("Used Swap:  {}", format_bytes(used_swap)));
    }

    Ok(())
}

async fn show_disk_usage() -> Result<()> {
    output::print_header("💿 Disk Usage");

    let mut sys = System::new_all();
    sys.refresh_all();

    output::print_info("Disk information not available in this version");

    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut bytes = bytes as f64;
    let mut unit_index = 0;

    while bytes >= 1024.0 && unit_index < UNITS.len() - 1 {
        bytes /= 1024.0;
        unit_index += 1;
    }

    format!("{:.2} {}", bytes, UNITS[unit_index])
}