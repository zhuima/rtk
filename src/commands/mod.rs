pub mod file;
pub mod system;
pub mod network;
pub mod text;
pub mod crypto;
pub mod enhanced_scan;
pub mod syn_scan;

pub use file::FileCommands;
use strum::IntoEnumIterator;

fn to_kebab_case(s: &str) -> String {
    s.replace(' ', "-")
}

pub use system::SystemCommands;
pub use network::NetworkCommands;
pub use text::TextCommands;
pub use crypto::CryptoCommands;

/// 获取所有可用命令用于自动补全建议
/// 
/// 这个函数使用CommandNames trait实现来自动生成完整的可用命令列表。
/// 当添加新的命令变体时，只需更新相应的CommandNames实现。
pub fn get_all_commands() -> Vec<String> {
    let mut commands = Vec::new();
    
    // 自动从每个命令类型中提取命令
    for cmd in FileCommands::iter() {
        commands.push(format!("file {}", to_kebab_case(&cmd.to_string())));
    }

    for cmd in SystemCommands::iter() {
        commands.push(format!("system {}", to_kebab_case(&cmd.to_string())));
    }
    
    for cmd in NetworkCommands::iter() {
        commands.push(format!("network {}", to_kebab_case(&cmd.to_string())));
    }
    
    for cmd in TextCommands::iter() {
        commands.push(format!("text {}", to_kebab_case(&cmd.to_string())));
    }
    
    for cmd in CryptoCommands::iter() {
        commands.push(format!("crypto {}", to_kebab_case(&cmd.to_string())));
    }
    
    // 全局命令 (在session.rs中处理)
    commands.extend([
        "help",
        "clear", 
        "exit",
    ].iter().map(|s| s.to_string()));
    
    commands
}