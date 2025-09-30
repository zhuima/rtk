use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;

mod commands;
mod interactive;
mod utils;
mod qqwry;

use interactive::InteractiveSession;
use utils::output;

#[derive(Parser)]
#[command(name = "rtk")]
#[command(about = "Rust Toolkit - A powerful CLI utility collection")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Clone)]
enum Commands {
    /// 文件操作
    File {
        #[command(subcommand)]
        action: commands::FileCommands,
    },
    /// 系统信息
    System {
        #[command(subcommand)]
        action: commands::SystemCommands,
    },
    /// 网络工具
    Network {
        #[command(subcommand)]
        action: commands::NetworkCommands,
    },
    /// 文本处理工具
    Text {
        #[command(subcommand)]
        action: commands::TextCommands,
    },
    /// 加密工具
    Crypto {
        #[command(subcommand)]
        action: commands::CryptoCommands,
    },
    /// Web安全工具
    Web {
        #[command(subcommand)]
        action: commands::WebCommands,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(command) => {
            // Direct command mode
            handle_direct_command(command).await?;
        }
        None => {
            // Interactive mode
            print_welcome();
            let mut session = InteractiveSession::new();
            session.run().await?;
        }
    }

    Ok(())
}

async fn handle_direct_command(command: Commands) -> Result<()> {
    match command {
        Commands::File { action } => {
            commands::file::handle_file_command(action).await?;
        }
        Commands::System { action } => {
            commands::system::handle_system_command(action).await?;
        }
        Commands::Network { action } => {
            commands::network::handle_network_command(action).await?;
        }
        Commands::Text { action } => {
            commands::text::handle_text_command(action).await?;
        }
        Commands::Crypto { action } => {
            commands::crypto::handle_crypto_command(action).await?;
        }
        Commands::Web { action } => {
            commands::web::handle_web_command(action).await?;
        }
    }
    Ok(())
}

fn print_welcome() {
    // 清屏
    print!("\x1B[2J\x1B[1;1H");

    output::print_header("🦀 Welcome to Rust Toolkit");
    println!();
    output::print_info("A powerful collection of CLI utilities.");
    println!();

    output::print_colored("🚀 Usage Modes:", colored::Color::Cyan);
    output::print_normal("  • Interactive Mode: Type commands in this interactive shell");
    output::print_normal("  • Direct Mode: Use commands directly from command line");
    println!();

    output::print_colored("💡 Direct Mode Examples:", colored::Color::Yellow);
    output::print_normal("  rtk system info");
    output::print_normal("  rtk network scan 127.0.0.1");
    output::print_normal("  rtk file search --pattern \"*.rs\" --dir .");
    output::print_normal("  rtk --help (for full CLI help)");
    println!();

    output::print_colored("🎯 Getting Started:", colored::Color::Green);
    println!(
        "{} {} {} {}",
        "Type".bright_black(),
        "help".bright_yellow().bold(),
        "for command list, or".bright_black(),
        "exit".bright_red().bold()
    );
    println!();
}