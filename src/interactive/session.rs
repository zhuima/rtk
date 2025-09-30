use anyhow::Result;
use colored::*;
use crate::commands;
use crate::utils::{output, tui::TuiApp};
use clap::{Parser, Subcommand};

pub struct InteractiveSession {
    history: Vec<String>,
}

#[derive(Parser)]
#[command(name = "rtk", disable_help_flag = true)]
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
    /// Web目录扫描命令
    #[command(name = "web-scan")]
    WebScan {
        #[command(subcommand)]
        action: commands::WebScanCommands,
    },
}

impl InteractiveSession {
    pub fn new() ->Self {
        Self {
            history: Vec::new(),
        }
    }

    async fn handle_command(&self, command: Commands) -> Result<()> {
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
            Commands::WebScan { action } => {
                commands::web_scan::handle_web_scan_command(action).await?;
            }
        }
        Ok(())
    }

    pub async fn run(&mut self) -> Result<()> {
        output::print_header("🚀 Starting Interactive Session");
        output::print_info("Type 'help' for available commands or 'exit' to quit");

        let commands = crate::commands::get_all_commands();

        loop {
            if let Some(input) = self.get_user_input(&commands).await? {
                let input = input.trim();
                if input.is_empty() {
                    continue;
                }

                // Add to history
                self.history.push(input.to_string());

                // Handle built-in commands
                match input {
                    "exit" | "quit" => {
                        output::print_info("Goodbye! 👋");
                        break;
                    }
                    "clear" => {
                        print!("\x1B[2J\x1B[1;1H");
                        continue;
                    }
                    "help" => {
                        self.show_help();
                        continue;
                    }
                    _ => {
                        // Parse and execute command
                        if let Err(e) = self.parse_and_execute(input).await {
                            output::print_error(&format!("Error: {}", e));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn get_user_input(&self, commands: &[String]) -> Result<Option<String>> {
        use crate::utils::tui::TuiApp;

        let mut tui = TuiApp::with_history(commands.to_vec(), self.history.clone());
        tui.run()
    }

    async fn parse_and_execute(&self, input: &str) -> Result<()> {
        use clap::Parser;

        let args: Vec<&str> = input.split_whitespace().collect();
        if args.is_empty() {
            return Ok(());
        }

        // Try to parse as a command
        let mut cli_args = vec!["rtk"];
        cli_args.extend(args.iter());
        let cli = Cli::try_parse_from(&cli_args);

        match cli {
            Ok(cli) => {
                if let Some(command) = cli.command {
                    self.handle_command(command).await?;
                } else {
                    output::print_error("Unknown command. Type 'help' for available commands.");
                }
            }
            Err(_) => {
                output::print_error("Invalid command syntax. Type 'help' for available commands.");
            }
        }

        Ok(())
    }

    fn show_help(&self) {
        output::print_header("📖 Help - Available Commands");

        output::print_colored("🚀 Usage Modes:", colored::Color::Cyan);
        output::print_normal("  • Interactive Mode: Type commands below");
        output::print_normal("  • Direct Mode: rtk [COMMAND] [OPTIONS]");
        output::print_normal("    Example: rtk system info, rtk network scan 127.0.0.1");
        println!();

        output::print_colored("📁 File Operations:", colored::Color::Cyan);
        output::print_normal("  file search <pattern>         - Search files by pattern");
        output::print_normal("  file stats [dir]              - Show directory statistics");
        output::print_normal("  file rename <pattern> <replacement> - Batch rename files");
        output::print_normal("  file duplicates [dir]         - Find duplicate files");

        output::print_colored("\n💻 System Information:", colored::Color::Cyan);
        output::print_normal("  system info                   - Show system information");
        output::print_normal("  system processes [count]       - Show running processes");
        output::print_normal("  system memory                - Show memory usage");
        output::print_normal("  system disk                  - Show disk usage");

        output::print_colored("\n🌐 Network Tools:", colored::Color::Cyan);
        output::print_normal("  network get <url>             - Make HTTP GET request");
        output::print_normal("  network ping <host>           - Ping a host");
        output::print_normal("  network scan <host>           - Scan ports (1-65535)");
        output::print_normal("  network dns <domain>          - DNS query");

        output::print_colored("\n📝 Text Processing:", colored::Color::Cyan);
        output::print_normal("  text grep <pattern> <file>    - Search in files");
        output::print_normal("  text replace <pattern> <replacement> <file> - Replace text");
        output::print_normal("  text count <file>             - Count lines/words/chars");
        output::print_normal("  text sort <file>              - Sort file content");

        output::print_colored("\n🔐 Crypto Tools:", colored::Color::Cyan);
        output::print_normal("  crypto hash <file>           - Calculate file hash");
        output::print_normal("  crypto password [length]      - Generate password");
        output::print_normal("  crypto base64 <text>         - Base64 encode/decode");
        output::print_normal("  crypto caesar <text>         - Caesar cipher");

        output::print_colored("\n🕸️  Web Security Tools:", colored::Color::Cyan);
        output::print_normal("  web scan <url>                - Web directory scanning");
        output::print_normal("  web recon <url>               - Web reconnaissance");

        output::print_colored("\n🔧 Other Commands:", colored::Color::Cyan);
        output::print_normal("  help                         - Show this help message");
        output::print_normal("  clear                        - Clear screen");
        output::print_normal("  exit                         - Exit the program");

        output::print_normal("\n💡 Tips:");
        output::print_normal("  • Use Tab key or '/' for command suggestions");
        output::print_normal("  • Direct mode: rtk --help for full CLI help");
        output::print_normal("  • Direct mode: rtk network --help for subcommand help");
    }
}