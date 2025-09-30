use colored::Colorize;

pub fn print_header(title: &str) {
    println!("{}", title.cyan().bold());
    println!("{}", "=".repeat(title.len()).blue());
}

pub fn print_success(msg: &str) {
    println!("{} {}", "✅".green(), msg.green());
}

pub fn print_error(msg: &str) {
    println!("{} {}", "❌".red(), msg.red());
}

pub fn print_warning(msg: &str) {
    println!("{} {}", "⚠️".yellow(), msg.yellow());
}

pub fn print_info(msg: &str) {
    println!("{} {}", "ℹ️".blue(), msg.blue());
}

pub fn print_normal(msg: &str) {
    println!("{}", msg);
}

pub fn print_colored(msg: &str, color: colored::Color) {
    println!("{}", msg.color(color));
}