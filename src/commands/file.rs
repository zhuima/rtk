use crate::utils::{output, progress};
use anyhow::Result;
use clap::Subcommand;
use colored::Color;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use strum::{Display, EnumIter};
use walkdir::WalkDir;

#[derive(Subcommand, Clone, EnumIter, Display)]
pub enum FileCommands {
    /// 按名称模式搜索文件
    Search {
        /// 搜索目录
        #[arg(short, long, default_value = ".")]
        dir: String,
        /// 搜索模式 (支持正则表达式)
        pattern: String,
        /// 不区分大小写搜索
        #[arg(short, long)]
        ignore_case: bool,
    },
    /// 获取文件统计信息
    Stats {
        /// 分析目录
        #[arg(short, long, default_value = ".")]
        dir: String,
    },
    /// 批量重命名文件
    Rename {
        /// 包含文件的目录
        #[arg(short, long, default_value = ".")]
        dir: String,
        /// 匹配模式 (正则表达式)
        pattern: String,
        /// 替换字符串
        replacement: String,
        /// 预览模式 (不实际重命名)
        #[arg(short, long)]
        preview: bool,
    },
    /// 查找重复文件
    Duplicates {
        /// 扫描目录
        #[arg(short, long, default_value = ".")]
        dir: String,
    },
}

pub async fn handle_file_command(command: FileCommands) -> Result<()> {
    match command {
        FileCommands::Search {
            dir,
            pattern,
            ignore_case,
        } => {
            search_files(&dir, &pattern, ignore_case).await?;
        }
        FileCommands::Stats { dir } => {
            show_file_stats(&dir).await?;
        }
        FileCommands::Rename {
            dir,
            pattern,
            replacement,
            preview,
        } => {
            batch_rename(&dir, &pattern, &replacement, preview).await?;
        }
        FileCommands::Duplicates { dir } => {
            find_duplicates(&dir).await?;
        }
    }
    Ok(())
}

async fn search_files(dir: &str, pattern: &str, ignore_case: bool) ->Result<()> {
    output::print_header("🔍 Searching files...");

    let regex = if ignore_case {
        Regex::new(&format!("(?i){}", pattern))?
    } else {
        Regex::new(pattern)?
    };

    let mut found_count = 0;

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if let Some(filename) = entry.file_name().to_str() {
            if regex.is_match(filename) {
                let path = entry.path().display();
                output::print_colored(&format!("  ✓ {}", path), Color::Green);
                found_count += 1;
            }
        }
    }

    output::print_success(&format!("Found {} files", found_count));
    Ok(())
}

async fn show_file_stats(dir: &str) ->Result<()> {
    output::print_header("📊 Analyzing directory...");

    let mut total_files = 0;
    let mut total_dirs = 0;
    let mut total_size = 0u64;
    let mut extensions: HashMap<String, (u32, u64)> = HashMap::new();

    let entries: Vec<_> = WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .collect();
    let pb = progress::create_progress_bar(entries.len() as u64);

    for entry in entries {
        pb.inc(1);

        if entry.file_type().is_dir() {
            total_dirs += 1;
        } else {
            total_files += 1;
            if let Ok(metadata) = entry.metadata() {
                let size = metadata.len();
                total_size += size;

                if let Some(ext) = entry.path().extension().and_then(|s| s.to_str()) {
                    let ext = ext.to_lowercase();
                    let entry = extensions.entry(ext).or_insert((0, 0));
                    entry.0 += 1;
                    entry.1 += size;
                }
            }
        }
    }

    pb.finish_with_message("Analysis complete!");

    output::print_normal("");
    output::print_colored("📈 Statistics:", Color::Green);
    output::print_normal(&format!("  Total files: {}", total_files));
    output::print_normal(&format!("  Total directories: {}", total_dirs));
    output::print_normal(&format!("  Total size: {}", format_size(total_size)));

    if !extensions.is_empty() {
        output::print_normal("");
        output::print_colored("📋 File type distribution:", Color::Green);
        let mut ext_vec: Vec<_> = extensions.into_iter().collect();
        ext_vec.sort_by(|a, b| b.1.1.cmp(&a.1.1));

        for (ext, (count, size)) in ext_vec.iter().take(10) {
            output::print_normal(&format!(
                "  .{}: {} files, {}",
                ext,
                count,
                format_size(*size)
            ));
        }
    }

    Ok(())
}

async fn batch_rename(dir: &str, pattern: &str, replacement: &str, preview: bool) -> Result<()> {
    output::print_header(&format!("🔄 Batch rename in {}", dir));

    let regex = Regex::new(pattern)?;
    let mut rename_count = 0;

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            if let Some(filename) = entry.file_name().to_str() {
                if regex.is_match(filename) {
                    let new_name = regex.replace(filename, replacement);
                    let old_path = entry.path();
                    let new_path = old_path.with_file_name(new_name.as_ref());

                    if preview {
                        output::print_normal(&format!("{} -> {}", old_path.display(), new_path.display()));
                    } else {
                        fs::rename(old_path, new_path)?;
                        output::print_success(&format!("Renamed: {} -> {}", filename, new_name));
                    }
                    rename_count += 1;
                }
            }
        }
    }

    if preview {
        output::print_info(&format!("Preview: {} files would be renamed", rename_count));
    } else {
        output::print_success(&format!("Renamed {} files", rename_count));
    }

    Ok(())
}

async fn find_duplicates(dir: &str) -> Result<()> {
    output::print_header(&format!("🔍 Finding duplicate files in {}", dir));

    let mut file_hashes: HashMap<String, Vec<String>> = HashMap::new();
    let entries: Vec<_> = WalkDir::new(dir).into_iter().filter_map(|e| e.ok()).collect();
    let pb = crate::utils::progress::create_progress_bar(entries.len() as u64);

    for entry in entries {
        pb.inc(1);

        if entry.file_type().is_file() {
            if let Ok(content) = fs::read(entry.path()) {
                let mut hasher = Sha256::new();
                hasher.update(&content);
                let hash = format!("{:x}", hasher.finalize());

                file_hashes.entry(hash).or_insert_with(Vec::new).push(
                    entry.path().to_string_lossy().to_string()
                );
            }
        }
    }

    pb.finish_with_message("Analysis complete!");

    let mut duplicates = Vec::new();
    for (hash, files) in file_hashes {
        if files.len() > 1 {
            duplicates.push((hash, files));
        }
    }

    if duplicates.is_empty() {
        output::print_success("No duplicate files found");
    } else {
        output::print_warning(&format!("Found {} sets of duplicate files", duplicates.len()));
        for (hash, files) in duplicates {
            output::print_normal(&format!("Hash: {}", hash));
            for file in &files {
                output::print_normal(&format!("  {}", file));
            }
            output::print_normal("");
        }
    }

    Ok(())
}

fn format_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = size as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    format!("{:.2} {}", size, UNITS[unit_index])
}