use crate::utils::output;
use anyhow::Result;
use clap::Subcommand;
use colored::*;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::fs;
use strum::{Display, EnumIter};
use base64::{Engine, engine::general_purpose::STANDARD};

#[derive(Subcommand, Clone, EnumIter, Display)]
pub enum CryptoCommands {
    /// 计算文件哈希
    Hash {
        /// 要哈希的文件
        #[arg(short, long)]
        file: String,
        /// 哈希算法 (md5, sha1, sha256, sha512)
        #[arg(short, long, default_value = "sha256")]
        algorithm: String,
    },
    /// 生成安全密码
    Password {
        /// 密码长度
        #[arg(short, long, default_value = "16")]
        length: usize,
        /// 包含大写字母
        #[arg(long, default_value = "true")]
        uppercase: bool,
        /// 包含小写字母
        #[arg(long, default_value = "true")]
        lowercase: bool,
        /// 包含数字
        #[arg(long, default_value = "true")]
        numbers: bool,
        /// 包含符号
        #[arg(long)]
        symbols: bool,
    },
    /// Base64编码/解码
    Base64 {
        /// 输入文本或文件
        input: String,
        /// 解码而不是编码
        #[arg(short, long)]
        decode: bool,
        /// 将输入视为文件路径
        #[arg(short, long)]
        file: bool,
    },
    /// 简单文本加密 (凯撒密码)
    Caesar {
        /// 要加密/解密的文本
        text: String,
        /// 偏移量
        #[arg(short, long, default_value = "3")]
        shift: i32,
        /// 解密而不是加密
        #[arg(short, long)]
        decrypt: bool,
    },
}

pub async fn handle_crypto_command(command: CryptoCommands) -> Result<()> {
    match command {
        CryptoCommands::Hash { file, algorithm } => {
            calculate_hash(&file, &algorithm).await?;
        }
        CryptoCommands::Password {
            length,
            uppercase,
            lowercase,
            numbers,
            symbols,
        } => {
            generate_password(length, uppercase, lowercase, numbers, symbols).await?;
        }
        CryptoCommands::Base64 {
            input,
            decode,
            file,
        } => {
            handle_base64(&input, decode, file).await?;
        }
        CryptoCommands::Caesar {
            text,
            shift,
            decrypt,
        } => {
            caesar_cipher(&text, shift, decrypt).await?;
        }
    }
    Ok(())
}

async fn calculate_hash(file_path: &str, algorithm: &str) -> Result<()> {
    output::print_header(&format!("🔐 Calculating {} hash for: {}", algorithm, file_path));

    let content = fs::read(file_path)?;
    let hash = match algorithm.to_lowercase().as_str() {
        "md5" => {
            return Err(anyhow::anyhow!("MD5 not yet implemented"));
        }
        "sha1" => {
            use sha1::{Digest, Sha1};
            let mut hasher = Sha1::new();
            hasher.update(&content);
            format!("{:x}", hasher.finalize())
        }
        "sha256" => {
            let mut hasher = Sha256::new();
            hasher.update(&content);
            format!("{:x}", hasher.finalize())
        }
        "sha512" => {
            use sha2::Sha512;
            let mut hasher = Sha512::new();
            hasher.update(&content);
            format!("{:x}", hasher.finalize())
        }
        _ => {
            return Err(anyhow::anyhow!("Unsupported algorithm: {}", algorithm));
        }
    };

    output::print_normal(&format!("{}: {}", algorithm.to_uppercase(), hash));
    Ok(())
}

async fn generate_password(length: usize, uppercase: bool, lowercase: bool, numbers: bool, symbols: bool) -> Result<()> {
    output::print_header(&format!("🔐 Generating password (length: {})", length));

    let mut charset = String::new();
    if uppercase { charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ"); }
    if lowercase { charset.push_str("abcdefghijklmnopqrstuvwxyz"); }
    if numbers { charset.push_str("0123456789"); }
    if symbols { charset.push_str("!@#$%^&*()_+-=[]{}|;:,.<>?"); }

    if charset.is_empty() {
        return Err(anyhow::anyhow!("At least one character type must be selected"));
    }

    let password: String = (0..length)
        .map(|_| {
            let idx = rand::rng().random_range(0..charset.len());
            charset.chars().nth(idx).unwrap()
        })
        .collect();

    output::print_success(&format!("Generated password: {}", password));
    Ok(())
}

async fn handle_base64(input: &str, decode: bool, is_file: bool) -> Result<()> {
    let content = if is_file {
        fs::read_to_string(input)?
    } else {
        input.to_string()
    };

    if decode {
        match STANDARD.decode(&content) {
            Ok(decoded_vec) => {
                output::print_header("🔓 Base64 Decoded:");
                output::print_normal(&String::from_utf8_lossy(&decoded_vec));
            }
            Err(e) => {
                output::print_error(&format!("Base64 decode failed: {}", e));
            }
        }
    } else {
        let encoded = STANDARD.encode(content);
        output::print_header("🔒 Base64 Encoded:");
        output::print_normal(&encoded);
    }

    Ok(())
}

async fn caesar_cipher(text: &str, shift: i32, decrypt: bool) -> Result<()> {
    output::print_header(&format!("🔐 Caesar Cipher (shift: {}, decrypt: {})", shift, decrypt));

    let actual_shift = if decrypt { -shift } else { shift };
    let result: String = text
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                let shifted = ((c as u8 - base + actual_shift as u8 + 26) % 26 + base) as u8;
                shifted as char
            } else {
                c
            }
        })
        .collect();

    output::print_normal(&format!("Result: {}", result));
    Ok(())
}