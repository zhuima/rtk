# 🦀 RTK (Rust Toolkit) - 强大的命令行安全工具包

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

RTK 是一个功能完整、高性能的 Rust 命令行安全工具包，集成了文件操作、系统监控、网络安全、文本处理、加密工具和 Web 安全等多个模块。无论你是安全研究员、系统管理员还是开发者，RTK 都能为你提供强大而便捷的工具支持。

## ✨ 主要特性

- 🎨 **交互式 Shell 界面** - 支持命令补全、历史记录和彩色输出
- ⚡ **高性能异步处理** - 基于 Tokio 异步运行时，处理速度快
- 🛡️ **安全工具集成** - 端口扫描、Web 目录爆破、漏洞检测
- 🔧 **模块化设计** - 六大功能模块，易于扩展和维护
- 🌈 **美观的终端输出** - 彩色输出和进度条显示
- 📊 **详细的结果报告** - 支持多种输出格式

## 🚀 快速开始

### 环境要求

- Rust 1.70 或更高版本
- 操作系统：Linux、macOS、Windows

### 安装步骤

#### 方法一：从源码编译（推荐）

```bash
# 1. 克隆仓库
git clone https://github.com/zhuima/rtk.git
cd rtk

# 2. 编译项目
cargo build --release

# 3. 运行工具
./target/release/rtk

# 4. 可选：安装到系统路径
cargo install --path .
```

#### 方法二：直接安装（如果已发布到 crates.io）

```bash
cargo install toolkit-rs
```

### 验证安装

```bash
# 查看版本信息
rtk --version

# 查看帮助信息
rtk --help
```

## 📖 使用指南

RTK 支持两种使用模式：

### 1. 交互式模式

直接运行 `rtk` 进入交互式 Shell：

```bash
rtk
```

在交互模式中，你可以：
- 输入 `help` 查看所有可用命令
- 使用 `Tab` 键自动补全命令
- 使用上下箭头键浏览命令历史
- 输入 `exit` 退出程序

### 2. 直接命令模式

直接在命令行中执行特定命令：

```bash
rtk system info
rtk network scan 192.168.1.1
rtk crypto password --length 20
```

## 🛠️ 功能模块详解

### 📁 文件操作 (File)

强大的文件管理和分析工具：

```bash
# 搜索文件（支持正则表达式）
rtk file search --pattern "*.rs" --dir ./src

# 获取目录统计信息
rtk file stats --dir ./

# 批量重命名文件
rtk file rename --pattern "old_name" --replacement "new_name" --dir ./

# 查找重复文件
rtk file duplicates --dir ./
```

**主要功能：**
- 🔍 智能文件搜索（支持正则表达式和大小写忽略）
- 📊 详细的目录统计分析
- 🔄 批量文件重命名（支持预览模式）
- 🔍 重复文件检测和清理

### 💻 系统信息 (System)

全面的系统监控和信息收集：

```bash
# 显示系统详细信息
rtk system info

# 查看运行进程（默认显示前10个）
rtk system processes --limit 20

# 内存使用情况
rtk system memory

# 磁盘使用情况
rtk system disk
```

**主要功能：**
- 🖥️ 系统硬件和软件信息
- 🔄 实时进程监控
- 💾 内存使用分析
- 💿 磁盘空间统计

### 🌐 网络工具 (Network)

专业的网络安全和诊断工具：

```bash
# HTTP 请求测试
rtk network get --url https://httpbin.org/get --headers

# 网络连通性测试
rtk network ping --host google.com --count 5

# 端口扫描（支持服务识别）
rtk network scan --target 192.168.1.1 --start-port 1 --end-port 1000

# DNS 查询
rtk network dns --domain example.com
```

**主要功能：**
- 🌍 HTTP/HTTPS 请求工具
- 📡 网络连通性测试
- 🔍 高性能端口扫描
- 🏷️ 服务版本识别
- 🌐 DNS 解析工具
- 📍 IP 地理位置查询

### 📝 文本处理 (Text)

高效的文本分析和处理工具：

```bash
# 文本搜索（支持正则表达式）
rtk text grep --pattern "fn main" --file src/main.rs --line-numbers

# 文本替换
rtk text replace --pattern "old_text" --replacement "new_text" --file data.txt

# 文件统计
rtk text count --file README.md --lines --words --chars

# 文件排序
rtk text sort --file data.txt
```

**主要功能：**
- 🔍 强大的文本搜索（正则表达式支持）
- 🔄 批量文本替换
- 📊 详细的文件统计
- 📝 文件内容排序

### 🔐 加密工具 (Crypto)

全面的加密和安全工具：

```bash
# 文件哈希计算
rtk crypto hash --file data.txt --algorithm sha256

# 安全密码生成
rtk crypto password --length 16 --symbols

# Base64 编码/解码
rtk crypto base64 "Hello World"
rtk crypto base64 "SGVsbG8gV29ybGQ=" --decode

# 凯撒密码
rtk crypto caesar "secret message" --shift 3
```

**主要功能：**
- 🔐 多种哈希算法（MD5、SHA1、SHA256、SHA512）
- 🔑 安全密码生成器
- 📝 Base64 编码/解码
- 🔄 经典密码算法

### 🕸️ Web 安全工具 (Web)

专业的 Web 安全测试工具：

```bash
# Web 目录扫描
rtk web scan --target http://example.com --threads 50 --extensions php,html,js

# Web 信息收集
rtk web recon --target http://example.com
```

**主要功能：**
- 🔍 Web 目录和文件扫描
- 🕷️ 递归爬虫扫描
- 🛡️ 安全漏洞检测
- 📊 Web 技术栈识别
- 🔍 隐藏文件发现

## 🎯 实用示例

### 安全渗透测试场景

```bash
# 1. 目标信息收集
rtk network dns --domain target.com
rtk web recon --target https://target.com

# 2. 端口扫描
rtk network scan --target target.com --start-port 1 --end-port 65535

# 3. Web 目录扫描
rtk web scan --target https://target.com --threads 100 --recursive

# 4. 生成报告密码
rtk crypto password --length 20 --symbols
```

### 系统管理场景

```bash
# 1. 系统健康检查
rtk system info
rtk system memory
rtk system disk

# 2. 日志文件分析
rtk text grep --pattern "ERROR" --file /var/log/app.log
rtk text count --file /var/log/app.log

# 3. 文件清理
rtk file duplicates --dir /home/user/Downloads
rtk file stats --dir /var/log
```

### 开发调试场景

```bash
# 1. 代码搜索
rtk file search --pattern "TODO" --dir ./src

# 2. API 测试
rtk network get --url http://localhost:8080/api/health --headers

# 3. 文件完整性验证
rtk crypto hash --file important_file.zip --algorithm sha256
```

## ⚙️ 配置选项

### 常用参数

- `--threads`: 设置并发线程数（适用于扫描类命令）
- `--timeout`: 设置超时时间
- `--output-file`: 指定输出文件
- `--verbose`: 启用详细输出
- `--help`: 查看命令帮助

### 环境变量

```bash
# 设置默认超时时间
export RTK_TIMEOUT=30

# 设置默认线程数
export RTK_THREADS=50
```

## 🔧 高级功能

### 批量处理

RTK 支持从文件读取目标列表进行批量处理：

```bash
# 批量端口扫描
echo -e "192.168.1.1\n192.168.1.2\n192.168.1.3" > targets.txt
rtk network scan --file targets.txt
```

### 输出格式

支持多种输出格式：

```bash
# JSON 格式输出
rtk web scan --target http://example.com --output-format json

# 保存到文件
rtk network scan --target 192.168.1.1 --output-file scan_results.txt
```

## 🤝 贡献指南

我们欢迎所有形式的贡献！

### 如何贡献

1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

### 开发环境设置

```bash
# 克隆仓库
git clone https://github.com/zhuima/rtk.git
cd rtk

# 安装开发依赖
cargo build

# 运行测试
cargo test

# 代码格式化
cargo fmt

# 代码检查
cargo clippy
```

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🙏 致谢

- [Rust 社区](https://www.rust-lang.org/community) 提供的优秀生态系统
- 所有贡献者的辛勤工作
- 开源社区的支持和反馈

## 📞 联系方式

- 项目主页: https://github.com/zhuima/rtk
- 问题反馈: https://github.com/zhuima/rtk/issues
- 功能建议: https://github.com/zhuima/rtk/discussions

---

⭐ 如果这个项目对你有帮助，请给我们一个 Star！

🐛 发现 Bug？请提交 Issue 或 Pull Request。

💡 有新想法？欢迎在 Discussions 中分享！