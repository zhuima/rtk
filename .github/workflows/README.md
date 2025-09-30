# GitHub Actions 工作流说明

本项目包含三个主要的 GitHub Actions 工作流，用于自动化构建、测试和发布流程。

## 📋 工作流概览

### 1. CI (Continuous Integration) - `ci.yml`

**触发条件：**
- 推送到 `main` 或 `develop` 分支
- 创建针对 `main` 或 `develop` 分支的 Pull Request

**主要功能：**
- 🔍 代码格式检查 (`cargo fmt`)
- 🔧 代码质量检查 (`cargo clippy`)
- 🧪 运行测试套件 (`cargo test`)
- 🏗️ 多平台构建验证 (Linux, macOS, Windows)

### 2. Release - `release.yml`

**触发条件：**
- 推送版本标签 (如 `v1.0.0`)
- 手动触发 (workflow_dispatch)

**主要功能：**
- 📦 创建 GitHub Release
- 🏗️ 多平台交叉编译构建
- 📤 上传二进制文件到 Release
- 🚀 发布到 crates.io (可选)

**支持平台：**
- Linux (x86_64)
- macOS (x86_64 和 ARM64)
- Windows (x86_64)

### 3. Auto Release - `auto-release.yml`

**触发条件：**
- 推送到 `main` 分支 (排除文档更新)

**主要功能：**
- 🔍 自动检测版本变更
- 🏷️ 自动创建版本标签
- 📝 生成详细的 Release Notes
- 🚀 触发完整的发布流程

## 🚀 使用指南

### 自动发布流程

1. **更新版本号**：在 `Cargo.toml` 中修改版本号
   ```toml
   [package]
   version = "0.2.0"  # 从 0.1.0 更新到 0.2.0
   ```

2. **提交并推送到 main 分支**：
   ```bash
   git add Cargo.toml
   git commit -m "bump version to 0.2.0"
   git push origin main
   ```

3. **自动化流程**：
   - `auto-release.yml` 检测到版本变更
   - 运行测试确保代码质量
   - 创建版本标签 `v0.2.0`
   - 触发 `release.yml` 构建多平台二进制文件
   - 创建 GitHub Release 并上传文件

### 手动发布

如果需要手动创建发布：

1. **创建标签**：
   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

2. **或使用 GitHub Actions 手动触发**：
   - 访问 GitHub Actions 页面
   - 选择 "Release" 工作流
   - 点击 "Run workflow"
   - 输入标签名称 (如 `v0.2.0`)

## 🔧 配置要求

### GitHub Secrets

为了完整使用所有功能，需要配置以下 Secrets：

1. **GITHUB_TOKEN** (自动提供)
   - 用于创建 Release 和上传文件

2. **CRATES_TOKEN** (可选)
   - 用于发布到 crates.io
   - 在 [crates.io](https://crates.io/me) 获取 API Token
   - 在仓库设置中添加为 Secret

### 权限设置

确保 GitHub Actions 具有以下权限：
- Contents: Write (创建 Release)
- Actions: Write (触发其他工作流)

## 📦 发布产物

每次发布会生成以下文件：

- `rtk-linux-x86_64.tar.gz` - Linux 64位版本
- `rtk-macos-x86_64.tar.gz` - macOS Intel 版本
- `rtk-macos-aarch64.tar.gz` - macOS Apple Silicon 版本
- `rtk-windows-x86_64.zip` - Windows 64位版本

## 🔍 故障排除

### 常见问题

1. **构建失败**
   - 检查代码是否通过 `cargo test`
   - 确保所有平台都能成功编译

2. **发布失败**
   - 检查版本号是否已存在
   - 确保 GITHUB_TOKEN 权限正确

3. **crates.io 发布失败**
   - 检查 CRATES_TOKEN 是否正确配置
   - 确保版本号在 crates.io 上不存在

### 调试方法

1. **查看工作流日志**：
   - 访问 GitHub Actions 页面
   - 点击失败的工作流查看详细日志

2. **本地测试**：
   ```bash
   # 测试构建
   cargo build --release
   
   # 测试多平台构建
   cargo build --release --target x86_64-unknown-linux-gnu
   ```

## 📈 工作流优化

### 缓存策略

- 使用 `Swatinem/rust-cache@v2` 缓存 Rust 编译产物
- 显著减少构建时间

### 并行构建

- 多平台构建并行执行
- 测试和构建分离，提高效率

### 条件执行

- 智能检测版本变更，避免不必要的发布
- 排除文档更新触发发布流程