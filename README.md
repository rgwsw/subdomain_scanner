# 子域名资产扫描工具 (Subdomain Asset Scanner)

一款功能完善的 Python 子域名资产探测与信息收集工具，能够自动化完成从子域名发现、DNS 解析、IP C 段探测、端口扫描到响应内容 URL 提取的全流程信息收集。

## 📋 功能特性

| 模块 | 功能说明 |
|------|---------|
| 🔍 子域名探测 | 多线程字典爆破，内置 200+ 条常用子域名字典 |
| 📡 DNS 解析 | 使用 dnspython 解析 A 记录，支持多 IP（CDN/负载均衡） |
| 🧹 泛解析检测 | 自动检测并过滤泛解析产生的"假"子域名 |
| 🌐 C 段扫描 | 提取 IP C 段，遍历 1~254 进行存活探测 |
| 🚪 端口扫描 | TCP Connect 多线程扫描，覆盖 230+ 常用端口 |
| 🔗 URL 提取 | HTTP GET 请求后提取绝对/相对 URL（href/src/action/form/CSS url()） |
| 📊 进度展示 | 内置进度条，实时显示扫描进度与发现数量 |
| 📁 结果保存 | 按时间戳创建独立目录，生成 6 个结果文件 |
| 📝 总结报告 | 自动生成 Markdown 格式扫描报告 |

## 🚀 快速开始

### 环境要求

- Python 3.6+
- 操作系统：Windows / Linux / macOS

### 安装依赖

```bash
pip install requests dnspython
```

> `tqdm` 为可选依赖，用于显示进度条。如果未安装，脚本会自动使用内置的降级版进度条，功能不受影响。

### 下载脚本

```bash
git clone https://github.com/yourusername/subdomain-scanner.git
cd subdomain-scanner
```

或者直接下载 `subdomain_scanner.py` 文件到本地。

## 💻 使用指南

### 基本用法

```bash
# 全功能扫描（推荐）
python subdomain_scanner.py -d example.com
```

### 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-d, --domain` | **（必填）** 目标域名，如 `example.com` | — |
| `-t, --threads` | 并发线程数 | `50` |
| `-p, --ports` | 自定义端口列表（空格分隔） | 230+ 常用端口 |
| `-f, --file` | 子域名字典文件路径 | 内置 200+ 条字典 |
| `-o, --output` | 输出目录 | `result_{domain}_{timestamp}` |
| `--timeout` | Socket 连接超时（秒） | `3` |
| `--http-timeout` | HTTP 请求超时（秒） | `5` |
| `--no-c` | 跳过 C 段扫描 | 不跳过 |
| `--no-p` | 跳过端口扫描 | 不跳过 |
| `--no-u` | 跳过 URL 提取 | 不跳过 |
| `--no-wildcard` | 跳过泛解析检测 | 不跳过 |
| `-v, --version` | 显示版本信息 | — |
| `-h, --help` | 显示帮助信息 | — |

### 使用示例

#### 1️⃣ 基本全功能扫描

扫描 `example.com` 的所有模块（子域名探测 → DNS 解析 → C 段扫描 → 端口扫描 → URL 提取）：

```bash
python subdomain_scanner.py -d example.com
```

#### 2️⃣ 使用自定义字典 + 高并发

```bash
python subdomain_scanner.py -d example.com -f my_subdomains.txt -t 100
```

#### 3️⃣ 仅进行子域名探测和 DNS 解析

跳过 C 段扫描、端口扫描、URL 提取，适合快速了解域名有哪些子域名：

```bash
python subdomain_scanner.py -d example.com --no-c --no-p --no-u
```

#### 4️⃣ 指定自定义端口

```bash
python subdomain_scanner.py -d example.com -p 80 443 8080 8443 3306 6379
```

#### 5️⃣ 指定输出目录

```bash
python subdomain_scanner.py -d example.com -o ./scan_results
```

#### 6️⃣ 设置更短的超时时间

网络环境较差时，可以缩短超时时间以加速扫描：

```bash
python subdomain_scanner.py -d example.com --timeout 2 --http-timeout 3
```

## 📂 输出文件说明

扫描完成后，会在结果目录下生成以下文件：

```
result_example.com_20260513_153000/
├── 1_subdomains.txt          # 发现的子域名列表
├── 2_dns.json               # 子域名 → IP 映射
├── 3_c_alive.txt            # C 段存活主机 IP 列表
├── 4_ports.json             # IP → 开放端口映射
├── 5_urls.json              # 子域名 → URL 提取结果
└── SUMMARY.md               # Markdown 总结报告
```

### 文件格式说明

| 文件 | 格式 | 示例内容 |
|------|------|---------|
| `1_subdomains.txt` | 纯文本（每行一个） | `www.example.com` |
| `2_dns.json` | JSON | `{"www.example.com": ["93.184.216.34"]}` |
| `3_c_alive.txt` | 纯文本（每行一个） | `93.184.216.1` |
| `4_ports.json` | JSON | `{"93.184.216.34": [80, 443]}` |
| `5_urls.json` | JSON | `{"www.example.com": {"status": 200, "absolute_urls": [...], "relative_urls": [...]}}` |
| `SUMMARY.md` | Markdown | 含表格的扫描统计报告 |

## 📊 输出示例

### 终端输出（部分）

```
╔══════════════════════════════════════════════════════════╗
║           子域名资产扫描工具 v1.0                       ║
║        Subdomain Asset Scanner                          ║
╚══════════════════════════════════════════════════════════╝
  目标域名: example.com
  结果目录: result_example.com_20260513_153000
  开始时间: 2026-05-13 15:30:00
  功能状态:
    - C 段扫描: ✓
    - 端口扫描: ✓
    - URL 提取: ✓
    - 泛解析检测: ✓

  📊 扫描统计:
    - 发现子域名: 12
    - 解析到 IP:  24 个地址
    - C 段存活:   8 台主机
    - 开放端口:   45 个端口
    - 提取 URL:   1,234 个链接
```

## 🧠 工作原理

扫描流程按顺序执行 5 个步骤，每个步骤的结果作为下一个步骤的输入：

```
子域名探测  ──→  DNS 解析  ──→  C 段扫描  ──→  端口扫描  ──→  URL 提取
    │                │              │              │              │
    ▼                ▼              ▼              ▼              ▼
1_subdomains.txt  2_dns.json   3_c_alive.txt  4_ports.json   5_urls.json
                           │                             │
                            └── SUMMARY.md ──────────────┘
```

### 详细流程

1. **子域名探测**：读取子域名字典（或使用内置默认字典），多线程并发执行 DNS 查询，记录解析成功的子域名
2. **DNS 解析**：使用 dnspython 对每个子域名进行权威 A 记录查询，获取完整的 IP 地址列表
3. **泛解析检测**：生成随机子域名前缀进行测试，若存在泛解析则自动过滤"假"子域名
4. **C 段扫描**：提取所有 IP 的 C 段网络，遍历 1~254 进行存活探测（socket + 反向 DNS）
5. **端口扫描**：对收集到的所有 IP 进行 TCP Connect 多线程端口扫描
6. **URL 提取**：对每个子域名发起 HTTP/HTTPS GET 请求，通过正则提取绝对 URL 和相对 URL

## ⚙️ 性能调优建议

| 场景 | 建议参数 | 说明 |
|------|---------|------|
| 快速探测 | `-t 100 --timeout 2` | 提高并发、缩短超时 |
| 完整扫描 | `-t 50 --timeout 3` | 默认配置，均衡性能 |
| 大量字典 | `-t 200 -f large_dict.txt` | 大字典需要更高并发 |
| 避免被拦截 | `-t 10 --no-wildcard` | 减少请求密度 |
| 纯扫描端口 | `--no-c --no-u` | 禁用 C 段和 URL 提取 |

## ❗ 注意事项

### 法律与道德

- **仅用于授权测试**：本工具仅应用于你拥有合法授权的目标系统
- **遵守当地法律法规**：未经授权的端口扫描和子域名枚举可能违反某些地区的法律
- **合理使用**：请勿对未授权的目标发起高强度扫描，避免造成拒绝服务

### 技术限制

- 子域名发现依赖于字典质量，无法发现不在字典中的子域名
- 端口扫描基于 TCP Connect，在某些网络环境下可能被防火墙/IDS 拦截
- C 段扫描使用反向 DNS 查询 + socket 探测，部分网络环境可能效果不佳
- URL 提取基于正则匹配，对于 JavaScript 动态加载的 URL 无法完整提取

## 🔧 常见问题

### Q: 安装依赖时报错怎么办？

```bash
# 尝试使用国内镜像源
pip install requests dnspython -i https://pypi.tuna.tsinghua.edu.cn/simple

# 或使用 pip3（如果同时安装了 Python 2 和 3）
pip3 install requests dnspython
```

### Q: 扫描速度很慢怎么办？

- 增加线程数：`-t 200`
- 缩短超时时间：`--timeout 2 --http-timeout 3`
- 跳过不需要的模块：`--no-c --no-u`
- 使用更小的端口列表：`-p 80 443 22 3306`

### Q: 为什么有的子域名没有解析到 IP？

- 该子域名可能只配置了 AAAA（IPv6）记录
- DNS 服务器暂时无响应
- 部分子域名可能配置了 CNAME 但没有 A 记录

### Q: 输出的 JSON 文件中文会乱码吗？

- 所有文件均使用 UTF-8 编码保存，现代编辑器均可正常显示

## 📦 依赖库

| 库名 | 用途 | 是否必需 |
|------|------|---------|
| `requests` | HTTP 请求与响应获取 | ✅ 必需 |
| `dnspython` | 权威 DNS 解析（A 记录） | ✅ 必需 |
| `tqdm` | 进度条显示 | ❌ 可选（内置降级版） |

## 📄 项目文件结构

```
subdomain-scanner/
├── subdomain_scanner.py      # 主脚本（1256 行）
├── README.md                 # 使用说明（本文件）
├── 子域名资产扫描工具_需求文档.md  # 需求文档
└── subdomain.txt             # 内置字典备份（84 条）
```

## 🔄 更新日志

### v1.0 (2026-05-13)

- ✅ 子域名探测（字典爆破 + 多线程）
- ✅ DNS 解析（A 记录，支持多 IP）
- ✅ 泛解析检测与自动过滤
- ✅ IP C 段扫描（1~254 存活探测）
- ✅ 端口扫描（TCP Connect，230+ 端口）
- ✅ URL 提取（绝对 URL + 相对 URL）
- ✅ 进度条展示（tqdm + 内置降级版）
- ✅ 结果自动保存（6 个输出文件）
- ✅ Markdown 总结报告
- ✅ 命令行参数全覆盖

## 🚧 未来计划

- [ ] 证书透明度（crt.sh）被动收集
- [ ] JavaScript 中的 URL 提取（AST 解析）
- [ ] Web 指纹识别（CMS/框架/服务器）
- [ ] HTML / PDF 报告导出
- [ ] 断点续传支持
- [ ] 速率控制（RPS 限制）
- [ ] 子域名存活重验证

## 🤝 贡献

欢迎提交 Issue 和 Pull Request 来改进这个工具！

## 📜 许可证

本项目采用 MIT 许可证。

---

**⭐ 如果这个工具对你有帮助，欢迎 Star 支持！**
