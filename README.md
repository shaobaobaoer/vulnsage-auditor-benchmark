# VulnSage Benchmark — E2E 测试库

基于真实 CVE 的端到端漏洞审计 benchmark 测试套件，覆盖 **4 语言 × 4 产品类目 × 4 样例 = 64 个测试用例**。

## 架构

```
Stage 1 (Product Identification)  →  Stage 2 (Vulnerability Analysis)  →  Stage 3 (Vulnerability Proof)
         产品识别                            漏洞静态分析                         漏洞动态验证
```

## 覆盖矩阵

|          | CLI | Library | WebApp | Service |
|----------|-----|---------|--------|---------|
| **Python**     | 4 CVE | 4 CVE | 4 CVE | 4 CVE |
| **Java**       | 4 CVE | 4 CVE | 4 CVE | 4 CVE |
| **Go**         | 4 CVE | 4 CVE | 4 CVE | 4 CVE |
| **JavaScript** | 4 CVE | 4 CVE | 4 CVE | 4 CVE |

## 螺旋上升开发模式

本项目采用螺旋迭代模式，而非线性流水：

- **Spiral 0**: 基础设施搭建
- **Spiral 1**: 1 个 CVE 跑通全流程（Python-Library CVE-2024-36039）
- **Spiral 2**: 4 个 CVE（每语言 1 个 Library）
- **Spiral 3**: 16 个 CVE（4×4 矩阵，每格 1 个）
- **Spiral 4**: 64 个 CVE（4×4×4 全量）

每个 Spiral 包含完整闭环：构建 fixture → 运行 E2E → 发现问题 → 修复插件 → 回归验证

## 快速开始

### 1. 安装插件

```bash
./install-plugins.sh
```

### 2. 运行单个 CVE 测试

```bash
./run-single.sh fixtures/python-lib-CVE-2024-36039/
```

### 3. 按 Spiral 级别运行

```bash
./run-benchmark.sh --spiral=1   # 仅 1 个 CVE
./run-benchmark.sh --spiral=2   # 4 个 CVE
./run-benchmark.sh --spiral=3   # 16 个 CVE
./run-benchmark.sh              # 全量 64 个
```

### 4. 检查 fixture 完整性

```bash
./run-benchmark.sh --check
```

## 前置依赖

| 依赖 | 最低版本 | 用途 |
|------|---------|------|
| Node.js | 18.x | Plugin 2 MCP Server |
| Python | 3.12 | Plugin 3 Engine |
| Docker | 20.10 | Stage 3 漏洞验证 |
| uv | latest | Python 包管理 |
| Git | 2.x | 克隆漏洞代码 |
| jq | 1.6 | JSON 解析 |
| Cursor | 0.40+ | Agent 插件宿主 |

## 目录结构

```
vulnsage-benchmark/
├── README.md                 # 本文件
├── .gitignore
├── install-plugins.sh        # 一键安装三个插件到 Cursor
├── run-benchmark.sh          # 全量 E2E 编排
├── run-single.sh             # 单个 CVE E2E 测试
├── lib/
│   ├── common.sh             # 公共函数库
│   ├── stage1.sh             # Stage 1 执行逻辑
│   ├── stage2.sh             # Stage 2 执行逻辑
│   ├── stage3.sh             # Stage 3 执行逻辑
│   ├── validate.sh           # 输出校验
│   └── report.sh             # 汇总报告生成
├── config/
│   ├── matrix.json           # 64 个 CVE 矩阵定义
│   └── cursor-mcp.json       # Cursor MCP 配置模板
├── fixtures/                 # 64 个 CVE fixture
│   └── {lang}-{category}-{CVE}/
│       ├── meta.json         # CVE 元信息
│       ├── clone.sh          # 克隆漏洞版本代码
│       ├── Dockerfile        # Stage 3 Docker 环境
│       └── expected/         # 三阶段期望输出
├── results/                  # 运行时结果输出
└── reports/                  # 汇总报告
```

## License

MIT
