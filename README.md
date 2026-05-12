# VulnSage SAST Benchmark — CVE 样本库

基于真实 CVE 的 SAST 审计 benchmark 样本集，覆盖 **4 语言 × 50 样例 = 200 个测试用例**。

> 数据源自 `sastbench.json`，排除 PHP 后按 `vulnsage-auditor-multi-product-benchmark` 的 fixture 结构展开。

## 覆盖矩阵

| Language       | Cases | 目录前缀        |
|----------------|-------|-----------------|
| **Go**         | 50    | `go-sast-*`     |
| **Java**       | 50    | `java-sast-*`   |
| **JavaScript** | 50    | `js-sast-*`     |
| **Python**     | 50    | `python-sast-*` |
| **Total**      | **200** |               |

## 目录结构

```
vulnsage-auditor-benchmark/
├── README.md
├── sast-bench-filtered.json    # 原始数据源
├── scripts/                    # 评估与分析脚本
│   ├── generate-fixtures.py    # 从数据源生成 fixtures + examples
│   ├── evaluate.py             # 评估审计结果（对比 GT）
│   ├── analyze-failures.sh     # 失败样本分析
│   └── generate-examples.sh    # 从失败分析 CSV 生成 example JSON
├── examples/                   # 200 个任务定义 JSON
│   └── {lang}-sast-{CVE}.json
├── fixtures/                   # 200 个 CVE fixture
│   └── {lang}-sast-{CVE}/
│       ├── meta.json           # CVE 元信息
│       ├── clone.sh            # 克隆漏洞版本代码
│       ├── Dockerfile          # Docker 环境
│       ├── entrypoint.sh       # 入口脚本
│       └── expected/           # 期望输出
│           ├── vuln_report.json      # 漏洞报告（含 data_flow）
│           └── verification.json     # 验证结果
└── reports/                    # 评估报告输出目录
```

## Fixture 命名规范

`{语言}-sast-{CVE编号}`

- **语言**: `go` / `java` / `js` / `python`
- **类别**: `sast`（静态分析 benchmark）
- **示例**: `go-sast-CVE-2025-64522`、`python-sast-CVE-2025-8917`

## 漏洞类型分布

涵盖 SSRF、Path Traversal、XSS、SQL Injection、Command Injection、Open Redirect、Code Injection 等多种漏洞类型。

## 脚本说明

### evaluate.py — 评估审计结果

对比审计器输出与 ground truth，计算命中率。

**匹配逻辑**：
1. 从 GT 的 `sink` + `data_flow` 提取路径节点 `(file, line)`（**不含 source**，避免将模型 sink 命中 GT source 误判为正确）
2. 文件路径**精确匹配**（normalize 后，支持后缀段容忍匹配）
3. 实际报告中**任意 finding 的 sink** 落在 GT 路径上任一节点 ±N 行内即算 **HIT**
4. 行号偏移容忍度可配置（`--line-tolerance`，默认 5）

### 当前召回率

> **150 / 187 = 80.2%**（基于 200 样本中可用的 187 个，±5 行容忍度）
>
> 未命中 37 个样本待持续优化。

```bash
# 基本用法：评估某个 batch 的 PASS 样本
python3 scripts/evaluate.py \
  --workspace-dir ../vulnsage-auditor-claude-orchestrator/workspaces \
  --batch-log-dir ../vulnsage-auditor-claude-orchestrator/logs/batch/20260429_191338 \
  --line-tolerance 5

# 输出所有格式（终端表格 + CSV + Markdown）
python3 scripts/evaluate.py \
  --workspace-dir ../vulnsage-auditor-cursor-orchestrator/workspaces \
  --examples-dir examples/ \
  --format all \
  --output-dir reports/

# 评估所有样本（不仅 PASS）
python3 scripts/evaluate.py \
  --workspace-dir ../vulnsage-auditor-claude-orchestrator/workspaces \
  --batch-log-dir ../vulnsage-auditor-claude-orchestrator/logs/batch/20260429_191338 \
  --status-filter ALL
```

### analyze-failures.sh — 失败样本分析

```bash
./scripts/analyze-failures.sh <batch-log-dir> <workspaces-dir> [output-dir]
```

### generate-examples.sh — 从失败分析 CSV 生成 example JSON

```bash
./scripts/generate-examples.sh <csv-file> [output-dir]
```

### generate-fixtures.py — 从数据源生成 fixtures 和 examples

```bash
python3 scripts/generate-fixtures.py [--dry-run]
```

## License

MIT
