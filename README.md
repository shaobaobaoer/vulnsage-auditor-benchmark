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
├── .gitignore
└── fixtures/                   # 200 个 CVE fixture
    └── {lang}-sast-{CVE}/
        ├── meta.json           # CVE 元信息
        ├── clone.sh            # 克隆漏洞版本代码
        ├── Dockerfile          # Docker 环境
        ├── entrypoint.sh       # 入口脚本
        └── expected/           # 期望输出
            ├── vuln_report.json      # 漏洞报告
            └── verification.json     # 验证结果
```

## Fixture 命名规范

`{语言}-sast-{CVE编号}`

- **语言**: `go` / `java` / `js` / `python`
- **类别**: `sast`（静态分析 benchmark）
- **示例**: `go-sast-CVE-2025-64522`、`python-sast-CVE-2025-8917`

## 漏洞类型分布

涵盖 SSRF、Path Traversal、XSS、SQL Injection、Command Injection、Open Redirect、Code Injection 等多种漏洞类型。

## License

MIT
