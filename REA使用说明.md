# REA 本地使用

- 官方仓库：https://github.com/morluto/rea
- 已下载源码：`rea/`（未修改）
- 已安装运行版：6.5.0，位于 `.work/rea-runtime/`
- 在本工作区 PowerShell 执行：`./rea.ps1 --help`
- 中文官方说明：`rea/docs/readme/README_zh.md`

## 已验证

`./rea.ps1 --version` 返回 6.5.0。

生产 stdio MCP 自检通过：207 个工具、6 个提示模板及实际请求成功，见 `output/rea-mcp-check.json`。

对下载源码中的 `scripts/rea.mjs` 完成静态 JavaScript 分析，退出码 0，完整结果见 `output/rea-analysis-check.json`。其余源码仅建立清单，不代表完成了整个项目的分析。

## 命令

```powershell
./rea.ps1 --help
./rea.ps1 analyze-javascript-application 'D:\你的应用目录' --json
./rea.ps1 mcp doctor --json
```

源码与发布运行版分开，使用 CLI 无需编译源码，也无需全局安装 npm。

## Codex 接入状态

已获用户确认并完成接入，安装器返回 `ready`。Codex 注册和配套技能检查均为 `aligned`，生产 MCP 自检再次通过。结果见 `output/rea-setup-result.json`、`output/rea-codex-check.json` 和 `output/rea-mcp-check.json`。已执行的变更：

1. 为 `C:\Users\LJL\.codex\config.toml` 添加 REA MCP 注册，使用本地 Node 和已安装入口，并保留其他配置。
2. 备份现有配置至安装器选择的 `.rea.backup` 路径。
3. 安装配套技能至 `C:\Users\LJL\.agents\skills\reverse-engineer-anything`。

已执行 `./rea.ps1 setup --client codex --yes --json` 并完成检查。重启 Codex 后加载新注册；当前会话尚未验证重启后的实际工具连接。全环境诊断仍提示未配置的外部分析引擎，Codex 接入本身检查通过。

## 当前限制

Ghidra、IDA、JADX 未配置，相关深度分析尚不可用。安装时包管理器阻止了 Frida 的构建脚本，未放行或验证其运行能力；上述静态分析与 MCP 自检已通过。

启动脚本依赖当前 Codex 捆绑 Node 的绝对路径；若运行时被迁移，需更新 `rea.ps1` 和后续 MCP 注册。保留 `.work/rea-runtime/`，它是实际运行依赖。
