# 扫描全能王算法研究备份

这是 2026-10-17 重装系统前的研究保存点。包括原 APK 分析脚本、Android 原库研究适配器、微信小程序页面、用户样片、原库执行证据以及恢复原算法的效果核对页。

**代码在 Git 仓库，完整二进制和研究中间产物在 [Release 附件](https://github.com/junlongli482-del/wnsmw/releases/tag/research-backup-2026-10-17)。仅克隆仓库不能恢复全部研究状态，请同时下载附件。**

## 重装后先做什么

1. 克隆本仓库，安装 Python 3.12（64 位）与 GitHub CLI。
2. 在仓库根目录运行 `python backup/restore_snapshot.py --download`。脚本用 `gh` 下载固定 Release 的分卷，核验 SHA-256 后拼接解压，恢复 `.work/` 和 `output/`。
3. 查看 `output/camscanner-reverse/恢复原算法效果核对.html`，阅读 `原调用链与实测进展.md`、`超级滤镜本地边界.md`。
4. 按 [恢复与继续研究](backup/恢复与继续研究.md) 补装 Android SDK/JDK/REA 运行环境，再继续执行原库实验。

如果已经手动下载 Release 分卷，将它们放到 `backup/assets/` 后运行 `python backup/restore_snapshot.py`。恢复脚本只用 Python 标准库。

## 当前已验证

- 16 个业务 DEX 已恢复，原 SHA-1 全部匹配；403,522 条方法记录唯一对应。
- Android 原始未修改库已执行普通动态四角、80 点曲线轮廓、曲线裁切及新旧去阴影增强。
- 最新研究 APK SHA-256：`715f8fbf05fa9ac9bbeccc9b366f448091456439b86b4dbf29f1a7a57a245185`。
- 两张样片的 `/scan` 输出与 Android 直接调用逐字节一致；曲线网关 10 项检查通过。
- 小程序页面代码经 Node 的 wx 适配器调用真实 Android JNI 验证通过。

上述验证使用 Android 模拟器和受控图像夹具。尚未验证实体手机、真实微信客户端，也未证明与原 App 默认配置完全同图一致。`-12` 超级滤镜包含云端算法，不能从现有 APK 宣称已经恢复服务端实现。

## 文件导览

| 路径 | 内容 |
|---|---|
| `scanner/` | 原库探针、壳恢复、DEX 验证、模型分析及回归脚本 |
| `scanner/android-research/` | Android 相机/JNI/HTTP 研究适配器源码 |
| `scanner/wechat-miniprogram/` | 动态框、拍照与网关请求页面 |
| `scanner/samples/` | 两张输入照片及两张效果参考图 |
| `backup/snapshot-manifest.json` | 完整备份的文件、分卷及 SHA-256 清单 |
| `.work/camscanner/`（附件恢复） | 原 APK、原库、提取模型、壳检查点 |
| `output/camscanner-reverse/`（附件恢复） | 完整报告、还原 DEX、图像、视频/回放和 APK |

早期 `scan.ps1`/`scanner/scan.py` 是独立算法原型，不作为 APK 原算法恢复的证据。最新结论以 `原调用链与实测进展.md` 及带哈希的执行报告为准。

备份不包含 GitHub 凭据、私人签名密钥、模拟器可变磁盘或可重新下载的 SDK 大型安装缓存；保留了研究所需原始输入、模型、还原产物和 Python 二进制依赖。已安装工具的重建方法见恢复说明。
