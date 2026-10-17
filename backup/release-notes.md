2026-10-17 重装系统前的扫描全能王研究保存点。代码、Android 原库适配器、微信页面与恢复说明在 main 分支；完整研究状态以本 Release 附件为准。

恢复：克隆仓库，安装 Python 3.12 x64 和 GitHub CLI，在仓库根目录执行 `python backup/restore_snapshot.py --download`。脚本下载分卷、检查 SHA-256、拼接并安全解压，随后核验全部文件。手动下载时将分卷放入 backup/assets 后运行同一脚本（不加 --download）。

research-state.zip.*：原 APK、原库、提取模型、壳恢复检查点、还原业务 DEX、完整研究报告、样片处理结果、Ghidra 项目与 Android 构建。

research-environment.zip.*：Python 3.12 二进制依赖、已校验 JADX JAR、Frida 组件、REA 源码 Git bundle 及 npm 锁文件。

snapshot-manifest.json：完整文件和分卷的 SHA-256 清单。单独的研究 APK 和效果核对 HTML 为便利下载副本，也包含在完整研究状态包内。恢复 HTML 下载后用浏览器打开；APK 是研究适配器，不是原 App UI。

已验证：16 个业务 DEX 原 SHA-1 匹配；原 JNI 普通框、80 点曲线、曲线裁切和新旧增强执行；网关扫描结果与 Android 直接输出逐字节一致；曲线网关 10 项检查及 Node 页面回归通过。

边界：使用模拟器和受控照片夹具；实体手机、真实微信客户端与原 App 默认配置同图对照尚待完成。-12 超级滤镜存在云端算法，未恢复其服务端实现。未保存 GitHub 凭据或私人签名密钥；可下载的 SDK 大型缓存及旧模拟器磁盘不在备份中。恢复详情和下一步任务见 backup/恢复与继续研究.md。
