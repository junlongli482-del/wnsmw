# REA 能力修复与壳恢复（2026-10-16）

目标仍是恢复扫描全能王的实际算法与调用参数。工具修复、壳解压、原算法执行和原应用界面运行是分别验证的事项。

**最新原调用链和回归见 `原调用链与实测进展.md`。** 已按恢复代码补齐曲线的 `initContourMask` 会话，两图各21帧原JNI检测成功，输出80点曲线；空白消失、恢复有效。原 `CurveCropDewarpImagePos2` 也已执行并保留输出。普通扫描4张PNG回归与此前逐字节一致。下面保留壳恢复的历史记录，不将历史停止点视为当前阻塞。

## 当前状态：16 个业务 DEX 精确还原（2026-10-17 新进展）

**已从原壳实际载荷恢复 16 个 DEX，403,522 条 AJM 记录全部唯一匹配、无遗漏。16 个文件的原先存储 SHA-1 全部匹配还原后的正文，未重写 SHA-1。** 仅在 SHA-1 已匹配后显式重算 Adler32；最终 16 个文件均通过头部、表边界、SHA-1、Adler32 和类描述符检查，共 85,010 个类定义。这里的校验不是 ART 指令验证，也不表示原应用界面已经启动。

复现与证据：

1. `datread30m` 原代码处理后的 dat 快照，在偏移 40 出现完整 ZIP。`inspect_dat_archive.py` 通过 ZIP 解压和 CRC 校验得到 97,991,240 字节的 `classes.dex` 成员；该成员仍是带 40-byte 保护头的载荷，不直接作为 DEX。
2. `datcomplete1b` 原加载链继续完成内层字节替换，得到 16 个 DEX。执行属于显式混合离线模型：原外层/内层保护变换与业务解析仍执行原指令；ajm 及 dat ZIP 的压缩计算使用严格校验输入与输出的 host zlib fixture；缓存 FILE 使用 Python 内存模型。没有把这类执行声称为真实 Android。`--block-trace` 只减少纯字节替换循环的 Python 观察回调，原指令照常执行。
3. `extract_heap_dex_candidates.py datcomplete1b` 导出原路径产物。16 个候选的 Adler32 均匹配，但 SHA-1 不匹配，因为方法体还受 AJM 保护。原始候选保留在 `recovered-dex/datcomplete1b/`。
4. 保护方法的 `code_item.debug_info_off` 实际是 AJM 的规范化键。`restore_business_dex.py` 按精确键及完全相同的指令长度，将还原方法体和记录的第二字段（原 debug_info_off）写回。403,522 个键各匹配一次，没有按名字或长度猜配。
5. `restored-business-dex/restoration-evidence.json` 逐个记录正文原 SHA-1 匹配、Adler32 规范化、最终 SHA256 与结构校验；`method-attribution.json` 保留全部键、类、方法签名和 code-item 偏移对应。
6. `rea-restored-enhanceImage.json` 已通过 REA/JADX 读取真实方法体：`enhanceImage` 调用原生 `enhanceBitmap` 并以返回值 `>=0` 判断成功。恢复后研究 ZIP 位于 `.work/camscanner/restored-business.apk`，仅用于静态分析，未签名、不是完整可安装应用。

深层检查点的寄存器/EAX/PC 和同一未知调用复停核对见 `shell-checkpoint-deep-check.json`。最新加载停点已推进至 `sigfillset64`，不是原先的 libdexfile mprotect。继续追原加载链与扫描业务参数，不再以工具缺失为停工理由。

待完成：定位动态预览边框与智能增强调用、恢复各模式实参；原 UI、实体手机、真实微信客户端及原产品默认效果对照仍未验证。下方“壳加载链继续推进”保留的是达成本次还原之前的过程记录，其中“尚无 DEX”的表述只适用于当时的历史阶段。

## 2026-10-17 壳加载链继续推进

本轮复核与新增证据：

- **外层变换与记录载荷已恢复**：250M 原指令回放成功保留快照，停在 `0x1091c46`，仍为指令预算耗尽；此时 ajm 原缓冲区已由原壳变换。其偏移 24 为有效 zlib 流，host zlib 完整校验后得到 29,113,292 字节，恰等于头部 offset20。`inspect_ajm_records.py` 严格按 `u32,u32,u32长度,数据` 解析出 403,522 条记录，数量恰等于头部 offset12，全部字节被消费，首字段逐条递减。记录语义、业务类/方法对应与有效 DEX 仍未恢复。验证见 `ajm-records/ajm-record-validation.json`。
- `probe_ajm_transform.py` 独立执行原 `0x8b1f0`，使用保留的初始化后 image/heap；输出与完整原路径快照逐字节一致，独立结构验证也通过。只用构造器结束状态不能复现，说明该变换依赖后续初始化状态，不能发布为无状态解密器。证据见 `shell-ajm-transform-isolated.json` 和 `ajm-records-isolated/ajm-record-validation.json`。
- `shell-resource-config-names.json`：保留快照 config+0x14 为 `ijiami.dat`，+0x18 为 `ijiami.ajm`，+0x34 为 `ijiami2.ajm`。`0xb0bf0` 的 fallback 资源名使用 +0x14，因此该内存 DEX 装载链请求的是 dat。原 APK 只含 dat/ajm，未含 ijiami2.ajm。不能将 ajm 记录本身当成已解出的业务 DEX。
- 为推进后续解析，新增显式 `--host-zlib-fixture`：只在原 `0x92aa0` 收到与独立原变换结果完全相同的压缩字节时，以 host zlib 填入输出并记录摘要；这类运行须标成混合执行，不能充当全原生指令或真实 Android 证据。此后 parser250m/parser500m 分支均已保留，历史全原指令快照不覆盖。

parser250m 混合分支已完成到下一明确停止点：原代码读出配置字符串 `ad7d`，调用尚未建模的 `strtol(NULL endptr, base16)`，因此停止；没有伪造未知返回。静态指令显示随后把该值从每条记录首字段中减去，再经 state+0x38 表查询/插入，首键为 `0x04000000`。表槽定位为 `0x41060` 查找、`0x40eb0` 插入，属于链式哈希表。对应证据：`shell-ajm-map-attribution.json`、`shell-ajm-record-map.txt`。已补入此具体签名的 C 32-bit strtol 语义并运行 parser500m，未推广到未知签名。

parser500m 已成功完成该索引初始化，下一停止点是 `dlopen("libaoc.so",0)`，不是预算耗尽。保留状态的表有 1,048,576 个桶、403,522 个节点；`verify_ajm_map.py` 遍历全部节点并与解压记录逐条比较，确认全部一致，只有首字段被原代码减去 `0xad7d`。见 `shell-ajm-map-runtime.json`、`shell-ajm-map-all-records-check.json`。尚未出现 DEX 候选。

本轮重建并安装另包 JNI 探针，实际测得 `libaocDlopenFlags0 = dlopen failed: library "libaoc.so" not found`，见 `shell-libaoc-actual-dlopen.json`。只把此另包 linker namespace 结果作为显式离线 fixture，继续 afteraoc200m 分支。该混合分支还用 host raw DEFLATE 替代原 APK 中 ajm 条目的重复解压，且严格核对输出与原始资源逐字节相同；这不替代原保护变换或后续记录解析，不属于全原指令执行证据。

**记录字节还原函数已单独执行验证**：原 `0x8aa40` 根据规范化键取记录，要求记录长度为传入 code-unit 数的两倍，在条件允许时逐字节变换。静态恢复规则为 `{0x00,0xff,0x23,0xdc}` 保持不变，其余字节 XOR `0xff`；`probe_ajm_record_restore.py` 对前 20 条记录实际执行原查表与还原机器码，输出全部与该规则一致，例如首条 `8fef530f0000f100 -> 7010acf000000e00`。这类字节具有 DEX 方法体指令的形态，但尚无所属类/方法或完整 DEX 验证，不能认定完整应用已恢复。证据见 `shell-ajm-original-record-restore.json`、`shell-ajm-map-consumer.txt`。

`restore_ajm_records.py` 按此规则导出全部 403,522 条记录，共 24,271,028 字节还原后的 body，输出 `ajm-records/restored-records.ajmrec`，SHA256 `2876e8bb6f1f6d9cd2c11fc5af2f77c6fcdf65d77f1a9bf7fadc88f6d9ad6e78`。这是自定义研究容器，不是 DEX、原始源码或可安装软件。每条保留规范化键、原第二字段和长度，便于后续与类/方法元数据对齐。证据 `ajm-records/restored-records-evidence.json`。

后续 afteraoc/concat/dexfile 分支已依次越过另包实测 libaoc 缺失、`%s%s` 格式化、`libdexfile.so` stat 等步骤。最新 dexfile200m 停于对实际 maps 中 `0xe98a2000` 区间的 mprotect；已只读拉取 emulator 的 `libdexfile.so`（324,068 bytes）和 96-byte stat，见 `shell-libdexfile-fixture.json`，并在 ART-file 模型中增加其 PT_LOAD。保护修改成功仍是明确的离线模型假设，不能写成 Android 实际允许 execmod。

新增 `--save-checkpoint` / `--resume-checkpoint=<本地标签>`，保存离线 CPU context、内存与显式 import/JNI 模型状态，只接受本任务自己生成的本地检查点。初步烟测：执行 1 条原指令后保存/加载再执行 1 条，与连续执行 2 条的 PC/EAX/GPR 相同，见 `shell-checkpoint-smoke-check.json`；这只是指令边界烟测，深层状态仍需验证。dexmapped200m 正在运行并保存深层检查点，供后续免去重复索引初始化。

- `provider-recheck-current.json`：新启动 REA CLI 的 Ghidra 12.1.4 headless/native decompiler 与 JADX 检查通过；`rea-frida-devices-current.json` 是本轮 REA 实际枚举到 `emulator-5580` 的结果。当前旧 MCP 进程仍报告缺环境/Frida binding，不能将 CLI 可用误写成旧 MCP 已热更新。
- `shell-resource-readback-check.json`：原壳离线 `0x4fce0` 返回的 14,112,882 字节缓冲区，与原包 `assets/ijiami.ajm` 逐字节相同，SHA256 `7ff2c22f9c62e26615bbd5c73ecba9980770601f77e7483636653473352560bf`。这是 APK 资源解压成功的证据，尚非载荷解密。
- `shell-resource-transform-decompiled.txt`、`shell-resource-entry-decompiled.txt`：`0x50b70` 是格式化包装器，`0x4f9b0` 通过 `assets/%s` 读取配置指定的资源。此前将 ZIP 链归于 ajm 内部封装的推断撤回。
- `emulate_shell_constructors.py` 增加返回缓冲区留存、资源名与摘要记录、独立运行标签。首次 250M 回放已保存上述 ajm 文件，随后堆快照读超出原 64MiB 映射；已经扩大显式离线堆并增加快照前的停点报告，重新执行。此修改只改变离线承载与观察，不改变目标指令或密码计算。

### 历史追踪步骤（当时停点，当前进展见上文）

原始 `N.al` 离线路径继续执行到动态检查 `dlopen("libmthook.so", 0)`。另包 Android API 30 模拟器上的 JNI 探针实际返回 `NULL`，`dlerror` 为 `library "libmthook.so" not found`；结果见 `shell-libmthook-dlopen-evidence.json`，并已接入 `emulate_shell_constructors.py` 的显式 fixture 分支。此结果只约束另包 linker namespace 的实测值，不等同原壳 namespace 已加载该库。

继续回放后，原路径到达 `dlopen("libpine.so", 0)`；同一 Android JNI 探针返回 `NULL`，`dlerror` 为 `library "libpine.so" not found`。证据见 `shell-libpine-dlopen-evidence.json`，并已接入离线分支。

`fancy.dat` 的真实 shell-UID 探针结果为 `openat=-1, errno=2 (ENOENT)`，随后原路径继续从已安装 APK 偏移读取数据。将 N.al 指令预算提高到 60M 后，已观察到 375 次 32KiB 块读取和大量 `memcpy`，但当前停点仍是预算耗尽，尚未出现 DEX 魔数；这证明是持续的资源处理循环，不能据此宣称业务 DEX 已解密。

对该循环的 Ghidra 静态追踪已确认 `FUN_0108d4c0` 是状态机式 DEFLATE/zlib 解码器：校验 gzip 头 `1f 8b`、窗口大小、stored/fixed/dynamic block 类型、CRC 和距离码，并把解压结果写入调用者输出缓冲区；`FUN_01091160` 负责动态 Huffman 表。该阶段只确认壳包含 inflater；ajm 自身格式的确认依赖本节开头列出的后续原变换和解压证据。

进一步追到 `FUN_01081500`：它先调用 `FUN_01080ef0` 读取条目元数据，再检查条目头 `0x04034b50`（ZIP local-file header）；无压缩条目直接拷贝，压缩条目调用 `FUN_01081680`，后者按 0x8000 字节块读入并交给 `FUN_0108d4c0`。2026-10-17 复核：上层 `0x4f9b0` 用 `assets/%s` 构造资源路径后调用 `0x4fce0`，因此这条链是读取 APK/ZIP 容器资源的链；此前将其当成 `ijiami.ajm` 内部 ZIP 的结论证据不足，撤回该归属。此处只确认 APK 容器读取；`indl01` 外层与记录格式的后续恢复见本节开头。

其上层调用者也已恢复：`0x4fce0/0x50140/0x508d0` 先按条目名通过 `0x80d10` 的 `0x1f` 滚动哈希查索引表，再按元数据中的未压缩大小分配输出；`0x81120/0x81890` 分别处理直接复制和压缩解压路径。相关调用者伪代码见 `shell-ijm-callers-decompiled.txt`。

归档初始化链也已明确：`0x80730 -> 0x807e0` 打开/初始化输入，`0x81c10` 定位并验证 ZIP end-of-central-directory `0x06054b50`，读取 central directory，`0x809d0` 为每个文件名建立开放寻址哈希表。由此可按文件名定位 APK/ZIP 中的资源条目，不代表已能索引 14MB `ijiami.ajm` 内部载荷。静态证据见 `shell-ijm-open-parse-decompiled.txt`、`shell-ijm-archive-chain.json` 和复核的 `shell-resource-entry-decompiled.txt`。

沿资源加载静态调用链已确认：`FUN_010b0bf0` 通过 AssetManager 取得资源，验证头部后调用 `makeInMemoryDexElements`；`FUN_010b4ec0` 使用 `ByteBuffer` 和 `dalvik.system.DexPathList` 反射把内存字节注入类加载器。相关反编译保存在 `shell-dex-resource-loader-decompiled.txt`。目前仍未恢复业务 DEX 字节，因此不能把该链描述为已解密完成。

## 已修复并实际验证

- 官方 Ghidra 12.1.4 已安装，REA CLI doctor 的 headless/decompiler 检查通过，见 `provider-recheck.json`。另已用官方 headless 将解压后的 x86 ELF 导入，导出 `shell-libexec-decompiled.txt`、`shell-vm-decompiled.txt`。REA Windows provider 的 ARM 限制仍存在，ARM 静态分析使用官方直接 headless 路径。
- Frida 17.23.2 binding 与模拟器服务器能连接；REA CLI 可枚举进程并注入 Java load 跟踪，见 `frida-processes-current.json`、`rea-frida-original-recheck.json`。这不等于原扫描界面已经启动。
- `rea.ps1` 与 Codex REA 配置补入正确的 `REA_ADB_PATH`，REA 实际识别 `emulator-5580`，见 `rea-adb-repaired.json`。配置修改前备份为 `C:/Users/LJL/.codex/config.toml.rea-adb-path.backup`。
- 已为后续 MCP 启动补入 Ghidra 环境。本会话旧 MCP 的 provider 状态可能仍缓存；当前工作通过已验证的 REA CLI 继续，不依赖用户重启。

## 新恢复证据

1. 两个 x86 壳库 DT_INIT 在 Unicorn 跑到调用者返回：`libexecmain.so` 322,659 个变化字节，`libexec.so` 775,587 个变化字节，均无内存异常。证据 `shell-init-emulation-evidence.json`。
2. ARM 两库 DT_INIT 同样跑到返回，分别恢复 296,082 / 425,085 个变化字节，见 `shell-arm-init-emulation-evidence.json`。这是隔离 CPU 仿真，不能据此宣称 Android 加载成功。
3. x86 构造函数继续解出 `classes.dex`、`classes2.dex`、壳类名和 ART/DexFile 加载相关字符串，见 `shell-constructor-emulation-evidence.json`、`shell-jni-table-evidence.json`。这些是字符串和结构，尚不是解出的业务 DEX。
4. 四组结构型 JNINativeMethod 候选含 `println_native`、`i(I)V`、`l()V`、`u(Object,Object)V`。候选尚未由运行时 RegisterNatives 验证；不能把相同名字直接归属业务类。
5. Ghidra 已恢复 JNI_OnLoad 包装函数：TLS 值栈分配，压入参数，进入解释器，再弹出结果。解释器含大量间接分支，普通反编译未恢复完整控制流。`shell-libexec-decompiled.txt` 与 `shell-vm-decompiled.txt` 是伪代码证据，非原始源码。
6. `shell-jni-entries-decompiled.txt` 为构造阶段内存的追加反编译，包含四个入口及其直接被调用函数。这里已应用离线 ELF 重定位，导入地址仍指向仿真 stub。`l()V` 候选与 REA/JADX 实际读取的 `N.l(Application,String)Z` 不同，不能直接对应。

构造仿真的旧版本曾将 `sysconf(30)` 按桌面 Linux 枚举假设为页大小；Android bionic 的枚举不同。后续通过 NDK 探针在模拟器实测 `sysconf(30)=1`、`sysconf(39/40)=4096`，clone 模式已按实测纠正。原始停止证据保留假设记录，不能用它证明 Android 构造语义一致。DT_INIT 解压证据不调用此 sysconf stub。

## 构造阶段进一步推进

`shell-constructor-clone-proc-emulation-evidence.json` 中，x86 `libexec.so` 的 70 个非零构造函数和 `libexecmain.so` 的 3 个非零构造函数均已返回。该模式使用明确的离线 clone 顺序调度、仿真 libc handle、真实模拟器 libc 符号表，以及 PID309 zygote 的 `/proc/self/status`、`wchan` 文件回放；不是原应用运行时。未知的子线程路径另行保留，不据此推断真实并发行为。

`shell-libexec.so.clone.proc-state-evidence.json` 已记录初始化后的 state+0x34 函数表，包含原 ELF 0x5a840、0x647d0、0x64860、0x66b20 等入口。这些入口正用于追 DEX 加载流程。较早停止于第 50 个构造的文件保留作过程证据，最新进度以 clone-proc 文件为准。

`shell-dex-loader-decompiled.txt` 保存沿这条线追出的函数：0x647d0 查询 `android.os.Debug.isDebuggerConnected`，0x66b20 涉及 ART/Dalvik 调试相关符号，0x5a840 则再次进入虚拟机解释器。文件名代表调查方向，不表示已恢复 DEX 解密函数。

最终构造内存静态重扫，见 `shell-final-jni-table-evidence.json`：为同四组三元组，相关字符串共 227 条。这是执行 JNI_OnLoad 之前的静态扫描结果，后续注册映射以如下独立执行证据为准。

## 原 JNI_OnLoad 已执行返回

`shell-jni-onload-emulation-evidence.json` 中，原 `libexec.so` 的解释器执行到返回 `0x10004`，产生 4 次 RegisterNatives、11 个方法映射。以下为原 ELF 相对地址；仿真加载基址为 `0x1000000`。

|类|方法及 DEX 描述符|ELF 地址|
|---|---|---|
|s/h/e/l/l/N|l(Application,String)Z|0x6f870|
|s/h/e/l/l/N|r(Application,String)Z|0x729e0|
|s/h/e/l/l/N|ra(Application,String)Z|0x73310|
|s/h/e/l/l/N|b2b([BI)[B|0x734f0|
|s/h/e/l/l/N|m(String,I)V|0x73500|
|s/h/e/l/l/N|sa(String,String)V|0x73510|
|s/h/e/l/l/N|al(ClassLoader,ApplicationInfo,String,String)ClassLoader|0x73520|
|s/h/e/l/l/C|i(I)V|0x93450|
|s/h/e/l/l/HM|l()V|0x75df0|
|s/h/e/l/l/HM|u(Object,Object)V|0x76440|
|s/h/e/l/l/SE|sd(String)String|0x7dc60|

JNI 类、字段、方法及对象句柄来自显式离线模型；Build 字段按实际模拟器属性填写。原 APK 映射内容的哈希与用户安装包一致。这不是原应用 ART 环境内捕获到的注册事件。先前静态 `l()V` 候选现明确对应 HM.l，不能误认为 N.l。

加载器入参进一步由原始 DEX 的 baksmali 输出确认：`.work/camscanner/shell-smali/s/h/e/l/l/A.smali` 的构造函数明确给 packageName 赋值 `com.intsig.camscanner`，给 orignAppName 赋值 `com.intsig.camscanner.launch.CsApplication`。REA 的 `rea-shell-a-instantiate.json` 显示原调用按这两个字段传给 N.al；它们并非 sourceDir/dataDir。REA/JADX 的构造函数查询没返回方法体，故用原始 DEX 指令补证，没有把“无反编译体”当成实际 native 构造函数。

`shell-n-loader-decompiled.txt` 保留 N.al 等入口及直接被调用函数的 Ghidra 伪代码。JNI 参数原型按上述实际描述符指定，内部间接分派和 ART 依赖仍未完全恢复。

## 后续 N.al 的系统依赖

单独 x86 probe 可选 `--ez call_al true` 读取原包的 ApplicationInfo，传入原包名、原 Application 类名及 probe 自身 ClassLoader。最初因 Android 30 包可见性缺少 queries 而报 NameNotFoundException；补齐只针对原包的 queries 后读元数据成功。前后日志分别为 `shell-probe-al-before-visibility-fix.txt`、`shell-probe-al-runtime.txt`，最新 APK 哈希见 `shell-probe-build-evidence.json`。这不是恢复原应用上下文。

实际调用后，`shell-probe-al-logcat.txt` 记录 SELinux 拒绝 ART/liblog 的 execmod，进程随后 signal9 退出；尚未返回 ClassLoader。离线 N.al 默认模式对应停在 mprotect 请求，把 libart 的 rx 区段设为 RWX（prot=7），此前已通过原 ELF 符号表找到 `_ZN3art3Dbg12DdmConnectedEv`。静态对应函数 ELF `0x46180` 先读取 SDK，再解析 `/proc/PID/maps` 和页大小，调用 mprotect，见 `shell-art-permissions-decompiled.txt`。日志先后及离线路径相互补证，仍不能断言 signal9 的唯一来源。

新增 Ghidra 对原 libexecmain 的 `ijiami` 和 `getOpCode` 的伪代码，见 `shell-main-core-decompiled.txt`。前者在此构造镜像中为 ret；后者为字节映射。`scanner/probe_shell_opcodes.py` 实际执行原 getOpCode 的所有 256 个单字节输入，各自返回，输出低字节形成完整置换，见 `shell-opcode-byte-map.json`。该函数无导入替代，但其输入镜像来自离线构造环境；未声称这张表能独立解密业务 DEX。

独立 targetSdk=25 兼容实验仍然观察到 ART/liblog execmod 拒绝与 signal9，见 `shell-probe-target25-logcat.txt`，未解决此运行限制。研究 probe 已恢复为 targetSdk=30；没有修改模拟器 SELinux。

## 线程栈检查及真实框架取证

Ghidra `shell-stack-check-decompiled.txt` 中原 ELF `0x3e520` 调 Thread.currentThread/getStackTrace，固定读取 StackTraceElement 数组索引 4，再取 getClassName。其 android.app. 前缀/特定类名检查失败分支写 state+0x1d8=0x22。`shell-n-al-probestack-emulation-evidence.json` 回放真实研究 Activity 主线程预调用栈，原代码最终发出 kill(309,9)，仿真停在该 syscall，未模拟成功，亦未恢复 DEX。其栈为研究包预调用位置，并非原 ACF 或 native 调用内位置。

为获取有真实来源的 JNI 初始化栈，新增 `scanner/stack-probe` 及 `scanner/build_shell_stack_probe.py`：另包 org.localresearch.stackprobe 的 AppComponentFactory.instantiateClassLoader 直接调用自有 JNI captureStack，JNI 通过实际 ART 调 Thread.currentThread/getStackTrace。此 APK 不含原扫描/壳代码和返回 hook。`shell-probe-actual-factory-stack.json` 是实际采集结果：索引 2 为自有 ProbeFactory.captureStack，索引 3 为自有 ProbeFactory.instantiateClassLoader，索引 4 自然为 android.app.LoadedApk.createOrUpdateClassLoaderLocked。完整 18 项栈、方法和行号均保留，未替换为原应用类名。构建哈希见 `shell-stack-probe-build-evidence.json`。后续离线回放这份实际栈仍属于不同包/不同 JNI 函数的环境模型，不能称原应用栈已经采到。

独立 `shell-n-al-factorystack-emulation-evidence.json` 回放实际框架栈后，原栈检查通过，status 保持 0；之后原代码解析 libc 的 pthread_create，入口线程为 ELF `0x4cd40`。可选离线队列模型下该线程执行返回，父线程继续到 android.os.Debug.isDebuggerConnected；原真实并发和 ART 线程状态仍不由该模型建立。`shell-loader-thread-decompiled.txt` 保留线程入口及相关函数伪代码。另 `shell-probe-actual-factory-debug.json` 实采研究包 Debug.isDebuggerConnected=false、waitingForDebugger=false，不用猜测值代替事实；这两个值属于另包进程的一次观察。

此分支后续使用 NDK 实测 access 结果：`/dev/socket/qemud` 不存在、`/dev/qemu_pipe` 存在，真实结果见采集的 android-access.json。原加载代码将 status 写为 0x27，清理后发出 kill(309,9)，仿真在该 syscall 停止；这不是工具缺失。该路径尚未进入主 VM 载荷解码，未恢复业务 DEX。后续明确将 qemu 路径视为不存在的受控分析只能回答“其后原代码怎样解码”，不能代表当前模拟器或真机的完整原环境执行。

## 受控后续路径与加密函数验证

`shell-n-al-qemuabsent-emulation-evidence.json` 只改变两项 qemu 路径结果，其余环境使用实测，仍因模拟器属性被原代码终止。`shell-n-al-nonemulator-emulation-evidence.json` 是另一个明确的 counterfactual 分支，记录了每项属性原值及替代值；不是物理手机 profile，也不是原模拟器运行成功。其余系统服务和路径继续用实际 JNI/NDK 查询补证。

`shell-probe-actual-mikrom-service.json`：独立研究 APK 的 JNI 实际查询 ServiceManager.getService("mikrom")，无 JNI 异常，返回 null。没有把 shell 的 service check 代替 JNI 事实；后者也得到 not found。

已恢复原 ELF `0x4a2e0`/`0x4a3e0`/`0x4a670`/`0x4a900` 加密函数，SM4 固定常量及 32 轮见 `shell-asset-cipher-decompiled.txt`。`scanner/probe_shell_cipher.py` 执行原机器码，对标准 key/plaintext `0123456789abcdeffedcba9876543210` 得到标准 ciphertext `681edf34d206965e86b3e94f536e4246`，反转轮密钥后还原输入。该验证不替换 cipher 或数学导入。

受控分支观察到的原调用 key 用于再次单独执行原机器码，可解原包 32 字节 `assets/icon/image_icon_constructor_encrypted.png` 为 `66822209\r\n66811535\r\n66810137\r\n`，原输出长度 30。文件名虽为 PNG，内容实际为数字配置；不是业务 DEX。独立结果及输入 SHA256 保存在 `shell-sm4-known-answer.json`。尚不能据此认定主 ijiami.ajm/ijiami.dat 载荷采用同一密钥或算法。

`shell-payload-xrefs-decompiled.txt` 保存类名/载荷名的 Ghidra 引用调查；大多数显式引用属于字符串初始化器，`0xb0bf0` 则实际通过资源函数读取 classes.dex 相关内容。覆盖取决于 Ghidra 已分析引用，不是所有隐式 PIC/VM 引用。`shell-payload-name-pointer-xrefs.txt` 对两个指针位置没有发现已登记引用，仅是有限负结果。

`scanner/validate_recovered_dex.py` 已对原包可见 classes.dex 校验长度、SHA1、Adler32 和表边界，保存 `shell-visible-dex-validation.json`：4 项真实 class_defs 为 A/C/N/S；JADX 显示的 6 项解析类不等同原 DEX class_defs 数量。该脚本只做有限结构检查，不是 ART verifier，也没有恢复隐藏业务类。原安装包通过官方 apksigner verify（exit0），签名证书摘要见 `original-apk-signature-report.txt`；证书匹配不代表原 UI 已运行。

## 当前边界

- 原 APK 在此模拟器上存在 ARM/x86 壳加载冲突。Java 跟踪明确观察到 EM_386 / EM_ARM 不匹配。额外 ARM 路径替换实验没有证明完整原应用启动。
- 早先最小兼容探针只观察到进入加载，未观察到返回。另保存 Android crash 记录 `compat-app-crash.txt`；记录中的独立原应用进程报 N.al 未注册。后来新建纯 x86 探针 `org.localresearch.shellprobe`，基线日志已观察到两个原始 x86 库 System.load 返回，见 `shell-probe-baseline.txt`；进程随后很快退出。其包名/上下文与原应用不同，Frida 跟踪尚未捕获到原运行时注册表，不能把该探针与离线 JNI 模型混为一谈。
- 完整受保护业务 DEX、原 UI 默认模式及相机回调参数仍未恢复。
- 原库检测、裁切/展平、增强的两张用户照片结果已存在，查看 `原库效果核对.html`。它们来自研究桥选定参数，不能宣传为与原应用默认模式完全一致。

## 继续工作

- 沿构造函数、JNI 注册候选与虚拟机分派追 DEX 加载入口。
- 对需要真实 linker/ART 的步骤补充可验证环境证据，保留 import/syscall stub 的明确边界。
- 恢复相机输入、模式选择和跨帧绘制调用者，再验证手机端与小程序的实际效果及延迟。
