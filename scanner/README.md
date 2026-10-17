# 扫描全能王 APK 算法研究

本目录同时保留早期独立扫描原型和后续 APK 逆向实验。当前研究以 APK 原始模型、ARM 代码和执行记录为依据；scan.ps1 是早期独立原型，不能作为原算法复现证明。

最新事实、证据摘要及未完成事项见 `output/camscanner-reverse/原调用链与实测进展.md`。重装恢复见仓库根目录 README 与 `backup/恢复与继续研究.md`；完整 output/.work 在 GitHub Release 附件中。

## 已实际运行

- REA/JADX 检查 Android 包和入口；16 个业务 DEX 已恢复且原 SHA-1 全部匹配，已追踪普通动态框、曲线检测、裁切与增强调用者。
- 官方 Ghidra 反编译 ARM 库。REA Windows Ghidra provider 不支持该目标，因此此部分使用直接 headless Ghidra。
- 八个 APK 内嵌 MNN 模型：纸张检测、三阶段增强、两种曲面展平、文档分类及旧增强。
- Unicorn 执行原 ARM：线段提取、四角选择和精修、目标透视点、跨帧稳定状态、锐化、曲面映射解码。
- Android 原库完整检测、裁切/展平及增强在两张照片运行成功，手机适配器和 HTTP 输出与直接调用逐字节一致；当前执行环境为 API30 x86 模拟器 ARM 转译。
- 原生透视裁切及展平中间图已保存；两张默认模型均触发展平，分阶段输出与原完整裁切入口逐像素一致。
- 三模型增强及原锐化分阶段输出与原 Bitmap mode3 逐像素一致。恢复的颜色增强与原 ARM 指令一致；电脑恢复链仍有少量数值残差，见 android-enhance-host-comparison.json。
- 手机适配器已验证 EXIF 八种方向，保持检测和原库裁切的原始坐标一致，处理完后输出方向变换。两张照片共 16 组输出与基准结果的对应方向变换逐像素一致；这是元数据夹具测试，不是真机拍照验收。

## 重复运行

在项目根目录，用本机缓存 Python 依次执行以下脚本。依赖已位于 .work/reverse-python 和 .work/scanner-python；原库需保留在 .work/camscanner/extracted。

1. scanner/extract_research_models.py
2. scanner/probe_page_detection.py
3. scanner/emulate_pagescan.py photo-1，然后 photo-2
4. scanner/probe_scan_chain.py
5. scanner/verify_native_postprocess.py
6. scanner/probe_frame_state.py
7. scanner/assemble_research_result.py
8. scanner/probe_dewarp.py
9. scanner/probe_cropped_dewarp.py

模型提取的原库地址和 SHA256 记录于 model-extraction-evidence.json。原库和模型保留在本地研究目录，没有加入发布组件。

当前 Android 验证入口：`build_android_research.py`、`collect_android_research.py enhance-stages --launch`。启动 `start_native_gateway.ps1` 后执行 `verify_native_gateway.py`、`verify_android_orientation.py`，可复跑原库与手机适配器的接口验证。真实手机和微信相机方向映射仍待运行。

## 查看输出

最新结果优先查看 `output/camscanner-reverse/恢复原算法效果核对.html`，含曲线轮廓、曲线裁切和新旧增强分支。此前完整原库核对页为 `原库效果核对.html`；`build_native_review.py` 校验执行报告中的图片哈希，嵌入原图、原生裁切／展平和原生增强图，不重新编码图像。下面文件名描述历史实验，不应与最新完整原库输出混用。

输出位于 output/camscanner-reverse/model-probe：

- photo-*-research-scan.png：原模型增强、恢复的锐化公式、原 ARM 四角及目标透视点，host OpenCV 重采样。
- photo-*-research-comparison.png：左原图裁切、右增强。
- photo-*-cropped-dewarp-*-comparison.png：左原图裁切、中展平、右增强加展平。
- cropped-dewarp-evidence.json：展平实验的模型、原库摘要、尺寸、mask 和 host 桥接记录。
- *-maps.npz：原 ARM 生成的映射，用于后续移植对照；函数还会调整输出尺寸，只重放一次 remap 不等效。

先裁切再展平、BGR 输入、模型选择仍是待核对的调用假设，组合图不是原应用完整输出。手机/小程序及 UI 动态框实机验证尚未完成，PC 仿真耗时不能作为手机性能承诺。参考白底图没有实拍中的手写答案，不能证明同内容等效。

## 早期独立原型

```powershell
./scan.ps1 scanner/samples/photo-1.jpg scanner/samples/photo-2.jpg --output output/scans --split
```

该命令使用独立轮廓检测、透视和光照归一化，不使用 APK 模型。输出为图像 PDF，没有 OCR 文字层；split 是中心分割，不是自动书脊识别。
