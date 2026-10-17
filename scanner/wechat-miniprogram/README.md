# 手机扫描研究接入

页面调用相机帧并通过网关请求Android原JNI。Android动态库不能在微信JavaScript环境中直接加载。

当前 `config.js` 默认沿用普通四角识别。启用已恢复的原曲线检测时，将 `curveBorder` 改为 `true`，并将 `baseUrl` 指向运行新版 `scanner/native_gateway.mjs` 的地址。当前本机新增路由测试服务为 `http://127.0.0.1:18767`；旧18766进程未重启，没有曲线路由。手机中的127.0.0.1不是这台电脑；真实微信还需要可达HTTPS地址、合法域名及AppID配置。

新路由：

- POST `/detect-curve`：NV21，帧宽高通过 `X-Frame-Width/Height` 传入。
- POST `/detect-curve-rgba`：微信RGBA帧，同样传宽高。
- 成功响应包含 `quad`、`curve`、`native_status`、`stable`、`width/height`。有效curve为160个整数，即80个二维点，按左上→左下→右下→右上→左上顺序绘制；无有效纸张时数组为空。

页面已支持绘制80点轮廓，保留普通框开关。帧单请求和拍照排队沿用现有处理。曲线显示暂使用原返回点直接绘制；原Java的7dp匹配、IoU分支和设备稳定传感器门控尚未全部移植。

验证脚本 `scanner/verify_wechat_page.mjs` 执行实际页面JS，以Node适配wx相机/画布API并调用真实Android原库后端；它不是微信客户端验收。`scanner/verify_curve_gateway.py` 验证实际HTTP/JNI，包括空白消失、恢复、RGBA转换和错误输入。完整原生证据和效果核对页见 `output/camscanner-reverse/`。
