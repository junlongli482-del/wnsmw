"""Build a self-contained, source-hashed review of the actual Android outputs."""
from pathlib import Path
import base64
import hashlib
import html
import json
import struct

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'output/camscanner-reverse'


def main():
    report = json.loads((OUT / 'android-full-native-report.json').read_text())
    outputs = {row['file']: row for row in report['outputs']}
    records, sections = [], []
    for number in (1, 2):
        sample = f'photo-{number}'
        panels = []
        for title, path, native in (
            ('用户原始照片', ROOT / f'scanner/samples/{sample}.jpg', False),
            ('原库裁切／展平', OUT / f'model-probe/{sample}-android-full-native-crop.png', True),
            ('原库最终增强', OUT / f'model-probe/{sample}-android-full-native.png', True),
        ):
            data = path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            if native:
                assert digest == outputs[path.name]['sha256'], path
                width, height = struct.unpack('>II', data[16:24])
            else:
                width = height = None
            records.append({'file': path.relative_to(ROOT).as_posix(), 'sha256': digest,
                            'bytes': len(data), 'width': width, 'height': height})
            mime = 'image/png' if native else 'image/jpeg'
            uri = f'data:{mime};base64,' + base64.b64encode(data).decode('ascii')
            panels.append(f'<figure><figcaption>{title}</figcaption><a href="{uri}" download="{html.escape(path.name)}"><img src="{uri}" alt="{title}"></a><small>{html.escape(path.name)}<br>SHA256 {digest}</small></figure>')
        sections.append(f'<section><h2>照片 {number}</h2><div class="panels">' + ''.join(panels) + '</div></section>')
    content = '''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>原库扫描效果核对</title>
<style>body{font:16px/1.7 system-ui,sans-serif;margin:24px;color:#20252b}h1{font-size:26px}p{max-width:1000px}.panels{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}figure{margin:0}figcaption{font-weight:600}img{width:100%;height:auto;border:1px solid #ddd}small{display:block;font-size:11px;overflow-wrap:anywhere}section{margin:32px 0}@media(max-width:800px){.panels{grid-template-columns:1fr}}</style>
<h1>扫描全能王原库：用户照片效果核对</h1>
<p>左为用户照片，中为 APK 原库裁切／曲面展平，右为原库增强结果。点击图片可保存完整分辨率文件；页面内嵌原始文件，未二次缩放或重新编码。显示时由浏览器按页面宽度缩放。</p>
<p>执行环境：Android API30 x86 模拟器 ARM 转译。检测角点缩放、增强 mode=3 和处理顺序由研究桥选择，尚未恢复原应用受保护界面的默认参数。因此这些图证明原库实际输出，不证明与原应用默认扫描模式完全相同。</p>
<p>另外两张白底参考图与实拍中的手写内容不同，未作为逐像素或效果等同基准。效果请以这里的完整图自行评判。动态边框存在稳定后直接移走纸张仍保留旧框的实测情况。</p>
''' + ''.join(sections) + '</html>'
    path = OUT / '原库效果核对.html'
    path.write_text(content, encoding='utf-8')
    evidence = {'scope': report['scope'], 'source_report': 'android-full-native-report.json',
                'records': records, 'html_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                'html_bytes': path.stat().st_size, 'image_reencoding': False}
    (OUT / 'native-review-evidence.json').write_text(json.dumps(evidence, indent=2, ensure_ascii=False), encoding='utf-8')
    print(json.dumps({'file': str(path), 'files_verified': len(records), 'html_bytes': path.stat().st_size}, ensure_ascii=False))


if __name__ == '__main__':
    main()
