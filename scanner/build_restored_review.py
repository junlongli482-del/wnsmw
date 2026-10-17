"""Create a source-hashed local review of recovered native branch outputs."""
from pathlib import Path
import json,hashlib,base64,html
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'output/camscanner-reverse'
def main():
    sections=[];records=[]
    def panel(label,path):
        data=path.read_bytes();digest=hashlib.sha256(data).hexdigest()
        records.append({'file':path.relative_to(ROOT).as_posix(),'sha256':digest})
        mime='image/gif' if path.suffix=='.gif' else 'image/jpeg' if path.suffix=='.jpg' else 'image/png'
        return '<figure><figcaption>'+html.escape(label)+'</figcaption><a href="data:'+mime+';base64,'+base64.b64encode(data).decode()+'" target="_blank"><img src="data:'+mime+';base64,'+base64.b64encode(data).decode()+'"></a><small>'+digest[:16]+'</small></figure>'
    checks=json.loads((OUT/'restored-enhance-branches/output-check.json').read_text())
    checks+=json.loads((OUT/'restored-curve-crop/output-check.json').read_text())
    expected={c['file']:c['sha256'] for c in checks}
    for stem in ['photo-1','photo-2']:
        cards=[]
        for label,path in [
            ('原始照片',ROOT/f'scanner/samples/{stem}.jpg'),
            ('原 JNI 曲线回放（绿线为80点轮廓）',OUT/f'restored-curve-contour/{stem}-original-curve-replay.gif'),
            ('原曲线裁切分支（未增强）',OUT/f'restored-curve-crop/{stem}-android-curve-crop.png'),
            ('原库当前完整扫描链',OUT/f'restored-jni-regression/{stem}-android-adapter-scan.png'),
            ('同一裁切输入：旧增强，fast=false',OUT/f'restored-enhance-branches/{stem}-recovered-enhance-old.png'),
            ('同一裁切输入：旧增强，fast=true',OUT/f'restored-enhance-branches/{stem}-recovered-enhance-old-fast.png'),
            ('同一裁切输入：新增强',OUT/f'restored-enhance-branches/{stem}-recovered-enhance-new.png')]:
            if path.name in expected:assert hashlib.sha256(path.read_bytes()).hexdigest()==expected[path.name]
            cards.append(panel(label,path))
        sections.append('<section><h2>'+stem+'</h2><div class="grid">'+''.join(cards)+'</div></section>')
    page='''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>恢复原算法 · 实测效果核对</title>
<style>body{font:16px/1.6 system-ui;margin:32px;background:#f5f4ef;color:#222}main{max-width:1500px;margin:auto}h1{font-size:30px}p{max-width:1000px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(350px,1fr));gap:18px}figure{margin:0;background:white;padding:12px;border:1px solid #d8d7d1}figcaption{font-weight:600;padding:4px 0 12px}img{width:100%;height:auto}small{color:#666}section{margin:36px 0}</style><main><h1>恢复原算法 · 实测效果核对</h1>
<p>2026-10-17 · 使用安装包中未修改的原生库。曲线回放将原 JNI 返回坐标画在照片上；这是受控输入回放。三种增强均使用同一份既有裁切图，参数 mode=3、threads=1，供直接比较。</p>
<p>当前完整扫描链与曲线裁切分支属于不同受控路径。尚未证明与原软件默认配置输出一致，未完成实体手机或真实微信客户端验证。点击图片可查看原尺寸。</p>'''+''.join(sections)+'</main></html>'
    (OUT/'恢复原算法效果核对.html').write_text(page,encoding='utf-8')
    (OUT/'restored-review-manifest.json').write_text(json.dumps({'records':records,'scope':'Actual native outputs and controlled curve replay; no original-app equivalence claim.'},indent=2),encoding='utf-8')
    print(OUT/'恢复原算法效果核对.html')
if __name__=='__main__':main()
