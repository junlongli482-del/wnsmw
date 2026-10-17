"""Visualize retained original JNI curve coordinates; no detection/inference."""
from pathlib import Path
import json
from PIL import Image,ImageDraw
ROOT=Path(__file__).resolve().parents[1]
def main():
    out=ROOT/'output/camscanner-reverse/restored-curve-contour'
    report=json.loads((out/'curve-border-report.json').read_text())
    for sample in report['records']:
        stem=sample['source'];source=Image.open(ROOT/f'scanner/samples/{stem}.jpg').convert('RGB').resize((480,360))
        frames=[]
        for frame in sample['frames']:
            canvas=Image.new('RGB',(480,390),'#242424')
            canvas.paste(Image.new('RGB',(480,360),(75,75,75)) if frame['fixture']=='blank' else source,(0,30))
            draw=ImageDraw.Draw(canvas)
            if frame['native_status']>=0:
                curve=frame['curve'];quad=frame['quad']
                points=[(curve[i],curve[i+1]+30) for i in range(0,len(curve),2)]
                draw.line(points+[points[0]],fill='#37fca4',width=3)
                for x,y in points:draw.ellipse((x-1,y-1,x+1,y+1),fill='#37fca4')
                for i in range(0,8,2):
                    x,y=quad[i],quad[i+1]+30;draw.ellipse((x-4,y-4,x+4,y+4),fill='#ffcf63')
            draw.text((8,8),f"Original JNI | frame {frame['frame']} | status {frame['native_status']} | {frame['fixture']}",fill='white')
            frames.append(canvas)
        frames[4].save(out/f'{stem}-original-curve.png')
        frames[0].save(out/f'{stem}-original-curve-replay.gif',save_all=True,append_images=frames[1:],duration=250,loop=0)
        print(out/f'{stem}-original-curve.png')
if __name__=='__main__':main()
