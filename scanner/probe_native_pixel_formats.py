"""Verify original getMatfromData dispatch, copying, and stride on fixtures."""
from emulate_pagescan import Arm,ROOT
import cv2,numpy as np,struct,json

def main():
    h,w=6,8
    bgr=np.arange(h*w*3,dtype=np.uint8).reshape(h,w,3)
    formats={1:('BGR',bgr),3:('RGBA',cv2.cvtColor(bgr,cv2.COLOR_BGR2RGBA)),
             4:('BGRA',cv2.cvtColor(bgr,cv2.COLOR_BGR2BGRA)),5:('RGB',cv2.cvtColor(bgr,cv2.COLOR_BGR2RGB))}
    i420=cv2.cvtColor(bgr,cv2.COLOR_BGR2YUV_I420).ravel();y=i420[:h*w];u=i420[h*w:h*w+h*w//4];v=i420[h*w+h*w//4:]
    nv21=np.concatenate([y,np.stack([v,u],axis=1).ravel()]).reshape(h*3//2,w)
    formats[0]=('NV21',nv21)
    rows=[]
    for mode,(name,source) in formats.items():
        for padding in ([0] if mode==0 else [0,12]):
            arm=Arm();stride=source.strides[0]+padding
            packed=np.full((source.shape[0],stride),0xa5,np.uint8)
            packed[:,:source.strides[0]]=source.reshape(source.shape[0],-1)
            data=arm.alloc(packed.nbytes);arm.uc.mem_write(data,packed.tobytes())
            output=arm.mat(np.zeros((h,w,3),np.uint8))
            symbol=next(v for n,v in arm.symbols.items() if 'getMatfromData' in n)
            record={'mode':mode,'layout':name,'row_padding_bytes':padding}
            try:
                arm.call(symbol,[data,w,h,stride,mode,output])
                actual=arm.image(output)
                expected=cv2.cvtColor(nv21,cv2.COLOR_YUV2BGR_NV21) if mode==0 else bgr
                record.update(status='executed',shape=list(actual.shape),max_difference=int(np.abs(actual.astype(int)-expected.astype(int)).max()),
                              cvtColor_calls={n:k for n,k in arm.trace.items() if 'cvtColor' in n})
            except Exception as exc:record.update(status='failed',error=str(exc))
            rows.append(record)
    report={'records':rows,'scope':'Original ARM getMatfromData dispatch and stride/copy tested. cvtColor itself uses host OpenCV. NV21 comparison uses the same host decoder, verifying dispatch only; no Android camera numeric equivalence.'}
    (ROOT/'output/camscanner-reverse/native-pixel-formats-evidence.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
