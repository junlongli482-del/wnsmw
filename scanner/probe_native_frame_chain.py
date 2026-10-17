"""Original cardCut/documentCrop ARM with a host MNN tensor bridge.

Controlled camera-frame fixture; no original Java/UI or Android MNN session.
"""
from emulate_pagescan import Arm, ROOT, load_image
from emulate_pagescan import save_image
from unicorn import UC_HOOK_CODE
import cv2, numpy as np, MNN, json, struct, os, sys

class FrameArm(Arm):
    def __init__(self):
        super().__init__()
        self.reuse_freed=True;self.bridge_buffers=[]
        # ELF static initializer _INIT_2 sets the real global SinglePageSet.
        self.call(self.BASE+0x4e6fc+1,[])
        self.frame_state=self.BASE+0xade2d4
        os.chdir(ROOT)
        self.net=MNN.Interpreter('.work/camscanner/models/pagescan.mnn')
        self.session=self.net.createSession({'backend':'CPU','numThread':2})
        self.input=self.net.getSessionInput(self.session)
        self.tensor=self.alloc(0x80);dims=self.alloc(0x80)
        self.w32(self.tensor+0x24,dims)
        for i,n in enumerate([1,2,240,240]):self.w32(dims+i*16+4,n)
        self.tensor_data=self.alloc(2*240*240*4);self.w32(self.tensor+0xc,self.tensor_data)
        for match,stub in [('InferNet9to_tensor','FRAME_TO_TENSOR'),('InferNet7forwardENSt','FRAME_FORWARD')]:
            target=next(v for n,v in self.symbols.items() if match in n and 'pagescan' in n)
            self.redirects[target&~1]=self.stub(stub)
            self.uc.hook_add(UC_HOOK_CODE,self.callback,begin=target&~1,end=target&~1)
        slot=self.BASE+0x76284+self.u32(self.BASE+0x76878)
        self.w32(self.u32(slot),self.alloc(0x80))
        self.model_inputs=[]

    def mat(self,image,p=None):
        result=super().mat(image,p)
        self.bridge_buffers.append(self.u32(result+16))
        return result

    def reclaim_frame_buffers(self):
        # Host-created Mat data is borrowed (NULL native refcount). documentCrop
        # keeps only integer context/quad state after return, so the bridge owns
        # and releases these image buffers at that explicit lifetime boundary.
        for p in self.bridge_buffers:self.release_allocation(p)
        self.bridge_buffers.clear()

    def callback(self,uc,address,size,user):
        name=self.stubs.get(address)
        if name=='FRAME_TO_TENSOR':
            self.trace[name]=self.trace.get(name,0)+1
            image=self.image(self.reg(2))
            self.model_inputs.append(list(image.shape))
            data=np.ascontiguousarray(cv2.resize(image,(240,240)).astype(np.float32)[None]/255)
            tensor=MNN.Tensor(data.shape,MNN.Halide_Type_Float,data,MNN.Tensor_DimensionType_Tensorflow)
            self.input.copyFrom(tensor);self.net.runSession(self.session)
            result=self.net.getSessionOutput(self.session)
            host=MNN.Tensor(result.getShape(),MNN.Halide_Type_Float,np.zeros(result.getShape(),np.float32),MNN.Tensor_DimensionType_Caffe)
            result.copyToHostTensor(host)
            raw=np.asarray(host.getData(),np.float32).reshape(result.getShape())
            self.uc.mem_write(self.tensor_data,raw.tobytes())
            self.w32(self.reg(0),0);self.w32(self.reg(0)+4,0);self.ret();return
        if name=='FRAME_FORWARD':
            self.trace[name]=self.trace.get(name,0)+1
            self.w32(self.reg(0),self.tensor);self.w32(self.reg(0)+4,0);self.ret();return
        if name and 'Tensor16getDimensionType' in name:
            self.trace[name]=self.trace.get(name,0)+1;self.ret(1);return
        return super().callback(uc,address,size,user)

def main():
    out=ROOT/'output/camscanner-reverse/model-probe';rows=[]
    motion='--motion' in sys.argv;document='--document' in sys.argv or motion
    for stem in ['photo-1','photo-2']:
        arm=FrameArm();source=load_image(ROOT/f'scanner/samples/{stem}.jpg')
        context=arm.alloc(0x2c);arm.w32(context+0x10,1);arm.w32(context+0x1c,1)
        mat=arm.mat(source) if not document else None;quad=arm.alloc(32)
        record={'source':stem,'status':'failed','native_frame_capacity':arm.u32(arm.frame_state)}
        try:
            if document:
                frames=[];previews=[];record['frames']=frames
                frame=cv2.resize(source,(480,360));data=arm.alloc(frame.nbytes)
                sequence=['stable']*9+(['shift']*4+['blank']*3+['stable']*9 if motion else [])
                for i,kind in enumerate(sequence):
                    if motion:
                        frame=np.full((360,480,3),70,np.uint8)
                        if kind!='blank':
                            page=cv2.resize(source,(300,225));x=90 if kind=='stable' else 165
                            frame[65:290,x:x+300]=page
                    arm.uc.mem_write(data,frame.tobytes())
                    before=len(arm.model_inputs)
                    code=arm.call(arm.symbols['documentCrop'],[context,data,480,360,quad,0,480*3,1,0])
                    frames.append({'frame':i,'return_value':code,'quad':list(struct.unpack('<8i',arm.uc.mem_read(quad,32))),
                                   'fixture_kind':kind,
                                   'context':list(struct.unpack('<11I',arm.uc.mem_read(context,44))),
                                   'model_inputs':arm.model_inputs[before:],'state_size':arm.u32(arm.frame_state+16)})
                    preview=frame.copy();points=np.asarray(frames[-1]['quad'],np.int32).reshape(4,2)
                    cv2.polylines(preview,[points],True,(0,200,0) if code==1 else (0,180,255),2)
                    cv2.putText(preview,f'Controlled ARM replay: frame {i}, code {code}',(8,20),cv2.FONT_HERSHEY_SIMPLEX,.42,(255,255,255),1,cv2.LINE_AA)
                    previews.append(cv2.cvtColor(preview,cv2.COLOR_BGR2RGB))
                    arm.reclaim_frame_buffers()
                record['frames']=frames
                if motion:
                    from PIL import Image
                    images=[Image.fromarray(p) for p in previews]
                    images[0].save(out/f'{stem}-native-frame-replay.gif',save_all=True,append_images=images[1:],duration=250,loop=0)
            else:code=arm.call(arm.symbols['_ZN8pagescan7cardCutEPvN2cv3MatEPib'],[context,mat,quad,0])
            record.update(status='executed',return_value=code,quad=list(struct.unpack('<8i',arm.uc.mem_read(quad,32))),model_inputs=arm.model_inputs)
            if not arm.trace.get('FRAME_FORWARD'):raise RuntimeError('No inference coverage')
        except Exception as exc:record.update(status='failed',error=str(exc))
        record.update(host_import_calls=arm.trace,library_sha256=arm.sha)
        rows.append(record)
    report={'records':rows,'scope':'Original ARM cardCut/documentCrop and native static initializer; model initialization bypassed, host MNN inference/input conversion and synthetic tensor metadata. Native geometry and output integer mapping remain original. Java color layout and live camera/UI unverified.'}
    (out/('native-motion-frame-evidence.json' if motion else 'native-document-frame-evidence.json' if document else 'native-cardcut-evidence.json')).write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
