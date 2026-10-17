"""Run original get_warp_mat post-inference code with a host tensor fixture.

Bypasses model initialization, input conversion and inference only. The field
comes from prior host MNN inference; original confidence code is not replaced.
"""
from emulate_pagescan import Arm, ROOT, load_image, save_image
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R1
import numpy as np, cv2, struct, json, sys

class WarpArm(Arm):
    def callback(self, uc, address, size, user):
        name=self.stubs.get(address)
        if name=='FIXTURE_TO_TENSOR':
            self.trace[name]=self.trace.get(name,0)+1
            self.w32(self.reg(0),0);self.w32(self.reg(0)+4,0);self.ret();return
        if name=='FIXTURE_FORWARD':
            self.trace[name]=self.trace.get(name,0)+1
            self.w32(self.reg(0),self.tensor);self.w32(self.reg(0)+4,0);self.ret();return
        if name and 'Tensor16getDimensionType' in name:
            self.trace[name]=self.trace.get(name,0)+1
            self.ret(1);return
        return super().callback(uc,address,size,user)

def main():
    stem=sys.argv[1] if len(sys.argv)>1 else 'photo-1'
    model=sys.argv[2] if len(sys.argv)>2 else 'default'
    out=ROOT/'output/camscanner-reverse/model-probe'
    arm=WarpArm();raw=np.load(out/f'{stem}-cropped-dewarp-{model}-raw.npy')
    planar=np.ascontiguousarray(raw.transpose(2,0,1),dtype=np.float32)
    data=arm.alloc(planar.nbytes);arm.uc.mem_write(data,planar.tobytes())
    arm.tensor=arm.alloc(0x80);dims=arm.alloc(0x80)
    arm.w32(arm.tensor+0xc,data);arm.w32(arm.tensor+0x24,dims)
    for i,n in enumerate([1,2,240,240]):arm.w32(dims+i*16+4,n)
    for match,stub in [('to_tensor_dewarp','FIXTURE_TO_TENSOR'),('InferNet7forwardENSt','FIXTURE_FORWARD')]:
        target=next(v for n,v in arm.symbols.items() if match in n and 'pagescan' in n)
        arm.redirects[target&~1]=arm.stub(stub)
        arm.uc.hook_add(UC_HOOK_CODE,arm.callback,begin=target&~1,end=target&~1)
    # Force the observed global model-ready check; no Android session created.
    check=arm.BASE+0x8514a
    arm.uc.hook_add(UC_HOOK_CODE,lambda uc,a,s,u:uc.reg_write(UC_ARM_REG_R1,1),begin=check,end=check)
    context=arm.alloc(0x80);arm.w32(context,1)
    source=arm.mat(load_image(out/f'{stem}-native-geometry-crop.png'))
    result=arm.mat(np.zeros((240,240,2),np.float32))
    record={'source':stem,'model':model,'status':'failed','scope':'Original get_warp_mat ARM post-inference; model-ready forced, input conversion and inference bridged to a synthetic tensor containing the APK model output. Android inference equivalence unverified.'}
    try:
        value=arm.call(arm.symbols['get_warp_mat'],[context,source,result])
        confidence=struct.unpack('<f',struct.pack('<I',value))[0]
        field=arm.image(result)
        expected=cv2.GaussianBlur(raw,(39,39),-1,borderType=cv2.BORDER_DEFAULT)
        if not arm.trace.get('FIXTURE_FORWARD'):raise RuntimeError('Original get_warp_mat returned before inference fixture; no confidence coverage')
        extrema=float(abs(field[:,:,0].min())+abs(field[:,:,0].max()))
        derived=0.0 if extrema>500 else float(field.astype(np.float64).std(axis=(0,1)).sum())
        record.update(status='executed',confidence=confidence,field_shape=list(field.shape),max_field_error=float(np.max(np.abs(field-expected))),
                      derived_confidence_formula='0 if abs(min(channel0))+abs(max(channel0))>500 else std(channel0)+std(channel1)',
                      derived_confidence=derived,derived_confidence_error=abs(confidence-derived))
        np.save(out/f'{stem}-native-warp-field-{model}.npy',field)
        # Execute the entry with original get_warp_mat and its actual computed
        # confidence; only the model runtime/conversion fixtures remain bridged.
        image=arm.image(source);mask=np.full(image.shape[:2],255,np.uint8)
        source_mask=arm.mat(mask);dest=arm.mat(np.zeros_like(image));dest_mask=arm.mat(np.zeros_like(mask))
        arm.capture_remaps=True
        entry=next(v for n,v in arm.symbols.items() if 'dewarp_process_with_mask' in n)
        arm.call(entry,[context,source,source_mask,dest,dest_mask,0,2])
        output=arm.image(dest)
        save_image(out/f'{stem}-native-confidence-dewarp-{model}.png',output)
        save_image(out/f'{stem}-native-confidence-dewarp-{model}-mask.png',arm.image(dest_mask))
        record['entry']={'mode_argument':2,'boolean_argument':False,'mode_selected_by':'researcher',
                         'remap_calls':len(arm.remap_captures),'output_shape':list(output.shape),
                         'identical_to_input':bool(np.array_equal(image,output))}
        record['status']='original_post_inference_and_entry_executed'
    except Exception as exc:record['error']=str(exc)
    record.update(host_import_calls=arm.trace,library_sha256=arm.sha)
    p=out/f'{stem}-native-warp-confidence-{model}.json';p.write_text(json.dumps(record,indent=2),encoding='utf-8')
    print(json.dumps(record,indent=2))
if __name__=='__main__':main()
