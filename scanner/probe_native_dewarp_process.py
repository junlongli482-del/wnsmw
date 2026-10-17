"""Attempt the exported dewarp_process_with_mask entry with real Mat arguments."""
from emulate_pagescan import Arm,ROOT,load_image,save_image
import cv2,numpy as np,json,time,sys,argparse
from unicorn.arm_const import UC_ARM_REG_PC

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('stem',nargs='?',default='photo-1');parser.add_argument('model',nargs='?',default='default')
    parser.add_argument('--confidence',type=float,default=1.0);parser.add_argument('--mode',type=int,default=2)
    parser.add_argument('--reset',action='store_true');parser.add_argument('--gate-probe',action='store_true')
    args=parser.parse_args()
    out=ROOT/'output/camscanner-reverse/model-probe'; arm=Arm()
    stem=args.stem;model=args.model
    source=load_image(out/f'{stem}-native-geometry-crop.png')
    mask=np.full(source.shape[:2],255,np.uint8)
    image=arm.mat(source); maskmat=arm.mat(mask)
    result=arm.mat(np.zeros_like(source)); resultmask=arm.mat(np.zeros_like(mask))
    context=arm.alloc(0x80)
    # Controlled fixture: bypass initialization and get_warp_mat completely.
    # This does not establish the app's context state or confidence calculation.
    arm.uc.mem_write(context,b'\x01'+b'\0'*0x7f)
    raw=np.load(out/f'{stem}-cropped-dewarp-{model}-raw.npy')
    arm.dewarp_field=cv2.GaussianBlur(raw,(39,39),-1,borderType=cv2.BORDER_DEFAULT).astype(np.float32)
    arm.dewarp_confidence=args.confidence
    arm.capture_remaps=True
    arm.patch_get_warp_mat()
    context_status={'constructor':'bypassed_entire_model_initialization','active_flag':1,'get_warp_mat':'entire function bypassed, including confidence computation'}
    symbol=next(n for n in arm.symbols if 'dewarp_process_with_mask' in n)
    record={'symbol':symbol,'input_shape':list(source.shape),'model':model,'status':'failed','context':context_status}; start=time.perf_counter()
    try:
        arm.call(arm.symbols[symbol],[context,image,maskmat,result,resultmask,0,args.mode])
        output=arm.image(result); outputmask=arm.image(resultmask)
        if not args.gate_probe:
            save_image(out/f'{stem}-native-dewarp-process-{model}.png',output);save_image(out/f'{stem}-native-dewarp-process-{model}-mask.png',outputmask)
        record.update(status='executed',source=stem,output_shape=list(output.shape),mask_shape=list(outputmask.shape),
            remap_calls=len(arm.remap_captures),identical_to_input=np.array_equal(source,output),
            injected_confidence=arm.dewarp_confidence,mode_argument=args.mode)
        if args.gate_probe:record['status']='controlled_gate_observation'
        else:
            if len(arm.remap_captures)!=2: raise RuntimeError('Expected two remaps; entry returned without dewarp coverage')
            record['status']='controlled_branch_success'
    except Exception as exc:
        record.update(status='failed',error=str(exc),pc=hex(arm.uc.reg_read(UC_ARM_REG_PC)))
    record.update(seconds=time.perf_counter()-start,host_import_calls=arm.trace,library_sha256=arm.sha)
    record['format_calls']=arm.format_calls
    evidence=out/('native-dewarp-gate-evidence.json' if args.gate_probe else 'native-dewarp-process-evidence.json'); prior=[]
    reset=args.reset
    if evidence.exists() and not reset: prior=json.loads(evidence.read_text(encoding='utf-8')).get('records',[])
    prior.append(record)
    evidence.write_text(json.dumps({'records':prior,'scope':'Controlled branch experiment: whole get_warp_mat bypassed, smoothed recovered field and chosen confidence injected; mode chosen by researcher. Does not verify original confidence calculation, model initialization or app mode selection.'},indent=2),encoding='utf-8');print(json.dumps(record,indent=2))

if __name__=='__main__':main()
