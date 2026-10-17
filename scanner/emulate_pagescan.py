"""Execute selected original ARM routines in Unicorn, with logged host shims.

No APK execution, network, or host filesystem access from emulated instructions.
OpenCV bridge and libc shims are independent host implementations.
"""
from probe_recovered_models import ROOT, load_image, save_image
import sys, struct, math, json, time, hashlib
import numpy as np
import cv2
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm_const import *

class Arm:
    BASE=0x1000000
    HEAP=0x10000000
    STUB=0x20000000
    STACK=0x70000000
    def __init__(self,library='libpagescanner.so'):
        self.uc=Uc(UC_ARCH_ARM,UC_MODE_ARM)
        self.uc.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A15)
        self.uc.mem_map(self.BASE,0x1000000)
        self.uc.mem_map(self.HEAP,0x10000000)
        self.uc.mem_map(self.STUB,0x100000)
        self.uc.mem_map(self.STACK,0x200000)
        self.cursor=self.HEAP
        self.stubs={};self.trace={};self.allocations={};self.error=None;self.tls={};self.next_key=1
        self.format_calls=[]
        self.reuse_freed=False;self.free_blocks=[]
        self.capture_remaps=False;self.remap_captures=[];self.redirects={}
        self.dewarp_field=None
        path=ROOT/'.work/camscanner/extracted/lib/armeabi'/library
        self.sha=hashlib.sha256(path.read_bytes()).hexdigest()
        with path.open('rb') as stream:
            elf=ELFFile(stream)
            for seg in elf.iter_segments():
                if seg['p_type']=='PT_LOAD':self.uc.mem_write(self.BASE+seg['p_vaddr'],seg.data())
            table=elf.get_section_by_name('.dynsym')
            self.symbols={s.name:s['st_value']+self.BASE for s in table.iter_symbols() if s.name and s['st_shndx']!='SHN_UNDEF'}
            for sec in elf.iter_sections():
                if sec['sh_type'] not in ('SHT_REL','SHT_RELA'):continue
                linked=elf.get_section(sec['sh_link'])
                for rel in sec.iter_relocations():
                    p=self.BASE+rel['r_offset'];kind=rel['r_info_type'];old=self.u32(p)
                    sym=linked.get_symbol(rel['r_info_sym']) if rel['r_info_sym'] else None
                    if kind==23:self.w32(p,old+self.BASE)
                    elif kind in (2,21,22):
                        if sym['st_shndx']!='SHN_UNDEF':value=self.BASE+sym['st_value']
                        elif sym.name=='__stack_chk_guard':value=self.alloc(4);self.w32(value,0x12345678)
                        else:value=self.stub(sym.name)
                        self.w32(p,value+(old if kind==2 else 0))
                    elif kind!=0:raise ValueError(f'Unsupported relocation {kind}')
        self.uc.hook_add(UC_HOOK_CODE,self.callback,begin=self.STUB,end=self.STUB+0xfffff)
        # Enable VFP/NEON; the code still follows the softfp call interface.
        self.uc.reg_write(UC_ARM_REG_C1_C0_2,0xf00000)
        self.uc.reg_write(UC_ARM_REG_FPEXC,0x40000000)
    def alloc(self,n):
        n=max(n,16)
        if n>0x2000000:raise ValueError(f'Unexpected allocation {n}')
        if self.reuse_freed:
            for i,(p,size) in enumerate(self.free_blocks):
                if size>=n:
                    self.free_blocks.pop(i);self.allocations[p]=size;return p
        p=(self.cursor+15)&~15;self.cursor=p+n
        if self.cursor>=self.HEAP+0x10000000:raise MemoryError('Research heap exhausted')
        self.allocations[p]=n
        return p
    def release_allocation(self,p):
        if self.reuse_freed and p in self.allocations:
            self.free_blocks.append((p,self.allocations.pop(p)))
    def u32(self,p):return struct.unpack('<I',self.uc.mem_read(p,4))[0]
    def w32(self,p,v):self.uc.mem_write(p,struct.pack('<I',v&0xffffffff))
    def string(self,p):
        result=bytearray()
        while p and len(result)<100000:
            ch=self.uc.mem_read(p,1)[0]
            if not ch:break
            result.append(ch);p+=1
        return result.decode('utf-8',errors='replace')
    def reg(self,i):return self.uc.reg_read([UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3][i])
    def ret(self,v=0):self.uc.reg_write(UC_ARM_REG_R0,int(v)&0xffffffff)
    def retfloat(self,v,fmt):
        raw=struct.pack('<'+fmt,v);self.ret(struct.unpack('<I',raw[:4])[0])
        if fmt=='d':self.uc.reg_write(UC_ARM_REG_R1,struct.unpack('<I',raw[4:])[0])
    def stub(self,name):
        for p,n in self.stubs.items():
            if n==name:return p|1
        p=self.STUB+4*len(self.stubs);self.stubs[p]=name
        self.uc.mem_write(p,b'\x70\x47\x00\xbf')
        return p|1
    def mat(self,image,p=None):
        image=np.ascontiguousarray(image);h,w=image.shape[:2]
        channels=1 if image.ndim==2 else image.shape[2]
        depth={np.dtype('uint8'):0,np.dtype('float32'):5}[image.dtype]
        p=p or self.alloc(56);data=self.alloc(image.nbytes)
        self.uc.mem_write(data,image.tobytes())
        vals=[0x42ff4000+depth+(channels-1)*8,2,h,w,data,data,data+image.nbytes,data+image.nbytes,0,0,p+8,p+48,image.strides[0],image.itemsize*channels]
        self.uc.mem_write(p,struct.pack('<14I',*vals));return p
    def image(self,p):
        flag,_,h,w,data=struct.unpack('<5I',self.uc.mem_read(p,20));depth=flag&7;c=((flag>>3)&511)+1
        dtype={0:np.uint8,5:np.float32}[depth];stride=self.u32(self.u32(p+44))
        raw=self.uc.mem_read(data,stride*h)
        a=np.ndarray((h,w,c),dtype=dtype,buffer=raw,strides=(stride,np.dtype(dtype).itemsize*c,np.dtype(dtype).itemsize)).copy()
        return a[:,:,0] if c==1 else a
    def callback(self,uc,address,size,user):
        if address in self.redirects:
            uc.reg_write(UC_ARM_REG_PC,self.redirects[address]); return
        name=self.stubs[address];self.trace[name]=self.trace.get(name,0)+1
        a,b,c,d=[self.reg(i) for i in range(4)]
        try:
            if name=='STOP':uc.emu_stop();return
            if name=='GET_WARP_MAT':
                if self.dewarp_field is None: raise RuntimeError('No recovered dewarp field configured')
                # r0=context, r1=source Mat by value, r2=output Mat.
                self.mat(self.dewarp_field.astype(np.float32),c)
                self.retfloat(self.dewarp_confidence,'f'); return
            if name in ('malloc','_Znwj','_Znaj'):self.ret(self.alloc(a))
            elif name in ('free','_ZdlPv','_ZdaPv'):self.release_allocation(a);self.ret()
            elif name=='calloc':self.ret(self.alloc(a*b))
            elif name=='realloc':
                p=self.alloc(b)
                if a:uc.mem_write(p,bytes(uc.mem_read(a,min(b,self.allocations.get(a,b)))))
                self.ret(p)
            elif name=='memalign':self.ret(self.alloc(b))
            elif name=='posix_memalign':
                self.cursor=(self.cursor+b-1)&~(b-1)
                self.w32(a,self.alloc(c));self.ret(0)
            elif name in ('memcpy','memmove') or name.startswith(('__aeabi_memcpy','__aeabi_memmove')):
                if c:uc.mem_write(a,bytes(uc.mem_read(b,c)))
                self.ret(a)
            elif name.startswith('__aeabi_memclr'):
                if b:uc.mem_write(a,bytes(b))
                self.ret()
            elif name.startswith('__aeabi_memset'):
                if b:uc.mem_write(a,bytes([c&255])*b)
                self.ret()
            elif name=='memset':
                if c:uc.mem_write(a,bytes([b&255])*c)
                self.ret(a)
            elif name=='memcmp':
                x=bytes(uc.mem_read(a,c));y=bytes(uc.mem_read(b,c));self.ret((x>y)-(x<y))
            elif name=='strlen':
                n=0
                while bytes(uc.mem_read(a+n,1))!=b'\0':
                    n+=1
                    if n>100000:raise ValueError('Unterminated string')
                self.ret(n)
            elif name=='strdup':
                value=self.string(a).encode()+b'\0';p=self.alloc(len(value));uc.mem_write(p,value);self.ret(p)
            elif name=='snprintf':
                fmt=self.string(c)
                if fmt=='%s%s':value=(self.string(d)+self.string(self.u32(uc.reg_read(UC_ARM_REG_SP)))).encode()
                elif fmt=='/proc/%d/cmdline':value=(fmt%d).encode()
                else:raise RuntimeError(f'Unsupported snprintf format {fmt!r}')
                if b:uc.mem_write(a,value[:b-1]+b'\0')
                self.ret(len(value))
            elif name=='sprintf':
                # Dewarp initialization formats a model/cache path before probing
                # the Android filesystem; keep the operation local to the emulator.
                fmt=self.string(b)
                if fmt=='Time consumption for event <%s> is: %.3fs':
                    # AAPCS varargs: after r2 string, the double is aligned to
                    # the next 8-byte slot, at SP rather than r3.
                    seconds=struct.unpack('<d',bytes(uc.mem_read(uc.reg_read(UC_ARM_REG_SP),8)))[0]
                    value=(fmt%(self.string(c),seconds)).encode()
                    self.format_calls.append({'function':'sprintf','format':fmt,'result':value.decode()})
                    uc.mem_write(a,value+b'\0');self.ret(len(value));return
                values=[c,d]+[self.u32(uc.reg_read(UC_ARM_REG_SP)+i*4) for i in range(0,8)]
                pieces=[];vi=0;pos=0
                while pos<len(fmt):
                    if fmt[pos]!='%':pieces.append(fmt[pos]);pos+=1;continue
                    if pos+1>=len(fmt):raise RuntimeError('Unterminated sprintf specifier')
                    spec=fmt[pos+1];pos+=2
                    if spec=='%':pieces.append('%');continue
                    if spec not in 'sduxX':raise RuntimeError(f'Unsupported sprintf format {fmt!r}')
                    if vi>=len(values):raise RuntimeError('sprintf argument limit exceeded')
                    raw=values[vi];vi+=1
                    if spec=='s':repl=self.string(raw)
                    elif spec=='d':repl=str(raw if raw<0x80000000 else raw-0x100000000)
                    elif spec=='u':repl=str(raw)
                    else:repl=format(raw,spec)
                    pieces.append(repl)
                value=''.join(pieces)
                self.format_calls.append({'function':'sprintf','format':fmt,'result':value})
                uc.mem_write(a,value.encode()+b'\0');self.ret(len(value))
            elif name=='printf':
                # Diagnostic output is suppressed; no formatting semantics claimed.
                self.format_calls.append({'function':'printf','format':self.string(a),'suppressed':True})
                self.ret(0)
            elif name in ('fopen','fopen64'):self.ret(0)
            elif name in ('open','open64','access','read'):self.ret(-1)
            elif name=='close':self.ret(0)
            elif name in ('getpid','gettid'):self.ret(1)
            elif name=='pthread_key_create':self.w32(a,self.next_key);self.next_key+=1;self.ret()
            elif name=='pthread_getspecific':self.ret(self.tls.get(a,0))
            elif name=='pthread_setspecific':self.tls[a]=b;self.ret()
            elif name.startswith('pthread_'):self.ret()
            elif name=='clock_gettime':
                now=time.monotonic_ns();uc.mem_write(b,struct.pack('<II',now//1000000000,now%1000000000));self.ret()
            elif name=='getenv':self.ret(0)
            elif name=='__aeabi_l2d':
                value=(b<<32)|a
                if value&(1<<63):value-=1<<64
                self.retfloat(float(value),'d')
            elif name in ('sysconf','getpagesize'):self.ret(4096 if name=='getpagesize' or a in (30,39) else 1)
            elif name in ('__cxa_guard_acquire','__cxa_guard_release'):
                if name.endswith('acquire'):self.ret(not self.u32(a))
                else:self.w32(a,1);self.ret()
            elif name in ('__cxa_atexit','__android_log_print') or 'ios_base4Init' in name:self.ret()
            elif name in ('cos','sin','sqrt','atan2','atan','acos','asin','tan','exp','log','log2','log10','floor','ceil','pow','round','hypot','fabs') or name.rstrip('f') in ('cos','sin','sqrt','atan2','atan','acos','asin','tan','exp','log','floor','ceil','pow','round','hypot','fabs'):
                is_float=name.endswith('f');base=name[:-1] if is_float else name;fmt='f' if is_float else 'd'
                x=struct.unpack('<'+fmt,struct.pack('<I',a) if is_float else struct.pack('<II',a,b))[0]
                args=[x]
                if base in ('atan2','pow','hypot'):
                    args.append(struct.unpack('<'+fmt,struct.pack('<I',b) if is_float else struct.pack('<II',c,d))[0])
                fn=(lambda x:math.floor(x+0.5) if x>=0 else math.ceil(x-0.5)) if base=='round' else getattr(math,base)
                self.retfloat(fn(*args),fmt)
            elif 'fitLine' in name:
                sp=uc.reg_read(UC_ARM_REG_SP)
                self.fit_debug={'input':list(struct.unpack('<4I',uc.mem_read(a,16))), 'output':list(struct.unpack('<4I',uc.mem_read(b,16))), 'stack':list(struct.unpack('<3d',uc.mem_read(sp,24)))}
                flags=self.u32(a);obj=self.u32(a+4)
                if ((flags>>16)&31)!=3 or (flags&0xfff)!=12 or ((self.u32(b)>>16)&31)!=2:
                    raise NotImplementedError('fitLine layout '+str(self.fit_debug))
                begin,end=self.u32(obj),self.u32(obj+4)
                points=np.frombuffer(uc.mem_read(begin,end-begin),np.int32).reshape(-1,2).copy()
                param,reps,aeps=self.fit_debug['stack']
                value=cv2.fitLine(points,c,param,reps,aeps).astype(np.float32)
                uc.mem_write(self.u32(b+4),value.tobytes());self.ret()
            elif name.startswith('_ZN2cv4blur'):
                inp=self.u32(a+4);out=self.u32(b+4)
                kernel=struct.unpack('<ii',uc.mem_read(c,8))
                anchor=struct.unpack('<ii',uc.mem_read(d,8))
                border=self.u32(uc.reg_read(UC_ARM_REG_SP))
                self.mat(cv2.blur(self.image(inp),kernel,anchor=anchor,borderType=border),out);self.ret()
            elif 'cvtColor' in name:
                self.mat(cv2.cvtColor(self.image(self.u32(a+4)),c,dstCn=d),self.u32(b+4));self.ret()
            elif name.startswith('_ZN2cv6resize'):
                inp=self.u32(a+4);out=self.u32(b+4)
                dimensions=struct.unpack('<ii',uc.mem_read(c,8))
                fx,fy,interpolation=struct.unpack('<ddi',uc.mem_read(uc.reg_read(UC_ARM_REG_SP),20))
                self.mat(cv2.resize(self.image(inp),dimensions,fx=fx,fy=fy,interpolation=interpolation),out);self.ret()
            elif name.startswith('_ZN2cv5remap'):
                sp=uc.reg_read(UC_ARM_REG_SP)
                interpolation,border=struct.unpack('<ii',uc.mem_read(sp,8))
                scalar_ptr=self.u32(sp+8)
                scalar=struct.unpack('<4d',uc.mem_read(scalar_ptr,32))
                inp=self.image(self.u32(a+4));map1=self.image(self.u32(c+4))
                map2ptr=self.u32(d+4)
                map2=self.image(map2ptr) if map2ptr and self.u32(map2ptr+16) else None
                if self.capture_remaps:
                    self.remap_captures.append({'map1':map1.copy(),'map2':None if map2 is None else map2.copy(),'source_shape':list(inp.shape),'interpolation':interpolation,'border':border,'scalar':scalar})
                self.mat(cv2.remap(inp,map1,map2,interpolation,borderMode=border,borderValue=scalar),self.u32(b+4));self.ret()
            elif 'GaussianBlur' in name:
                inp=self.u32(a+4);out=self.u32(b+4)
                sp=uc.reg_read(UC_ARM_REG_SP)
                sx,sy,border=struct.unpack('<ddi',uc.mem_read(sp,20))
                c,d=struct.unpack('<ii',uc.mem_read(c,8))
                self.gaussian={'kernel':[c,d],'sigma':[sx,sy],'border':border}
                value=cv2.GaussianBlur(self.image(inp),(c,d),sx,sigmaY=sy,borderType=border)
                self.mat(value,out);self.ret()
            else:raise NotImplementedError(f'Unimplemented import {name}, args={[hex(v) for v in (a,b,c,d)]}')
        except Exception as e:self.error=f'{type(e).__name__}: {e}';uc.emu_stop()
    def call(self,address,args):
        self.error=None
        sp=self.STACK+0x1f0000
        self.uc.reg_write(UC_ARM_REG_SP,sp)
        for i,v in enumerate(args):
            if i<4:self.uc.reg_write([UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3][i],v)
            else:self.w32(sp+(i-4)*4,v)
        stop=self.stub('STOP');self.uc.reg_write(UC_ARM_REG_LR,stop)
        self.uc.emu_start(address,0,timeout=45_000_000,count=100_000_000)
        if self.error:raise RuntimeError(self.error)
        if self.uc.reg_read(UC_ARM_REG_PC)!=stop&~1:raise RuntimeError('Emulation instruction/time budget exhausted')
        return self.reg(0)
    def patch_get_warp_mat(self):
        """Redirect only the model-producing function to a recovered field.

        Entire get_warp_mat is bypassed, including its confidence calculation.
        The caller's confidence gates, mask, coordinate normalization and remap
        operations remain ARM code. Injected confidence is a research parameter.
        """
        target=next(v for n,v in self.symbols.items() if n.endswith('get_warp_mat') or n=='get_warp_mat')
        stub=self.stub('GET_WARP_MAT')
        self.redirects[target&~1]=stub
        self.uc.hook_add(UC_HOOK_CODE,self.callback,begin=target&~1,end=target&~1)

def main():
    arm=Arm();out=ROOT/'output/camscanner-reverse/model-probe'
    stem=sys.argv[1] if len(sys.argv)>1 else 'photo-1'
    if stem not in ('photo-1','photo-2'):raise ValueError('Choose photo-1 or photo-2')
    image=load_image(out/f'{stem}-pagescan-BGR-0.png')
    image=cv2.cvtColor(image,cv2.COLOR_BGR2GRAY)
    mat=arm.mat(image);lines=arm.alloc(12)
    start=time.perf_counter()
    result={}
    try:
        arm.call(arm.symbols['_ZN8pagescan16findLines_EDLineEN2cv3MatERNSt6__ndk16vectorINS0_3VecIfLi3EEENS2_9allocatorIS5_EEEE'],[mat,lines])
        begin,end=arm.u32(lines),arm.u32(lines+4)
        values=np.frombuffer(arm.uc.mem_read(begin,end-begin),np.float32).reshape(-1,3).tolist() if begin!=end else []
        result={'status':'success','lines':values}
        selected=arm.alloc(12)
        ok=arm.call(arm.BASE+0x730c0+1,[lines,mat,selected])
        begin,end=arm.u32(selected),arm.u32(selected+4)
        pairs=[struct.unpack('<IB3x',arm.uc.mem_read(p,8)) for p in range(begin,end,8)]
        result.update({'selection_status':ok,'selected_pairs':pairs})
        if ok and len(pairs)==4:
            vec=arm.alloc(12);data=arm.alloc(48)
            for i,(index,flag) in enumerate(pairs):
                arm.uc.mem_write(data+i*12,struct.pack('<3f',*values[index]))
            arm.uc.mem_write(vec,struct.pack('<3I',data,data+48,data+48))
            flags=arm.alloc(16);bits=arm.alloc(4)
            arm.w32(bits,sum(int(flag)<<i for i,(_,flag) in enumerate(pairs)))
            arm.uc.mem_write(flags,struct.pack('<4I',bits,0,4,1))
            corners=arm.alloc(32)
            arm.call(arm.BASE+0x75330+1,[vec,flags,mat,corners])
            arm.call(arm.symbols['_ZN8pagescan21reSortPointsClockWiseEPf'],[corners])
            quad=np.frombuffer(arm.uc.mem_read(corners,32),np.float32).reshape(4,2)
            result['corners_working_image']=quad.tolist()
            original=load_image(ROOT/f'scanner/samples/{stem}.jpg')
            quad=quad*np.array([original.shape[1]/image.shape[1],original.shape[0]/image.shape[0]])
            result['corners_original_image']=quad.tolist()
            preview=original.copy();cv2.polylines(preview,[np.rint(quad).astype(np.int32)],True,(0,255,0),4)
            save_image(out/f'{stem}-original-ARM-outline.png',preview)
    except Exception as e:
        result.update({'status':'failed','error':str(e),'pc':hex(arm.uc.reg_read(UC_ARM_REG_PC)),'gaussian':getattr(arm,'gaussian',None)})
    result.update({'library_sha256':arm.sha,'seconds':time.perf_counter()-start,'host_import_calls':arm.trace,
                   'source':stem,'scope':'Original ARM line detection, selection, corner refinement and sorting on recovered network map; libc/math, GaussianBlur and fitLine use host shims. Not live camera or app end-to-end validation.'})
    (out/f'{stem}-arm-geometry-evidence.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
