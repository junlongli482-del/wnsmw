"""Run restored x86 constructors with explicit ELF relocations/import stubs."""
from pathlib import Path
import sys,struct,json,re,hashlib,xml.etree.ElementTree as ET
import pickle
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.work/reverse-python'))
from unicorn import *
from unicorn.x86_const import *
from elftools.elf.elffile import ELFFile
CLONE_MODEL='--clone-model' in sys.argv
PROC_SNAPSHOT='--proc-snapshot' in sys.argv
JNI_MODEL='--jni-model' in sys.argv
AL_MODEL='--al-model' in sys.argv
ART_FILE_MODEL='--art-file-model' in sys.argv
PROBE_STACK_MODEL='--probe-stack-model' in sys.argv
FACTORY_STACK_MODEL='--factory-stack-model' in sys.argv
STACK_MODEL=PROBE_STACK_MODEL or FACTORY_STACK_MODEL
PTHREAD_MODEL='--pthread-model' in sys.argv
WITHOUT_QEMU_FIXTURE='--without-qemu-fixture' in sys.argv
NONEMULATOR_PROFILE='--nonemulator-profile' in sys.argv
HOST_ZLIB_FIXTURE='--host-zlib-fixture' in sys.argv
BLOCK_TRACE='--block-trace' in sys.argv
AL_BUDGET=int(next((s.split('=',1)[1] for s in sys.argv if s.startswith('--al-instructions=')),'15000000'))
RUN_TAG=next((s.split('=',1)[1] for s in sys.argv if s.startswith('--run-tag=')), '')
if RUN_TAG and not re.fullmatch(r'[a-zA-Z0-9_-]+',RUN_TAG):
    raise ValueError('Invalid run-tag')
RESUME_TAG=next((s.split('=',1)[1] for s in sys.argv if s.startswith('--resume-checkpoint=')), '')
SAVE_CHECKPOINT='--save-checkpoint' in sys.argv
if RESUME_TAG and not re.fullmatch(r'[a-zA-Z0-9_-]+',RESUME_TAG):
    raise ValueError('Invalid checkpoint tag')
if SAVE_CHECKPOINT and not RUN_TAG:raise ValueError('Checkpoint save requires run-tag')

def run(name):
    p=ROOT/'.work/camscanner/shell-unpacked/x86'/name;b=p.read_bytes();h=struct.unpack_from('<16sHHIIIIIHHHHHH',b)
    tags={}
    for i in range(h[10]):
        typ,off,va,pa,fs,ms,fl,al=struct.unpack_from('<8I',b,h[5]+i*h[9])
        if typ==2:
            for pos in range(va,va+fs,8):
                tag,val=struct.unpack_from('<II',b,pos)
                if not tag:break
                tags[tag]=val
    base=0x1000000;u=Uc(UC_ARCH_X86,UC_MODE_32);u.mem_map(base,(len(b)+4095)&~4095);u.mem_write(base,b)
    heap_capacity=0x10000000
    u.mem_map(0x60000000,0x10000);u.mem_map(0x70000000,0x100000);u.mem_map(0x30000000,heap_capacity)
    # Minimal GS:0x14 stack-canary backing; not a real Android thread/TLS block.
    u.mem_map(0,0x1000);u.mem_write(0x14,struct.pack('<I',0x13579bdf))
    # Real emulator linker file at its observed zygote AT_BASE. File PT_LOAD
    # bytes are used, not a claim that linker dynamic state has been restored.
    context=ROOT/'.work/camscanner/shell-unpacked/x86'
    properties=json.loads((context/'android-properties.json').read_text())
    package_dump=(context/'android-target-package.txt').read_text();package_meta={'targetSdkVersion':int(re.search(r'targetSdk=(\d+)',package_dump).group(1)),'packageName':'com.intsig.camscanner','sourceDir':re.search(r'codePath=(\S+)',package_dump).group(1)+'/base.apk','dataDir':re.search(r'dataDir=(\S+)',package_dump).group(1)}
    package_meta['nativeLibraryDir']=re.search(r'legacyNativeLibraryDir=(\S+)',package_dump).group(1)+'/arm' # adb ls confirms sole lib/arm directory; target primaryCpuAbi=armeabi
    apk_evidence=json.loads((ROOT/'output/camscanner-reverse/rea-android-package.json').read_text(encoding='utf-8-sig'));manifest_call=next(c for c in apk_evidence['raw_result']['calls'] if c['operation']=='get_android_manifest');manifest=ET.fromstring(manifest_call['response']['content'][0]['text']);package_meta['className']=manifest.find('application').attrib['{http://schemas.android.com/apk/res/android}name']
    aux=dict(struct.iter_unpack('<II',(context/'android-zygote-auxv.bin').read_bytes()))
    linker=(context/'android-linker').read_bytes();lh=struct.unpack_from('<16sHHIIIIIHHHHHH',linker)
    lseg=[struct.unpack_from('<8I',linker,lh[5]+i*lh[9]) for i in range(lh[10])]
    lsize=(max(s[2]+s[5] for s in lseg if s[0]==1)+4095)&~4095
    u.mem_map(aux[7],lsize)
    for typ,off,va,pa,fs,ms,fl,al in lseg:
        if typ==1:u.mem_write(aux[7]+va,linker[off:off+fs])
    art_model=None;art_writes=[];file_library_ranges=[]
    if ART_FILE_MODEL:
        artbase=int(re.search(r'^([0-9a-f]+)-[^\n]+\s00000000[^\n]+/apex/com.android.art/lib/libart.so', (context/'android-zygote-maps.txt').read_text(), re.M)[1],16)
        with (context/'android-libart.so').open('rb') as af:
            art=ELFFile(af);asegs=[s for s in art.iter_segments() if s['p_type']=='PT_LOAD'];asize=(max(s['p_vaddr']+s['p_memsz'] for s in asegs)+4095)&~4095;u.mem_map(artbase,asize)
            for s in asegs:u.mem_write(artbase+s['p_vaddr'],s.data())
            art_model={'base':hex(artbase),'size':asize,'sha256':hashlib.sha256((context/'android-libart.so').read_bytes()).hexdigest(),'segments':[{'file_offset':s['p_offset'],'virtual_address':hex(artbase+s['p_vaddr']),'file_size':s['p_filesz'],'memory_size':s['p_memsz'],'flags':s['p_flags']} for s in asegs],'scope':'Original libart ELF PT_LOAD file bytes at observed zygote base. No dynamic relocations applied; no live ART/JVM state, objects, threads or loader state. mprotect success is an explicit offline-only assumption; real device execmod denied.'}
        file_library_ranges.append((artbase,asize,'libart.so'))
        logbase=int(re.search(r'^([0-9a-f]+)-[^\n]+\s00000000[^\n]+/system/lib/liblog.so', (context/'android-zygote-maps.txt').read_text(), re.M)[1],16)
        with (context/'android-liblog.so').open('rb') as lf:
            logelf=ELFFile(lf);lsegs=[s for s in logelf.iter_segments() if s['p_type']=='PT_LOAD'];logsize=(max(s['p_vaddr']+s['p_memsz'] for s in lsegs)+4095)&~4095;u.mem_map(logbase,logsize)
            for s in lsegs:u.mem_write(logbase+s['p_vaddr'],s.data())
            art_model['additional_file_libraries']=[{'name':'liblog.so','base':hex(logbase),'size':logsize,'sha256':hashlib.sha256((context/'android-liblog.so').read_bytes()).hexdigest(),'segments':[{'file_offset':s['p_offset'],'virtual_address':hex(logbase+s['p_vaddr']),'file_size':s['p_filesz'],'memory_size':s['p_memsz'],'flags':s['p_flags']} for s in lsegs]}]
        file_library_ranges.append((logbase,logsize,'liblog.so'))
        dexbase=int(re.search(r'^([0-9a-f]+)-[^\n]+\s00000000[^\n]+/apex/com.android.art/lib/libdexfile.so', (context/'android-zygote-maps.txt').read_text(), re.M)[1],16)
        with (context/'android-libdexfile.so').open('rb') as df:
            dexelf=ELFFile(df);dsegs=[s for s in dexelf.iter_segments() if s['p_type']=='PT_LOAD'];dexsize=(max(s['p_vaddr']+s['p_memsz'] for s in dsegs)+4095)&~4095;u.mem_map(dexbase,dexsize)
            for s in dsegs:u.mem_write(dexbase+s['p_vaddr'],s.data())
        file_library_ranges.append((dexbase,dexsize,'libdexfile.so'))
        art_model['additional_file_libraries'].append({'name':'libdexfile.so','base':hex(dexbase),'size':dexsize,'sha256':hashlib.sha256((context/'android-libdexfile.so').read_bytes()).hexdigest(),'scope':'Read-only emulator file PT_LOAD at observed zygote address. No relocations, live ART state or Android protection semantics.'})
        def art_write_hook(uc,access,address,size,value,data):
            for lo,sz,libname in file_library_ranges:
                if lo<=address<lo+sz:art_writes.append({'library':libname,'address':hex(address),'pc':hex(uc.reg_read(UC_X86_REG_EIP)),'old':bytes(uc.mem_read(address,size)).hex(),'new':(value&((1<<(size*8))-1)).to_bytes(size,'little').hex(),'source':'Original CPU store into offline library-file mapping'})
        u.hook_add(UC_HOOK_MEM_WRITE,art_write_hook)
    libcbase=0x40000000;libcpath=context/'android-libc.so'
    with libcpath.open('rb') as f:
        libc=ELFFile(f);libcseg=[s for s in libc.iter_segments() if s['p_type']=='PT_LOAD']
        libcsize=(max(s['p_vaddr']+s['p_memsz'] for s in libcseg)+4095)&~4095
        u.mem_map(libcbase,libcsize)
        for s in libcseg:u.mem_write(libcbase+s['p_vaddr'],s.data())
        libcsymbols={s.name:libcbase+s['st_value'] for s in libc.get_section_by_name('.dynsym').iter_symbols() if s['st_shndx']!='SHN_UNDEF'}
    stubs={};imports=[];relocs=[];heap=0x30000000;calls=[];faults=[];last=[];tls={};children=[];files={};strtok_next=0;jclasses={};jfields={};jstrings={};jmethods={};jarrays={};jobjects={};additional_libraries={};rand48_state=0x1234abcd330e;pthread_tasks=[];pthread_results=[];cipher_observations=[];cipher_pending=[]
    def read32(x):return struct.unpack('<I',u.mem_read(x,4))[0]
    def write32(x,v):u.mem_write(x,struct.pack('<I',v&0xffffffff))
    def sym(index):
        ni,value,size,info,other,sh=struct.unpack_from('<IIIBBH',b,tags[6]+index*16)
        start=tags[5]+ni;end=b.find(b'\0',start)
        return b[start:end].decode('ascii','replace'),value,sh
    def stub(n):
        for a,s in stubs.items():
            if s==n:return a
        a=0x60000100+len(stubs)*16;stubs[a]=n;u.mem_write(a,b'\xc3');return a
    for addr,length in [(tags.get(17,0),tags.get(18,0)),(tags.get(23,0),tags.get(2,0))]:
        for pos in range(addr,addr+length,8):
            target,info=struct.unpack_from('<II',b,pos);typ=info&255;si=info>>8;old=read32(base+target)
            if typ==8:new=old+base
            elif typ in (1,6,7):
                n,value,sh=sym(si);dest=base+value if sh else stub(n)
                new=dest+(old if typ==1 else 0)
            else:relocs.append({'offset':hex(target),'type':typ,'unsupported':True});continue
            write32(base+target,new);relocs.append({'offset':hex(target),'type':typ})
    payload_observations=[];payload_pending=[]
    def code(uc,address,length,data):
        nonlocal heap,strtok_next,rand48_state
        if HOST_ZLIB_FIXTURE and name=='libexec.so' and address==base+0x7fa20:
            import zlib,zipfile,io
            sp=uc.reg_read(UC_X86_REG_ESP);argv=[read32(sp+4+i*4) for i in range(3)];entry=argv[0]
            carrier=(ROOT/'output/camscanner-reverse/payload-dumps/dat-transformed-at-cache-open.bin').read_bytes()[40:]
            archive=zipfile.ZipFile(io.BytesIO(carrier));info=archive.getinfo('classes.dex')
            offset=info.header_offset+30+len(info.filename.encode())+struct.unpack_from('<H',carrier,info.header_offset+28)[0]
            expected_compressed=carrier[offset:offset+info.compress_size]
            compressed=bytes(uc.mem_read(read32(entry+0x14),read32(entry+0x10)))
            if compressed!=expected_compressed or read32(entry+0xc)!=info.file_size or struct.unpack('<H',uc.mem_read(entry+8,2))[0]!=8:
                calls.append({'name':'host-dat-zip-fixture','unsupported':True,'reason':'Input does not match independently validated transformed dat ZIP member'});uc.emu_stop();return
            expanded=zlib.decompress(compressed,-15);expected=archive.read(info)
            if expanded!=expected or len(expanded)>argv[2]:raise ValueError('Dat ZIP fixture mismatch or capacity exceeded')
            uc.mem_write(argv[1],expanded)
            calls.append({'name':'host-dat-zip-fixture','input_sha256':hashlib.sha256(compressed).hexdigest(),'output_sha256':hashlib.sha256(expanded).hexdigest(),'output_bytes':len(expanded),'scope':'Host raw DEFLATE replacement only after exact input comparison with validated original-transformed dat ZIP member; CRC and output equality checked. Protected carrier, not recovered DEX or original Android execution.'})
            uc.reg_write(UC_X86_REG_EAX,0);uc.reg_write(UC_X86_REG_EIP,read32(sp));uc.reg_write(UC_X86_REG_ESP,sp+4);return
        if HOST_ZLIB_FIXTURE and name=='libexec.so' and address==base+0x81680:
            import zlib
            sp=uc.reg_read(UC_X86_REG_ESP);argv=[read32(sp+4+i*4) for i in range(4)]
            if argv[0] in files and argv[2]==14112882:
                blob,pos=files[argv[0]];compressed=blob[pos:pos+argv[3]]
                expanded=zlib.decompress(compressed,-15);expected=(ROOT/'.work/camscanner/extracted/assets/ijiami.ajm').read_bytes()
                if expanded!=expected:raise ValueError('APK resource fixture mismatch')
                uc.mem_write(argv[1],expanded);files[argv[0]][1]+=len(compressed)
                calls.append({'name':'host-apk-inflate-fixture','output_bytes':len(expanded),'output_sha256':hashlib.sha256(expanded).hexdigest(),'scope':'Explicit replacement of raw DEFLATE for APK ajm member only; output equality to original APK resource checked. Not all-original instruction evidence.'})
                uc.reg_write(UC_X86_REG_EAX,0);uc.reg_write(UC_X86_REG_EIP,read32(sp));uc.reg_write(UC_X86_REG_ESP,sp+4);return
        if HOST_ZLIB_FIXTURE and name=='libexec.so' and address==base+0x92aa0:
            import zlib
            sp=uc.reg_read(UC_X86_REG_ESP);argv=[read32(sp+4+i*4) for i in range(4)]
            compressed=bytes(uc.mem_read(argv[2],argv[3]));expected=(ROOT/'output/camscanner-reverse/payload-dumps/ajm-transform-isolated.bin').read_bytes()[24:]
            if compressed!=expected:
                calls.append({'name':'host-zlib-fixture','unsupported':True,'reason':'Input does not match independently verified ajm transform'});uc.emu_stop();return
            expanded=zlib.decompress(compressed);capacity=read32(argv[1])
            if len(expanded)>capacity:raise ValueError('Host zlib fixture exceeds output capacity')
            uc.mem_write(argv[0],expanded);write32(argv[1],len(expanded))
            calls.append({'name':'host-zlib-fixture','entry':hex(address),'input_sha256':hashlib.sha256(compressed).hexdigest(),'output_sha256':hashlib.sha256(expanded).hexdigest(),'output_bytes':len(expanded),'scope':'Explicit host replacement of original zlib uncompress only, exact input equality checked against independently original-transformed resource; subsequent parser code remains original. Not all-original execution evidence.'})
            uc.reg_write(UC_X86_REG_EAX,0);uc.reg_write(UC_X86_REG_EIP,read32(sp));uc.reg_write(UC_X86_REG_ESP,sp+4);return
        for pending in list(payload_pending):
            if address==pending['return'] and uc.reg_read(UC_X86_REG_ESP)==pending['sp']+4:
                rec=pending['record'];rec['eax']=hex(uc.reg_read(UC_X86_REG_EAX))
                ptr=read32(pending['outptr']);size=read32(pending['sizeptr'])
                rec.update(output_pointer=hex(ptr),output_length=size)
                if ptr and 0<size<=64*1024*1024:
                    raw=bytes(uc.mem_read(ptr,size));dest=ROOT/'output/camscanner-reverse/payload-dumps'
                    dest.mkdir(exist_ok=True);path=dest/(name+'-'+(RUN_TAG or 'untagged')+'-'+str(rec['sequence'])+'.bin')
                    path.write_bytes(raw);rec.update(file=str(path.relative_to(ROOT)),sha256=hashlib.sha256(raw).hexdigest(),head_hex=raw[:256].hex())
                payload_pending.remove(pending)
        if name=='libexec.so' and address in (base+0x4fce0,base+0x50140,base+0x4ff50):
            sp=uc.reg_read(UC_X86_REG_ESP);argv=[read32(sp+4+i*4) for i in range(4)]
            rec={'sequence':len(payload_observations),'entry':hex(address),'args':list(map(hex,argv)),
                 'scope':'Original offline resource-reader arguments and return buffer; not original Android runtime.'}
            for index in (0,1):
                try:rec['string'+str(index)]=bytes(uc.mem_read(argv[index],512)).split(b'\0')[0].decode('utf-8','replace')
                except Exception:pass
            payload_observations.append(rec)
            payload_pending.append({'return':read32(sp),'sp':sp,'outptr':argv[2],'sizeptr':argv[3],'record':rec})
        for pending in list(cipher_pending):
            if address==pending['return']:
                rec=pending['record'];length=read32(pending['outlen']);rec['output_length']=length;rec['output_hex']=bytes(uc.mem_read(pending['out'],min(max(length,0),4096))).hex();rec['output_cstring_preview']=bytes(uc.mem_read(pending['out'],256)).split(b'\0')[0].decode('ascii','replace');cipher_pending.remove(pending)
        if name=='libexec.so' and address==base+0x4a3e0:
            sp=uc.reg_read(UC_X86_REG_ESP);keyptr=read32(sp+8);cipher_observations.append({'function':'original SM4 reversed key schedule','entry':hex(address),'key_hex':bytes(uc.mem_read(keyptr,16)).hex(),'scope':'Observed function arguments from original offline N.al path; no substitution cipher'})
        if name=='libexec.so' and address==base+0x4a900:
            sp=uc.reg_read(UC_X86_REG_ESP);args=[read32(sp+4+i*4) for i in range(5)];rec={'function':'original padded block decrypt','entry':hex(address),'input_length':args[1],'input_hex':bytes(uc.mem_read(args[2],min(args[1],4096))).hex(),'scope':'Original function machine code; input arguments and returned output bytes only'};cipher_observations.append(rec);cipher_pending.append({'return':read32(sp),'out':args[3],'outlen':args[4],'record':rec})
        if 0x50000000<=address<0x50100000 and 'libexecmain_x86.so' in additional_libraries:
            lib=additional_libraries['libexecmain_x86.so'];counter='executed_blocks' if BLOCK_TRACE else 'executed_instructions';lib[counter]=lib.get(counter,0)+1
        if len(last)>20:last.pop(0)
        last.append(hex(address))
        if address==libcsymbols.get('pthread_create'):
            sp=uc.reg_read(UC_X86_REG_ESP);args=[read32(sp+4+i*4) for i in range(4)];event={'name':'pthread_create','entry':hex(address),'args':list(map(hex,args)),'return_address':hex(read32(sp)),'argument_words':[hex(read32(args[3]+off)) for off in (0,4)] if args[3] else []};calls.append(event)
            if not PTHREAD_MODEL:event.update({'unsupported':True,'source':'Original shell resolved actual emulator libc pthread_create export from mapped ELF. Stop before executing unrelocated libc or inventing Android pthread state.'});uc.emu_stop();return
            if args[1]!=0:event['unsupported']=True;event['reason']='Non-null pthread_attr_t not modeled';uc.emu_stop();return
            pthread_tasks.append({'entry':args[2],'arg':args[3],'tid':2000+len(pthread_tasks)});write32(args[0],pthread_tasks[-1]['tid']);event['model']='Explicit sequential offline pthread queue: synthetic tid, return success, callback runs after parent stage. No actual OS thread, libc pthread state, concurrency or scheduler.';event['result']='0x0';uc.reg_write(UC_X86_REG_EAX,0);uc.reg_write(UC_X86_REG_EIP,read32(sp));uc.reg_write(UC_X86_REG_ESP,sp+4);return
        if address==0x60000000:uc.emu_stop();return
        if address not in stubs:return
        n=stubs[address];sp=uc.reg_read(UC_X86_REG_ESP);args=[read32(sp+4+i*4) for i in range(4)];r=0
        event={'name':n,'args':list(map(hex,args)),'return_address':hex(read32(sp))};calls.append(event)
        if n=='JNI.GetMethodID':
            frames=[];fp=uc.reg_read(UC_X86_REG_EBP)
            for depth in range(8):
                try:
                    nextfp,ret=struct.unpack('<II',uc.mem_read(fp,8));frames.append({'frame':hex(fp),'return':hex(ret)})
                    if nextfp<=fp or not 0x70000000<=nextfp<0x70100000:break
                    fp=nextfp
                except Exception:break
            event['native_frames']=frames
        if n in ('malloc','_Znwj','_Znaj','calloc'):
            size=args[0]*(args[1] if n=='calloc' else 1);r=heap;heap+=(size+15)&~15
        elif n in ('free','__cxa_atexit','__cxa_finalize','__register_atfork','pthread_atfork','pthread_mutex_init','pthread_once'):pass
        elif n in ('pthread_mutex_lock','pthread_mutex_unlock'):event['model']='Sequential emulation: mutex acquisition/release no-op; no real concurrent thread'
        elif n=='pthread_key_create':write32(args[0],1)
        elif n=='pthread_getspecific':r=tls.get(args[0],0)
        elif n=='pthread_setspecific':tls[args[0]]=args[1]
        elif n=='__errno':r=0x800;event['model']='Explicit offline thread-local errno integer cell, synthetic address; no Bionic TLS'
        elif n=='getpid' and PROC_SNAPSHOT:r=309;event['model']='Fixture PID=309, matching captured zygote proc files; not actual application process'
        elif n=='access' and PTHREAD_MODEL:
            path=bytes(uc.mem_read(args[0],512)).split(b'\0')[0].decode();fixture=json.loads((context/'android-access.json').read_text());observed=fixture['results'].get(path);event.update({'path':path,'mode':args[1]})
            if not observed or observed['mode']!=args[1]:event['unsupported']=True;uc.emu_stop();return
            r=observed['result']&0xffffffff;event['observed_errno']=observed['errno'];event['source']=fixture['source'];event['scope']=fixture['scope']
            if (WITHOUT_QEMU_FIXTURE or NONEMULATOR_PROFILE) and path in ('/dev/socket/qemud','/dev/qemu_pipe'):
                event['observed_actual_result']=observed['result'];event['counterfactual_override']={'result':-1,'errno':2,'reason':'Explicit static-path exploration fixture: both qemu paths treated absent, contrary to actual emulator /dev/qemu_pipe presence. Not real-device/application execution evidence.'};r=0xffffffff
        elif n=='time' and ART_FILE_MODEL:
            fixture=json.loads((context/'android-time.json').read_text());r=fixture['unix_seconds'];event['source']=fixture
            if args[0]:write32(args[0],r)
        elif n=='srand48':rand48_state=((args[0]&0xffffffff)<<16)|0x330e;event['model']='POSIX 48-bit LCG seed semantics on offline frozen-time fixture'
        elif n in ('lrand48','mrand48'):
            rand48_state=(0x5deece66d*rand48_state+0xb)&((1<<48)-1);r=rand48_state>>(17 if n=='lrand48' else 16);event['model']='POSIX 48-bit LCG integer return semantics, deterministic offline state'
        elif n=='mprotect' and ART_FILE_MODEL and any(lo<=args[0]<lo+sz for lo,sz,libname in file_library_ranges):
            event['model']='Optional offline ART-file model accepts requested protection on file PT_LOAD mapping; no real OS/SELinux call. Real Android execution denied execmod at this point. File bytes omit live relocations and ART runtime state.'
        elif n=='mprotect' and ART_FILE_MODEL and 0x30000000<=args[0]<heap:
            event['model']='Optional offline model accepts protection of synthetic allocator memory; mapped Unicorn pages remain accessible. No OS protection/SELinux semantics.'
        elif n=='sysconf' and args[0] in (0x1e,0x27,0x28):r={0x1e:1,0x27:4096,0x28:4096}[args[0]];event['source']='Actual emulator-5580 probe-shell-sysconf: bionic sysconf(30)=1, sysconf(39/40)=4096; corrected prior Linux-enum assumption'
        elif n in ('mmap','__mmap2') and args[0]==0:
            r=(heap+4095)&~4095;heap=r+((args[1]+4095)&~4095);fd=read32(sp+20);off=read32(sp+24)*(4096 if n=='__mmap2' else 1)
            if fd in files:
                uc.mem_write(r,files[fd][0][off:off+args[1]]);event['file_fixture']={'fd':fd,'offset':off,'requested_bytes':args[1]}
            elif not (args[3]&0x20):event['unsupported']=True;uc.emu_stop();return
        elif n=='munmap':event['model']='Offline unmap accepted but bytes retained for analysis; not OS memory protection semantics'
        elif n=='__system_property_get':
            key=bytes(uc.mem_read(args[0],100)).split(b'\0')[0].decode('ascii','replace');event['property']=key
            value=properties.get(key,'');event['source']='Observed emulator-5580 full getprop inventory (absent key returns empty)';event['value']=value
            if NONEMULATOR_PROFILE:
                profile=json.loads((context/'counterfactual-nonemulator-properties.json').read_text())
                if key in profile['overrides']:event['observed_actual_value']=value;value=profile['overrides'][key];event['counterfactual_override']={'value':value,'scope':profile['scope']}
            raw=value.encode();uc.mem_write(args[1],raw+b'\0');r=len(raw)
        elif n in ('strlen','__strlen_chk'):r=bytes(uc.mem_read(args[0],8192)).index(0)
        elif n=='atoi':
            value=bytes(uc.mem_read(args[0],256)).split(b'\0')[0];m=re.match(rb'\s*([+-]?\d+)',value);r=int(m.group(1)) if m else 0
        elif n=='strtol' and args[1]==0 and args[2]==16:
            value=bytes(uc.mem_read(args[0],256)).split(b'\0')[0]
            match=re.match(rb'[\t\n\v\f\r ]*([+-]?)(?:0[xX](?=[0-9a-fA-F]))?([0-9a-fA-F]+)',value)
            parsed=int(match[2],16)*(-1 if match[1]==b'-' else 1) if match else 0
            if not -0x80000000<=parsed<=0x7fffffff:
                parsed=max(-0x80000000,min(parsed,0x7fffffff));write32(0x800,34)
            r=parsed&0xffffffff;event.update(input=value.decode('ascii','replace'),base=16,model='Bounded C 32-bit strtol(base16), null endptr; overflow clamps and sets ERANGE. Other signatures remain unsupported.')
        elif n=='strtok':
            ptr=args[0] or strtok_next;delims=bytes(uc.mem_read(args[1],256)).split(b'\0')[0]
            if ptr:
                while bytes(uc.mem_read(ptr,1))[0] in delims:ptr+=1
                if bytes(uc.mem_read(ptr,1))!=b'\0':
                    r=ptr
                    while bytes(uc.mem_read(ptr,1))!=b'\0' and bytes(uc.mem_read(ptr,1))[0] not in delims:ptr+=1
                    if bytes(uc.mem_read(ptr,1))!=b'\0':uc.mem_write(ptr,b'\0');strtok_next=ptr+1
                    else:strtok_next=0
        elif n=='__vsprintf_chk':
            fmt=bytes(uc.mem_read(args[3],256)).split(b'\0')[0].decode('ascii','replace');ap=read32(sp+20);event['format']=fmt
            if fmt=='%02x':
                value=format(read32(ap),'02x').encode()
                if len(value)+1>args[2]:event['unsupported']=True;uc.emu_stop();return
                uc.mem_write(args[0],value+b'\0');r=len(value)
            elif fmt in ('%s%s','%s/i%s'):
                parts=[bytes(uc.mem_read(read32(ap+i*4),4096)).split(b'\0')[0] for i in range(2)]
                value=(b'' if fmt=='%s%s' else b'/i').join(parts);event['string_arguments']=[part.decode('utf-8','replace') for part in parts]
                if len(value)+1>args[2]:event['unsupported']=True;uc.emu_stop();return
                uc.mem_write(args[0],value+b'\0');r=len(value)
            elif (fmt.count('%s')==1 and '%' not in fmt.replace('%s','')) or (fmt.count('%d')==1 and '%' not in fmt.replace('%d','')):
                if '%s' in fmt:source=bytes(uc.mem_read(read32(ap),1024)).split(b'\0')[0];value=fmt.encode().replace(b'%s',source)
                else:
                    number=read32(ap);number=number-0x100000000 if number&0x80000000 else number;value=fmt.encode().replace(b'%d',str(number).encode())
                if len(value)+1>args[2]:event['unsupported']=True;uc.emu_stop();return
                uc.mem_write(args[0],value+b'\0');r=len(value)
            else:event['unsupported']=True;uc.emu_stop();return
        elif n=='strdup':
            value=bytes(uc.mem_read(args[0],4096)).split(b'\0')[0]+b'\0';r=heap;heap+=(len(value)+15)&~15;uc.mem_write(r,value);event['string']=value[:-1].decode('ascii','replace')
        elif n=='getauxval' and args[0]==7:r=aux[7];event['source']='Observed emulator-5580 zygote /proc/309/auxv AT_BASE; only linker PT_LOAD file bytes mapped, dynamic memory state absent'
        elif n=='dlopen':
            library=bytes(uc.mem_read(args[0],256)).split(b'\0')[0].decode('ascii','replace');event['library']=library
            if library=='libdvm.so':r=0;event['source']='Android 11 emulator ls: libdvm.so absent from /system/lib and ART/runtime APEX lib paths; offline loader models absent optional Dalvik library'
            elif library=='libsotweak.so' and args[1]==0 and PTHREAD_MODEL:
                fixture_path=ROOT/'output/camscanner-reverse/shell-probe-actual-dlopen.json';fixture=json.loads(fixture_path.read_text(encoding='utf-8-sig'))
                if fixture.get('libsotweakDlopenFlags0')!='dlopen failed: library "libsotweak.so" not found':event['unsupported']=True;uc.emu_stop();return
                r=0;event.update({'flags':args[1],'result_source':str(fixture_path.relative_to(ROOT)),'observed_dlerror':fixture['libsotweakDlopenFlags0'],'scope':'Actual JNI dlopen with exact flags 0 in separate research app linker namespace. Used as explicit offline fixture; original shell namespace was not observed.'})
            elif library=='libmthook.so' and args[1]==0 and PTHREAD_MODEL:
                fixture_path=ROOT/'output/camscanner-reverse/shell-probe-actual-dlopen.json';fixture=json.loads(fixture_path.read_text(encoding='utf-8-sig'))
                if fixture.get('libmthookDlopenFlags0')!='dlopen failed: library "libmthook.so" not found':event['unsupported']=True;uc.emu_stop();return
                r=0;event.update({'flags':args[1],'result_source':str(fixture_path.relative_to(ROOT)),'observed_dlerror':fixture['libmthookDlopenFlags0'],'scope':'Actual JNI dlopen with exact flags 0 in separate research app linker namespace. Used as explicit offline fixture; original shell namespace was not observed.'})
            elif library=='libpine.so' and args[1]==0 and PTHREAD_MODEL:
                fixture_path=ROOT/'output/camscanner-reverse/shell-probe-actual-dlopen.json';fixture=json.loads(fixture_path.read_text(encoding='utf-8-sig'))
                if fixture.get('libpineDlopenFlags0')!='dlopen failed: library "libpine.so" not found':event['unsupported']=True;uc.emu_stop();return
                r=0;event.update({'flags':args[1],'result_source':str(fixture_path.relative_to(ROOT)),'observed_dlerror':fixture['libpineDlopenFlags0'],'scope':'Actual JNI dlopen with exact flags 0 in separate research app linker namespace. Used as explicit offline fixture; original shell namespace was not observed.'})
            elif library=='libaoc.so' and args[1]==0 and PTHREAD_MODEL:
                fixture_path=ROOT/'output/camscanner-reverse/shell-libaoc-actual-dlopen.json';fixture=json.loads(fixture_path.read_text(encoding='utf-8-sig'))
                if fixture.get('libaocDlopenFlags0')!='dlopen failed: library "libaoc.so" not found':event['unsupported']=True;uc.emu_stop();return
                r=0;event.update({'flags':args[1],'result_source':str(fixture_path.relative_to(ROOT)),'observed_dlerror':fixture['libaocDlopenFlags0'],'scope':'Separate research app actual JNI linker namespace result; explicit offline fixture only, not original namespace observation.'})
            elif library=='libc.so':r=libcbase;event['assumption']='Synthetic handle; real emulator libc PT_LOAD file bytes mapped, no Android loader/constructors'
            elif library in additional_libraries:
                lib=additional_libraries[library]
                if not lib['ready']:event['unsupported']=True;event['reason']='Original library constructors did not complete';uc.emu_stop();return
                r=lib['base'];event['model']='Original DT_INIT-unpacked library mapped and REL-relocated into same offline address space; synthetic dlopen handle; constructors executed offline'
            else:event['unsupported']=True;uc.emu_stop();return
        elif n=='dlsym' and args[0]==libcbase:
            symbol=bytes(uc.mem_read(args[1],256)).split(b'\0')[0].decode('ascii','replace');event['symbol']=symbol;r=libcsymbols.get(symbol,0);event['source']='Real emulator libc .dynsym; synthetic map at 0x40000000'
        elif n=='dlsym' and any(lib['base']==args[0] for lib in additional_libraries.values()):
            symbol=bytes(uc.mem_read(args[1],256)).split(b'\0')[0].decode('ascii','replace');event['symbol']=symbol;lib=next(lib for lib in additional_libraries.values() if lib['base']==args[0]);r=lib['exports'].get(symbol,0);event['source']='Original additional shell library dynamic symbol table; offline relocated address'
        elif n=='dlclose' and args[0]==libcbase:event['assumption']='Synthetic handle release is a no-op; mapped libc file stays available'
        elif n=='lseek64' and args[0] in files:
            off=(args[2]<<32)|args[1];off=off-(1<<64) if off&(1<<63) else off;blob,pos=files[args[0]];whence=args[3]
            if whence not in (0,1,2):event['unsupported']=True;uc.emu_stop();return
            pos=off+(pos if whence==1 else len(blob) if whence==2 else 0);files[args[0]][1]=pos;r=pos&0xffffffff;uc.reg_write(UC_X86_REG_EDX,(pos>>32)&0xffffffff);event['position']=pos
        elif n=='read' and args[0] in files:
            blob,pos=files[args[0]];value=blob[pos:pos+args[2]];uc.mem_write(args[1],value);files[args[0]][1]+=len(value);r=len(value);event['fixture_bytes']=r
        elif n=='close' and args[0] in files:event['model']='Close read-only synthetic APK/proc file descriptor'
        elif n=='fopen':
            path=bytes(uc.mem_read(args[0],512)).split(b'\0')[0].decode();mode=bytes(uc.mem_read(args[1],32)).split(b'\0')[0].decode();event.update({'path':path,'mode':mode})
            if path in ('/proc/309/maps','/proc/tty/drivers') and mode in ('r','rb'):
                fixture='android-zygote-maps.txt' if path=='/proc/309/maps' else 'android-tty-drivers.txt';r=100+len(files);files[r]=[(context/fixture).read_bytes(),0];event['model']='Synthetic FILE handle over actual emulator snapshot '+fixture+'; not libc FILE layout or live process'
            elif path=='/data/user/0/com.intsig.camscanner/files/ic14d975884fe3c96' and mode=='wb+':
                r=100+len(files);files[r]=[b'',0];event['model']='Explicit synthetic writable FILE in offline Python memory only. Assumes cache creation succeeds; no device or host target file opened, no real application UID evidence.'
            else:event['unsupported']=True;uc.emu_stop();return
        elif n=='fwrite' and args[3] in files:
            blob,pos=files[args[3]];count=args[1]*args[2];value=bytes(uc.mem_read(args[0],count));files[args[3]]=[blob[:pos]+b'\0'*max(0,pos-len(blob))+value+blob[pos+count:],pos+count];r=args[2] if args[1] else 0;event['model']='Synthetic in-memory FILE write; no filesystem operation';event['bytes']=count;event['sha256']=hashlib.sha256(value).hexdigest()
        elif n=='fileno' and args[0] in files:r=args[0];event['model']='Synthetic FILE and descriptor share a handle; not libc FILE layout'
        elif n in ('flock','fflush','fsync') and args[0] in files:event['model']='Explicit sequential in-memory FILE model assumes lock/flush success; no OS lock, persistence or concurrent writer evidence'
        elif n=='fgets' and args[2] in files:
            blob,pos=files[args[2]];end=min(len(blob),pos+args[1]-1);newline=blob.find(b'\n',pos,end)
            if newline>=0:end=newline+1
            raw=blob[pos:end]
            if raw:uc.mem_write(args[0],raw+b'\0');r=args[0];files[args[2]][1]=end
            event['model']='Read next recorded proc maps line, bounded by caller buffer size'
        elif n=='fclose' and args[0] in files:event['model']='Close synthetic FILE fixture; bytes retained for inspection'
        elif n=='fscanf' and args[0] in files:
            fmt=bytes(uc.mem_read(args[1],256)).split(b'\0')[0].decode();event['format']=fmt
            if fmt!='%s %s %d %s %s':event['unsupported']=True;uc.emu_stop();return
            blob,pos=files[args[0]];tokens=[]
            for i in range(5):
                while pos<len(blob) and chr(blob[pos]).isspace():pos+=1
                startpos=pos
                while pos<len(blob) and not chr(blob[pos]).isspace():pos+=1
                if pos==startpos:break
                tokens.append(blob[startpos:pos])
            files[args[0]][1]=pos;r=len(tokens) if tokens else 0xffffffff;event['tokens']=[v.decode('ascii','replace') for v in tokens]
            for i,value in enumerate(tokens):
                dest=read32(sp+12+i*4)
                if i==2:write32(dest,int(value))
                else:uc.mem_write(dest,value+b'\0')
            event['model']='Only observed proc tty drivers fscanf format over actual snapshot token stream'
        elif n=='stat' and bytes(uc.mem_read(args[0],512)).split(b'\0')[0] in (b'/apex/com.android.art/lib/libart.so',b'/system/lib/liblog.so',b'/apex/com.android.art/lib/libdexfile.so'):
            path=bytes(uc.mem_read(args[0],512)).split(b'\0')[0].decode();raw=(context/('android-'+path.rsplit('/',1)[1][:-3]+'-stat.bin')).read_bytes();uc.mem_write(args[1],raw);event['source']='Raw 96-byte struct stat captured by i686 Android NDK probe executing stat on this exact emulator file';event['sha256']=hashlib.sha256(raw).hexdigest();event['path']=path
        elif n=='stat' and bytes(uc.mem_read(args[0],512)).split(b'\0')[0]==b'/data/user/0/com.intsig.camscanner/files/ic14d975884fe3c96':
            fixture=json.loads((ROOT/'output/camscanner-reverse/shell-dat-cache-stat.json').read_text());r=fixture['result']&0xffffffff;write32(0x800,fixture['errno']);event['fixture']=fixture
        elif n=='JavaVM.GetEnv':write32(args[1],0x61002000);event['model']='Synthetic JNIEnv pointer; no actual JVM or ART'
        elif n=='JNI.FindClass':
            cn=bytes(uc.mem_read(args[1],512)).split(b'\0')[0].decode('ascii','replace');event['class_name']=cn;r=0x61008000+len(jclasses)*16;jclasses[r]=cn;event['model']='Synthetic jclass handle with observed requested class name'
        elif n=='JNI.ExceptionCheck':event['model']='Synthetic JNI fixture has no pending exception'
        elif n=='JNI.GetStaticFieldID':
            field=bytes(uc.mem_read(args[2],256)).split(b'\0')[0].decode('ascii','replace');sig=bytes(uc.mem_read(args[3],256)).split(b'\0')[0].decode('ascii','replace');cn=jclasses.get(args[1]);event.update({'class_name':cn,'field':field,'signature':sig})
            keys={'HARDWARE':'ro.hardware','CPU_ABI':'ro.product.cpu.abi','CPU_ABI2':'ro.product.cpu.abi2','SDK_INT':'ro.build.version.sdk','SDK':'ro.build.version.sdk','RELEASE':'ro.build.version.release','MANUFACTURER':'ro.product.manufacturer','MODEL':'ro.product.model','BRAND':'ro.product.brand','DEVICE':'ro.product.device','PRODUCT':'ro.product.name','BOARD':'ro.product.board'}
            if cn not in ('android/os/Build','android/os/Build$VERSION') or field not in keys:event['unsupported']=True;uc.emu_stop();return
            key=keys[field];value=properties.get(key,'');r=0x61009000+len(jfields)*16;jfields[r]={'value':value,'property':key,'signature':sig};event['source']='Actual emulator-5580 getprop '+key;event['value']=value;event['model']='Synthetic jfieldID'
        elif n in ('JNI.GetStaticObjectField','JNI.GetStaticIntField'):
            field=jfields.get(args[2]);event['field_fixture']=field
            if not field:event['unsupported']=True;uc.emu_stop();return
            if n.endswith('IntField'):r=int(field['value'])
            else:r=0x6100a000+len(jstrings)*16;jstrings[r]=field['value'];event['model']='Synthetic jstring handle containing actual property fixture'
        elif n=='JNI.GetStringUTFChars':
            value=jstrings.get(args[1]);event['value']=value
            if value is None:event['unsupported']=True;uc.emu_stop();return
            raw=value.encode()+b'\0';r=heap;heap+=(len(raw)+15)&~15;uc.mem_write(r,raw)
            if args[2]:uc.mem_write(args[2],b'\x01')
        elif n=='JNI.NewStringUTF':
            value=bytes(uc.mem_read(args[1],8192)).split(b'\0')[0].decode('utf-8','replace');r=0x6100a000+len(jstrings)*16;jstrings[r]=value;event['value']=value;event['model']='Synthetic jstring containing original code-provided UTF-8 bytes'
        elif n in ('JNI.ReleaseStringUTFChars','JNI.DeleteLocalRef'):event['model']='Synthetic JNI fixture reference release is a no-op'
        elif n=='JNI.NewGlobalRef':r=args[1];event['model']='Synthetic JNI fixture reuses handle'
        elif n=='JNI.GetMethodID':
            method=bytes(uc.mem_read(args[2],256)).split(b'\0')[0].decode('ascii','replace');sig=bytes(uc.mem_read(args[3],256)).split(b'\0')[0].decode('ascii','replace');cn=jclasses.get(args[1]);event.update({'class_name':cn,'method':method,'signature':sig})
            allowed=[('java/lang/String','getBytes','()[B'),('java/lang/Thread','getContextClassLoader','()Ljava/lang/ClassLoader;')]
            if STACK_MODEL:allowed += [('java/lang/Thread','getStackTrace','()[Ljava/lang/StackTraceElement;'),('java/lang/StackTraceElement','getClassName','()Ljava/lang/String;'),('java/lang/StackTraceElement','getMethodName','()Ljava/lang/String;')]
            if (cn,method,sig) not in allowed:event['unsupported']=True;uc.emu_stop();return
            r=0x6100b000+len(jmethods)*16;jmethods[r]=(cn,method,sig);event['model']='Synthetic jmethodID for String.getBytes'
        elif n=='JNI.GetFieldID':
            field=bytes(uc.mem_read(args[2],256)).split(b'\0')[0].decode('ascii','replace');sig=bytes(uc.mem_read(args[3],256)).split(b'\0')[0].decode('ascii','replace');cn=jclasses.get(args[1]);event.update({'class_name':cn,'field':field,'signature':sig})
            allowed=[('android/app/ActivityThread','mBoundApplication','Landroid/app/ActivityThread$AppBindData;'),('android/app/ActivityThread$AppBindData','processName','Ljava/lang/String;'),('android/app/ActivityThread$AppBindData','appInfo','Landroid/content/pm/ApplicationInfo;')]
            if cn=='android/content/pm/ApplicationInfo' and field in package_meta:allowed.append((cn,field,sig))
            if (cn,field,sig) not in allowed:event['unsupported']=True;uc.emu_stop();return
            r=0x61009000+len(jfields)*16;jfields[r]={'class_name':cn,'field':field,'signature':sig};event['model']='Synthetic fieldID for explicitly observed framework member'
        elif n=='JNI.GetObjectField':
            field=jfields.get(args[2]);event['field_fixture']=field
            if not field:event['unsupported']=True;uc.emu_stop();return
            sig=field['signature']
            if field.get('class_name')=='android/content/pm/ApplicationInfo' and field.get('field') in package_meta and isinstance(package_meta[field['field']],str):
                r=0x6100a000+len(jstrings)*16;jstrings[r]=package_meta[field['field']];event['model']='Actual installed target package metadata fixture from adb dumpsys';event['value']=jstrings[r]
            elif field.get('field')=='processName':
                r=0x6100a000+len(jstrings)*16;jstrings[r]='com.intsig.camscanner';event['model']='Target APK default process name fixture, not actual ActivityThread runtime'
            elif sig.startswith('L') and sig.endswith(';') and sig!='Ljava/lang/String;':
                r=0x6100d000+len(jobjects)*16;jobjects[r]=sig[1:-1];event['model']='Synthetic framework object graph link derived from observed field signature; not actual Android object'
            else:event['unsupported']=True;uc.emu_stop();return
        elif n=='JNI.GetIntField':
            field=jfields.get(args[2]);event['field_fixture']=field
            if not field or field.get('field') not in package_meta or not isinstance(package_meta[field['field']],int):event['unsupported']=True;uc.emu_stop();return
            r=package_meta[field['field']];event['source']='Actual adb dumpsys package target metadata'
        elif n=='JNI.GetStaticMethodID':
            method=bytes(uc.mem_read(args[2],256)).split(b'\0')[0].decode('ascii','replace');sig=bytes(uc.mem_read(args[3],256)).split(b'\0')[0].decode('ascii','replace');cn=jclasses.get(args[1]);event.update({'class_name':cn,'method':method,'signature':sig})
            allowed=[('android/app/ActivityThread','currentPackageName','()Ljava/lang/String;'),('android/app/ActivityThread','currentActivityThread','()Landroid/app/ActivityThread;'),('java/lang/Thread','currentThread','()Ljava/lang/Thread;')]
            if PTHREAD_MODEL:allowed += [('android/os/Debug','isDebuggerConnected','()Z'),('android/os/Debug','waitingForDebugger','()Z')]
            if NONEMULATOR_PROFILE:allowed += [('android/os/ServiceManager','getService','(Ljava/lang/String;)Landroid/os/IBinder;')]
            if (cn,method,sig) not in allowed:event['unsupported']=True;uc.emu_stop();return
            r=0x6100b000+len(jmethods)*16;jmethods[r]=(cn,method,sig);event['model']='Synthetic jmethodID for observed static method'
        elif n in ('JNI.CallStaticBooleanMethod','JNI.CallStaticBooleanMethodV') and PTHREAD_MODEL:
            method=jmethods.get(args[2]);event['method_fixture']=method
            if method not in [('android/os/Debug','isDebuggerConnected','()Z'),('android/os/Debug','waitingForDebugger','()Z')]:event['unsupported']=True;uc.emu_stop();return
            fixture=json.loads((ROOT/'output/camscanner-reverse/shell-probe-actual-factory-debug.json').read_text());r=int(fixture[method[1]]);event['source']='Actual separate research AppComponentFactory single API measurement; not original application process';event['fixture_file']='shell-probe-actual-factory-debug.json';event['measured_package']=fixture['package']
        elif n in ('JNI.CallStaticObjectMethod','JNI.CallStaticObjectMethodV'):
            method=jmethods.get(args[2]);event['method_fixture']=method
            if method==('android/app/ActivityThread','currentPackageName','()Ljava/lang/String;'):
                r=0x6100a000+len(jstrings)*16;jstrings[r]='com.intsig.camscanner';event['model']='Target APK/package fixture; not a real ActivityThread call';event['value']=jstrings[r]
            elif method==('android/app/ActivityThread','currentActivityThread','()Landroid/app/ActivityThread;'):
                r=0x6100d000+len(jobjects)*16;jobjects[r]='android/app/ActivityThread';event['model']='Synthetic framework object graph node, not observed live ActivityThread'
            elif method==('java/lang/Thread','currentThread','()Ljava/lang/Thread;'):
                r=0x6100d000+len(jobjects)*16;jobjects[r]='java/lang/Thread';event['model']='Synthetic current-thread object node; no Android Thread runtime'
            elif method==('android/os/ServiceManager','getService','(Ljava/lang/String;)Landroid/os/IBinder;') and NONEMULATOR_PROFILE:
                handle=read32(args[3]) if n.endswith('MethodV') else args[3];service=jstrings.get(handle);event['service_name']=service
                fixture=json.loads((ROOT/'output/camscanner-reverse/shell-probe-actual-mikrom-service.json').read_text())
                if service!='mikrom' or fixture['mikromServiceNativeResult']!=0:event['unsupported']=True;uc.emu_stop();return
                r=0;event['source']='Actual separate research ACF JNI ServiceManager.getService(mikrom) returned null without exception';event['fixture_file']='shell-probe-actual-mikrom-service.json'
            else:event['unsupported']=True;uc.emu_stop();return
        elif n in ('JNI.CallObjectMethod','JNI.CallObjectMethodV'):
            method=jmethods.get(args[2]);event['method_fixture']=method
            if method==('java/lang/Thread','getContextClassLoader','()Ljava/lang/ClassLoader;'):
                r=next(k for k,v in jobjects.items() if v=='java/lang/ClassLoader');event['model']='Synthetic thread context class loader aliases supplied input fixture; no actual ART ClassLoader'
            elif STACK_MODEL and method==('java/lang/Thread','getStackTrace','()[Ljava/lang/StackTraceElement;'):
                fixture_name='shell-probe-actual-factory-stack.json' if FACTORY_STACK_MODEL else 'shell-probe-actual-mainthread-stack.json';fixture=json.loads((ROOT/'output/camscanner-reverse'/fixture_name).read_text());r=0x6100c000+len(jarrays)*16;jarrays[r]=[]
                for frame in fixture['captured_frames']:
                    handle=0x6100d000+len(jobjects)*16;jobjects[handle]={'type':'java/lang/StackTraceElement','frame':frame};jarrays[r].append(handle)
                event['fixture']=fixture;event['model']='Replay actual separate research APK stack fixture '+fixture_name+'; different package/native function from original app; frames preserved exactly as captured'
            elif STACK_MODEL and method in [('java/lang/StackTraceElement','getClassName','()Ljava/lang/String;'),('java/lang/StackTraceElement','getMethodName','()Ljava/lang/String;')] and isinstance(jobjects.get(args[1]),dict):
                value=jobjects[args[1]]['frame']['className' if method[1]=='getClassName' else 'methodName'];r=0x6100a000+len(jstrings)*16;jstrings[r]=value;event['value']=value;event['source']='Captured research probe Java frame; original app frames are not claimed'
            elif method==('java/lang/String','getBytes','()[B') and args[1] in jstrings:
                r=0x6100c000+len(jarrays)*16;jarrays[r]=jstrings[args[1]].encode();event['model']='Synthetic byte array from actual property string UTF-8 bytes';event['bytes_hex']=jarrays[r].hex()
            else:event['unsupported']=True;uc.emu_stop();return
        elif n=='JNI.GetArrayLength':
            if args[1] not in jarrays:event['unsupported']=True;uc.emu_stop();return
            r=len(jarrays[args[1]])
        elif n=='JNI.GetObjectArrayElement' and STACK_MODEL:
            if not isinstance(jarrays.get(args[1]),list) or args[2]>=len(jarrays[args[1]]):event['unsupported']=True;uc.emu_stop();return
            r=jarrays[args[1]][args[2]];event['frame_fixture']=jobjects[r]
        elif n=='JNI.GetByteArrayElements':
            if args[1] not in jarrays:event['unsupported']=True;uc.emu_stop();return
            raw=jarrays[args[1]];r=heap;heap+=(len(raw)+15)&~15;uc.mem_write(r,raw)
            if args[2]:uc.mem_write(args[2],b'\x01')
            event['model']='Copy bytes from synthetic byte-array fixture'
        elif n=='JNI.ReleaseByteArrayElements':event['model']='Release synthetic byte-array fixture copy; no real JVM array'
        elif n=='JNI.RegisterNatives':
            event['class_name']=jclasses.get(args[1])
            methods=[]
            for i in range(args[3]):
                np,sptr,fp=struct.unpack('<III',uc.mem_read(args[2]+i*12,12));methods.append({'name':bytes(uc.mem_read(np,256)).split(b'\0')[0].decode('ascii','replace'),'signature':bytes(uc.mem_read(sptr,512)).split(b'\0')[0].decode('ascii','replace'),'function':hex(fp)})
            event['methods']=methods;event['model']='Record original code method triples, report JNI_OK synthetically; no real registration'
        elif n in ('strcmp','strncmp'):
            a=bytes(uc.mem_read(args[0],1024)).split(b'\0')[0];c=bytes(uc.mem_read(args[1],1024)).split(b'\0')[0]
            if n=='strncmp':a=a[:args[2]];c=c[:args[2]]
            r=(a>c)-(a<c);event['strings']=[a.decode('ascii','replace'),c.decode('ascii','replace')]
        elif n=='strstr':
            a=bytes(uc.mem_read(args[0],8192)).split(b'\0')[0];c=bytes(uc.mem_read(args[1],8192)).split(b'\0')[0];pos=a.find(c);r=args[0]+pos if pos>=0 else 0;event['strings']=[a.decode('ascii','replace'),c.decode('ascii','replace')]
        elif n=='memchr':
            pos=bytes(uc.mem_read(args[0],args[2])).find(bytes([args[1]&255]));r=args[0]+pos if pos>=0 else 0
        elif n in ('strchr','strrchr'):
            a=bytes(uc.mem_read(args[0],8192)).split(b'\0')[0]+b'\0';c=bytes([args[1]&255]);pos=a.find(c) if n=='strchr' else a.rfind(c);r=args[0]+pos if pos>=0 else 0;event['string']=a[:-1].decode('ascii','replace')
        elif n in ('strspn','strcspn'):
            a=bytes(uc.mem_read(args[0],8192)).split(b'\0')[0];c=bytes(uc.mem_read(args[1],8192)).split(b'\0')[0];r=0
            for ch in a:
                if (ch in c)!=(n=='strspn'):break
                r+=1
        elif n=='memcmp':
            a=bytes(uc.mem_read(args[0],args[2]));c=bytes(uc.mem_read(args[1],args[2]));r=(a>c)-(a<c)
            if args[2]<=256:event['compared_hex']=[a.hex(),c.hex()]
        elif n=='sscanf':
            value=bytes(uc.mem_read(args[0],4096)).split(b'\0')[0].decode('ascii','replace');fmt=bytes(uc.mem_read(args[1],256)).split(b'\0')[0].decode('ascii','replace');event.update({'format':fmt,'input_preview':value[:256]})
            if fmt=='%lx-%lx %*s %*s %*s %*s %s\n':
                m=re.match(r'([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+\S+\s+\S+\s+\S+\s+\S+(?:\s+(\S+))?',value)
                if not m:r=0
                else:
                    write32(args[2],int(m[1],16));write32(args[3],int(m[2],16));r=2
                    if m[3]:uc.mem_write(read32(sp+20),m[3].encode()+b'\0');r=3
                event['model']='Only observed 32-bit libc maps-line sscanf format; skipped tokens do not count as assignments'
            elif fmt=='%lx-%lx %*c%c':
                m=re.match(r'([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+.([^\r\n])',value)
                if m:write32(args[2],int(m[1],16));write32(args[3],int(m[2],16));uc.mem_write(read32(sp+20),m[3].encode());r=3
                else:r=0
                event['model']='Only observed maps-range sscanf format; returns second permissions character'
            elif fmt=='%lx-%lx %s':
                m=re.match(r'([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+(\S+)',value)
                if m:write32(args[2],int(m[1],16));write32(args[3],int(m[2],16));uc.mem_write(read32(sp+20),m[3].encode()+b'\0');r=3
                else:r=0
                event['model']='Only observed maps address-range and permissions sscanf format'
            else:event['unsupported']=True;uc.emu_stop();return
        elif n in ('memcpy','memmove','__memcpy_chk'):
            if ART_FILE_MODEL and artbase<=args[0]<artbase+asize:art_writes.append({'address':hex(args[0]),'pc':hex(read32(sp)),'old':bytes(uc.mem_read(args[0],args[2])).hex(),'new':bytes(uc.mem_read(args[1],args[2])).hex(),'source':'Original code called explicit '+n+' import model into ART-file mapping'})
            uc.mem_write(args[0],bytes(uc.mem_read(args[1],args[2])));r=args[0]
        elif n=='strncpy':
            value=bytes(uc.mem_read(args[1],args[2])).split(b'\0')[0][:args[2]];uc.mem_write(args[0],value+b'\0'*(args[2]-len(value)));r=args[0]
        elif n in ('strcpy','__strcpy_chk'):
            value=bytes(uc.mem_read(args[1],4096)).split(b'\0')[0]+b'\0'
            if n=='__strcpy_chk' and len(value)>args[2]:event['unsupported']=True;uc.emu_stop();return
            uc.mem_write(args[0],value);r=args[0]
        elif n in ('strcat','__strcat_chk'):
            old=bytes(uc.mem_read(args[0],8192)).split(b'\0')[0];value=bytes(uc.mem_read(args[1],8192)).split(b'\0')[0]+b'\0'
            if n=='__strcat_chk' and len(old)+len(value)>args[2]:event['unsupported']=True;uc.emu_stop();return
            uc.mem_write(args[0]+len(old),value);r=args[0]
        elif n in ('memset','__memset_chk'):uc.mem_write(args[0],bytes([args[1]&255])*args[2]);r=args[0]
        else:
            event['unsupported']=True
            if n=='JNI.unknown33':event['jni_operation']='GetMethodID';event['method_name']=bytes(uc.mem_read(args[2],256)).split(b'\0')[0].decode('ascii','replace');event['signature']=bytes(uc.mem_read(args[3],256)).split(b'\0')[0].decode('ascii','replace')
            if n=='JNI.unknown113':event['jni_operation']='GetStaticMethodID';event['class_name']=jclasses.get(args[1]);event['method_name']=bytes(uc.mem_read(args[2],256)).split(b'\0')[0].decode('ascii','replace');event['signature']=bytes(uc.mem_read(args[3],256)).split(b'\0')[0].decode('ascii','replace')
            if n=='JNI.unknown94':event['jni_operation']='GetFieldID';event['class_name']=jclasses.get(args[1]);event['field_name']=bytes(uc.mem_read(args[2],256)).split(b'\0')[0].decode('ascii','replace');event['signature']=bytes(uc.mem_read(args[3],256)).split(b'\0')[0].decode('ascii','replace')
            if n=='JNI.unknown144':event['jni_operation']='GetStaticFieldID';event['field_name']=bytes(uc.mem_read(args[2],256)).split(b'\0')[0].decode('ascii','replace');event['signature']=bytes(uc.mem_read(args[3],256)).split(b'\0')[0].decode('ascii','replace')
            if n in ('dlopen','dlsym','open','fopen','stat','stat64'):
                event['string_argument']=bytes(uc.mem_read(args[0] if n!='dlsym' else args[1],256)).split(b'\0')[0].decode('ascii','replace')
            uc.emu_stop();return
        event['result']=hex(r);uc.reg_write(UC_X86_REG_EAX,r)
    def invalid(uc,access,address,size,value,data):faults.append({'address':hex(address),'pc':hex(uc.reg_read(UC_X86_REG_EIP))});return False
    def intr(uc,no,data):
        nr=uc.reg_read(UC_X86_REG_EAX);rec={'interrupt':no,'eax':hex(nr),'registers':{n:hex(uc.reg_read(r)) for n,r in [('ebx',UC_X86_REG_EBX),('ecx',UC_X86_REG_ECX),('edx',UC_X86_REG_EDX),('esi',UC_X86_REG_ESI),('edi',UC_X86_REG_EDI)]}};calls.append(rec)
        if nr==37:rec.update({'syscall_name':'kill','pid':uc.reg_read(UC_X86_REG_EBX),'signal':uc.reg_read(UC_X86_REG_ECX),'scope':'Original emulated code requested process signal; stopped without sending any host/device signal'})
        if nr in (5,307):rec['path']=bytes(uc.mem_read(uc.reg_read(UC_X86_REG_EBX if nr==5 else UC_X86_REG_ECX),512)).split(b'\0')[0].decode('ascii','replace')
        if nr==307 and PTHREAD_MODEL and uc.reg_read(UC_X86_REG_EDX)==0:
            fixture=json.loads((context/'android-access.json').read_text());observed=fixture['results'].get(rec['path'])
            if not observed or observed['mode']!=0:rec['unsupported']=True;uc.emu_stop();return
            value=0 if observed['result']==0 else -observed['errno'];uc.reg_write(UC_X86_REG_EAX,value&0xffffffff);rec['model']='Raw faccessat result from standalone Android access(F_OK) snapshot, shell UID provenance';rec['observed']=observed
        elif JNI_MODEL and nr==5 and rec['path']==package_meta['sourceDir']:
            fd=100+len(files);files[fd]=[(ROOT/'.work/camscanner/camscanner.apk').read_bytes(),0];uc.reg_write(UC_X86_REG_EAX,fd);rec['model']='Read-only original target APK mapped into synthetic fd at observed installed sourceDir';rec['sha256']=hashlib.sha256(files[fd][0]).hexdigest()
        elif AL_MODEL and nr==5 and rec['path'] in ('/apex/com.android.art/lib/libart.so','/system/lib/liblog.so','/apex/com.android.art/lib/libdexfile.so'):
            fd=100+len(files);files[fd]=[(context/('android-'+rec['path'].rsplit('/',1)[1])).read_bytes(),0];uc.reg_write(UC_X86_REG_EAX,fd);rec['model']='Read-only emulator system ELF file mapped into synthetic fd; no live runtime state';rec['sha256']=hashlib.sha256(files[fd][0]).hexdigest()
        elif PROC_SNAPSHOT and nr==5 and rec['path'] in ('/proc/self/status','/proc/self/maps','/proc/self/wchan','/proc/309/maps'):
            fn='android-zygote-'+rec['path'].rsplit('/',1)[1]+'.txt'
            fd=100+len(files);files[fd]=[(context/fn).read_bytes(),0];uc.reg_write(UC_X86_REG_EAX,fd);rec['model']='Replay actual emulator zygote snapshot as offline /proc/self fixture; not original app state';rec['snapshot']=fn
        elif PROC_SNAPSHOT and nr==3 and uc.reg_read(UC_X86_REG_EBX) in files:
            fd=uc.reg_read(UC_X86_REG_EBX);blob,pos=files[fd];size=uc.reg_read(UC_X86_REG_EDX);value=blob[pos:pos+size];uc.mem_write(uc.reg_read(UC_X86_REG_ECX),value);files[fd][1]+=len(value);uc.reg_write(UC_X86_REG_EAX,len(value));rec['bytes']=len(value)
        elif PROC_SNAPSHOT and nr==6 and uc.reg_read(UC_X86_REG_EBX) in files:uc.reg_write(UC_X86_REG_EAX,0);rec['model']='Close synthetic snapshot fd'
        elif JNI_MODEL and nr==19 and uc.reg_read(UC_X86_REG_EBX) in files:
            fd=uc.reg_read(UC_X86_REG_EBX);off=uc.reg_read(UC_X86_REG_ECX);off=off-0x100000000 if off&0x80000000 else off;whence=uc.reg_read(UC_X86_REG_EDX);blob,pos=files[fd]
            if whence not in (0,1,2):rec['unsupported']=True;uc.emu_stop();return
            pos=off+(pos if whence==1 else len(blob) if whence==2 else 0);files[fd][1]=pos;uc.reg_write(UC_X86_REG_EAX,pos);rec['position']=pos
        elif PROC_SNAPSHOT and nr==20:uc.reg_write(UC_X86_REG_EAX,309);rec['model']='Fixture PID=309, matching captured zygote proc files'
        elif CLONE_MODEL and nr==120:
            children.append({'context':uc.context_save(),'pc':uc.reg_read(UC_X86_REG_EIP),'stack':uc.reg_read(UC_X86_REG_ECX)})
            uc.reg_write(UC_X86_REG_EAX,1000+len(children));rec['model']='Sequential offline clone model: parent synthetic tid; queued child eax=0 at supplied stack. No OS thread or true concurrency.'
        else:rec['unsupported']=True;uc.emu_stop()
    if BLOCK_TRACE:
        # c5900..c59d8 is the statically verified, call-free byte substitution
        # loop. Execute every original instruction but omit Python observation
        # inside that loop. Import/function/return boundaries remain observed.
        u.hook_add(UC_HOOK_BLOCK,code,begin=1,end=base+0xc58ff)
        u.hook_add(UC_HOOK_BLOCK,code,begin=base+0xc59d9,end=0xffffffff)
    else:u.hook_add(UC_HOOK_CODE,code)
    u.hook_add(UC_HOOK_MEM_INVALID,invalid);u.hook_add(UC_HOOK_INTR,intr)
    stages=[]
    entries=[read32(base+tags[25]+i) for i in range(0,tags[27],4)]
    for entry in entries:
        if not entry:continue
        if entry<base:entry+=base
        sp=0x700f0000;write32(sp,0x60000000);u.reg_write(UC_X86_REG_ESP,sp);error=None;start=len(calls)
        try:u.emu_start(entry,0,count=2000000)
        except Exception as e:error=str(e)
        pc=u.reg_read(UC_X86_REG_EIP);stages.append({'entry':hex(entry-base),'returned':pc==0x60000000,'pc':hex(pc),'error':error,'calls':calls[start:]})
        if pc!=0x60000000:break
    child_results=[]
    for child in children[:4]:
        u.context_restore(child['context']);u.reg_write(UC_X86_REG_EAX,0);u.reg_write(UC_X86_REG_ESP,child['stack']);error=None;start=len(calls)
        try:u.emu_start(child['pc'],0,count=2000000)
        except Exception as e:error=str(e)
        child_results.append({'entry':hex(child['pc']),'stack':hex(child['stack']),'pc':hex(u.reg_read(UC_X86_REG_EIP)),'error':error,'calls':calls[start:],'last_addresses':list(last)})
    constructor_state=read32(read32(base+0x110178)) if name=='libexec.so' else 0
    jni_result=None
    if JNI_MODEL and name=='libexec.so':
        u.mem_map(0x61000000,0x10000);write32(0x61000000,0x61001000);write32(0x61002000,0x61003000)
        for i in range(8):write32(0x61001000+i*4,stub('JavaVM.GetEnv' if i==6 else 'JavaVM.unknown'+str(i)))
        for i in range(234):write32(0x61003000+i*4,stub({6:'JNI.FindClass',21:'JNI.NewGlobalRef',23:'JNI.DeleteLocalRef',33:'JNI.GetMethodID',34:'JNI.CallObjectMethod',35:'JNI.CallObjectMethodV',94:'JNI.GetFieldID',95:'JNI.GetObjectField',100:'JNI.GetIntField',113:'JNI.GetStaticMethodID',114:'JNI.CallStaticObjectMethod',115:'JNI.CallStaticObjectMethodV',117:'JNI.CallStaticBooleanMethod',118:'JNI.CallStaticBooleanMethodV',144:'JNI.GetStaticFieldID',145:'JNI.GetStaticObjectField',150:'JNI.GetStaticIntField',167:'JNI.NewStringUTF',169:'JNI.GetStringUTFChars',170:'JNI.ReleaseStringUTFChars',171:'JNI.GetArrayLength',173:'JNI.GetObjectArrayElement',184:'JNI.GetByteArrayElements',192:'JNI.ReleaseByteArrayElements',215:'JNI.RegisterNatives',228:'JNI.ExceptionCheck'}.get(i,'JNI.unknown'+str(i))))
        sp=0x700f0000;write32(sp,0x60000000);write32(sp+4,0x61000000);write32(sp+8,0);u.reg_write(UC_X86_REG_ESP,sp);error=None;start=len(calls)
        try:u.emu_start(base+0x6e280,0,count=5000000)
        except Exception as e:error=str(e)
        jni_result={'entry':hex(base+0x6e280),'pc':hex(u.reg_read(UC_X86_REG_EIP)),'eax':hex(u.reg_read(UC_X86_REG_EAX)),'returned':u.reg_read(UC_X86_REG_EIP)==0x60000000,'error':error,'calls':calls[start:],'last_addresses':list(last),'scope':'Offline actual JNI_OnLoad machine code with synthetic JavaVM/JNIEnv/class handles; unknown JNI calls stop. This is not Android JVM or original UI execution.'}
    al_result=None
    if AL_MODEL and name=='libexec.so' and jni_result and jni_result['returned']:
        # Prepare the observed libexecmain_x86.so request from its original
        # DT_INIT-unpacked bytes, at a distinct base. Do not reuse constructor
        # snapshots relocated for the primary library's base.
        extra=(context/'libexecmain.so').read_bytes();eh=struct.unpack_from('<16sHHIIIIIHHHHHH',extra);et={};eb=0x50000000
        for i in range(eh[10]):
            typ,off,va,pa,fs,ms,fl,al=struct.unpack_from('<8I',extra,eh[5]+i*eh[9])
            if typ==2:
                for pos in range(va,va+fs,8):
                    tag,val=struct.unpack_from('<II',extra,pos)
                    if not tag:break
                    et[tag]=val
        u.mem_map(eb,(len(extra)+4095)&~4095);u.mem_write(eb,extra)
        esymbols=[]
        for i in range(struct.unpack_from('<II',extra,et[4])[1]):
            ni,value,size,info,other,sh=struct.unpack_from('<IIIBBH',extra,et[6]+i*16);begin=et[5]+ni;end=extra.find(b'\0',begin);esymbols.append((extra[begin:end].decode('ascii','replace'),value,sh))
        lib={'base':eb,'exports':{n:eb+v for n,v,sh in esymbols if sh and v},'ready':False,'relocations':0,'constructors':[],'source_sha256':hashlib.sha256(extra).hexdigest()};additional_libraries['libexecmain_x86.so']=lib
        for addr,length in [(et.get(17,0),et.get(18,0)),(et.get(23,0),et.get(2,0))]:
            for pos in range(addr,addr+length,8):
                target,info=struct.unpack_from('<II',extra,pos);typ=info&255;si=info>>8;old=read32(eb+target)
                if typ==8:new=old+eb
                elif typ in (1,6,7):
                    n,value,sh=esymbols[si];dest=eb+value if sh else stub(n);new=dest+(old if typ==1 else 0)
                else:raise RuntimeError('Unsupported additional library relocation '+str(typ))
                write32(eb+target,new);lib['relocations']+=1
        for i in range(0,et[27],4):
            entry=read32(eb+et[25]+i)
            if not entry:continue
            if entry<eb:entry+=eb
            sp=0x700f0000;write32(sp,0x60000000);u.reg_write(UC_X86_REG_ESP,sp);error=None;start=len(calls)
            try:u.emu_start(entry,0,count=2000000)
            except Exception as e:error=str(e)
            returned=u.reg_read(UC_X86_REG_EIP)==0x60000000;lib['constructors'].append({'entry':hex(entry),'returned':returned,'error':error,'calls':calls[start:]})
            if not returned:break
        lib['ready']=all(stage['returned'] for stage in lib['constructors'])
        lib['export_bytes_after_constructors']={n:bytes(u.mem_read(a,16)).hex() for n,a in lib['exports'].items() if n in ('core','x','y')}
        classhandle=next(k for k,v in jclasses.items() if v=='s/h/e/l/l/N');loader=0x6100d000+len(jobjects)*16;jobjects[loader]='java/lang/ClassLoader';appinfo=0x6100d000+len(jobjects)*16;jobjects[appinfo]='android/content/pm/ApplicationInfo'
        strings=[]
        for value in ('com.intsig.camscanner','com.intsig.camscanner.launch.CsApplication'):
            ptr=0x6100a000+len(jstrings)*16;jstrings[ptr]=value;strings.append(ptr)
        sp=0x700f0000;args=[0x60000000,0x61002000,classhandle,loader,appinfo,*strings]
        for i,value in enumerate(args):write32(sp+i*4,value)
        u.reg_write(UC_X86_REG_ESP,sp);start=len(calls);error=None
        resume_entry=base+0x73520
        if RESUME_TAG:
            # Only agent-created local checkpoints are accepted. Pickle is never
            # loaded from an APK, download, user attachment or arbitrary path.
            checkpoint_path=ROOT/'.work/camscanner/checkpoints'/(RESUME_TAG+'.pkl')
            with checkpoint_path.open('rb') as saved_file:checkpoint=pickle.load(saved_file)
            if checkpoint['source_sha256']!=hashlib.sha256(b).hexdigest() or checkpoint['library']!=name:
                raise ValueError('Checkpoint source mismatch')
            expected_flags=[CLONE_MODEL,PROC_SNAPSHOT,JNI_MODEL,AL_MODEL,ART_FILE_MODEL,FACTORY_STACK_MODEL,PTHREAD_MODEL,NONEMULATOR_PROFILE,HOST_ZLIB_FIXTURE]
            if checkpoint['flags']!=expected_flags:raise ValueError('Checkpoint model flags mismatch')
            for address,raw in checkpoint['memory']:u.mem_write(address,raw)
            state=checkpoint['state']
            for key,target in [('stubs',stubs),('tls',tls),('files',files),('jclasses',jclasses),('jfields',jfields),('jstrings',jstrings),('jmethods',jmethods),('jarrays',jarrays),('jobjects',jobjects),('additional_libraries',additional_libraries)]:
                target.clear();target.update(state[key])
            for key,target in [('calls',calls),('cipher_observations',cipher_observations),('cipher_pending',cipher_pending),('payload_observations',payload_observations),('payload_pending',payload_pending),('pthread_tasks',pthread_tasks),('pthread_results',pthread_results)]:
                target[:]=state[key]
            heap=state['heap'];strtok_next=state['strtok_next'];rand48_state=state['rand48_state']
            u.context_restore(checkpoint['cpu']);resume_entry=u.reg_read(UC_X86_REG_EIP);start=len(calls)
        try:u.emu_start(resume_entry,0,count=AL_BUDGET)
        except Exception as e:error=str(e)
        al_result={'entry':hex(base+0x73520),'pc':hex(u.reg_read(UC_X86_REG_EIP)),'eax':hex(u.reg_read(UC_X86_REG_EAX)),'returned':u.reg_read(UC_X86_REG_EIP)==0x60000000,'error':error,'calls':calls[start:],'last_addresses':list(last),'input_fixture':{'loader':'synthetic java/lang/ClassLoader','application_info':'synthetic object with installed target metadata fields','string1':'com.intsig.camscanner','string2':'com.intsig.camscanner.launch.CsApplication','argument_meaning':'REA A.instantiateApplication caller passes packageName,orignAppName; see rea-shell-a-instantiate.json; actual Java objects remain synthetic'},'scope':'Offline original N.al code after successful synthetic JNI_OnLoad. No actual ART class loader, Android Context, original UI or original application runtime.'}
        al_result['instruction_budget']=AL_BUDGET;al_result['registers']={n:hex(u.reg_read(r)) for n,r in [('ebx',UC_X86_REG_EBX),('ecx',UC_X86_REG_ECX),('edx',UC_X86_REG_EDX),('esi',UC_X86_REG_ESI),('edi',UC_X86_REG_EDI),('ebp',UC_X86_REG_EBP),('esp',UC_X86_REG_ESP)]}
        al_result['trace_granularity']='basic-block entry addresses, excluding call-free original byte substitution loop c5900..c59d8; original instructions still executed' if BLOCK_TRACE else 'instruction addresses'
        al_result['instruction_limit_reached']=not error and u.reg_read(UC_X86_REG_EIP)!=0x60000000 and not any(c.get('unsupported') for c in calls[start:])
        if RESUME_TAG:al_result['resumed_from_local_checkpoint']=RESUME_TAG
        if SAVE_CHECKPOINT:
            checkpoint_dir=ROOT/'.work/camscanner/checkpoints';checkpoint_dir.mkdir(exist_ok=True)
            memory=[]
            for lo,hi,permissions in u.mem_regions():
                if lo==0x30000000:hi=min(hi,((heap+4095)&~4095)-1)
                memory.append((lo,bytes(u.mem_read(lo,hi-lo+1))))
            state={'stubs':stubs,'tls':tls,'files':files,'jclasses':jclasses,'jfields':jfields,'jstrings':jstrings,'jmethods':jmethods,'jarrays':jarrays,'jobjects':jobjects,'additional_libraries':additional_libraries,'calls':calls,'cipher_observations':cipher_observations,'cipher_pending':cipher_pending,'payload_observations':payload_observations,'payload_pending':payload_pending,'pthread_tasks':pthread_tasks,'pthread_results':pthread_results,'heap':heap,'strtok_next':strtok_next,'rand48_state':rand48_state}
            checkpoint={'library':name,'source_sha256':hashlib.sha256(b).hexdigest(),'flags':[CLONE_MODEL,PROC_SNAPSHOT,JNI_MODEL,AL_MODEL,ART_FILE_MODEL,FACTORY_STACK_MODEL,PTHREAD_MODEL,NONEMULATOR_PROFILE,HOST_ZLIB_FIXTURE],'memory':memory,'state':state,'cpu':u.context_save()}
            with (checkpoint_dir/(RUN_TAG+'.pkl')).open('wb') as saved_file:pickle.dump(checkpoint,saved_file,protocol=5)
        if RUN_TAG:
            traceprefix=ROOT/'output/camscanner-reverse'/('shell-al-stop-'+RUN_TAG+('-hostzlib' if HOST_ZLIB_FIXTURE else ''))
            Path(str(traceprefix)+'.stack.bin').write_bytes(bytes(u.mem_read(0x70000000,0x100000)))
            Path(str(traceprefix)+'.json').write_text(json.dumps({'pc':hex(u.reg_read(UC_X86_REG_EIP)),'eax':hex(u.reg_read(UC_X86_REG_EAX)),'registers':al_result['registers'],'stack_base':'0x70000000','stack_bytes':0x100000,'import_stubs':{hex(k):v for k,v in stubs.items()},'scope':'Exact offline N.al stop registers, synthetic stack and import-address map before queued thread callbacks. Not an Android core dump.'},indent=2),encoding='utf-8')
        lib['export_bytes_after_al']={n:bytes(u.mem_read(a,16)).hex() for n,a in lib['exports'].items() if n in ('core','x','y')}
        for task in pthread_tasks[:4]:
            sp=0x700d0000;write32(sp,0x60000000);write32(sp+4,task['arg']);u.reg_write(UC_X86_REG_ESP,sp);u.reg_write(UC_X86_REG_EBP,0);start=len(calls);error=None
            try:u.emu_start(task['entry'],0,count=5000000)
            except Exception as e:error=str(e)
            pthread_results.append({'task':task,'pc':hex(u.reg_read(UC_X86_REG_EIP)),'returned':u.reg_read(UC_X86_REG_EIP)==0x60000000,'error':error,'calls':calls[start:],'last_addresses':list(last),'scope':'Queued original pthread start routine on synthetic stack, sequentially after parent stage; no actual OS thread or concurrent runtime'})
    suffix=('.clone' if CLONE_MODEL else '')+('.proc' if PROC_SNAPSHOT else '')+('.jni' if JNI_MODEL else '')+('.al' if AL_MODEL else '')+('.artfile' if ART_FILE_MODEL else '')+('.probestack' if PROBE_STACK_MODEL else '')+('.factorystack' if FACTORY_STACK_MODEL else '')+('.pthread' if PTHREAD_MODEL else '')+('.qemuabsent' if WITHOUT_QEMU_FIXTURE else '')
    if NONEMULATOR_PROFILE:suffix+='.nonemulator'
    if RUN_TAG:suffix+='.'+RUN_TAG
    if HOST_ZLIB_FIXTURE:suffix+='.hostzlib'
    (ROOT/('output/camscanner-reverse/shell-stop-'+name+suffix+'.json')).write_text(json.dumps({'al_model':al_result,'heap_requested_bytes':heap-0x30000000,'heap_capacity':heap_capacity,'faults':faults,'payload_observations':payload_observations},indent=2),encoding='utf-8')
    image=bytes(u.mem_read(base,len(b)));out=p.with_name(name+suffix+'.constructors.bin');out.write_bytes(image)
    heapout=p.with_name(name+suffix+'.constructors.heap.bin');heapbytes=bytes(u.mem_read(0x30000000,heap-0x30000000));heapout.write_bytes(heapbytes)
    state_info={}
    if name=='libexec.so':
        try:
            globalptr=read32(base+0x110178);state=read32(globalptr)
            state_info={'got_offset':'0x110178','global_pointer':hex(globalptr),'state':hex(state),'state_words':[hex(read32(state+i)) for i in range(0,0x60,4)] if state else [],'state_status_1d8':hex(read32(state+0x1d8)) if state else None,'constructor_state':hex(constructor_state),'constructor_state_status_1d8_final':hex(read32(constructor_state+0x1d8)) if constructor_state else None,'constructor_state_scope':'Address recorded immediately after constructors. If original code freed this object, offline free retains bytes; final retained status is not a valid live object.','vtables':{}}
            for off in (0x10,0x24,0x34):
                if not state:break
                obj=read32(state+off)
                info={'object':hex(obj)}
                if obj:
                    info['direct_table_entries']=[hex(read32(obj+i)) for i in range(0,0x40,4)]
                    info['interpretation']='State slot points directly to a function-pointer table; no C++ object vptr dereference assumed'
                state_info['vtables'][hex(off)]=info
        except Exception as e:state_info['error']=str(e)
    (ROOT/f'output/camscanner-reverse/shell-{name}{suffix}-state-evidence.json').write_text(json.dumps({'library':name,'emulation_base':hex(base),'state':state_info,'heap_dump':str(heapout.relative_to(ROOT)),'heap_base':'0x30000000','heap_bytes':len(heapbytes),'heap_sha256':hashlib.sha256(heapbytes).hexdigest(),'clone_model':CLONE_MODEL,'scope':'Offline constructor stop snapshot. Heap addresses and state belong to the synthetic emulator allocator; no Android runtime equivalence.'},indent=2),encoding='utf-8')
    # Rebase all PHDR virtual addresses to the actual emulation base, preserving
    # already-applied absolute relocations. Root can import this separate file.
    analysis=bytearray(p.with_name(name+'.analysis.elf').read_bytes());analysis[:]=image
    template=p.with_name(name+'.analysis.elf').read_bytes()
    analysis[:h[5]+h[9]*h[10]]=template[:h[5]+h[9]*h[10]]
    struct.pack_into('<I',analysis,24,h[4]+base if h[4] else 0)
    for i in range(h[10]):
        pos=h[5]+i*h[9];va,pa=struct.unpack_from('<II',analysis,pos+8);struct.pack_into('<II',analysis,pos+8,va+base,pa+base)
    # Dynamic address tags also need rebasing for an analysis loader to resolve
    # symbols. Relocations already applied; remove relocation sizes to avoid twice.
    pointer_tags={3,4,5,6,12,13,17,23,25,26,0x6ffffef5,0x6ffffff0,0x6ffffffe,0x6ffffffc}
    for i in range(h[10]):
        typ,off,va,pa,fs,ms,fl,al=struct.unpack_from('<8I',b,h[5]+i*h[9])
        if typ==2:
            for pos in range(va,va+fs,8):
                t,v=struct.unpack_from('<II',analysis,pos)
                if not t:break
                if t in pointer_tags:struct.pack_into('<I',analysis,pos+4,v+base)
                elif t in (2,18):struct.pack_into('<I',analysis,pos+4,0)
    symbol_count=struct.unpack_from('<II',b,tags[4])[1]
    for i in range(symbol_count):
        pos=tags[6]+i*16;value=struct.unpack_from('<I',analysis,pos+4)[0];section=struct.unpack_from('<H',analysis,pos+14)[0]
        if section and value:struct.pack_into('<I',analysis,pos+4,value+base)
    out.with_name(name+suffix+'.constructors.analysis.elf').write_bytes(analysis)
    focused=[]
    for m in re.finditer(rb'[ -~]{5,}',image):
        s=m.group().decode()
        if re.search(r'camscanner|RegisterNatives|Java_|classes[0-9]*\.dex|dex\n|s/h/e/l/l',s):focused.append({'offset':hex(m.start()),'text':s[:180]})
    (ROOT/('output/camscanner-reverse/shell-payload-observations-'+name+suffix+'.json')).write_text(json.dumps(payload_observations,indent=2),encoding='utf-8')
    dex_candidates=[]
    for m in re.finditer(rb'dex\n0[0-9]{2}\x00',heapbytes):
        dex_candidates.append({'address':hex(0x30000000+m.start()),'heap_offset':hex(m.start()),'magic':m.group().hex(),'header_bytes':heapbytes[m.start():m.start()+112].hex()})
    return {'library':name,'relocations_applied':len(relocs),'unsupported_relocations':[r for r in relocs if r.get('unsupported')],'constructor_stages':stages,'clone_model':CLONE_MODEL,'child_threads':child_results,'jni_model':jni_result,'al_model':al_result,'pthread_model':pthread_results,'cipher_observations':cipher_observations,'art_file_model':art_model,'art_file_writes':art_writes,'additional_libraries':additional_libraries,'heap_dex_magic_candidates':dex_candidates,'faults':faults,'last_addresses':last,'changed_bytes':sum(x!=y for x,y in zip(b,image)),'focused_strings':focused,'output':str(out.relative_to(ROOT)),'sha256':hashlib.sha256(image).hexdigest(),'scope':'Offline x86 constructors after restored DT_INIT with ELF REL relocations. Only explicitly listed import stubs; unknown calls stop emulation. No Android runtime, JNI, original UI, or dex extraction.'}

if __name__=='__main__':
    rows=[run(n) for n in ('libexecmain.so','libexec.so')]
    evidence='shell-n-al-artfile-emulation-evidence.json' if ART_FILE_MODEL else ('shell-n-al-emulation-evidence.json' if AL_MODEL else ('shell-jni-onload-emulation-evidence.json' if JNI_MODEL else ('shell-constructor-clone-proc-emulation-evidence.json' if PROC_SNAPSHOT else ('shell-constructor-clone-emulation-evidence.json' if CLONE_MODEL else 'shell-constructor-emulation-evidence.json'))))
    if PROBE_STACK_MODEL:evidence='shell-n-al-probestack-emulation-evidence.json'
    if FACTORY_STACK_MODEL:evidence='shell-n-al-factorystack-emulation-evidence.json'
    if PTHREAD_MODEL:evidence='shell-n-al-pthread-emulation-evidence.json'
    if WITHOUT_QEMU_FIXTURE:evidence='shell-n-al-qemuabsent-emulation-evidence.json'
    if NONEMULATOR_PROFILE:evidence='shell-n-al-nonemulator-emulation-evidence.json'
    if RUN_TAG:evidence=evidence.replace('.json','-'+RUN_TAG+'.json')
    if HOST_ZLIB_FIXTURE:evidence=evidence.replace('.json','-hostzlib.json')
    (ROOT/'output/camscanner-reverse'/evidence).write_text(json.dumps(rows,indent=2),encoding='utf-8')
    for r in rows:
        s=r['constructor_stages'][-1];print(r['library'],'stages',len(r['constructor_stages']),'last',{k:s[k] for k in ('entry','returned','pc','error')},'calls',s['calls'][-3:],'changed',r['changed_bytes'])
