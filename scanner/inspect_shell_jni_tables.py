"""Find structural JNINativeMethod triples in constructor-restored memory."""
from pathlib import Path
import struct,re,json,hashlib,argparse
ROOT=Path(__file__).resolve().parents[1]
def inspect(image=None,output=None):
    p=Path(image) if image else ROOT/'.work/camscanner/shell-unpacked/x86/libexec.so.constructors.bin'
    if not p.is_absolute():p=ROOT/p
    b=p.read_bytes();base=0x1000000
    def offset(ptr):return ptr-base if base<=ptr<base+len(b) else (ptr if ptr<len(b) else None)
    def string(ptr):
        off=offset(ptr)
        if off is None:return None
        end=b.find(b'\0',off,min(off+512,len(b)))
        if end<0:return None
        try:return b[off:end].decode('ascii')
        except UnicodeDecodeError:return None
    candidates=[]
    for pos in range(0,len(b)-12,4):
        np,sp,fp=struct.unpack_from('<III',b,pos);n=string(np);s=string(sp);fn=offset(fp)
        if n and s and fn is not None and re.fullmatch(r'[A-Za-z_$][\w$]{0,100}',n) and re.fullmatch(r'\([^)]*\)(?:[VZBCSIJFD]|L[^;]+;|\[.+)',s):
            candidates.append({'table_offset':hex(pos),'name':n,'signature':s,'function_offset':hex(fn),'function_first_bytes':b[fn:fn+16].hex()})
    strings=[]
    for m in re.finditer(rb'[ -~]{3,}',b):
        s=m.group().decode('ascii')
        if re.search(r'\([^)]*\)(?:V|I|Z|J|L|\[)|RegisterNatives|JNIEnv|DexFile|OpenMemory|dexFile|loadDex|defineClass|attachBaseContext|classes[0-9]*\.dex|s/h/e/l/l',s):strings.append({'offset':hex(m.start()),'text':s[:400]})
    result={'source':str(p.relative_to(ROOT)),'sha256':hashlib.sha256(b).hexdigest(),'jni_native_method_candidates':candidates,'focused_strings':strings,'limitations':'Structural candidates from offline constructor memory with documented environment stubs. Constructor coverage is recorded separately. Signatures and function pointers are static evidence, not observed RegisterNatives; additional tables may be virtualized or built later.'}
    destination=Path(output) if output else ROOT/'output/camscanner-reverse/shell-jni-table-evidence.json'
    if not destination.is_absolute():destination=ROOT/destination
    destination.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({'jni_native_method_candidates':candidates,'focused_string_count':len(strings)},indent=2))
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--image');parser.add_argument('--output')
    args=parser.parse_args();inspect(args.image,args.output)
