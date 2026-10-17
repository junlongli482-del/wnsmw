"""Check a candidate standard DEX header, hashes and class descriptor inventory.

This is a bounded structural checker, not an ART bytecode verifier.
"""
from pathlib import Path
import argparse,hashlib,json,struct,zlib

def inspect(path):
    b=path.read_bytes();errors=[]
    result={'path':str(path.resolve()),'sha256':hashlib.sha256(b).hexdigest(),'actual_bytes':len(b),
      'scope':'Standard DEX header/hash/table bounds and class descriptor inventory only. Does not verify instructions, references, original-app provenance or runtime usability.'}
    if len(b)<112 or b[:4]!=b'dex\n' or b[7]!=0:
        return dict(result,errors=['Not a complete standard DEX header'],structural_checks_passed=False)
    u=lambda off:struct.unpack_from('<I',b,off)[0]
    size=u(32);result.update(version=b[4:7].decode('ascii',errors='replace'),declared_bytes=size,header_bytes=u(36),endian_tag=hex(u(40)))
    if size!=len(b):errors.append('Declared file size differs from candidate length')
    if u(36)!=112:errors.append('Header size unsupported (expected 112)')
    if u(40)!=0x12345678:errors.append('Endian format unsupported')
    result['sha1_matches']=hashlib.sha1(b[32:]).digest()==b[12:32]
    result['adler32_matches']=(zlib.adler32(b[12:])&0xffffffff)==u(8)
    if not result['sha1_matches']:errors.append('SHA1 mismatch')
    if not result['adler32_matches']:errors.append('Adler32 mismatch')
    tables={}
    for name,off,width in [('strings',56,4),('types',64,4),('protos',72,12),('fields',80,8),('methods',88,8),('classes',96,32)]:
        count,start=u(off),u(off+4);tables[name]={'count':count,'offset':start}
        if count and (start<112 or start%4 or start+count*width>len(b)):errors.append(name+' table bounds/alignment invalid')
    result['tables']=tables
    # Hash mismatches do not prevent bounded metadata inspection. Preserve the
    # failed validation verdict while independently reporting readable tables.
    if not any(error not in ('SHA1 mismatch','Adler32 mismatch') for error in errors):
        classes=[]
        try:
            for i in range(tables['classes']['count']):
                idx=u(tables['classes']['offset']+32*i)
                if idx>=tables['types']['count']:raise ValueError('Class type index out of range')
                string=u(tables['types']['offset']+4*idx)
                if string>=tables['strings']['count']:raise ValueError('Class string index out of range')
                pos=u(tables['strings']['offset']+4*string)
                # Skip bounded utf16_size ULEB128; class names here are ASCII.
                for _ in range(5):
                    byte=b[pos];pos+=1
                    if byte<128:break
                else:raise ValueError('Malformed string length ULEB128')
                end=b.index(0,pos);raw=b[pos:end]
                classes.append(raw.decode('ascii') if raw.isascii() else '<non-ASCII descriptor: '+raw.hex()+'>')
            result['class_descriptors']=classes
            result['scan_related_classes']=[c for c in classes if any(t in c.lower() for t in ('camera','capture','scan','enhanc','dewarp','crop'))]
        except (ValueError,IndexError,struct.error) as error:errors.append(str(error))
    result.update(errors=errors,structural_checks_passed=not errors)
    return result

def main():
    parser=argparse.ArgumentParser();parser.add_argument('path',type=Path);parser.add_argument('--output',type=Path)
    args=parser.parse_args();result=inspect(args.path)
    if args.output:args.output.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('class_descriptors','scan_related_classes')},indent=2))
    raise SystemExit(0 if result['structural_checks_passed'] else 1)
if __name__=='__main__':main()
