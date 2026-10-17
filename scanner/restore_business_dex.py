"""Join protected DEX code items to original-restored AJM records by exact key.

Never replace SHA-1. Only normalize Adler32 when the original stored SHA-1
already verifies after restoring method bytes and debug_info_off.
"""
from pathlib import Path
import struct,json,hashlib,zlib
from dex_methods import Dex
from validate_recovered_dex import inspect

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'output/camscanner-reverse'
def main():
    blob=(OUT/'ajm-records/restored-records.ajmrec').read_bytes()
    magic,version,count=struct.unpack_from('<8sII',blob)
    assert magic==b'AJMREC01' and version==1
    pos=16;records={}
    for _ in range(count):
        key,debug,size=struct.unpack_from('<III',blob,pos);pos+=12
        if key in records or pos+size>len(blob):raise ValueError('Invalid record container')
        records[key]=(debug,blob[pos:pos+size]);pos+=size
    assert pos==len(blob)
    inventory=json.loads((OUT/'recovered-dex/datcomplete1b/inventory.json').read_text())
    target=OUT/'restored-business-dex';target.mkdir(exist_ok=True)
    used=set();results=[];attribution=[]
    for number,item in enumerate(inventory['candidates'],1):
        source=Path(item['path']);original=source.read_bytes();data=bytearray(original);dex=Dex(original)
        seen=set();patched=0
        for method in dex.defined_methods():
            offset=method['code_offset']
            if not offset or offset in seen:continue
            seen.add(offset);key=dex.u32(offset+8)
            if key not in records:continue
            debug,body=records[key]
            if len(body)!=method['code_units']*2:raise ValueError('Code unit count mismatch: '+str(method))
            if key in used:raise ValueError('Ambiguous AJM key across DEX methods')
            used.add(key);patched+=1
            data[offset+16:offset+16+len(body)]=body
            struct.pack_into('<I',data,offset+8,debug)
            attribution.append({'dex_number':number,'key':hex(key),'method':{k:v for k,v in method.items() if k!='insns_hex'},'original_debug_info_offset':debug,'restored_bytes':len(body)})
        sha_matches=hashlib.sha1(data[32:]).digest()==data[12:32]
        before=struct.unpack_from('<I',data,8)[0];computed=zlib.adler32(data[12:])&0xffffffff
        if sha_matches:struct.pack_into('<I',data,8,computed)
        path=target/('classes'+(str(number) if number>1 else '')+'.dex');path.write_bytes(data)
        validation=inspect(path);(path.with_suffix('.validation.json')).write_text(json.dumps(validation,indent=2),encoding='utf-8')
        results.append({'dex_number':number,'source':str(source),'source_sha256':hashlib.sha256(original).hexdigest(),'restored_methods':patched,'stored_original_sha1_matches_restored_body':sha_matches,'adler32_before':hex(before),'adler32_after':hex(computed) if sha_matches else hex(before),'adler32_normalized_only_after_sha1_match':sha_matches and before!=computed,'output':str(path),'sha256':hashlib.sha256(data).hexdigest(),'structural_checks_passed':validation['structural_checks_passed'],'errors':validation['errors'],'classes':len(validation.get('class_descriptors',[]))})
    (target/'method-attribution.json').write_text(json.dumps(attribution,indent=2),encoding='utf-8')
    result={'ajm_records':count,'unique_matched_records':len(used),'unmatched_records':len(records.keys()-used),'dex_files':results,'scope':'Exact code-item debug_info_off key joins and matching instruction lengths. Original stored SHA-1 is never rewritten; after it matches, Adler32 is explicitly normalized. No ART verifier, original UI or device run implied.'}
    (target/'restoration-evidence.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()
