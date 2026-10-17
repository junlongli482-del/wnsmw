"""Execute original shell's SM4 key schedule/block against a public known vector."""
from pathlib import Path
import sys,struct,hashlib,json
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.work/reverse-python'))
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32
from unicorn.x86_const import UC_X86_REG_ESP,UC_X86_REG_EIP

def main():
    path=ROOT/'.work/camscanner/shell-unpacked/x86/libexec.so.clone.proc.constructors.bin'
    data=path.read_bytes();base=0x1000000;stop=0x60000000;stack=0x70008000
    u=Uc(UC_ARCH_X86,UC_MODE_32);u.mem_map(base,(len(data)+4095)&~4095);u.mem_write(base,data)
    u.mem_map(stop,4096);u.mem_write(stop,b'\x90');u.mem_map(0x70000000,0x10000);u.mem_map(0x30000000,0x10000)
    u.mem_map(0,4096);u.mem_write(0x14,struct.pack('<I',0x13579bdf))
    def call(offset,*args):
        u.mem_write(stack,struct.pack('<'+'I'*(len(args)+1),stop,*args));u.reg_write(UC_X86_REG_ESP,stack)
        u.emu_start(base+offset,stop,count=1000000)
        if u.reg_read(UC_X86_REG_EIP)!=stop:raise RuntimeError('Original function did not return')
    key=bytes.fromhex('0123456789abcdeffedcba9876543210');expected=bytes.fromhex('681edf34d206965e86b3e94f536e4246')
    context=0x30000000;keyptr=0x30001000;src=0x30002000;out=0x30003000
    u.mem_write(keyptr,key);u.mem_write(src,key)
    call(0x4a2e0,context+4,keyptr);call(0x4a670,context+4,src,out)
    encrypted=bytes(u.mem_read(out,16));assert encrypted==expected,(encrypted.hex(),expected.hex())
    call(0x4a3e0,context,keyptr);u.mem_write(src,encrypted);call(0x4a670,context+4,src,out)
    decrypted=bytes(u.mem_read(out,16));assert decrypted==key
    # Key observed at the original caller in the explicitly counterfactual
    # non-emulator analysis branch; this does not infer a business-DEX key.
    resource=ROOT/'.work/camscanner/extracted/assets/icon/image_icon_constructor_encrypted.png'
    config_key=bytes.fromhex('92dc31b7326c50fc7408e9cabcd67693')
    u.mem_write(keyptr,config_key);u.mem_write(src,resource.read_bytes())
    call(0x4a3e0,context,keyptr);lengthptr=0x30004000
    call(0x4a900,context,len(resource.read_bytes()),src,out,lengthptr)
    output_length=struct.unpack('<I',u.mem_read(lengthptr,4))[0]
    config=bytes(u.mem_read(out,output_length))
    assert config==b'66822209\r\n66811535\r\n66810137\r\n'
    result={'image':str(path.relative_to(ROOT)),'image_sha256':hashlib.sha256(data).hexdigest(),
        'key_and_plaintext':key.hex(),'expected_ciphertext':expected.hex(),'original_ciphertext':encrypted.hex(),
        'original_decrypted':decrypted.hex(),'passed':True,
        'resource_fixture':{'path':str(resource.relative_to(ROOT)),
            'sha256':hashlib.sha256(resource.read_bytes()).hexdigest(),
            'key_hex':config_key.hex(),'key_source':'Original 0x4a3e0 call in shell-n-al-nonemulator-emulation-evidence.json cipher_observations; counterfactual analysis environment',
            'output_length':output_length,'plaintext':config.decode('ascii'),
            'scope':'Original file is 32 bytes despite .png name. Numeric configuration plaintext, not a recovered business DEX.'},
        'entries_elf':{'key_schedule':'0x4a2e0','reverse_key_schedule':'0x4a3e0','block':'0x4a670'},
        'scope':'Original x86 instructions executed for SM4 standard single-block known answer and reverse schedule roundtrip. No cipher function/import substituted. Offline image plus synthetic stack/canary. Does not establish protected DEX format/key or scanner algorithm.'}
    (ROOT/'output/camscanner-reverse/shell-sm4-known-answer.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()
