"""Read resource names from a retained offline shell-state snapshot."""
from pathlib import Path
import hashlib, json, struct

ROOT = Path(__file__).resolve().parents[1]
PREFIX = ROOT / '.work/camscanner/shell-unpacked/x86/libexec.so.clone.proc.jni.al.artfile.factorystack.pthread.nonemulator'

def main():
    paths = [Path(str(PREFIX) + '.constructors.bin'), Path(str(PREFIX) + '.constructors.heap.bin')]
    image, heap = [p.read_bytes() for p in paths]
    def read(address, size):
        data, start = (heap, 0x30000000) if address >= 0x30000000 else (image, 0x1000000)
        offset = address - start
        if offset < 0 or offset + size > len(data):
            raise ValueError(f'Address outside retained snapshot: {address:#x}')
        return data[offset:offset + size]
    def u32(address):
        return struct.unpack('<I', read(address, 4))[0]
    state = u32(u32(0x1110178))
    config = u32(state + 0x1a0)
    names = []
    for offset in (0x14, 0x18, 0x34):
        pointer = u32(config + offset)
        names.append({'config_offset': hex(offset), 'pointer': hex(pointer),
                      'name': read(pointer, 80).split(b'\0')[0].decode('ascii')})
    result = {'inputs': [{'path': str(p.relative_to(ROOT)), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in paths],
              'state': hex(state), 'config': hex(config), 'resource_names': names,
              'scope': 'Retained offline counterfactual non-emulator snapshot only. Synthetic allocator addresses; no original Android runtime attribution. Resource names do not establish payload format or successful decryption.'}
    target = ROOT / 'output/camscanner-reverse/shell-resource-config-names.json'
    target.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
