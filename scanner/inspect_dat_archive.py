"""Validate the ZIP exposed by the original shell's outer dat transform.

The archive's classes.dex name does not establish that its bytes are DEX.
"""
from pathlib import Path
import io, zipfile, hashlib, json, struct

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'output/camscanner-reverse'
SOURCE = ROOT / '.work/camscanner/extracted/assets/ijiami.dat'
HEAP = ROOT / '.work/camscanner/shell-unpacked/x86/libexec.so.clone.proc.jni.al.artfile.factorystack.pthread.nonemulator.datread30m.hostzlib.constructors.heap.bin'

def sha(data):
    return hashlib.sha256(data).hexdigest()

def main():
    original = SOURCE.read_bytes()
    heap = HEAP.read_bytes()
    transformed = heap[0x64de040:0x64de040 + len(original)]
    assert len(transformed) == len(original)
    assert transformed[:40] == original[:40]
    target = OUT / 'dat-records'
    target.mkdir(exist_ok=True)
    (OUT / 'payload-dumps/dat-transformed-at-cache-open.bin').write_bytes(transformed)
    archive = zipfile.ZipFile(io.BytesIO(transformed[40:]))
    assert archive.namelist() == ['classes.dex']
    members = []
    for info in archive.infolist():
        body = archive.read(info)  # zipfile checks decompression and CRC32.
        (target / 'classes.dex').write_bytes(body)
        members.append({'name':info.filename, 'bytes':len(body),
                        'compressed_bytes':info.compress_size, 'crc32':hex(info.CRC),
                        'sha256':sha(body), 'header_hex':body[:64].hex(),
                        'is_standard_dex':body[:4] == b'dex\n'})
    result = {'source_sha256':sha(original), 'transformed_sha256':sha(transformed),
              'bytes':len(transformed), 'zip_offset':40,
              'outer_header_u32':list(struct.unpack('<10I',transformed[:40])),
              'crc_validation_passed':True, 'members':members,
              'scope':'Outer transform executed by original x86 shell in documented mixed offline model. ZIP expanded with host zipfile and CRC verified. classes.dex member is still a protected carrier, not validated business DEX or original Android UI execution.'}
    (OUT / 'shell-dat-archive-validation.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))

if __name__ == '__main__':
    main()
