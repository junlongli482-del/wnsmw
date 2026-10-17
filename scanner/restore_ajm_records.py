"""Export restored record bodies using the original-function-validated byte rule.

The output is a research record container, NOT a DEX file or original source.
"""
from pathlib import Path
import hashlib, json, struct

ROOT = Path(__file__).resolve().parents[1]

def main():
    source = ROOT / 'output/camscanner-reverse/ajm-records/ajm-expanded-validated.bin'
    evidence = json.loads((ROOT / 'output/camscanner-reverse/shell-ajm-original-record-restore.json').read_text())
    if evidence['records_checked'] != 20 or not all(r['matches_recovered_formula'] for r in evidence['samples']):
        raise ValueError('Required original function sample evidence missing')
    data = source.read_bytes()
    table = bytes(v if v in (0, 255, 35, 220) else v ^ 255 for v in range(256))
    # Fixed-size header: magic, version, count. Records: normalized key,
    # original second field, body length, restored bytes.
    output = bytearray(struct.pack('<8sII', b'AJMREC01', 1, 403522))
    cursor = 0
    total_body = 0
    for index in range(403522):
        first, second, size = struct.unpack_from('<3I', data, cursor)
        if size % 2 or cursor + 12 + size > len(data):
            raise ValueError(f'Invalid record {index}')
        key = (first - 0xad7d) & 0xffffffff
        restored = data[cursor + 12:cursor + 12 + size].translate(table)
        if index < len(evidence['samples']):
            sample = evidence['samples'][index]
            if sample['key'] != hex(key) or sample['bytes'] != size or sample['original_output'] != restored[:64].hex():
                raise ValueError(f'Original-function sample mismatch: {index}')
        output.extend(struct.pack('<3I', key, second, size))
        output.extend(restored)
        total_body += size
        cursor += 12 + size
    if cursor != len(data):
        raise ValueError('Unparsed input bytes')
    target = ROOT / 'output/camscanner-reverse/ajm-records/restored-records.ajmrec'
    target.write_bytes(output)
    result = {'input': str(source.relative_to(ROOT)), 'input_sha256': hashlib.sha256(data).hexdigest(),
              'output': str(target.relative_to(ROOT)), 'output_sha256': hashlib.sha256(output).hexdigest(),
              'records': 403522, 'restored_body_bytes': total_body,
              'original_function_validation': 'shell-ajm-original-record-restore.json',
              'scope': 'Host export using statically recovered byte rule, matching 20 actual original-function calls and complete original parser index. Method/class attribution and complete DEX reconstruction remain unverified. File is custom research container, not installable code.'}
    (target.parent / 'restored-records-evidence.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
