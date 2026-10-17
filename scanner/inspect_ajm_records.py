"""Validate an original-shell-transformed indl01 resource and its records.

Record field semantics are deliberately unnamed beyond raw integers. This does
not claim DEX recovery or ART verification. Only supplied local bytes are read.
"""
from pathlib import Path
import argparse, collections, hashlib, json, struct, zlib

def inspect(path, output):
    raw = path.read_bytes()
    if raw[:8] != b'indl01\0\0' or len(raw) < 24:
        raise ValueError('Unsupported resource header')
    start, count, compressed_size, expected_size = struct.unpack_from('<4I', raw, 8)
    if start != 24 or start + compressed_size != len(raw):
        raise ValueError('Compressed resource bounds mismatch')
    inflater = zlib.decompressobj()
    expanded = inflater.decompress(raw[start:], expected_size + 1)
    if not inflater.eof or inflater.unused_data or inflater.unconsumed_tail or len(expanded) != expected_size:
        raise ValueError('Incomplete zlib stream, trailing data, or expanded size mismatch')
    cursor = 0
    previous = None
    descending = True
    sizes = collections.Counter()
    zero_second = 0
    samples = []
    for index in range(count):
        if cursor + 12 > len(expanded):
            raise ValueError(f'Truncated record header: {index}')
        first, second, size = struct.unpack_from('<3I', expanded, cursor)
        end = cursor + 12 + size
        if end > len(expanded):
            raise ValueError(f'Record exceeds buffer: {index}')
        if previous is not None:
            descending &= first == previous - 1
        previous = first
        zero_second += second == 0
        sizes[size] += 1
        if index < 8 or index >= count - 3:
            samples.append({'index': index, 'byte_offset': cursor, 'first_u32': first,
                            'second_u32': second, 'data_bytes': size,
                            'data_preview_hex': expanded[cursor + 12:min(end, cursor + 44)].hex()})
        cursor = end
    if cursor != len(expanded):
        raise ValueError('Unparsed trailing bytes')
    output.mkdir(parents=True, exist_ok=True)
    expanded_path = output / 'ajm-expanded-validated.bin'
    expanded_path.write_bytes(expanded)
    result = {'input': str(path.resolve()), 'input_sha256': hashlib.sha256(raw).hexdigest(),
              'header': {'payload_offset': start, 'record_count': count, 'compressed_bytes': compressed_size, 'expanded_bytes': expected_size},
              'zlib_complete_checksum_passed': True, 'record_bounds_passed': True,
              'parsed_records': count, 'consumed_bytes': cursor, 'first_field_descends_by_one': descending,
              'second_field_zero_count': zero_second, 'data_size_top20': sizes.most_common(20),
              'expanded_path': str(expanded_path.resolve()), 'expanded_sha256': hashlib.sha256(expanded).hexdigest(),
              'dex_magic_offset': expanded.find(b'dex\n'), 'samples': samples,
              'scope': 'Complete structural parsing of resource transformed by original offline shell instructions. Record semantic roles, code devirtualization, DEX recovery and Android runtime equivalence remain unverified.'}
    (output / 'ajm-record-validation.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps({k: v for k, v in result.items() if k not in ('samples', 'data_size_top20')}, indent=2))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('input', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    inspect(args.input, args.output)
