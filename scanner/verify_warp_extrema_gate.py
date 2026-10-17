"""Exercise original ARM confidence extrema gate with synthetic tensor fields.

Model-ready and inference are bridged, never the original statistics or gate.
This is a post-inference boundary probe, not Android model validation.
"""
from probe_native_warp_confidence import WarpArm, ROOT
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R1, UC_ARM_REG_S16, UC_ARM_REG_S18
import hashlib
import json
import struct
import numpy as np


def main():
    arm = WarpArm()
    planar = np.zeros((2, 240, 240), np.float32)
    data = arm.alloc(planar.nbytes)
    arm.tensor = arm.alloc(0x80)
    dims = arm.alloc(0x80)
    arm.w32(arm.tensor + 0xc, data)
    arm.w32(arm.tensor + 0x24, dims)
    for i, n in enumerate([1, 2, 240, 240]):
        arm.w32(dims + i * 16 + 4, n)
    for match, stub in [('to_tensor_dewarp', 'FIXTURE_TO_TENSOR'), ('InferNet7forwardENSt', 'FIXTURE_FORWARD')]:
        target = next(v for n, v in arm.symbols.items() if match in n and 'pagescan' in n)
        arm.redirects[target & ~1] = arm.stub(stub)
        arm.uc.hook_add(UC_HOOK_CODE, arm.callback, begin=target & ~1, end=target & ~1)
    check = arm.BASE + 0x8514a
    arm.uc.hook_add(UC_HOOK_CODE, lambda uc, a, s, u: uc.reg_write(UC_ARM_REG_R1, 1), begin=check, end=check)
    context = arm.alloc(0x80)
    arm.w32(context, 1)
    source = arm.mat(np.zeros((120, 160, 3), np.uint8))
    records = []
    comparisons = []
    def capture(uc, address, size, user):
        comparisons.append([struct.unpack('<f', struct.pack('<I', uc.reg_read(reg)))[0]
                            for reg in (UC_ARM_REG_S16, UC_ARM_REG_S18)])
    arm.uc.hook_add(UC_HOOK_CODE, capture, begin=arm.BASE + 0x85534, end=arm.BASE + 0x85534)
    for variant in ('channel1-only', 'channel0-range'):
      for sign in (1, -1):
        for extreme in (499, 500, 501):
            # A broad step guarantees exact zero extrema in one channel and
            # nonzero variance; a constant second channel sets the tested bound.
            raw = np.zeros((240, 240, 2), np.float32)
            raw[:, 120:, 0] = sign
            raw[:, :, 1] = sign * extreme
            if variant == 'channel0-range':
                raw[:, :, 0] += sign * (extreme - 1) / 2
                raw[:, :, 1] = sign * 10000
            encoded = np.ascontiguousarray(raw.transpose(2, 0, 1)).tobytes()
            arm.uc.mem_write(data, encoded)
            result = arm.mat(np.zeros_like(raw))
            count_before = arm.trace.get('FIXTURE_FORWARD', 0)
            value = arm.call(arm.symbols['get_warp_mat'], [context, source, result])
            assert arm.trace.get('FIXTURE_FORWARD', 0) == count_before + 1
            confidence = struct.unpack('<f', struct.pack('<I', value))[0]
            field = arm.image(result)
            extrema = float(abs(field[:, :, 0].min()) + abs(field[:, :, 0].max()))
            deviation = float(field.astype(np.float64).std(axis=(0, 1)).sum())
            expected = 0.0 if extrema > 500 else deviation
            register_extrema = sum(abs(v) for v in comparisons[-1])
            passed = abs(confidence - expected) < 1e-5 and deviation > 0.1 and abs(register_extrema-extrema)<1e-3
            record = {'variant': variant, 'sign': sign, 'requested_extreme': extreme,
                      'tensor_sha256': hashlib.sha256(encoded).hexdigest(),
                      'observed_extrema_sum': extrema, 'observed_std_sum': deviation,
                      'compare_registers_s16_s18': comparisons[-1], 'compare_register_extrema_sum': register_extrema,
                      'arm_confidence': confidence, 'expected': expected,
                      'absolute_error': abs(confidence - expected), 'passed': passed}
            records.append(record)
            print(json.dumps(record), flush=True)
    report = {'library_sha256': arm.sha, 'records': records,
              'passed': all(row['passed'] for row in records),
              'scope': 'Synthetic post-inference tensors. Original get_warp_mat ARM statistics and gate execute; model-ready forced, conversion/inference bypassed, GaussianBlur and libc/math use host shims. No real model, Android runtime, or complete dewarp entry claim.',
              'formula_under_test': 'zero when abs(min(channel0))+abs(max(channel0))>500; otherwise sum of per-channel standard deviations',
              'host_import_calls': arm.trace}
    out = ROOT / 'output/camscanner-reverse/warp-extrema-gate-evidence.json'
    out.write_text(json.dumps(report, indent=2), encoding='utf-8')
    assert report['passed'], out


if __name__ == '__main__':
    main()
