"""Offline research probe of APK-embedded MNN networks, with explicit provenance.

Models remain in .work; this does not implement the original application's full pipeline.
"""
import sys, json, time, hashlib, os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / '.work/reverse-python'), str(ROOT / '.work/scanner-python')]
import numpy as np
import cv2
import MNN

def load_image(path):
    image = cv2.imdecode(np.fromfile(path, dtype=np.uint8), cv2.IMREAD_COLOR)
    if image is None:
        raise ValueError(f'Cannot decode {path}')
    return image

def save_image(path, image):
    ok, encoded = cv2.imencode('.png', image)
    if not ok:
        raise ValueError(f'Cannot encode {path}')
    encoded.tofile(path)

def main():
    out = ROOT / 'output/camscanner-reverse/model-probe'
    out.mkdir(parents=True, exist_ok=True)
    model = ROOT / '.work/camscanner/models/model-1.mnn'
    os.chdir(ROOT)
    interpreter = MNN.Interpreter(str(model.relative_to(ROOT)))
    session = interpreter.createSession({'backend': 'CPU', 'numThread': 2})
    tensor = interpreter.getSessionInput(session)
    shape = tensor.getShape()
    assert tuple(shape) == (1, 3, 480, 480), shape
    evidence = {
        'model_sha256': hashlib.sha256(model.read_bytes()).hexdigest(),
        'input_shape': shape,
        'path': 'scanet::deshadow -> InferNet::to_tensor/forward -> cvt_type_and_resize<float> -> per-channel division',
        'preprocess': 'OpenCV linear resize 480x480; BGR to RGB; float32 /255; NHWC host tensor',
        'postprocess': 'clip(output*255,0,255), truncate uint8 per plane, linear resize to original; reverse RGB planes; clip(floor(source*255/illumination+0.5),0,255)',
        'limitations': ['Independent MNN 3.6.1 CPU runtime; original Android MNN numerical equivalence untested.',
                       'Only recovered deshadow branch; original sharpEnhance and UI selection not reproduced.',
                       'No geometric crop or book dewarp included.'],
        'samples': []}
    for source in sorted((ROOT / 'scanner/samples').glob('photo-*.jpg')):
        image = load_image(source)
        rgb = cv2.cvtColor(cv2.resize(image, (480,480)), cv2.COLOR_BGR2RGB)
        data = np.ascontiguousarray(rgb.astype(np.float32)[None] / 255.0)
        host = MNN.Tensor(data.shape, MNN.Halide_Type_Float, data, MNN.Tensor_DimensionType_Tensorflow)
        tensor.copyFrom(host)
        start = time.perf_counter()
        interpreter.runSession(session)
        result = interpreter.getSessionOutput(session)
        host_out = MNN.Tensor(result.getShape(), MNN.Halide_Type_Float,
                              np.zeros(result.getShape(), dtype=np.float32), MNN.Tensor_DimensionType_Caffe)
        result.copyToHostTensor(host_out)
        predicted = np.asarray(host_out.getData(), dtype=np.float32).reshape(result.getShape())[0]
        elapsed = time.perf_counter() - start
        assert np.isfinite(predicted).all()
        low_res = np.clip(predicted * 255.0, 0, 255).astype(np.uint8)
        illumination = np.stack([cv2.resize(plane, (image.shape[1],image.shape[0])) for plane in low_res[::-1]], axis=-1)
        # A zero denominator saturates positive pixels; zero/zero is represented as 0.
        ratio = np.divide(image.astype(np.float32)*255, illumination,
                          out=np.full(image.shape, np.inf, np.float32), where=illumination!=0)
        ratio[(image==0)&(illumination==0)] = 0
        enhanced = np.clip(np.floor(ratio+0.5),0,255).astype(np.uint8)
        save_image(out / f'{source.stem}-illumination.png', illumination)
        save_image(out / f'{source.stem}-deshadow.png', enhanced)
        preview = np.concatenate([cv2.resize(x,(640,480)) for x in [image,illumination,enhanced]],axis=1)
        save_image(out / f'{source.stem}-comparison.png', preview)
        record = {'source': str(source), 'sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                  'shape': list(image.shape), 'seconds': elapsed, 'raw_min':float(predicted.min()),
                  'raw_max':float(predicted.max()), 'raw_mean':float(predicted.mean())}
        evidence['samples'].append(record)
        print(json.dumps(record,ensure_ascii=False),flush=True)
    (out / 'evidence.json').write_text(json.dumps(evidence,ensure_ascii=False,indent=2),encoding='utf-8')

if __name__ == '__main__':
    main()
