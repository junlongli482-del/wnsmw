"""Local document scanner. No proprietary CamScanner code or weights required."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.work' / 'scanner-python'))
import argparse
import json
import time
import cv2
import numpy as np
from PIL import Image, ImageOps


def read_image(path):
    with Image.open(path) as image:
        return cv2.cvtColor(np.array(ImageOps.exif_transpose(image).convert('RGB')), cv2.COLOR_RGB2BGR)


def save(path, image):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    ok, data = cv2.imencode(path.suffix, image)
    if not ok:
        raise ValueError(f'Cannot encode {path}')
    data.tofile(str(path))


def order_quad(points):
    points = np.array(points, np.float32).reshape(4, 2)
    center = points.mean(axis=0)
    points = points[np.argsort(np.arctan2(points[:, 1] - center[1], points[:, 0] - center[0]))]
    points = np.roll(points, -np.argmin(points.sum(axis=1)), axis=0)
    return points


def detect_page(image):
    h, w = image.shape[:2]
    scale = min(1., 1200 / max(h, w))
    small = cv2.resize(image, None, fx=scale, fy=scale)
    sh, sw = small.shape[:2]
    hsv = cv2.cvtColor(small, cv2.COLOR_BGR2HSV)
    gray = cv2.cvtColor(small, cv2.COLOR_BGR2GRAY)
    masks = []
    # Paper is bright and mostly neutral; several thresholds cover different light.
    for cutoff in (125, 155, 180):
        mask = ((hsv[:, :, 1] < 38) & (gray > cutoff)).astype(np.uint8) * 255
        mask = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, np.ones((11, 11), np.uint8))
        mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, np.ones((25, 25), np.uint8))
        masks.append(mask)
    edges = cv2.Canny(cv2.GaussianBlur(gray, (5, 5), 0), 35, 110)
    masks.append(cv2.morphologyEx(edges, cv2.MORPH_CLOSE, np.ones((5, 5), np.uint8)))
    candidates = []
    for mask in masks:
        contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        for contour in contours:
            area = cv2.contourArea(contour)
            if area < sh * sw * .24:
                continue
            hull = cv2.convexHull(contour)
            for epsilon in (.012, .02, .03, .045):
                quad = cv2.approxPolyDP(hull, epsilon * cv2.arcLength(hull, True), True)
                if len(quad) != 4 or not cv2.isContourConvex(quad):
                    continue
                quad = order_quad(quad)
                qa = cv2.contourArea(quad)
                fill = min(area / max(qa, 1), 1)
                border = sum(x < 3 or y < 3 or x > sw-4 or y > sh-4 for x, y in quad)
                inside = np.zeros((sh, sw), np.uint8)
                cv2.fillConvexPoly(inside, quad.astype(np.int32), 255)
                neutral = np.mean(hsv[:, :, 1][inside > 0] < 38)
                score = qa / (sw * sh) * fill * neutral**4 - border * .6
                candidates.append((score, quad / scale))
    if not candidates:
        return np.array([[0, 0], [w-1, 0], [w-1, h-1], [0, h-1]], np.float32), 'full-image-fallback'
    return max(candidates, key=lambda item: item[0])[1], 'automatic'


def rectify(image, quad):
    tl, tr, br, bl = order_quad(quad)
    w = int(round(max(np.linalg.norm(tr-tl), np.linalg.norm(br-bl))))
    h = int(round(max(np.linalg.norm(bl-tl), np.linalg.norm(br-tr))))
    if min(w, h) < 32:
        raise ValueError('Page corners are too close together')
    destination = np.float32([[0, 0], [w-1, 0], [w-1, h-1], [0, h-1]])
    matrix = cv2.getPerspectiveTransform(np.float32([tl, tr, br, bl]), destination)
    return cv2.warpPerspective(image, matrix, (w, h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)


def enhance(image, strength=.85):
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    h, w = gray.shape
    # Estimate paper illumination without treating dark text as paper background.
    ratio = min(1., 1000 / max(h, w))
    reduced = cv2.resize(gray, None, fx=ratio, fy=ratio, interpolation=cv2.INTER_AREA)
    background = cv2.morphologyEx(reduced, cv2.MORPH_CLOSE, cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (31, 31)))
    background = cv2.GaussianBlur(background, (0, 0), 9)
    background = cv2.resize(background, (w, h), interpolation=cv2.INTER_CUBIC)
    normalized = np.clip(gray.astype(np.float32) * 255 / np.maximum(background.astype(np.float32), 20), 0, 255)
    # Keep gray diagrams; avoid hard thresholding in the default output.
    black = min(float(np.percentile(normalized, 2)), 100.) * strength
    white = 250.
    clean = np.clip((normalized - black) * 255 / (white-black), 0, 255).astype(np.uint8)
    blur = cv2.GaussianBlur(clean, (0, 0), .8)
    clean = cv2.addWeighted(clean, 1.45, blur, -.45, 0)
    bw = cv2.adaptiveThreshold(clean, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 41, 12)
    return clean, bw


def process(paths, output, corners=None, split=False):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    records, pdf_pages = [], []
    for index, source in enumerate(paths, 1):
        started = time.perf_counter()
        image = read_image(source)
        quad, detection = detect_page(image) if corners is None else (order_quad(corners), 'manual')
        warped = rectify(image, quad)
        clean, bw = enhance(warped)
        stem = f'{index:02d}-{Path(source).stem}'
        overlay = image.copy()
        cv2.polylines(overlay, [quad.astype(np.int32)], True, (30, 180, 30), 4)
        save(output / f'{stem}-detected.jpg', overlay)
        save(output / f'{stem}-color.png', warped)
        save(output / f'{stem}-scan.png', clean)
        save(output / f'{stem}-bw.png', bw)
        pages = [clean]
        if split:
            midpoint = clean.shape[1] // 2
            pages = [clean[:, :midpoint], clean[:, midpoint:]]
        for n, page in enumerate(pages, 1):
            save(output / f'{stem}-page-{n}.png', page)
            pdf_pages.append(Image.fromarray(page).convert('RGB'))
        records.append({'source': str(Path(source).resolve()), 'corners': quad.tolist(), 'detection': detection,
                        'output_size': list(clean.shape[::-1]), 'seconds': round(time.perf_counter()-started, 3),
                        'handwriting': 'preserved', 'geometry': 'planar-perspective-only'})
        print(f'{index}/{len(paths)}: {source} -> {clean.shape[1]}x{clean.shape[0]}', flush=True)
    if pdf_pages:
        # Resolution is output metadata, not an assertion of recovered optical detail.
        pdf_pages[0].save(output / 'scanned.pdf', save_all=True, append_images=pdf_pages[1:], resolution=200.)
    (output / 'report.json').write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding='utf-8')
    return records


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Local multi-page exam scanner')
    parser.add_argument('images', nargs='+', help='Input photo paths')
    parser.add_argument('--output', default='output/scans')
    parser.add_argument('--split', action='store_true', help='Split each two-page spread into left/right PDF pages')
    parser.add_argument('--corners', help='Optional TL,TR,BR,BL points as JSON [[x,y],...] (single image only)')
    args = parser.parse_args()
    if args.corners and len(args.images) != 1:
        parser.error('--corners requires one image')
    process(args.images, args.output, json.loads(args.corners) if args.corners else None, args.split)
