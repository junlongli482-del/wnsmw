import unittest
from scan import detect_page, rectify, enhance
import numpy as np
import cv2


class ScannerTests(unittest.TestCase):
    def test_page_detection_with_colored_background(self):
        image = np.full((700, 900, 3), (80, 35, 95), np.uint8)
        quad = np.float32([[100, 90], [790, 120], [830, 620], [80, 600]])
        cv2.fillConvexPoly(image, quad.astype(np.int32), (190, 190, 190))
        cv2.putText(image, 'EXAM 123', (200, 300), cv2.FONT_HERSHEY_SIMPLEX, 2, (35, 35, 35), 3)
        found, status = detect_page(image)
        self.assertEqual(status, 'automatic')
        self.assertLess(float(np.max(np.linalg.norm(found-quad, axis=1))), 18)
        warped = rectify(image, found)
        self.assertGreater(warped.shape[1], 650)

    def test_shadow_removed_without_erasing_strokes(self):
        field = np.tile(np.linspace(100, 220, 600), (400, 1)).astype(np.uint8)
        image = cv2.cvtColor(field, cv2.COLOR_GRAY2BGR)
        cv2.line(image, (80, 200), (520, 200), (35, 35, 35), 2)
        clean, _ = enhance(image)
        self.assertGreater(float(np.mean(clean[50:100])), 245)
        self.assertLess(float(np.mean(clean[200, 100:500])), 120)

    def test_empty_frame_is_explicit_fallback(self):
        _, status = detect_page(np.zeros((200, 300, 3), np.uint8))
        self.assertEqual(status, 'full-image-fallback')


if __name__ == '__main__':
    unittest.main()
