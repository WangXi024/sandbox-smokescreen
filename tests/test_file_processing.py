"""文件内容识别、图片规范化和 PDF 转图的边界测试。"""
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from PIL import Image, PngImagePlugin
from pypdf import PdfWriter
from pypdf.generic import DecodedStreamObject, NameObject
from sandbox_model import guest


def image_bytes(format='PNG', size=(32, 16), **options):
    stream = io.BytesIO()
    Image.new('RGB', size, 'red').save(stream, format=format, **options)
    return stream.getvalue()


def pdf_bytes(pages=2, encrypted=False):
    writer = PdfWriter()
    for index in range(pages):
        page = writer.add_blank_page(width=240, height=120)
        stream = DecodedStreamObject()
        stream.set_data((('1 0 0' if index % 2 == 0 else '0 0 1') + ' rg 0 0 240 120 re f').encode())
        page[NameObject('/Contents')] = writer._add_object(stream)
    if encrypted:
        writer.encrypt('synthetic-test-password')
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


class FileProcessingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='file-processing-')
        self.workspace = Path(self.temp.name)
        (self.workspace / 'inputs').mkdir()
        (self.workspace / 'out').mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def parse(self, name, data, **options):
        (self.workspace / 'inputs' / name).write_bytes(data)
        return guest.run_task({'kind':'parse', 'environment':'files',
                              'options':{'input':name, **options}}, self.workspace)

    def report(self):
        return json.loads((self.workspace / 'out/parsed.json').read_text())

    def test_binary_extension_mismatch(self):
        for name, data in [('fake.pdf', image_bytes()), ('fake.png', pdf_bytes()),
                           ('fake.txt', pdf_bytes()), ('fake.json', b'\x00binary')]:
            with self.subTest(name=name):
                result = self.parse(name, data)
                self.assertEqual(result['status'], 'failed', result)
                self.assertFalse((self.workspace / 'out/parsed.json').exists())

    def test_no_extension_detected_from_content(self):
        result = self.parse('upload', image_bytes())
        self.assertEqual(result['status'], 'success', result)
        self.assertEqual(self.report()['type'], 'png')

    def test_supported_image_formats(self):
        for format, name in [('PNG','a.png'), ('JPEG','a.jpg'), ('WEBP','a.webp')]:
            with self.subTest(format=format):
                result = self.parse(name, image_bytes(format))
                self.assertEqual(result['status'], 'success', result)
                with Image.open(self.workspace / 'out/normalized.png') as normalized:
                    self.assertEqual(normalized.format, 'PNG')
                    self.assertEqual(normalized.size, (32,16))
                    red, green, blue = normalized.convert('RGB').getpixel((10,10))
                    self.assertGreater(red, 240)
                    self.assertLess(max(green, blue), 15)

    def test_orientation_resize_and_metadata_removed(self):
        exif = Image.Exif(); exif[274] = 6; exif[315] = 'synthetic metadata'
        result = self.parse('photo.jpg', image_bytes('JPEG', (400,200), exif=exif), max_long_edge=100)
        self.assertEqual(result['status'], 'success', result)
        with Image.open(self.workspace / 'out/normalized.png') as image:
            self.assertEqual(image.size, (50,100))
            self.assertFalse(image.getexif())
            self.assertNotIn('icc_profile', image.info)

    def test_png_text_removed_and_alpha_preserved(self):
        buffer = io.BytesIO()
        info = PngImagePlugin.PngInfo(); info.add_text('Comment', 'synthetic-private-metadata')
        Image.new('RGBA', (12,20), (1,2,3,40)).save(buffer, format='PNG', pnginfo=info)
        result = self.parse('alpha.png', buffer.getvalue())
        self.assertEqual(result['status'], 'success', result)
        with Image.open(self.workspace / 'out/normalized.png') as image:
            self.assertEqual(image.getpixel((0,0)), (1,2,3,40))
            self.assertNotIn('Comment', image.info)

    def test_bad_structure_animation_and_pixel_limit(self):
        result = self.parse('broken.png', b'\x89PNG\r\n\x1a\ninvalid')
        self.assertEqual(result['status'], 'failed')
        with patch.object(guest, 'MAX_IMAGE_PIXELS', 100):
            result = self.parse('too-big.png', image_bytes(size=(20,20)))
            self.assertIn('像素', result['error'])
        buffer = io.BytesIO()
        Image.new('RGB',(10,10),'red').save(buffer, format='PNG', save_all=True,
                                           append_images=[Image.new('RGB',(10,10),'blue')])
        result = self.parse('animated.png', buffer.getvalue())
        self.assertIn('动图', result['error'])

    def test_pdf_pages_render_actual_pixels(self):
        result = self.parse('source.pdf', pdf_bytes(), pdf_images=True, max_long_edge=128)
        self.assertEqual(result['status'], 'success', result)
        self.assertEqual(self.report()['page_count'], 2)
        self.assertEqual(self.report()['images'], ['page-001.png', 'page-002.png'])
        for number, expected in [(1,(255,0,0)), (2,(0,0,255))]:
            with Image.open(self.workspace / 'out' / f'page-{number:03d}.png') as image:
                self.assertEqual(image.size, (128,64))
                self.assertEqual(image.convert('RGB').getpixel((40,30)), expected)

    def test_pdf_limits_password_damage_and_wrong_option(self):
        for name, data, options in [
                ('many.pdf', pdf_bytes(8), {'pdf_images':True}),
                ('encrypted.pdf', pdf_bytes(encrypted=True), {'pdf_images':True}),
                ('broken.pdf', b'%PDF-1.7\nbroken', {'pdf_images':True}),
                ('image.png', image_bytes(), {'pdf_images':True}),
                ('edge.pdf', pdf_bytes(), {'pdf_images':True, 'max_long_edge':4096})]:
            with self.subTest(name=name):
                result = self.parse(name, data, **options)
                self.assertEqual(result['status'], 'failed', result)
                self.assertFalse(list((self.workspace / 'out').glob('page-*.png')))

    def test_pdf_text_behavior_unchanged(self):
        result = self.parse('source.pdf', pdf_bytes(8))
        self.assertEqual(result['status'], 'success', result)
        self.assertEqual(self.report()['page_count'], 8)
        self.assertNotIn('images', self.report())

    def test_output_limit_does_not_return_partial_pages(self):
        with patch.object(guest, 'MAX_TOTAL_BYTES', 150):
            result = self.parse('source.pdf', pdf_bytes(), pdf_images=True)
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(list((self.workspace / 'out').glob('page-*.png')))


if __name__ == '__main__':
    unittest.main()
