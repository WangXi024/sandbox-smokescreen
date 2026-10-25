"""新增文件能力在真实 gVisor 沙箱里的验收，可独立或随完整回归运行。"""
import io
import json

from PIL import Image
from acceptance import Acceptance, input_file, require
from sandbox_model.proto import sandbox_pb2 as pb
from test_file_processing import image_bytes, pdf_bytes


def run_file_checks(test):
    def parse(name, content, success=True, **options):
        req = test.request(kind='parse', environment='files', inputs=[input_file(name,content)])
        req.parse_options.CopyFrom(pb.ParseOptions(**options))
        test.submit(req)
        result = test.result(req, success=success)
        test.no_resources([req.request_id])
        return result

    def image():
        exif = Image.Exif(); exif[274]=6; exif[315]='synthetic metadata'
        result = parse('photo.jpg',image_bytes('JPEG',(400,200),exif=exif),max_long_edge=128)
        with Image.open(io.BytesIO(test.artifact(result,'normalized.png'))) as normalized:
            require(normalized.size==(64,128), '图片未校正方向或缩放')
            require(not normalized.getexif(), '图片残留 EXIF')
            require(normalized.getpixel((20,20))[0]>240,'像素内容错误')
        require(json.loads(test.artifact(result,'parsed.json'))['type']=='jpeg')

    def pdf():
        result=parse('pages.pdf',pdf_bytes(),pdf_images=True,max_long_edge=128)
        require(json.loads(test.artifact(result,'parsed.json'))['page_count']==2)
        for index,color in [(1,(255,0,0)),(2,(0,0,255))]:
            with Image.open(io.BytesIO(test.artifact(result,f'page-{index:03d}.png'))) as page:
                require(page.size==(128,64),'PDF 输出尺寸错误')
                require(page.convert('RGB').getpixel((20,20))==color,'PDF 页面像素错误')

    def fail(name,data,reason,**options):
        result=parse(name,data,success=False,**options)
        require(result.status.error_code=='EXECUTION_FAILED')
        require(reason in result.stderr,'失败原因不明确')
        require(not result.artifacts,'失败任务交回了部分产物')

    test.check('文件：JPEG校正方向、缩放、去元数据',image)
    test.check('文件：PDF逐页PNG真实像素与元数据',pdf)
    test.check('文件：无扩展名按内容识别',lambda:require(json.loads(test.artifact(
        parse('upload',image_bytes()),'parsed.json'))['type']=='png'))
    test.check('文件：扩展名与内容冲突拒绝',lambda:fail('fake.pdf',image_bytes(),'文件类型不符'))
    test.check('文件：伪造PDF头无法通过解析',lambda:fail('bad.pdf',b'%PDF-1.7\nbroken','Error',pdf_images=True))
    test.check('文件：PDF超页数不交回部分页面',lambda:fail('many.pdf',pdf_bytes(8),'不会截断',pdf_images=True))
    test.check('文件：加密PDF明确拒绝',lambda:fail('locked.pdf',pdf_bytes(encrypted=True),'加密 PDF',pdf_images=True))
    test.check('文件：原PDF纯文字模式保留',lambda:require(json.loads(test.artifact(
        parse('text.pdf',pdf_bytes(8)),'parsed.json'))['page_count']==8))


if __name__ == '__main__':
    test=Acceptance(include_faults=False)
    try:
        run_file_checks(test)
        test.no_resources(test.ids)
        test.completed=True
        test.save()
    finally:
        for channel in test.channels.values():channel.close()
    raise SystemExit(0 if all(item['passed'] for item in test.checks) else 1)
