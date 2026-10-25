"""管理侧缓存准入的离线测试；不启动或模拟一次沙箱执行。"""
import asyncio
import time
import unittest
from unittest.mock import AsyncMock

from sandbox_model.proto import sandbox_pb2 as pb
from sandbox_model.service import Manager
import grpc


class Rejected(Exception):
    def __init__(self, code, detail):
        self.code, self.detail = code, detail


class Context:
    async def abort(self, code, detail):
        raise Rejected(code, detail)


class SizedData:
    """仅计算元数据声明长度，测试不需要真的分配32MiB。"""
    def __init__(self, length):
        self.length = length

    def __len__(self):
        return self.length


class AdmissionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # 不调用Manager.__init__：此测试只检验准入，与Docker和网络无关。
        self.manager = object.__new__(Manager)
        from sandbox_model.settings import Settings
        self.manager.settings = Settings()
        self.manager.healthy = lambda: self.manager.ready
        self.manager.persist = lambda: None
        self.manager.ready = True
        self.manager.jobs = {}
        self.manager.catalog = {'python': {}}
        self.manager.event = lambda job, phase: job.update(phase=phase)
        self.manager.execute = AsyncMock()
        self.request = pb.TaskRequest(request_id='unit_admission', kind='code', environment='python',
                                      code=b'print(1)', memory_mb=512, timeout_seconds=60)

    def finished(self, size):
        return {'phase': 'finished', 'artifacts': [{'data': SizedData(size)}], 'stdout': '', 'stderr': ''}

    async def rejected(self):
        with self.assertRaises(Rejected) as caught:
            await self.manager.Submit(self.request, Context())
        self.assertEqual(caught.exception.code, grpc.StatusCode.RESOURCE_EXHAUSTED)
        self.assertEqual(caught.exception.detail, 'RESULT_CACHE_FULL')
        self.assertNotIn(self.request.request_id, self.manager.jobs)
        self.manager.execute.assert_not_called()

    async def test_finished_results_cannot_exceed_total_cache_budget(self):
        for index in range(8):
            self.manager.jobs[str(index)] = self.finished(4 * 1024 * 1024)
        await self.rejected()

    async def test_inflight_result_reservations_count_toward_cache_budget(self):
        self.manager.jobs['old'] = self.finished(12 * 1024 * 1024)
        for index in range(4):
            self.manager.jobs[str(index)] = {'phase': 'queued'}
        # 未完成任务各预留4MiB产物及128KiB日志，不能等实际产物出来才计数。
        await self.rejected()

    async def test_small_result_cache_still_accepts_new_work(self):
        self.manager.jobs['old'] = self.finished(1024)
        response = await self.manager.Submit(self.request, Context())
        self.assertEqual(response.request_id, self.request.request_id)
        job = self.manager.jobs[self.request.request_id]
        await job['task']
        self.manager.execute.assert_awaited_once_with(job)

    async def test_duplicate_does_not_reserve_another_result_buffer(self):
        stamp = time.time()
        for index in range(7):
            self.manager.jobs[str(index)] = self.finished(4 * 1024 * 1024)
        self.manager.jobs[self.request.request_id] = {
            'request_id': self.request.request_id, 'owner': 'alice', 'digest': Manager.digest(self.request),
            'phase': 'finished', 'outcome': 'success', 'error_code': '', 'cleanup_done': True,
            'delivery_done': True, 'started': stamp, 'finished': stamp, 'events': [],
            'artifacts': [{'data': SizedData(4 * 1024 * 1024)}], 'stdout': '', 'stderr': '',
        }
        response = await self.manager.Submit(self.request, Context())
        self.assertEqual(response.request_id, self.request.request_id)
        self.manager.execute.assert_not_called()

    def test_parse_options_are_bounded_and_task_specific(self):
        req = pb.TaskRequest(request_id='parse_limits', kind='parse', environment='python')
        for values in ({'max_pages':8,'pdf_images':True}, {'max_pages':1},
                       {'max_long_edge':63}, {'max_long_edge':2049}):
            req.parse_options.CopyFrom(pb.ParseOptions(**values))
            with self.subTest(values=values), self.assertRaisesRegex(ValueError, 'INVALID_PARSE_OPTIONS'):
                self.manager.validate(req)
        req.parse_options.CopyFrom(pb.ParseOptions(pdf_images=True,max_pages=7,max_long_edge=2048))
        self.manager.validate(req)
        req.kind, req.code = 'code', b'print(1)'
        with self.assertRaisesRegex(ValueError, 'INVALID_PARSE_OPTIONS'):
            self.manager.validate(req)


if __name__ == '__main__':
    unittest.main()
