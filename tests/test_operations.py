"""免认证、记录边界、管理日志和故障准入；不启动沙箱。"""
import asyncio
from dataclasses import replace
import io
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

import grpc
from sandbox_model.logs import consume
from sandbox_model.service import Manager
from sandbox_model.settings import Settings
from sandbox_model.proto import sandbox_pb2 as pb
from test_admission import Context, Rejected


class OperationsTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.manager = object.__new__(Manager)
        self.manager.settings = Settings()
        self.manager.jobs = {}
        self.manager.catalog = {'python': {}}
        self.manager.healthy = lambda: True
        self.manager.persist = Mock()
        self.manager.event = lambda job, phase:job.update(phase=phase)
        self.manager.execute = AsyncMock()
        self.request = pb.TaskRequest(request_id='no_auth',kind='code',environment='python',code=b'print(1)')

    def old_job(self, age=90000, **fields):
        stamp = time.time()-age
        return dict(request_id='old', phase='finished',cleanup_done=True,task=None,
                    finished=stamp, started=stamp,events=[],outcome='success',error_code='',
                    delivery_done=True,digest='synthetic',artifacts=[],stdout='',stderr='') | fields

    async def test_no_auth_methods_or_credentials_are_required(self):
        context = SimpleNamespace(abort=Context().abort)  # 没有 auth_context。
        result = await self.manager.Submit(self.request,context)
        await self.manager.jobs['no_auth']['task']
        self.assertEqual(result.request_id,'no_auth')
        self.assertEqual((await self.manager.Status(pb.JobRef(request_id='no_auth'),context)).request_id,'no_auth')

    async def test_history_full_rejects_new_but_preserves_duplicates(self):
        self.manager.settings = replace(Settings(), max_history=1)
        self.manager.jobs['no_auth'] = self.old_job(age=10, request_id='no_auth',digest=Manager.digest(self.request))
        self.assertEqual((await self.manager.Submit(self.request,Context())).request_id,'no_auth')
        self.request.request_id='new'
        with self.assertRaises(Rejected) as caught:
            await self.manager.Submit(self.request,Context())
        self.assertEqual(caught.exception.detail,'HISTORY_FULL')
        self.assertIn('no_auth',self.manager.jobs)
        self.manager.execute.assert_not_called()

    async def test_expiry_keeps_active_and_unclean_records(self):
        self.manager.jobs={'old':self.old_job(),'recent':self.old_job(age=5),
                           'unclean':self.old_job(cleanup_done=False),'active':self.old_job(phase='running')}
        self.manager.prune_history()
        self.assertEqual(set(self.manager.jobs),{'recent','unclean','active'})
        self.manager.persist.assert_called_once()

    async def test_history_cleanup_makes_room_for_new_task(self):
        self.manager.settings=replace(Settings(),max_history=1)
        self.manager.jobs={'old':self.old_job()}
        await self.manager.Submit(self.request,Context())
        await self.manager.jobs['no_auth']['task']
        self.assertEqual(set(self.manager.jobs),{'no_auth'})

    async def test_quota_above_node_cap_rejected_before_execution(self):
        for field in ('network_upload_bytes','network_download_bytes'):
            request=pb.TaskRequest();request.CopyFrom(self.request)
            setattr(request,field,129*1024*1024)
            with self.assertRaises(Rejected) as caught:
                await self.manager.Submit(request,Context())
            self.assertEqual(caught.exception.detail,'INVALID_NETWORK_LIMIT')
        self.manager.execute.assert_not_called()

    async def test_unhealthy_never_admits_new_work(self):
        self.manager.healthy=lambda:False
        with self.assertRaises(Rejected) as caught:
            await self.manager.Submit(self.request,Context())
        self.assertEqual(caught.exception.code,grpc.StatusCode.UNAVAILABLE)
        self.manager.execute.assert_not_called()


class NodeTests(unittest.TestCase):
    def test_logging_bounds_single_line_and_keeps_latest_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'service.log'
            data=b'a'*5000+b'latest'
            consume(io.BytesIO(data),path,limit=1024)
            files=list(Path(directory).iterdir())
            self.assertEqual(len(files),2)
            self.assertTrue(all(x.stat().st_size<=1024 for x in files))
            self.assertTrue(path.read_bytes().endswith(b'latest'))
            consume(io.BytesIO(b'b'*3000+b'newest'),path,limit=1024)
            self.assertTrue(path.read_bytes().endswith(b'newest'))
            self.assertLessEqual(sum(x.stat().st_size for x in files),2048)

    def test_invalid_settings_fail_closed(self):
        for value in ({'concurrency':3},{'upload_bytes':0},{'history_seconds':False},
                      {'dns_server':'127.0.0.1'},{'dns_over_https':1},{'unknown':1},{'max_inflight':1}):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'settings.json';path.write_text(json.dumps(value))
                with patch.dict('os.environ',SANDBOX_CONFIG=str(path)), self.assertRaises(ValueError):
                    Settings.load()

    def test_watchdog_heartbeat_and_control_process_are_required(self):
        manager=object.__new__(Manager);manager.ready=True
        manager.last_progress=time.monotonic()
        manager.server_process=SimpleNamespace(poll=lambda:None)
        manager.watchdog=SimpleNamespace(pid=123,poll=lambda:None)
        for heartbeat, expected in (({'pid':123,'time':time.time()},True),
                                    ({'pid':124,'time':time.time()},False),
                                    ({'pid':123,'time':time.time()-10},False)):
            with patch('sandbox_model.service.read_private_json',return_value=heartbeat):
                self.assertEqual(manager.healthy(),expected)
        manager.watchdog.poll=lambda:1
        self.assertFalse(manager.healthy())

    def test_suspended_manager_or_pending_restart_is_not_ready(self):
        manager=object.__new__(Manager);manager.ready=True
        manager.server_process=SimpleNamespace(poll=lambda:None)
        manager.watchdog=SimpleNamespace(pid=123,poll=lambda:None)
        manager.last_progress=time.monotonic()-10
        with tempfile.TemporaryDirectory() as directory, patch('sandbox_model.service.RUN',Path(directory)), \
                patch('sandbox_model.service.read_private_json',return_value={'pid':123,'time':time.time()}):
            self.assertFalse(manager.healthy())
            manager.last_progress=time.monotonic()
            self.assertTrue(manager.healthy())
            (Path(directory)/'restart-request').touch()
            self.assertFalse(manager.healthy())
