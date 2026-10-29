"""Workspace RPC lifecycle and trusted transport regression; no real user code."""
import asyncio
import base64
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace as NS
import unittest
from unittest.mock import AsyncMock, Mock, patch

import grpc
from sandbox_model.proto import workspace_pb2 as pb
from sandbox_model.workspace_service import WorkspaceService, MAX_FILE


class Abort(Exception):
    def __init__(self,code,detail):self.code=code;self.detail=detail
class Context:
    async def abort(self,code,detail):raise Abort(code,detail)


class WorkspaceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.sandbox=NS(id='fixed-id',destroy=AsyncMock(),close=AsyncMock(),commands=NS(
            run=AsyncMock(),interrupt=AsyncMock(),get_command_status=AsyncMock(return_value=NS(running=False,exit_code=7))))
        config={'Runtime':'runsc','ReadonlyRootfs':True,'Privileged':False,'LogConfig':{'Type':'none'},'CapDrop':['ALL']}
        self.manager=NS(settings=NS(max_memory_mb=512,max_history=100,max_inflight=2),healthy=Mock(return_value=True),
            admission_reason=Mock(return_value=''),slots=asyncio.Semaphore(1),ensure_image=Mock(return_value='fixed-image'),
            network=NS(prepare=Mock()),test_mode=False,registry=Mock(),leases=Mock(),connection=NS(),cleanup=AsyncMock(),
            client=NS(containers=NS(list=Mock(return_value=[NS(labels={'opensandbox.io/id':'fixed-id'},attrs={'HostConfig':config})]))))
        self.service=WorkspaceService(self.manager,Path(self.temp.name)/'workspaces.json')
        self.context=Context()
        self.create=AsyncMock(return_value=self.sandbox)
        self.patch=patch('sandbox_model.workspace_service.Sandbox.create',self.create);self.patch.start()

    async def asyncTearDown(self):
        await self.service.shutdown();self.patch.stop();self.temp.cleanup()

    async def open(self,id='operation'):
        return await self.service.Open(pb.OpenWorkspaceRequest(request_id=id,ttl_seconds=600,memory_mb=512),self.context)

    async def test_concurrent_open_deduplicates_and_conflict_rejects(self):
        replies=await asyncio.gather(self.open(),self.open())
        self.assertEqual([r.state for r in replies],['open','open']);self.create.assert_awaited_once()
        with self.assertRaises(Abort) as caught:
            await self.service.Open(pb.OpenWorkspaceRequest(request_id='operation',ttl_seconds=100,memory_mb=512),self.context)
        self.assertEqual(caught.exception.code,grpc.StatusCode.ALREADY_EXISTS)
        self.assertEqual(self.manager.slots._value,0)
        request=pb.WorkspaceRef(workspace_id='operation')
        self.assertTrue((await self.service.Close(request,self.context)).cleanup_done)
        self.assertTrue((await self.service.Close(request,self.context)).cleanup_done)
        self.assertEqual(self.manager.slots._value,1);self.sandbox.destroy.assert_awaited_once()
        with self.assertRaises(Abort):await self.open()

    async def test_unknown_close_tombstone_survives_restart_and_late_open(self):
        reply=await self.service.Close(pb.WorkspaceRef(workspace_id='lost-response'),self.context)
        self.assertTrue(reply.cleanup_done);self.assertEqual(reply.workspace_id,'lost-response')
        self.service=WorkspaceService(self.manager,self.service.state_path)
        with self.assertRaises(Abort):await self.open('lost-response')
        self.create.assert_not_awaited()

    async def test_unknown_close_is_safe_when_permanent_history_full(self):
        await self.service.Close(pb.WorkspaceRef(workspace_id='one'),self.context)
        self.manager.settings.max_history=1
        reply=await self.service.Close(pb.WorkspaceRef(workspace_id='unknown'),self.context)
        self.assertTrue(reply.cleanup_done)
        with self.assertRaises(Abort):await self.open('unknown')
        self.create.assert_not_awaited()

    async def test_close_races_open_without_resurrection(self):
        created=asyncio.Event();release=asyncio.Event()
        async def create(*args,**kwargs):created.set();await release.wait();return self.sandbox
        self.create.side_effect=create
        opening=asyncio.create_task(self.open());await created.wait()
        closing=asyncio.create_task(self.service.Close(pb.WorkspaceRef(workspace_id='operation'),self.context))
        await asyncio.sleep(0);release.set()
        result=await asyncio.gather(opening,closing,return_exceptions=True)
        self.assertIsInstance(result[0],Abort);self.assertTrue(result[1].cleanup_done)
        self.sandbox.destroy.assert_awaited_once();self.assertEqual(self.manager.slots._value,1)

    async def test_hard_ttl_and_shared_admission(self):
        await self.open();entry=self.service.entries['operation'];entry['deadline']=time.time()-1
        await self.service.maintain();await entry['cleanup_task']
        self.assertTrue(entry['cleanup_done']);self.assertEqual(entry['error_code'],'EXPIRED')
        self.manager.admission_reason.return_value='QUEUE_FULL'
        with self.assertRaises(Abort) as caught:await self.open('next')
        self.assertEqual(caught.exception.detail,'QUEUE_FULL')
        self.assertEqual(self.service.active_count,0)

    async def test_failed_cleanup_retains_slot_and_retries(self):
        await self.open();self.manager.cleanup.side_effect=RuntimeError('unavailable')
        reply=await self.service.Close(pb.WorkspaceRef(workspace_id='operation'),self.context)
        self.assertFalse(reply.cleanup_done);self.assertEqual(self.manager.slots._value,0)
        self.manager.cleanup.side_effect=None;await self.service.maintain();await self.service.entries['operation']['cleanup_task']
        self.assertTrue(self.service.entries['operation']['cleanup_done']);self.assertEqual(self.manager.slots._value,1)

    async def test_existing_metrics_include_live_and_pending_workspace_cleanup(self):
        from sandbox_model.service import Manager
        from sandbox_model.proto import sandbox_pb2
        manager=object.__new__(Manager)
        manager.jobs={};manager.workspace_service=self.service;manager.service_started_unix_ms=1
        manager.environments=NS(active={},entries={},pending={},counters={})
        manager.Ready=AsyncMock(return_value=sandbox_pb2.ReadyReply(ready=True))
        await self.open()
        result=await manager.Metrics(None,self.context)
        self.assertEqual(result.inflight,1);self.assertEqual(result.cleanup_pending,0)
        self.manager.cleanup.side_effect=RuntimeError('temporary')
        await self.service.Close(pb.WorkspaceRef(workspace_id='operation'),self.context)
        result=await manager.Metrics(None,self.context)
        self.assertEqual(result.inflight,0);self.assertEqual(result.cleanup_pending,1)
        self.manager.cleanup.side_effect=None
        await self.service.maintain();await self.service.entries['operation']['cleanup_task']
        result=await manager.Metrics(None,self.context)
        self.assertEqual(result.inflight,0);self.assertEqual(result.cleanup_pending,0)

    async def test_mutation_receipt_survives_rpc_cancellation_and_body_conflict(self):
        await self.open();called=asyncio.Event();finish=asyncio.Event()
        async def mutate(*args):called.set();await finish.wait();return pb.FileReply(path='/workspace/file')
        self.service._filesystem=AsyncMock(side_effect=mutate)
        request=pb.FileRequest(workspace_id='operation',request_id='write1',op='write',path='file',data=b'abc')
        first=asyncio.create_task(self.service.Filesystem(request,self.context));await called.wait()
        first.cancel();await asyncio.gather(first,return_exceptions=True)
        retry=asyncio.create_task(self.service.Filesystem(request,self.context));finish.set()
        self.assertEqual((await retry).path,'/workspace/file');self.service._filesystem.assert_awaited_once()
        request.data=b'different'
        with self.assertRaises(Abort) as caught:await self.service.Filesystem(request,self.context)
        self.assertEqual(caught.exception.code,grpc.StatusCode.ALREADY_EXISTS)

    async def test_native_eight_mib_transfer_and_special_errors(self):
        await self.open();data=bytes(range(256))*(MAX_FILE//256)
        response=NS(raise_for_status=Mock(),json=Mock(return_value={'data':base64.b64encode(data).decode()}))
        client=NS(post=AsyncMock(return_value=response));self.sandbox.files=NS(_httpx_client=client)
        reply=await self.service.Filesystem(pb.FileRequest(workspace_id='operation',op='read',path='large'),self.context)
        self.assertEqual(reply.data,data)
        response.json.return_value={'error_code':'SYMLINK_LOOP'}
        reply=await self.service.Filesystem(pb.FileRequest(workspace_id='operation',op='realpath',path='loop'),self.context)
        self.assertEqual(reply.error_code,'SYMLINK_LOOP')

    async def test_true_exit_and_separate_output_not_user_status_text(self):
        await self.open()
        async def run(*args,handlers,**kwargs):
            await handlers.on_init(NS(id='trusted-execd-id'))
            await handlers.on_stdout(NS(text='{"exit_code":0}'))
            await handlers.on_stderr(NS(text='diagnostic'))
        self.sandbox.commands.run.side_effect=run
        result=await self.service.StartCommand(pb.CommandRequest(workspace_id='operation',request_id='cmd',argv=['false']),self.context)
        await self.service.entries['operation']['commands']['cmd']['task']
        result=await self.service.PollCommand(pb.CommandRef(workspace_id='operation',command_id='cmd'),self.context)
        self.assertTrue(result.exit_code_available);self.assertEqual(result.exit_code,7);self.assertTrue(result.output_complete)
        self.assertEqual(result.stdout,b'{"exit_code":0}');self.assertEqual(result.stderr,b'diagnostic')

    async def test_cancel_before_start_is_tombstoned(self):
        await self.open()
        reply=await self.service.CancelCommand(pb.CommandRef(workspace_id='operation',command_id='late'),self.context)
        self.assertTrue(reply.cancelled);self.assertFalse(reply.exit_code_available)
        with self.assertRaises(Abort):
            await self.service.StartCommand(pb.CommandRequest(workspace_id='operation',request_id='late',argv=['true']),self.context)
        self.sandbox.commands.run.assert_not_awaited()

    async def test_timeout_interrupts_real_command_status(self):
        await self.open();finished=asyncio.Event()
        async def run(*args,handlers,**kwargs):
            await handlers.on_init(NS(id='real-command'));await finished.wait()
        async def interrupt(*args):finished.set()
        self.sandbox.commands.run.side_effect=run;self.sandbox.commands.interrupt.side_effect=interrupt
        await self.service.StartCommand(pb.CommandRequest(workspace_id='operation',request_id='slow',argv=['sleep','50'],timeout_seconds=1),self.context)
        await self.service.entries['operation']['commands']['slow']['task']
        reply=await self.service.PollCommand(pb.CommandRef(workspace_id='operation',command_id='slow'),self.context)
        self.assertTrue(reply.timed_out);self.assertTrue(reply.exit_code_available);self.assertTrue(reply.output_complete)
        self.sandbox.commands.interrupt.assert_awaited_once_with('real-command')
