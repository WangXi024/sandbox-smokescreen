"""启动对账、持久化故障和实际容器 OOM 状态的管理侧模块回归。"""
import asyncio
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

from sandbox_model.proto import sandbox_pb2 as pb
from sandbox_model.service import Manager


class RecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.manager=object.__new__(Manager)
        self.manager.ready=False
        self.manager.jobs={'old-job':{'cleanup_done':False}}
        self.manager.network=SimpleNamespace(jobs={},restore_context=Mock(),orphan_context=Mock())
        def restore(context):
            self.manager.network.jobs[context['job_id']]=SimpleNamespace(
                name=context['name'],proxy_out_ip=context['proxy_out_ip'])
        self.manager.network.restore_context.side_effect=restore
        self.manager.client=SimpleNamespace(networks=SimpleNamespace(list=Mock(return_value=[])),
            containers=SimpleNamespace(list=Mock(return_value=[])))
        self.manager.persist=Mock()
        self.manager.cleanup=AsyncMock()

    async def test_cleanup_tolerates_watchdog_removal_and_still_verifies_no_resources(self):
        from docker.errors import NotFound
        container=SimpleNamespace(labels={'lazyx.sb':'true'},remove=Mock(side_effect=NotFound('already removed')))
        self.manager.client.containers.list.side_effect=[[container],[]]
        self.manager.network=SimpleNamespace(jobs={},revoke=Mock(),remaining_resources=Mock(return_value={'networks':0,'rules':0}))
        self.manager.registry=Mock();self.manager.server_process=None;self.manager.test_mode=False
        await Manager.cleanup(self.manager,'concurrent-watchdog')
        self.manager.network.remaining_resources.assert_called_once_with('concurrent-watchdog')
        self.assertEqual(self.manager.client.containers.list.call_count,2)

    async def test_private_leases_restore_proxy_identity_before_cleanup(self):
        context={'job_id':'old-job','name':'old-network','proxy_out_ip':'172.27.250.100'}
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'leases.json'
            path.write_text(json.dumps({'jobs':{'old-job':{'network':context}}}))
            path.chmod(0o600)
            def check_cleanup(ident):
                self.assertEqual(self.manager.network.jobs[ident].proxy_out_ip,'172.27.250.100')
                self.assertEqual(json.loads(path.read_text())['jobs']['old-job']['network'],context)
            self.manager.cleanup.side_effect=check_cleanup
            with patch('sandbox_model.service.RUN',Path(directory)):
                await self.manager.reconcile()
        self.manager.network.restore_context.assert_called_once_with(context)
        self.manager.cleanup.assert_awaited_once_with('old-job')
        self.assertTrue(self.manager.jobs['old-job']['cleanup_done'])
        self.manager.persist.assert_called_once()

    async def test_missing_leases_use_live_network_before_proxy_removal_and_include_unknown_jobs(self):
        network=SimpleNamespace(name='orphan-network',attrs={'Labels':{'lazyx.sb':'true','lazyx.job':'orphan-job'}})
        proxy=SimpleNamespace(labels={'lazyx.sb':'true','lazyx.job':'orphan-job'})
        self.manager.client.networks.list.return_value=[network]
        self.manager.client.containers.list.return_value=[proxy]
        context={'job_id':'orphan-job','name':'orphan-network','proxy_out_ip':'172.27.250.101'}
        self.manager.network.orphan_context.return_value=context
        with tempfile.TemporaryDirectory() as directory, patch('sandbox_model.service.RUN',Path(directory)):
            await self.manager.reconcile()
        self.manager.network.orphan_context.assert_called_once_with(network)
        self.manager.network.restore_context.assert_called_once_with(context)
        self.assertEqual(self.manager.cleanup.await_args_list[1].args,('orphan-job',))
        self.assertNotIn('orphan-job',self.manager.jobs)

    async def test_reconcile_failure_prevents_startup_and_does_not_overwrite_leases(self):
        self.manager.cleanup.side_effect=RuntimeError('SYNTHETIC_CLEANUP_FAILURE')
        with tempfile.TemporaryDirectory() as directory, patch('sandbox_model.service.RUN',Path(directory)):
            with self.assertRaisesRegex(RuntimeError,'SYNTHETIC_CLEANUP_FAILURE'):
                await self.manager.launch()
            self.assertFalse((Path(directory)/'opensandbox.toml').exists())
        self.assertFalse(self.manager.ready)
        self.assertFalse(self.manager.jobs['old-job']['cleanup_done'])
        self.manager.persist.assert_not_called()

    async def test_untrusted_lease_permissions_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'leases.json'
            path.write_text('{"jobs":{}}')
            path.chmod(0o644)
            with patch('sandbox_model.service.RUN',Path(directory)):
                with self.assertRaises(ValueError):
                    await self.manager.reconcile()
        self.manager.cleanup.assert_not_awaited()
        self.manager.persist.assert_not_called()

    async def test_cleanup_without_context_cannot_ignore_actual_network_residuals(self):
        self.manager.test_mode=False
        self.manager.server_process=None
        self.manager.registry=Mock()
        self.manager.network.revoke=Mock()
        self.manager.network.remaining_resources=Mock(return_value={'networks':1,'rules':0})
        with self.assertRaisesRegex(RuntimeError,'NETWORK_RESOURCES_REMAIN'):
            await Manager.cleanup(self.manager,'orphan-job')
        self.manager.network.remaining_resources.assert_called_once_with('orphan-job')
        self.manager.registry.assert_not_called()

    async def test_startup_cleans_orphan_network_and_container_without_state_record(self):
        self.manager.jobs={}
        self.manager.test_mode=False
        self.manager.server_process=None
        self.manager.registry=Mock()
        order=[]
        network=SimpleNamespace(name='orphan-network',attrs={'Labels':{'lazyx.sb':'true','lazyx.job':'orphan-job'}})
        proxy=SimpleNamespace(labels={'lazyx.sb':'true','lazyx.job':'orphan-job'},removed=False)
        def remove(**kwargs):
            order.append('remove')
            proxy.removed=True
        proxy.remove=remove
        self.manager.client.networks.list.return_value=[network]
        self.manager.client.containers.list.side_effect=lambda **kwargs:[] if proxy.removed else [proxy]
        context={'job_id':'orphan-job','name':'orphan-network','proxy_out_ip':'172.27.250.101'}
        self.manager.network.orphan_context.return_value=context
        self.manager.network.revoke=lambda ident:order.append('revoke')
        def release(ident):
            self.assertTrue(proxy.removed)
            self.assertEqual(self.manager.network.jobs[ident].proxy_out_ip,'172.27.250.101')
            order.append('release')
            self.manager.network.jobs.pop(ident)
        self.manager.network.release=release
        self.manager.network.remaining_resources=Mock(return_value={'networks':0,'rules':0})
        self.manager.cleanup=lambda ident:Manager.cleanup(self.manager,ident)
        with tempfile.TemporaryDirectory() as directory, patch('sandbox_model.service.RUN',Path(directory)):
            await self.manager.reconcile()
        self.assertEqual(order,['revoke','remove','release'])
        self.assertEqual(self.manager.jobs,{})
        self.manager.network.remaining_resources.assert_called_once_with('orphan-job')
        self.manager.persist.assert_called_once()


class FinalizationTests(unittest.IsolatedAsyncioTestCase):
    async def test_expired_task_after_prepare_gate_never_creates_network(self):
        manager=object.__new__(Manager)
        manager.test_mode=False
        manager.key=b'synthetic-unit-test-key'
        manager.network=SimpleNamespace(prepare=Mock())
        request=pb.TaskRequest(request_id='expired-before-network',kind='code',environment='python',code=b'print(1)')
        manager.jobs={request.request_id:{'spec':request,'outcome':'','deadline':0}}
        with self.assertRaisesRegex(ValueError,'TASK_STOPPED'):
            manager.prepare_network(request.request_id,[])
        manager.network.prepare.assert_not_called()

    async def test_metadata_write_failure_propagates_but_releases_acquired_slot(self):
        manager=object.__new__(Manager)
        manager.slots=asyncio.Semaphore(1)
        manager.key=b'synthetic-unit-test-key'
        manager.ensure_image=lambda value:(_ for _ in ()).throw(ValueError('SYNTHETIC_IMAGE_FAILURE'))
        manager.cleanup=AsyncMock()
        def event(job,phase):
            job['phase']=phase
            if phase=='finished':raise OSError('SYNTHETIC_METADATA_FAILURE')
        manager.event=event
        request=pb.TaskRequest(request_id='metadata-failure',kind='code',environment='python',code=b'print(1)')
        job={'request_id':request.request_id,'owner':'alice','spec':request,'phase':'queued','outcome':'',
             'error_code':'','cleanup_done':False,'artifacts':[],'stdout':'','stderr':'','proposal_json':b'','requests':{}}
        with self.assertRaisesRegex(OSError,'SYNTHETIC_METADATA_FAILURE'):
            await manager.execute(job)
        self.assertEqual(manager.slots._value,1)
        manager.cleanup.assert_awaited_once()
        self.assertTrue(job['cleanup_done'])

    async def test_only_actual_oom_killed_guest_state_stops_task(self):
        manager=object.__new__(Manager)
        manager.jobs={'oom':{'phase':'running','outcome':''},'normal':{'phase':'running','outcome':''}}
        containers=[SimpleNamespace(labels={'lazyx.job':'oom'},attrs={'State':{'OOMKilled':True}}),
                    SimpleNamespace(labels={'lazyx.job':'normal'},attrs={'State':{'OOMKilled':False,'Running':False}})]
        manager.client=SimpleNamespace(containers=SimpleNamespace(list=Mock(return_value=containers)))
        manager.stop_job=Mock()
        await manager.check_oom()
        manager.stop_job.assert_called_once_with(manager.jobs['oom'],'failed','MEMORY_LIMIT')
        manager.client.containers.list.assert_called_once_with(all=True,
            filters={'label':['lazyx.sb=true','opensandbox.io/id']})


if __name__=='__main__':
    unittest.main()
