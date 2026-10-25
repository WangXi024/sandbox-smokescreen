"""计量来自可信 cgroup；缺失值、保留范围和就绪/容量语义。"""
from collections import Counter
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sandbox_model import resources
from sandbox_model.service import Manager
from sandbox_model.settings import Settings
from sandbox_model.proto import sandbox_pb2 as pb


class ResourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.job = {'request_id':'measured', '_usage_path':self.root}

    def write(self, cpu='1200000', peak='67108864'):
        (self.root/'cpu.stat').write_text('usage_usec '+cpu+'\nuser_usec 1000\n')
        (self.root/'memory.peak').write_text(peak)

    def test_cumulative_cpu_and_kernel_peak_survive_finalization(self):
        self.write();resources.sample(self.job)
        self.write(cpu='2400000');resources.sample(self.job,final=True)
        self.assertEqual(self.job['cpu_usage_usec'],2400000)
        self.assertEqual(self.job['peak_memory_bytes'],67108864)
        self.assertTrue(self.job['resource_usage_final'])
        self.assertGreater(self.job['resource_sample_unix_ms'],0)
        self.write(cpu='9999999');resources.sample(self.job)
        self.assertEqual(self.job['cpu_usage_usec'],2400000)

    def test_missing_peak_never_uses_current_or_limit_as_peak(self):
        self.write();(self.root/'memory.peak').unlink()
        (self.root/'memory.current').write_text('100')
        (self.root/'memory.max').write_text('999999')
        resources.sample(self.job,final=True)
        self.assertTrue(self.job['cpu_usage_available'])
        self.assertNotIn('peak_memory_available',self.job)
        self.assertNotIn('peak_memory_bytes',self.job)
        self.assertFalse(self.job['resource_usage_final'])

    def test_disappeared_cgroup_preserves_last_values_as_partial(self):
        self.write();resources.sample(self.job)
        (self.root/'cpu.stat').unlink();(self.root/'memory.peak').unlink()
        resources.sample(self.job,final=True)
        self.assertTrue(self.job['cpu_usage_available'])
        self.assertEqual(self.job['cpu_usage_usec'],1200000)
        self.assertFalse(self.job['resource_usage_final'])

    def test_invalid_values_are_not_fabricated_zero(self):
        for value in ('-1','max',str(2**64)):
            self.write(cpu=value,peak=value)
            resources.sample(self.job,final=True)
            self.assertNotIn('cpu_usage_available',self.job)
            self.assertNotIn('peak_memory_available',self.job)
            self.assertFalse(self.job['resource_usage_final'])

    def test_bind_rejects_other_task_proxy_and_node_cgroup(self):
        ident='a'*64
        container=SimpleNamespace(id=ident,labels={'lazyx.job':'measured','opensandbox.io/id':'sandbox'},
                                  attrs={'HostConfig':{'Runtime':'runsc'},'State':{'Pid':123}})
        proc=self.root/'proc';(proc/'123').mkdir(parents=True)
        group=proc/'123/cgroup'
        for relative,expected in (('/',False),('/docker/other',False),('/docker/'+ident,True)):
            job={'request_id':'measured'};group.write_text('0::'+relative+'\n')
            with patch.object(resources,'PROC',proc),patch.object(resources,'CGROUP',self.root/'cgroup'):
                resources.bind(job,container)
            self.assertEqual('_usage_path' in job,expected)
        for labels in ({'lazyx.job':'measured'}, {'lazyx.job':'other','opensandbox.io/id':'sandbox'}):
            job={'request_id':'measured'};container.labels=labels
            resources.bind(job,container)
            self.assertNotIn('_usage_path',job)


class MetricsTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.manager=object.__new__(Manager)
        self.manager.settings=Settings()
        self.manager.jobs={}
        self.manager.catalog={'python':{}}
        self.manager.test_mode=False
        self.manager.readiness_reason=lambda:'READY'
        self.manager.service_started_unix_ms=100
        self.manager.environments=SimpleNamespace(active={},pending={},entries={},counters=Counter(cache_hits=2))

    async def test_queue_full_is_healthy_but_not_accepting_new_ids(self):
        self.manager.jobs={str(i):{'phase':'queued'} for i in range(6)}
        ready=await self.manager.Ready(pb.Empty(),None)
        self.assertTrue(ready.ready)
        self.assertFalse(ready.accepting_tasks)
        self.assertEqual(ready.admission_reason,'QUEUE_FULL')
        self.assertEqual(ready.reason,'READY')

    async def test_fault_is_not_ready_regardless_of_capacity(self):
        self.manager.readiness_reason=lambda:'WATCHDOG_STALE'
        ready=await self.manager.Ready(pb.Empty(),None)
        self.assertFalse(ready.ready)
        self.assertFalse(ready.accepting_tasks)
        self.assertEqual(ready.reason,'WATCHDOG_STALE')

    async def test_metrics_only_contain_aggregate_metadata(self):
        self.manager.jobs={'secret-job':{'phase':'running','spec':'secret code'},
                           'finished':{'phase':'finished','outcome':'failed','cleanup_done':False,
                                       'artifacts':[{'data':b'secret'}],'stdout':'abc'}}
        self.manager.environments.active={'build':{'deadline':0}}
        self.manager.environments.entries={'private-name':{'image_id':'image','bytes':42}}
        result=await self.manager.Metrics(pb.Empty(),None)
        self.assertEqual(result.cleanup_pending,2)
        self.assertEqual(result.inflight,1)
        self.assertEqual(result.result_cache_bytes,9)
        self.assertEqual(result.cache_images,1)
        self.assertEqual(result.cache_bytes,42)
        self.assertEqual(result.environment_counters['cache_hits'],2)
        self.assertNotIn(b'secret',result.SerializeToString())
        self.assertNotIn(b'private-name',result.SerializeToString())

    async def test_usage_persisted_without_host_paths_or_task_content(self):
        job={'request_id':'done','phase':'finished','outcome':'success','cleanup_done':True,
             'delivery_done':False,'error_code':'','events':[],'started':time.time(),'finished':time.time(),
             'cpu_usage_available':True,'cpu_usage_usec':123,'peak_memory_available':True,
             'peak_memory_bytes':456,'resource_usage_final':True,'_usage_path':Path('/private/host'),
             'spec':'private task data'}
        self.manager.jobs={'done':job}
        with tempfile.TemporaryDirectory() as directory,patch('sandbox_model.service.STATE',Path(directory)/'jobs.json'):
            self.manager.persist()
            saved=json.loads((Path(directory)/'jobs.json').read_text())['done']
        self.assertNotIn('_usage_path',saved)
        self.assertNotIn('spec',saved)
        status=self.manager.response(saved)
        self.assertEqual(status.cpu_usage_usec,123)
        self.assertEqual(status.peak_memory_bytes,456)
        self.assertTrue(status.resource_usage_final)

    async def test_unmeasured_task_is_explicitly_unavailable(self):
        job={'request_id':'early','phase':'finished','outcome':'cancelled','cleanup_done':True,
             'delivery_done':False,'error_code':'CANCELLED','events':[],'started':time.time()}
        status=self.manager.response(job)
        self.assertFalse(status.cpu_usage_available)
        self.assertFalse(status.peak_memory_available)
        self.assertFalse(status.resource_usage_final)

    async def test_cleanup_retry_resamples_a_still_existing_cgroup(self):
        # 首次销毁未完成时，重试不能一直返回第一次销毁尝试前的旧快照。
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)
            (path/'cpu.stat').write_text('usage_usec 9000\n')
            (path/'memory.peak').write_text('8192')
            job={'request_id':'retry','cpu_usage_usec':1000,'resource_usage_final':True,
                 '_usage_path':path,'_usage_closed':True}
            self.manager.jobs={'retry':job}
            self.manager.network=SimpleNamespace(revoke=Mock(),jobs={},remaining_resources=Mock(return_value={}))
            self.manager.client=SimpleNamespace(containers=SimpleNamespace(list=Mock(return_value=[])))
            self.manager.registry=Mock();self.manager.server_process=None
            await self.manager.cleanup('retry')
            self.assertEqual(job['cpu_usage_usec'],9000)
            self.assertEqual(job['peak_memory_bytes'],8192)
