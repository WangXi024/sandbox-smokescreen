"""受限转交通道单元回归；真实容器与免认证接口验收由 acceptance 独立执行。"""
import asyncio
import json
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sandbox_model.service import Manager
from sandbox_model.test_caller import SyntheticConnector, SyntheticUpstream, TestCaller


class ConnectorTests(unittest.TestCase):
    def test_independent_upstream_authenticates_connector_without_returning_key(self):
        upstream = SyntheticUpstream(b'synthetic-upstream-key')
        connector = SyntheticConnector(b'synthetic-upstream-key', upstream)
        context = {'owner':'alice','job_id':'job-a','request_id':'request-a'}
        result = connector.echo(context, 'synthetic-value')
        self.assertEqual(result, {'value':'synthetic-value','credential_used':True})
        self.assertEqual(upstream.accepted_calls, 1)
        self.assertNotIn('synthetic-upstream-key', json.dumps(result))
        wrong = SyntheticConnector(b'wrong-synthetic-key', upstream)
        with self.assertRaisesRegex(ValueError, 'SYNTHETIC_CONNECTOR_AUTH_FAILED'):
            wrong.echo(context, 'synthetic-value')
        self.assertEqual(upstream.accepted_calls, 1)


class GatewayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.manager = object.__new__(Manager)
        self.manager.test_caller = TestCaller()
        self.manager.gateway_lock = threading.Lock()
        self.manager.loop = asyncio.get_running_loop()
        self.manager.network = SimpleNamespace(source_job=lambda address:'job-a' if address=='trusted-source' else None)
        self.manager.persist = Mock()
        self.manager.event = lambda job,phase:job.update(phase=phase)
        self.job = {'request_id':'job-a','owner':'alice','spec':SimpleNamespace(kind='skill'),
                    'phase':'running','outcome':'','error_code':'','task':None,'started':time.time(),
                    'deadline':time.time()+60,'gateway_closed':False,
                    'requests':{},'calls':0,'model_calls':0,'tool_calls':0,'input_bytes':19,
                    'output_bytes':0,'cleanup_done':False,'delivery_done':False,'events':[],'proposal_json':b''}
        self.manager.jobs = {'job-a':self.job}

    def message(self, request_type='tool', operation='echo', request_id='request-a'):
        return {'type':request_type,'operation':operation,'arguments':{'value':'synthetic'},'request_id':request_id}

    def call(self, message=None, address='trusted-source'):
        return self.manager.gateway_request(address, message or self.message())

    async def test_forwarded_context_and_original_request_response_are_bound(self):
        status, result = self.call(self.message('model','complete'))
        self.assertEqual(status, 200)
        self.assertEqual((result['owner'],result['job_id'],result['request_id']),('internal','job-a','request-a'))
        self.assertEqual(result['module'], '06')
        received = self.manager.test_caller.received[0]
        self.assertEqual(received['owner'], 'internal')
        self.assertEqual(received['job_id'], 'job-a')
        self.assertEqual(received['request_id'], 'request-a')
        self.assertEqual(self.job['model_calls'], 1)
        await asyncio.sleep(0)
        self.manager.persist.assert_called_once()

    async def test_same_identifier_deduplicates_without_repeating_connector_action(self):
        message = self.message(operation='key_demo')
        first = self.call(message)
        self.assertEqual(self.call(message), first)
        self.assertEqual(self.manager.test_caller.connector.upstream.accepted_calls, 1)
        self.assertEqual(self.job['tool_calls'], 1)
        self.assertEqual(self.job['calls'], 1)
        self.assertEqual(len(self.job['requests']), 1)

    async def test_identifier_conflict_is_rejected_without_dispatch(self):
        self.call()
        status, result = self.call(self.message(operation='key_demo'))
        self.assertEqual((status,result['reason']), (409,'REQUEST_ID_CONFLICT'))
        self.assertEqual(len(self.manager.test_caller.received), 1)

    async def test_legacy_message_receives_generated_identifier(self):
        message = self.message()
        del message['request_id']
        _, first = self.call(message)
        _, second = self.call(message)
        self.assertTrue(first['request_id'].startswith('legacy_'))
        self.assertNotEqual(first['request_id'], second['request_id'])

    async def test_unknown_result_stops_and_does_not_resend(self):
        self.manager.test_caller.available = False
        message = self.message()
        status, result = self.call(message)
        self.assertEqual((status,result['reason']), (503,'CALLER_UNAVAILABLE'))
        self.call(message)
        self.assertEqual(len(self.manager.test_caller.received), 1)
        await asyncio.sleep(0)
        self.assertEqual((self.job['outcome'],self.job['error_code']),('unknown','CALLER_LOST'))
        self.assertEqual(self.job['tool_calls'], 1)

    async def test_simulated_caller_loss_and_context_mismatch_stop(self):
        status, _ = self.call(self.message(operation='caller_lost'))
        self.assertEqual(status, 503)
        await asyncio.sleep(0)
        self.assertEqual(self.job['outcome'], 'unknown')
        self.job.update(outcome='',error_code='',gateway_closed=False)
        self.manager.test_caller.request = lambda *args:{'status':'ok','owner':'bob','job_id':'other-job','request_id':'other-request'}
        status, _ = self.call(self.message(request_id='mismatch'))
        self.assertEqual(status, 503)
        await asyncio.sleep(0)
        self.assertEqual(self.job['error_code'], 'CALLER_LOST')

    async def test_request_cache_and_actual_call_counts_have_eight_call_bound(self):
        for number in range(8):
            self.assertEqual(self.call(self.message(request_id='request-'+str(number)))[0], 200)
        self.assertEqual(self.call(self.message(request_id='request-0'))[0], 200)
        status, result = self.call(self.message(request_id='request-8'))
        self.assertEqual((status,result['reason']), (403,'CALL_LIMIT'))
        await asyncio.sleep(0)
        self.assertEqual(self.job['calls'], 8)
        self.assertEqual(self.job['tool_calls'], 8)
        self.assertEqual(len(self.job['requests']), 8)
        self.assertEqual(self.job['error_code'], 'CALL_LIMIT')

    async def test_untrusted_source_forged_identity_invalid_id_and_code_model_not_forwarded(self):
        self.assertEqual(self.call(address='untrusted-source')[0], 403)
        message = self.message() | {'owner':'bob'}
        self.assertEqual(self.call(message)[0], 403)
        self.assertEqual(self.call(self.message(request_id='../invalid'))[0], 403)
        self.job['spec'].kind = 'code'
        self.assertEqual(self.call(self.message('model','complete'))[0], 403)
        self.assertEqual(len(self.manager.test_caller.received), 0)

    async def test_approval_and_budget_decisions_are_returned_by_caller_then_stop(self):
        status, result = self.call(self.message(operation='approval'))
        self.assertEqual((status,result['status']), (200,'needs_approval'))
        self.assertEqual(json.loads(self.job['proposal_json'])['request_id'], 'request-a')
        await asyncio.sleep(0)
        self.assertEqual(self.job['outcome'], 'needs_approval')
        self.job.update(outcome='',error_code='',gateway_closed=False)
        self.call(self.message('model','budget_exhausted','budget'))
        await asyncio.sleep(0)
        self.assertEqual(self.job['error_code'], 'BUDGET_EXHAUSTED')

    async def test_status_and_persistent_metadata_report_only_measured_usage(self):
        self.call(self.message('model','complete'))
        self.call(self.message(request_id='tool'))
        self.job['output_bytes'] = 23
        self.job['log_bytes'] = 7
        status = self.manager.response(self.job)
        self.assertEqual((status.input_bytes,status.output_bytes,status.model_calls,status.tool_calls),(19,23,1,1))
        self.assertEqual(status.log_bytes, 7)
        self.assertFalse(status.cpu_usage_available)
        self.assertFalse(status.peak_memory_available)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'jobs.json'
            with patch('sandbox_model.service.STATE',path):
                Manager.persist(self.manager)
            saved = json.loads(path.read_text())['job-a']
        self.assertEqual((saved['input_bytes'],saved['output_bytes'],saved['model_calls'],saved['tool_calls']),(19,23,1,1))
        self.assertEqual(saved['log_bytes'], 7)
        self.assertNotIn('requests', saved)
        self.assertNotIn('spec', saved)
        self.assertNotIn('synthetic', json.dumps(saved))

    async def test_repeated_stop_preserves_first_reason_and_does_not_interrupt_cleanup(self):
        slots = asyncio.Semaphore(1)
        started = asyncio.Event()
        cleaning = asyncio.Event()
        release = asyncio.Event()
        pending = asyncio.create_task(release.wait())
        async def lifecycle():
            await slots.acquire()
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cleaning.set()
                await asyncio.shield(pending)
                self.job['cleanup_done'] = True
                self.job['phase'] = 'finished'
                slots.release()
        task = asyncio.create_task(lifecycle())
        self.job['task'] = task
        await started.wait()
        self.manager.stop_job(self.job, 'cancelled', 'CANCELLED')
        await cleaning.wait()
        self.manager.stop_job(self.job, 'unknown', 'CONTROL_LOST')
        self.manager.stop_job(self.job, 'failed', 'CALL_LIMIT')
        self.assertEqual(task.cancelling(), 1)
        self.assertEqual((self.job['outcome'],self.job['error_code']), ('cancelled','CANCELLED'))
        self.assertFalse(self.job['cleanup_done'])
        release.set()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(self.job['cleanup_done'])
        self.assertEqual(slots._value, 1)

    async def test_stop_does_not_cancel_successful_execution_during_cleanup(self):
        release = asyncio.Event()
        task = asyncio.create_task(release.wait())
        self.job.update(phase='returning',outcome='success',task=task)
        self.manager.stop_job(self.job, 'cancelled', 'CANCELLED')
        self.assertEqual(task.cancelling(), 0)
        self.assertEqual((self.job['outcome'],self.job['error_code']), ('success',''))
        release.set()
        await task

    async def test_queued_cancel_is_idempotent(self):
        task = asyncio.create_task(asyncio.Event().wait())
        self.job.update(phase='queued',task=task)
        self.manager.stop_job(self.job, 'cancelled', 'CANCELLED')
        self.manager.stop_job(self.job, 'unknown', 'CONTROL_LOST')
        self.assertEqual(task.cancelling(), 1)
        self.assertEqual((self.job['phase'],self.job['outcome'],self.job['error_code']), ('finished','cancelled','CANCELLED'))
        self.assertTrue(self.job['cleanup_done'])
        self.assertIsNone(self.job['spec'])
        with self.assertRaises(asyncio.CancelledError):
            await task


if __name__ == '__main__':
    unittest.main()
