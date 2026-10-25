"""依赖请求、导出边界与缓存语义；真实 gVisor 链路另行验收。"""
import asyncio
import io
import json
from pathlib import Path
import tarfile
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
from sandbox_model.environments import declaration, checked_context, fingerprint, Environments


def archive(entries):
    data = io.BytesIO()
    with tarfile.open(fileobj=data,mode='w') as output:
        entries = [('env/lock.json',json.dumps({'language':'python','packages':[]}).encode(),None)] + entries
        for name, content, link in entries:
            info=tarfile.TarInfo(name)
            if link:
                info.type=tarfile.SYMTYPE;info.linkname=link
            else:info.size=len(content)
            output.addfile(info,io.BytesIO(content) if not link else None)
    return data.getvalue()


class DeclarationTests(unittest.TestCase):
    def test_canonical_order_and_duplicates(self):
        self.assertEqual(declaration('python',['Some_Pkg==1.2.3','some-pkg==1.2.3','foo==1.0']), ['foo==1.0','some-pkg==1.2.3'])
        self.assertEqual(declaration('node',['@scope/pkg@1.2.3']),['@scope/pkg@1.2.3'])

    def test_arbitrary_commands_urls_ranges_and_conflicts_rejected(self):
        for language, value in [('python','x>=1'),('python','--extra-index-url=https://evil.test'),
                ('python','x==1\ny==2'),('python','x @ https://pypi.org/a'),('node','a@latest'),
                ('node','../x@1.0.0'),('node','a@https://registry.npmjs.org/a')]:
            with self.subTest(value=value),self.assertRaises(ValueError):declaration(language,[value])
        with self.assertRaisesRegex(ValueError,'CONFLICT'):declaration('python',['a==1','a==2'])

    def test_unsupported_environment_and_limit(self):
        with self.assertRaises(ValueError):declaration('browser',['a==1'])
        with self.assertRaises(ValueError):declaration('python',[f'a{i}==1' for i in range(33)])

    def test_no_dependencies_remains_backward_compatible(self):
        self.assertEqual(declaration('browser',[]),[])

    def test_fingerprint_includes_base_architecture_and_lock(self):
        value={'base':'one','architecture':'arm64','lock':['x==1']}
        for key in value:
            self.assertNotEqual(fingerprint(value),fingerprint(value|{key:'changed'}))


class ExportTests(unittest.TestCase):
    def test_copy_only_context_and_internal_symlink(self):
        raw=archive([('env/python/a',b'public-package',None),('env/python/b',b'', 'a')])
        context,ident,size,lock=checked_context(raw,'sha256:'+'a'*64,'b'*64)
        with tarfile.open(fileobj=io.BytesIO(context)) as output:
            dockerfile=output.extractfile('Dockerfile').read().decode()
            self.assertNotIn('RUN ',dockerfile)
            self.assertIn('COPY env/ /opt/env/',dockerfile)
        self.assertEqual(len(ident),64)
        self.assertGreater(size,0)

    def test_traversal_absolute_duplicate_and_link_escape(self):
        cases=[('env/../etc/file',b'x',None),('/etc/file',b'x',None),('env/a',b'', '../../etc'),
               ('env/a',b'', '/etc'),('env/lock.json',b'{}',None),('env/a\nb',b'x',None)]
        for entry in cases:
            with self.subTest(entry=entry),self.assertRaises(ValueError):
                checked_context(archive([entry]),'base','key')

    def test_symlink_parent_rejected(self):
        with self.assertRaisesRegex(ValueError,'UNSAFE_LINK'):
            checked_context(archive([('env/link',b'','target'),('env/link/file',b'x',None)]),'base','key')

    def test_special_file_rejected(self):
        raw=io.BytesIO()
        with tarfile.open(fileobj=raw,mode='w') as output:
            info=tarfile.TarInfo('env/device');info.type=tarfile.CHRTYPE;output.addfile(info)
        with self.assertRaisesRegex(ValueError,'SPECIAL_FILE'):checked_context(raw.getvalue(),'base','key')

    def test_total_limit(self):
        with patch('sandbox_model.environments.LIMIT',10),self.assertRaisesRegex(ValueError,'LIMIT'):
            checked_context(archive([('env/a',b'x'*20,None)]),'base','key')


class CacheTests(unittest.IsolatedAsyncioTestCase):
    def manager(self):
        from collections import Counter
        env=object.__new__(Environments)
        env.client=MagicMock();env.client.images.get.return_value.id='builder'
        env.entries={};env.pending={};env.pins=Counter();env.guard=asyncio.Lock()
        env.counters=Counter()
        env.persist=MagicMock();env.valid=MagicMock(return_value=True)
        return env

    def job(self, ident):
        from types import SimpleNamespace
        return {'request_id':ident,'spec':SimpleNamespace(environment='python',dependencies=['requests==2.32.3'])}

    async def test_concurrent_waiters_build_once(self):
        env=self.manager();gate=asyncio.Event()
        async def build(*args):
            await gate.wait()
            return {'image_id':'image','environment_id':'environment'}
        env.build=AsyncMock(side_effect=build)
        a,b=self.job('a'),self.job('b')
        tasks=[asyncio.create_task(env.ensure(j,'base')) for j in (a,b)]
        for _ in range(100):
            if env.pending and next(iter(env.pending.values()))['waiters']==2:break
            await asyncio.sleep(.01)
        gate.set()
        self.assertEqual(await asyncio.gather(*tasks),['image','image'])
        env.build.assert_awaited_once()
        env.release(a);env.release(b)
        self.assertFalse(env.pins)

    async def test_cancel_one_waiter_does_not_cancel_shared_build(self):
        env=self.manager();gate=asyncio.Event();cancel_flag=[]
        async def build(key,spec,cancel):
            cancel_flag.append(cancel);await gate.wait()
            return {'image_id':'image','environment_id':'environment'}
        env.build=AsyncMock(side_effect=build)
        a,b=self.job('a'),self.job('b')
        tasks=[asyncio.create_task(env.ensure(j,'base')) for j in (a,b)]
        for _ in range(100):
            if env.pending and next(iter(env.pending.values()))['waiters']==2:break
            await asyncio.sleep(.01)
        tasks[0].cancel()
        with self.assertRaises(asyncio.CancelledError):await tasks[0]
        self.assertFalse(cancel_flag[0].is_set())
        gate.set();self.assertEqual(await tasks[1],'image')

    async def test_cache_hit_skips_build(self):
        env=self.manager();env.build=AsyncMock()
        lock={'language':'python','packages':[{'name':'requests','version':'2.32.3','sha256':'a'*64,'url':'https://files.pythonhosted.org/a.whl'}]}
        job=self.job('hit')
        async def build(key,spec,cancel):
            entry={'image_id':'image','environment_id':fingerprint({'key':key,'lock':lock}),'lock_sha256':fingerprint(lock)}
            env.entries[key]=entry;return entry
        env.build.side_effect=build
        await env.ensure(job,'base');env.release(job)
        again=self.job('again')
        with patch('sandbox_model.environments.read_private_json',return_value=lock):
            await env.ensure(again,'base')
        self.assertTrue(again['environment_cache_hit']);env.build.assert_awaited_once()
        with patch('sandbox_model.environments.read_private_json',return_value={'language':'python'}):
            with self.assertRaisesRegex(ValueError,'LOCK_INVALID'):await env.ensure(self.job('bad'),'base')

    def test_lru_keeps_pinned_images(self):
        env=self.manager()
        env.entries={str(i):{'used':i,'bytes':1,'image_id':str(i)} for i in range(8)}
        env.pins['0']=1
        env.prune(1)
        self.assertEqual(env.entries['0']['image_id'],'0');self.assertEqual(env.entries['1']['image_id'],'')



class LockTests(unittest.TestCase):
    def test_lock_must_match_requested_versions_and_sources(self):
        from sandbox_model.environments import validate_lock
        spec={'environment':'python','dependencies':['requests==2.32.3']}
        lock={'language':'python','packages':[{'name':'requests','version':'2.32.3','sha256':'a'*64,'url':'https://files.pythonhosted.org/file.whl'}]}
        validate_lock(spec,lock)
        for change in ({'version':'2.31.0'},{'url':'https://evil.test/a'},{'sha256':'invalid'}):
            with self.subTest(change=change),self.assertRaises(ValueError):
                validate_lock(spec,{'language':'python','packages':[lock['packages'][0]|change]})

    def test_node_lock_cannot_change_root_dependencies(self):
        from sandbox_model.environments import validate_lock
        with self.assertRaisesRegex(ValueError,'MISMATCH'):
            validate_lock({'environment':'node','dependencies':['a@1.0.0']},
                {'language':'node','lockfile':{'packages':{'':{'dependencies':{'b':'1.0.0'}},'node_modules/b':{}}}})


class BuildQueueTests(unittest.IsolatedAsyncioTestCase):
    async def test_queued_build_cancel_does_not_wait_for_other_build(self):
        import threading
        env=object.__new__(Environments);env.slot=asyncio.Semaphore(0)
        cancel=threading.Event()
        task=asyncio.create_task(env.build('key',{},cancel))
        await asyncio.sleep(.02);cancel.set()
        with self.assertRaisesRegex(ValueError,'CANCELLED'):
            await asyncio.wait_for(task,1)


if __name__=='__main__':unittest.main()
