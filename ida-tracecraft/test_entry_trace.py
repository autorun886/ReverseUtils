"""Offline contract checks; no IDA or Frida dependency."""
import copy
import json
import tempfile
import unittest
import shutil
import subprocess
import io
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch
import socket

import entry_trace as trace


class Contracts(unittest.TestCase):
    def setUp(self):
        self.snapshot = dict(schema=1, module='sample.so', imagebase='0x1000',
                             root='0x10', selection_mode='history',
                             functions=[dict(offset='0x10', name='trigger', thumb=True),
                                        dict(offset='0x20', name='next', thumb=False)])

    def data(self, request):
        source = trace.generate(request, self.snapshot)['script']
        marker = 'const CONFIG = ' if 'const CONFIG = ' in source else 'const DATA = '
        return json.loads(source.split(marker, 1)[1].split(';\n', 1)[0])

    def test_default_and_custom_window(self):
        self.assertEqual(self.data({'mode':'window'})['windowSize'], 100)
        data = self.data({'mode':'history', 'count':20})
        self.assertEqual((data['historySize'], data['windowSize']), (20,20))
        data = self.data({'mode':'history','count':20,'window_size':7})
        self.assertEqual((data['historySize'],data['windowSize']), (20,7))

    def test_plan_is_bounded_by_ida_functions(self):
        with self.assertRaisesRegex(ValueError, 'outside snapshot'):
            self.data({'mode':'selected', 'plan':{'hooks':[{'offset':'0x99'}]}})
        with self.assertRaisesRegex(ValueError, 'types'):
            self.data({'mode':'selected', 'plan':{'hooks':[{'offset':'0x10','args':['float']} ]}})

    def test_typed_plan_and_thumb(self):
        data = self.data({'mode':'selected','plan':{'hooks':[{'offset':'0x20','args':['int','cstring'],'ret':'uint'}]}})
        self.assertEqual([h['offset'] for h in data['hooks']], ['0x20'])
        self.assertEqual(data['hooks'][0]['args'], ['int','cstring'])
        self.assertFalse(data['hooks'][0]['thumb'])

    def test_parameter_conditions(self):
        when = {'all':[{'arg':0,'type':'int','op':'eq','value':7},
                       {'any':[{'arg':1,'type':'cstring','op':'contains','value':'hello'},
                               {'arg':1,'type':'cstring','op':'startsWith','value':'world'}]}]}
        data = self.data({'mode':'selected','when':when})
        self.assertEqual(data['hooks'][0]['when'],when)
        self.assertEqual(len(data['hooks']),2)
        with self.assertRaisesRegex(ValueError,'arg'):
            self.data({'mode':'selected','when':{'arg':8,'op':'eq','value':'0x0'}})

    @unittest.skipUnless(shutil.which('node'), 'Node required')
    def test_runtime_filter_skips_enter_and_leave(self):
        source = trace.generate({'mode':'selected','when':{'all':[
            {'arg':0,'type':'int','op':'eq','value':7},
            {'arg':1,'type':'cstring','op':'contains','value':'hello'}]}},self.snapshot)['script']
        prelude = """
let moduleObserver, callbacks, output=[];
const console={log:s=>output.push(s),error:s=>output.push(s)};
const rpc={};
const Process={id:1,attachModuleObserver:o=>(moduleObserver=o,{detach(){}})};
const Interceptor={attach:(p,c)=>(callbacks=c,{detach(){}})};
const address={add(){return this;},or(){return this;},equals(){return true;}};
const val=(n,text)=>({toInt32:()=>n,toString:()=>String(n),isNull:()=>false,readUtf8String:()=>text,
 add:i=>({readU8:()=> (text || '').charCodeAt(i) || 0})});
"""
        checks = """
moduleObserver.onAdded({name:'sample.so',base:address});
const context={threadId:1};
callbacks.onEnter.call(context,[val(6),val(0,'hello')]);
callbacks.onLeave.call(context,val(1));
if (matches!==0) throw Error('nonmatch logged');
callbacks.onEnter.call(context,[val(7),val(0,'say hello')]);
callbacks.onLeave.call(context,val(1));
if (matches!==1 || output.filter(s=>s.startsWith('[ENTER')).length!==1 ||
    output.filter(s=>s.startsWith('[LEAVE')).length!==1) throw Error('filter logging failure');
"""
        result = subprocess.run(['node','-e',prelude+source+checks],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_count_validation(self):
        for value in (0,-1,100001):
            with self.assertRaises(ValueError):
                self.data({'mode':'history','count':value})

    def test_absolute_path_and_collision(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory)/'hook.js')
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                first = trace.generate_file({'mode':'window'},path,self.snapshot)
            self.assertEqual(json.loads(stdout.getvalue())['script_path'],first['script_path'])
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                second = trace.generate_file({'mode':'window'},path,self.snapshot)
            self.assertEqual(json.loads(stdout.getvalue())['script_path'],second['script_path'])
            self.assertTrue(Path(first['script_path']).is_absolute())
            self.assertNotEqual(first['script_path'],second['script_path'])
            self.assertTrue(Path(first['script_path']).read_text().startswith("\n'use strict';"))

    def test_trigger_validation(self):
        snapshot = copy.deepcopy(self.snapshot)
        snapshot['root'] = None
        with self.assertRaisesRegex(ValueError,'root'):
            trace.generate({'mode':'window'},snapshot)

    def test_offline_cli_returns_path(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory)/'context.json'
            snapshot.write_text(json.dumps(self.snapshot),encoding='utf-8')
            output = Path(directory)/'generated.js'
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                status = trace.main(['generate','--snapshot',str(snapshot),'--mode','history',
                                     '--count','20','--output',str(output)])
            self.assertEqual(status,0)
            self.assertEqual(json.loads(stdout.getvalue())['script_path'],str(output))
            self.assertTrue(output.is_file())

    def test_short_and_long_help(self):
        for flag in ('-h','--help'):
            stdout = io.StringIO()
            with redirect_stdout(stdout), self.assertRaises(SystemExit) as result:
                trace.main([flag])
            self.assertEqual(result.exception.code,0)
            self.assertIn('--count',stdout.getvalue())
            self.assertIn('script_path',stdout.getvalue())
            self.assertTrue(stdout.getvalue().isascii())
            self.assertIn('--input',stdout.getvalue())
            self.assertIn('instances',stdout.getvalue())
            for mode in ('full', 'window', 'history', 'hooks', 'selected', 'regex', 'callers', 'callees'):
                self.assertIn(mode,stdout.getvalue())
            self.assertIn('--ai-level', stdout.getvalue())
            self.assertIn('--plan', stdout.getvalue())

    @unittest.skipIf(trace.idaapi is not None, 'Outside-IDA CLI contract')
    def test_outside_ida_reports_missing_plugin(self):
        stderr = io.StringIO()
        with patch.object(trace,'discover_instance',side_effect=RuntimeError('No instance; use --snapshot')), redirect_stderr(stderr):
            status = trace.main(['generate'])
        self.assertEqual(status,1)
        self.assertIn('--snapshot',stderr.getvalue())

    @unittest.skipUnless(shutil.which('node'), 'Node required for JS event simulation')
    def test_runtime_window_counts_after_trigger(self):
        source = trace.generate({'mode':'window','count':20},self.snapshot)['script']
        prelude = """
const Process = {arch:'x64',platform:'linux',findModuleByName:()=>null,
    attachModuleObserver:()=>({detach(){}})};
const Frida = {version:'17.23.3'};
const Stalker = {unfollow(){},garbageCollect(){}};
const rpc = {};
const setInterval = ()=>1, clearInterval = ()=>{}, setImmediate = ()=>{};
"""
        checks = """
threads.set(7,makeThread());
threads.get(7).following = true;
entry(7,'0x10',true);
if (threads.get(7).remaining !== 20 || sequence !== 0) throw Error('trigger consumed quota');
for (let i=0;i<19;i++) entry(7,'0x20');
if (threads.get(7).remaining !== 1 || sequence !== 19) throw Error('early stop');
entry(7,'0x20');
entry(7,'0x20');
if (threads.get(7).remaining !== 0 || sequence !== 20 || threads.get(7).following)
    throw Error('window boundary failure');
"""
        result = subprocess.run(['node','-e',prelude+source+checks],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)


class LocalCLI(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.registry = patch.object(trace,'state_directory',return_value=Path(self.directory.name))
        self.registry.start()
        self.env = patch.dict(trace.os.environ,{'TRACECRAFT_PORT':''})
        # Port overrides are irrelevant to these isolated test instances.
        self.env.start()
        trace.os.environ.pop('TRACECRAFT_PORT',None)
        self.services = []
        self.snapshot = dict(module='sample.so',imagebase='0x1000',root='0x10',
                             selection_mode='window',input_path=str(Path(self.directory.name)/'sample.so'),
                             functions=[dict(offset='0x10',name='trigger',thumb=False)])

    def tearDown(self):
        for service in self.services:
            service.stop()
        self.env.stop()
        self.registry.stop()
        self.directory.cleanup()

    def start(self):
        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1',0))
            port = occupied.getsockname()[1]
            if port > 65530:
                self.skipTest('Ephemeral port too close to maximum')
            identity = dict(module='sample.so',input_path=self.snapshot['input_path'])
            service = trace.LocalService(port_range='%d:%d' % (port,port+5),
                dispatcher=lambda request:dict(self.snapshot,input_path=identity['input_path']),
                identity=identity)
            service.test_identity = identity
            self.services.append(service)
            self.assertNotEqual(service.port,port)
            return service

    def test_direct_cli_without_snapshot(self):
        service = self.start()
        output = Path(self.directory.name)/'after20.js'
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = trace.main(['--mode','window','--root','trigger','--count','20','-o',str(output)])
        self.assertEqual(code,0)
        self.assertEqual(json.loads(stdout.getvalue())['script_path'],str(output))
        self.assertIn('"windowSize": 20',output.read_text())
        self.assertEqual(trace.discover_instance(port=service.port)['port'],service.port)

    def test_multiple_instances_require_selection(self):
        first, second = self.start(), self.start()
        with self.assertRaisesRegex(RuntimeError,'Multiple IDA'):
            trace.discover_instance()
        self.assertEqual(trace.discover_instance(port=second.port)['port'],second.port)
        self.assertEqual(trace.discover_instance(port_range='%d:%d' % (first.port,first.port))['port'],first.port)

    def test_instance_listing_and_ambiguity(self):
        first, second = self.start(), self.start()
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(trace.main(['instances']), 0)
        report = json.loads(stdout.getvalue())
        self.assertEqual(len(report), 2)
        self.assertEqual({i['id'] for i in report}, {first._record['id'], second._record['id']})
        self.assertTrue(all(set(row) == {'id','endpoint','input_path'} for row in report))
        self.assertNotIn('token', stdout.getvalue())
        with redirect_stderr(stderr):
            self.assertEqual(trace.main(['--mode', 'window', '--root', 'trigger']), 1)
        self.assertIn('Multiple IDA instances', stderr.getvalue())
        self.assertNotIn('token', stderr.getvalue())

    def test_exact_path_selection_and_explicit_override(self):
        first, second = self.start(), self.start()
        first.test_identity['input_path'] = str(Path(self.directory.name) / 'one' / 'sample.so')
        second.test_identity['input_path'] = str(Path(self.directory.name) / 'two' / 'sample.so')
        first.refresh_identity()
        second.refresh_identity()
        with patch.dict(trace.os.environ, {'TRACECRAFT_PORT': str(first.port)}):
            path = str(Path(self.directory.name) / 'two' / '..' / 'two' / 'sample.so')
            self.assertEqual(trace.discover_instance(input_name=path)['port'], second.port)
            self.assertEqual(trace.discover_instance(port=second.port)['port'], second.port)
        second.test_identity['input_path'] = first.identity['input_path']
        second.refresh_identity()
        with self.assertRaisesRegex(RuntimeError,'Multiple IDA'):
            trace.discover_instance(input_name=first.identity['input_path'])
        self.assertEqual(trace.discover_instance(input_name=first.identity['input_path'],
                                               port=second.port)['port'], second.port)

    def test_stale_registry_and_no_matching_instances(self):
        Path(self.directory.name, 'stale.json').write_text('{}', encoding='utf-8')
        self.assertEqual(trace.list_instances(), [])
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(trace.main(['--input', 'missing.so']), 1)
        self.assertIn('No matching live IDA instance', stderr.getvalue())
        service = self.start()
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(trace.main(['instances', '--port', str(service.port)]), 0)
        self.assertEqual(len(json.loads(stdout.getvalue())), 1)
        snapshot = trace.remote_snapshot({'mode': 'window'}, port=service.port)
        self.assertEqual(snapshot['input_path'], service.identity['input_path'])

    def test_authentication_validation_and_cleanup(self):
        service = self.start()
        record = trace.discover_instance(port=service.port)
        with self.assertRaisesRegex(RuntimeError,'credentials'):
            trace.local_request(dict(record,token='invalid'),'info')
        with self.assertRaisesRegex(RuntimeError,'Unknown snapshot'):
            trace.local_request(record,'snapshot',{'code':'arbitrary code'})
        record_path = service.registry.directory / (service._record['id'] + '.json')
        service.stop()
        self.services.remove(service)
        self.assertFalse(record_path.exists())

    def test_database_work_runs_through_execute_sync(self):
        import types
        calls = []
        kernwin = types.SimpleNamespace(MFF_READ=123,execute_sync=lambda callback,flags:(calls.append(flags),callback())[1])
        with patch.dict('sys.modules',{'ida_kernwin':kernwin}), patch.object(trace,'collect_snapshot',return_value=self.snapshot):
            self.assertEqual(trace.collect_on_ida_thread({'mode':'window'}),self.snapshot)
            with self.assertRaisesRegex(RuntimeError,'stopping'):
                trace.collect_on_ida_thread({},lambda:False)
        self.assertEqual(calls,[123,123])


if __name__ == '__main__':
    unittest.main()
