"""Workflow contracts and generated-runtime event simulations."""
import copy
import importlib.util
import io
import json
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('tracecraft_workflow', ROOT / 'entry_trace.py')
trace = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trace)

SNAPSHOT = dict(schema=1, module='sample.so', imagebase='0x1000', root='0x10',
    selection_mode='selected', functions=[
        dict(offset='0x10', ea='0x1010', name='first', prototype='int __fastcall(int value)'),
        dict(offset='0x20', ea='0x1020', name='second', prototype='double __fastcall(double value)')])

PRELUDE = r'''
let moduleObserver, callbacks=[], output=[], deferred=[], ticks=[];
let now=1000;
const Date={now:()=>now};
const console={log:s=>output.push(s),error:s=>output.push(s)};
const rpc={};
const Process={id:1,attachModuleObserver:o=>(moduleObserver=o,{detach(){}})};
const Interceptor={attach:(p,c)=>{callbacks.push(c);return {detach(){}}}};
const address={add(){return this;},or(){return this;},equals(){return true;},toString(){return '0x1000'}};
const val=(n,text)=>({toInt32:()=>n,toString:()=>String(n),isNull:()=>false,readUtf8String:()=>text,
 add:i=>({readU8:()=> (text || '').charCodeAt(i) || 0})});
const setInterval=fn=>(ticks.push(fn),ticks.length), clearInterval=()=>{};
const setImmediate=fn=>deferred.push(fn);
function drain(){while(deferred.length)deferred.shift()();}
'''


class WorkflowTests(unittest.TestCase):
    def cli(self, args):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            status = trace.main(args)
        return status, output.getvalue(), errors.getvalue()

    @unittest.skipUnless(shutil.which('node'), 'Node required')
    def run_js(self, request, checks, snapshot=SNAPSHOT, prelude=PRELUDE):
        source = trace.generate(dict({'mode': 'selected'}, **request), copy.deepcopy(snapshot))['script']
        result = subprocess.run(['node', '-e', prelude + source + checks], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_preview_exclusion_and_inference(self):
        result = trace.generate(dict(mode='selected', exclude=['second'], infer_types=True), SNAPSHOT)
        self.assertEqual(result['preview']['excluded'], 1)
        self.assertEqual(result['preview']['targets'][0]['type_suggestion']['args'], ['int'])
        config = json.loads(result['script'].split('const CONFIG = ', 1)[1].split(';\n', 1)[0])
        self.assertEqual(config['hooks'][0]['args'], ['int'])
        self.assertEqual(config['hooks'][0]['ret'], 'int')
        self.assertTrue(trace.suggest_types('double __fastcall(double value)')['warnings'])
        self.assertIsNone(trace.suggest_types('unsigned __int64 __fastcall(int value)')['args'])
        with self.assertRaisesRegex(ValueError, 'No hook targets'):
            trace.generate(dict(mode='selected', exclude=['.*']), SNAPSHOT)
        result = trace.generate(dict(mode='selected', exclude=['first']), SNAPSHOT)
        self.assertEqual(result['preview']['targets'][0]['name'], 'second')

    def test_template_markers_in_function_names_remain_data(self):
        snapshot = copy.deepcopy(SNAPSHOT)
        snapshot['functions'][0]['name'] = '__RUNTIME__'
        for mode, marker in [('selected', 'const CONFIG = '), ('full', 'const DATA = ')]:
            source = trace.generate(dict(mode=mode), snapshot)['script']
            data = json.loads(source.split(marker, 1)[1].split(';\n', 1)[0])
            self.assertIn('__RUNTIME__', json.dumps(data))

    def test_runtime_options_reject_invalid_budgets(self):
        for request in [dict(max_events=-1), dict(sample_every=0), dict(duration=float('nan')),
                        dict(duration=float('inf')), dict(per_function_limit=True), dict(thread_ids=['7'])]:
            with self.subTest(request=request), self.assertRaises(ValueError):
                trace.generate(dict(mode='selected', **request), SNAPSHOT)

    def test_config_override_preview_and_bundle_roundtrip(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            snapshot = directory / 'snapshot.json'
            snapshot.write_text(json.dumps(SNAPSHOT), encoding='utf-8')
            config = directory / 'config.json'
            config.write_text(json.dumps(dict(mode='selected', snapshot=str(snapshot),
                max_events=10, exclude=['first'], log_format='jsonl')), encoding='utf-8')
            saved = directory / 'saved.json'
            status, output, error = self.cli(['preview', '--config', str(config), '--exclude', 'second',
                '--max-events', '2', '--save-config', str(saved)])
            self.assertEqual(status, 0, error)
            preview = json.loads(output)
            self.assertEqual([item['name'] for item in preview['targets']], ['first'])
            self.assertEqual(preview['runtime']['maxEvents'], 2)
            status, output, error = self.cli(['--config', str(saved), '--bundle', str(directory / 'bundle'),
                '-o', str(directory / 'trace.js')])
            self.assertEqual(status, 0, error)
            files = json.loads(output)['files']
            manifest = json.loads(Path(files['manifest']).read_text(encoding='utf-8'))
            self.assertEqual(manifest['preview']['runtime']['maxEvents'], 2)
            status, output, error = self.cli(['preview', '--config', files['bundle_config']])
            self.assertEqual(status, 0, error)
            self.assertEqual(json.loads(output)['functions'], 1)

    def test_invalid_config_has_clear_error(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'bad.json'
            for value in [[], dict(unknown=True), dict(max_events=1.5), dict(log_format='bad'), dict(infer_types='yes')]:
                path.write_text(json.dumps(value), encoding='utf-8')
                status, _, error = self.cli(['preview', '--config', str(path)])
                self.assertEqual(status, 1)
                self.assertIn('[entry-trace]', error)

    def test_results_deduplicate_history_and_filter_sessions_threads(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'events.jsonl'
            events = [dict(schema=1, session='s1', module='sample.so', type='entry', id=1,
                tid=7, offset='0x10', name='first'),
                dict(schema=1, session='s2', module='sample.so', type='enter', id=1,
                tid=8, offset='0x10', name='first')]
            path.write_text('Frida banner\n' + '\n'.join(json.dumps(event) for event in
                [events[0], events[0], events[1]]) + '\n', encoding='utf-8')
            report = trace.read_results(path, limit=1)
            self.assertEqual(report['skipped_lines'], 1)
            self.assertEqual([row['hits'] for row in report['functions']], [1, 1])
            self.assertEqual(len(report['timeline']), 1)
            report = trace.read_results(path, tid=7, session='s1', limit=0)
            self.assertEqual(report['functions'][0]['threads'], [7])
            self.assertEqual(report['timeline'], [])

    def test_runtime_sampling_limits_filters_and_return_pairing(self):
        self.run_js(dict(log_format='jsonl', max_events=2, sample_every=2,
            when={'arg': 0, 'type': 'int', 'op': 'eq', 'value': 7}), r'''
moduleObserver.onAdded({name:'sample.so',base:address});
const c=callbacks[0];
for(const n of [6,7,7,7,7]){
 const ctx={threadId:7}; c.onEnter.call(ctx,[val(n)]); c.onLeave.call(ctx,val(9));
}
const before=rpc.exports.status();
if(before.accepted!==2 || before.filtered!==1 || before.sampled!==1 || before.capped!==1)
 throw Error('bad counters '+JSON.stringify(before));
drain();
const events=output.map(JSON.parse);
if(events.filter(e=>e.type==='enter').length!==2 || events.filter(e=>e.type==='leave').length!==2)
 throw Error('broken pairing');
if(rpc.exports.status().running || rpc.exports.status().stopReason!=='max-events')throw Error('not stopped');
''')

    def test_runtime_partial_install_reload_duration_and_read_errors(self):
        prelude = PRELUDE.replace('callbacks.push(c);return',
            "if(callbacks.length===1)throw Error('fixture failure'); callbacks.push(c);return")
        self.run_js(dict(log_format='jsonl', duration=2, arg_types=['cstring']), r'''
moduleObserver.onAdded({name:'sample.so',base:address});
if(rpc.exports.status().state!=='partial' || rpc.exports.status().hookFailures!==1)throw Error('false ready');
const bad={isNull:()=>false,readUtf8String(){throw Error('invalid pointer')}};
callbacks[0].onEnter.call({threadId:7},[bad]);
if(rpc.exports.status().readErrors!==1)throw Error('read not counted');
moduleObserver.onRemoved({base:address});
if(rpc.exports.status().state!=='waiting-module')throw Error('not waiting');
now=3001; ticks.forEach(fn=>fn()); drain();
if(rpc.exports.status().stopReason!=='duration' || rpc.exports.status().running)throw Error('duration');
''', prelude=prelude)

    def test_per_function_limits_and_explicit_thread_filter(self):
        self.run_js(dict(log_format='jsonl', per_function_limit=1, thread_ids=[7]), r'''
moduleObserver.onAdded({name:'sample.so',base:address});
for(const tid of [8,7,7])callbacks[0].onEnter.call({threadId:tid},[val(1)]);
callbacks[1].onEnter.call({threadId:7},[val(1)]);
const s=rpc.exports.status();
if(s.accepted!==2 || s.filtered!==1 || s.capped!==1 || !s.running)throw Error(JSON.stringify(s));
''')

    def test_history_trigger_budget_and_thread_local_snapshot_ids(self):
        prelude = PRELUDE.replace('moduleObserver', 'capturedObserver') + r'''
const Frida={version:'17.23.3',heapSize:0};
const Stalker={unfollow(){},flush(){},garbageCollect(){}};
'''
        self.run_js(dict(mode='history', log_format='jsonl', max_events=4), r'''
threads.set(7,makeThread()); threads.set(8,makeThread());
entry(7,'0x10',true); entry(8,'0x10',true);
entry(7,'0x20'); entry(8,'0x20'); entry(7,'0x20');
drain();
const rows=output.flatMap(s=>s.split('\n')).map(JSON.parse);
const after=rows.filter(e=>e.phase==='after');
if(after.length!==2 || after[0].snapshot!==1 || after[1].snapshot!==2)
 throw Error('snapshot thread association');
if(status().accepted!==4 || status().stopReason!=='max-events') throw Error('trigger budget');
''', prelude=prelude)

    def test_results_window_rows_and_navigation(self):
        class Choose:
            NOTHING_CHANGED = 0
            def __init__(self, title, columns):
                self.title, self.columns = title, columns
            def Show(self, modal):
                pass
        from types import SimpleNamespace
        event = dict(schema=1, session='s', module='sample.so', type='enter', id=1,
                     tid=7, offset='0x10', name='first', args=[7])
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'trace.jsonl'
            path.write_text(json.dumps(event), encoding='utf-8')
            jump = []
            with patch.object(trace, 'idaapi', SimpleNamespace(Choose=Choose, jumpto=jump.append)), \
                 patch.object(trace, 'ida_nalt', SimpleNamespace(get_imagebase=lambda: 0x1000), create=True):
                ranking = trace.show_results(path)
                self.assertEqual(ranking.OnGetLine(0)[:3], ['1', 'first', '0x10'])
                ranking.OnSelectLine(0)
                self.assertEqual(jump, [0x1010])
                timeline = trace.show_results(path, tid=7, timeline=True)
                self.assertEqual(timeline.OnGetLine(0)[:3], ['7', 'enter', 'first'])


if __name__ == '__main__':
    unittest.main()
