# IDA Tracecraft

You only need to give your AI one line:

```sh
python /path/to/entry_trace.py -h
```

Have the AI read the help, choose a mode for your observation goal, select the IDA instance, and generate a Frida script.

[中文文档](README.md)

## Quick start

1. Copy `entry_trace.py` into IDA's `plugins` directory, restart IDA, and open the target database.
2. Give the AI the command above with the actual script path, then describe the function or behavior to observe.
3. Load the file at the returned `script_path` into Frida, for example:

```sh
frida -U -f com.example.app -l trace.js
```

## Modes

| Mode | Purpose |
| --- | --- |
| `full` | Explore module execution flow through known function entries on tracked threads |
| `window` | Record the next N entries after a specified function is reached |
| `history` | Inspect entries before and after reaching a specified function |
| `hooks` | Inspect arguments and returns for names containing a substring |
| `selected` | Inspect arguments and returns of explicitly selected functions |
| `regex` | Select and hook functions by a name regex |
| `callers` | Follow incoming code references; hook seeds and referring functions |
| `callees` | Follow outgoing direct calls; hook seeds and called functions |

The first three use Stalker; the others use Interceptor. Hook modes support typed arguments and conditions. Windows default to 100 entries before/after, independently configurable. Counts represent entry events.

## Common commands

```sh
# List instances, then select the intended input file or port
python entry_trace.py instances
python entry_trace.py --input "D:/samples/libsample.so" --mode full -o trace.js

# Inspect 50 entries before and 100 after a function
python entry_trace.py --mode history --root FUNC --before 50 --after 100

# Log arguments and returns only when a condition matches
python entry_trace.py --mode selected --select FUNC --arg-types int,cstring --where 0:int:eq:7

# Export analysis context and generate offline later
python entry_trace.py context --mode selected --select FUNC --ai-level guided --context-out context.json --prompt-out task.txt
python entry_trace.py --snapshot context.json --mode selected -o hooks.js
```

## Multiple instances

Each database registers automatically and receives an OS-assigned local port. Its short ID stays stable for that live database session; switching or reopening databases creates a new ID.

```sh
python entry_trace.py instances
python entry_trace.py --input libsec2026.so --mode full -o sec.js
python entry_trace.py --instance k7m2 --mode full -o trace.js
```

Replace `k7m2` with the returned ID. `--input` exactly matches a filename or full path, case-insensitively. Duplicate filenames require a full path or short ID. Legacy `--instance PID` selection still works. `--port` accepts the dynamic CLI port shown by `instances`, not the MCP port.

Listings contain only `id`, `endpoint`, and `input_path`. Every snapshot validates database identity before and after collection. Expired IDs, ambiguous matches, and unavailable targets fail explicitly rather than routing to another database. Different instances can handle commands concurrently; busy instances do not hold a global routing lock.

Registry records are published atomically and maintained by heartbeats. Closing removes the active record; confirmed dead-process records are pruned. Following the [ida-multi-mcp architecture](https://github.com/MeroZemory/ida-multi-mcp/blob/main/docs/architecture.md), independent records avoid lost concurrent updates, and there is no shared current-instance selection.

Reload the plugin in already-open IDAs after upgrading, then run `instances` again.

## Notes

- Select functions by exact name, IDA virtual address, or `+0xMODULE_OFFSET`. Database and runtime layouts must agree; `--module` overrides the runtime filename.
- Instance listings contain only `id`, `endpoint`, and `input_path`. Use a full path or `--instance ID` for duplicate filenames; use the listed dynamic CLI endpoint when selecting by `--port`.
- Output avoids existing filenames. Use the returned absolute `script_path` for subsequent operations.
- History starts when thread tracking begins; tracing does not guarantee every entry on every thread. ARM64 tracing requires Frida 17.10+. Android ART tracing enables Java interpreter mode by default, adding overhead.
- The tool exports AI context; model calls happen externally. Offline snapshots fix the target set; recollect to change selection.

See `-h` for all options, mode semantics, and the AI workflow. See [conditional_hooks.js](examples/conditional_hooks.js) for an editable conditional Hook example.

## Tests

```sh
python -m unittest -v test_entry_trace.py
python tests/entry_trace/test_instances.py -v
```

Tests need no IDA/Frida. Install Node.js to run generated-script event simulations.
