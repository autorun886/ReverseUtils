#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(dirname "$SCRIPT_DIR")
IDA_EXPORT_CLI_SCRIPT_DIR=$SCRIPT_DIR
. "$SCRIPT_DIR/load-config.sh"

if [ -z "${IDA_PYTHON:-}" ]; then
    for candidate in \
        "$(command -v python3 2>/dev/null || true)" \
        "$(command -v python 2>/dev/null || true)"
    do
        if [ -n "$candidate" ] && [ -x "$candidate" ] \
            && "$candidate" -c 'import ida_domain' >/dev/null 2>&1
        then
            IDA_PYTHON=$candidate
            break
        fi
    done
fi

if [ -z "${IDA_PYTHON:-}" ] || [ ! -x "$IDA_PYTHON" ]; then
    echo "ida-export-cli: IDAPython interpreter not found: ${IDA_PYTHON:-<unset>}" >&2
    echo "ida-export-cli: set IDA_PYTHON=/path/to/python" >&2
    exit 1
fi

if ! "$IDA_PYTHON" -c 'import ida_domain' >/dev/null 2>&1; then
    echo "ida-export-cli: ida-domain is not available in $IDA_PYTHON" >&2
    exit 1
fi

export PYTHONPATH="$PROJECT_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
exec "$IDA_PYTHON" -m cli "$@"
