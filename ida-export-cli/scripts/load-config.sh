#!/bin/sh

# Load the optional configuration beside ida-export-cli.sh without requiring jq.
IDA_EXPORT_CLI_SCRIPT_DIR=${IDA_EXPORT_CLI_SCRIPT_DIR:-$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)}
IDA_EXPORT_CLI_PROJECT_ROOT=$(dirname "$IDA_EXPORT_CLI_SCRIPT_DIR")
IDA_EXPORT_CLI_CONFIG=${IDA_EXPORT_CLI_CONFIG:-"$IDA_EXPORT_CLI_SCRIPT_DIR/ida-export-cli.config.json"}

_ida_export_cli_config_python=$(command -v python3 2>/dev/null || true)

_ida_export_cli_config_value() {
    key=$1
    [ -n "$_ida_export_cli_config_python" ] || return 0
    "$_ida_export_cli_config_python" - "$IDA_EXPORT_CLI_CONFIG" "$key" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        value = json.load(stream)
    for part in sys.argv[2].split("."):
        if not isinstance(value, dict):
            value = None
            break
        value = value.get(part)
    if isinstance(value, (str, int, float)) and str(value):
        print(value)
except (OSError, ValueError, TypeError, KeyError):
    pass
PY
}

if [ -f "$IDA_EXPORT_CLI_CONFIG" ] && [ -n "$_ida_export_cli_config_python" ]; then
    if [ -z "${IDA_PYTHON:-}" ]; then
        IDA_PYTHON=$(_ida_export_cli_config_value ida_python)
    fi
    if [ -z "${IDADIR:-}" ]; then
        IDADIR=$(_ida_export_cli_config_value ida_dir)
    fi
fi

: "${IDA_PYTHON:=}"
: "${IDADIR:=}"
export IDA_EXPORT_CLI_CONFIG
export IDA_PYTHON IDADIR
