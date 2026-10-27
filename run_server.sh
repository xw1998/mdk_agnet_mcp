#!/usr/bin/env bash
# =============================================================================
#  mdkdebug MCP Server 启动脚本（Linux / macOS / Git Bash）
#
#  宿主会把**它自己的** PYTHONPATH / PYTHONHOME 传给子进程；这两个变量指向另一套
#  Python 时，解释器在 site 初始化阶段就崩（"SRE module mismatch"），轮不到进程内
#  自愈。所以清理必须发生在 python **之前**。
#
#  用法：把 MCP 客户端的 command 指向本脚本（参数原样透传）。
#       "command": "/path/to/run_server.sh"
#  可选用 MDKDEBUG_PYTHON 指定解释器（默认 python）。
# =============================================================================
set -eu

unset PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONEXECUTABLE PYTHONUSERBASE \
      PYTHONNOUSERSITE PYTHONPLATLIBDIR 2>/dev/null || true
# 保留 PYTHONIOENCODING / PYTHONUTF8：不影响 import，中文输出还需要它们

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${MDKDEBUG_PYTHON:-python}"
if [ -x "$HERE/.venv/bin/python" ] && [ -z "${MDKDEBUG_PYTHON:-}" ]; then
  PY="$HERE/.venv/bin/python"
fi

# -E -s：即使有变量漏网也不会被读；-u：stdio 不缓冲
exec "$PY" -E -s -u "$HERE/run_server.py" "$@"
