"""
IDA Plugin: AI Function Analyzer
================================
Send the current function (decompiled pseudocode or disassembly) to an AI
for instant analysis. Supports Anthropic Claude, OpenAI, and DeepSeek.

INSTALLATION
------------
1. Make sure `requests` is installed for IDA's Python:
     <IDA_Python> -m pip install requests
2. Copy this file to IDA's plugins directory, or run via File -> Script File.

USAGE
-----
- Hotkey: Ctrl+Shift+A
- Menu:   Edit > AI Analyzer > Analyze Function
- Right-click in disassembly or pseudocode view > AI Analyzer > Analyze Function
- First run will prompt you to configure your API key.

COMPATIBILITY
-------------
IDA Pro 7.5+, IDA 8.x, IDA 9.x (with Hex-Rays decompiler recommended)

Author: Generated with Claude Code
"""

import idaapi
import ida_kernwin
import ida_hexrays
import ida_funcs
import ida_idaapi
import ida_nalt
import idautils
import idc

import json
import threading
import sys
import os
import re
import time

# ---------------------------------------------------------------------------
# Optional import -- missing if user hasn't pip-installed into IDA's Python
# ---------------------------------------------------------------------------
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ---------------------------------------------------------------------------
# Plugin metadata
# ---------------------------------------------------------------------------
PLUGIN_NAME    = "AI Function Analyzer"
PLUGIN_HOTKEY  = "Ctrl+Shift+A"
PLUGIN_VERSION = "1.1.0"
PLUGIN_AUTHOR  = "Claude Code"

# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------
DEFAULT_CONFIG = {
    "provider":           "anthropic",
    "api_key_anthropic":  "",
    "api_key_openai":     "",
    "api_key_deepseek":   "",
    "api_url_anthropic":  "https://api.anthropic.com/v1/messages",
    "api_url_openai":     "https://api.openai.com/v1/chat/completions",
    "api_url_deepseek":   "https://api.deepseek.com/anthropic/v1/messages",
    "model_anthropic":    "claude-sonnet-4-6",
    "model_openai":       "gpt-4o",
    "model_deepseek":     "deepseek-v4-flash",
    "max_tokens":         16384,
    "language":           "Chinese",
}

# Per-provider presets: (default_url, default_model, model_list)
_PROVIDER_PRESETS = {
    "anthropic": (
        "https://api.anthropic.com/v1/messages",
        "claude-sonnet-4-6",
        ["claude-sonnet-4-6", "claude-opus-4-8", "claude-haiku-4-5"],
    ),
    "openai": (
        "https://api.openai.com/v1/chat/completions",
        "gpt-4o",
        ["gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"],
    ),
    "deepseek": (
        "https://api.deepseek.com/anthropic/v1/messages",
        "deepseek-v4-flash",
        ["deepseek-v4-flash", "deepseek-v4-pro"],
    ),
}

_PROVIDER_LABELS = ["Anthropic (Claude)", "OpenAI", "DeepSeek"]
_PROVIDER_KEYS   = ["anthropic", "openai", "deepseek"]

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = (
    "你是一位顶尖的逆向工程专家，正在分析一段反编译/反汇编的代码。\n"
    "请对以下函数进行详细分析，使用 Markdown 格式组织内容，包括：\n\n"
    "## 1. 函数功能\n这个函数在高层面上做什么？它的整体目的是什么？\n\n"
    "## 2. 参数分析\n推测参数的类型、名称和含义\n\n"
    "## 3. 返回值\n函数返回什么？返回值的含义是什么？\n\n"
    "## 4. 算法逻辑\n逐步解释核心算法和关键逻辑流程\n\n"
    "## 5. 关键发现\n值得注意的模式、潜在漏洞、反分析技巧、硬编码常量等\n\n"
    "## 6. 伪代码\n如果需要，给出更清晰易读的等效伪代码\n\n"
    "注意：不要使用表格。使用列表、代码块和分段组织信息。\n"
    "请用中文回答，技术术语可保留英文。"
)


# ===================================================================
#  Config persistence (global file, works across all IDBs)
# ===================================================================

def _config_path():
    """Global config file next to the plugin."""
    plugin_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(plugin_dir, "ai_analyze_config.json")


def load_config():
    """Load config from global JSON file."""
    cfg = DEFAULT_CONFIG.copy()
    path = _config_path()
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                saved = json.load(f)
                cfg.update(saved)
    except Exception:
        pass

    # Migrate old DeepSeek-in-Anthropic-slot config
    try:
        if "deepseek" in cfg.get("api_url_anthropic", "").lower():
            cfg["provider"] = "deepseek"
            if not cfg.get("api_key_deepseek"):
                cfg["api_key_deepseek"] = cfg.get("api_key_anthropic", "")
            cfg["api_url_deepseek"] = DEFAULT_CONFIG["api_url_deepseek"]
            if "claude" in str(cfg.get("model_anthropic", "")).lower():
                cfg["model_deepseek"] = DEFAULT_CONFIG["model_deepseek"]
    except Exception:
        pass

    return cfg


def save_config(cfg):
    """Persist config to global JSON file."""
    try:
        with open(_config_path(), "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[AI Analyzer] WARNING: Could not save config: {e}")


# ===================================================================
#  Code extraction
# ===================================================================

def get_func_name_and_ea(ea):
    func = ida_funcs.get_func(ea)
    if not func:
        return None, None
    return idc.get_func_name(func.start_ea), func.start_ea


def get_disassembly_text(func_ea):
    """Return cleaned disassembly (code only, data definitions stripped)."""
    func = ida_funcs.get_func(func_ea)
    if not func:
        return ""

    lines = [
        f"; Disassembly of {idc.get_func_name(func_ea)}",
        f"; 0x{func_ea:X} - 0x{func.end_ea:X}  ({func.end_ea - func_ea} bytes)",
        "",
    ]
    data_count = 0
    ea = func.start_ea
    while ea < func.end_ea:
        flags = idc.get_full_flags(ea)
        if idc.is_code(flags):
            disasm = idc.GetDisasm(ea)
            cmt = idc.get_cmt(ea, 0) or ""
            line = f"0x{ea:08X}: {disasm}"
            if cmt:
                line += f"  ; {cmt}"
            lines.append(line)
        else:
            data_count += 1
        ea = idc.next_head(ea, func.end_ea)

    if data_count:
        lines.insert(2, f"; [{data_count} data item(s) omitted]")
        lines.insert(3, "")

    return "\n".join(lines)


def get_decompiled_text(func_ea):
    try:
        dec = ida_hexrays.decompile(func_ea)
        if dec:
            return str(dec)
    except Exception:
        pass
    return get_disassembly_text(func_ea)


def get_current_function_info():
    """
    Returns (func_name, func_ea, code_text, in_pseudocode)
    or (None, None, None, False).
    """
    widget = ida_kernwin.get_current_widget()
    if not widget:
        ea = ida_kernwin.get_screen_ea()
        if ea != idc.BADADDR:
            name, fea = get_func_name_and_ea(ea)
            if name:
                return name, fea, get_decompiled_text(fea), False
        return None, None, None, False

    wtype = ida_kernwin.get_widget_type(widget)

    if wtype == ida_kernwin.BWN_PSEUDOCODE:
        try:
            vu = ida_hexrays.get_widget_vdui(widget)
            if vu and vu.cfunc:
                fea = vu.cfunc.entry_ea
                name = idc.get_func_name(fea) or f"sub_{fea:X}"
                return name, fea, str(vu.cfunc), True
        except Exception:
            pass

    if wtype == ida_kernwin.BWN_DISASM:
        ea = ida_kernwin.get_screen_ea()
        name, fea = get_func_name_and_ea(ea)
        if name:
            return name, fea, get_decompiled_text(fea), False

    ea = ida_kernwin.get_screen_ea()
    if ea != idc.BADADDR:
        name, fea = get_func_name_and_ea(ea)
        if name:
            return name, fea, get_decompiled_text(fea), False

    return None, None, None, False


# ===================================================================
#  Config helpers
# ===================================================================

def _provider_key(cfg):
    return cfg.get("provider", "anthropic")

def _get_active_api_key(cfg):
    k = _provider_key(cfg)
    return cfg.get(f"api_key_{k}", "")

def _get_active_api_url(cfg):
    k = _provider_key(cfg)
    return cfg.get(f"api_url_{k}", DEFAULT_CONFIG.get(f"api_url_{k}", ""))

def _get_active_model(cfg):
    k = _provider_key(cfg)
    return cfg.get(f"model_{k}", DEFAULT_CONFIG.get(f"model_{k}", ""))


# ===================================================================
#  API callers
# ===================================================================

def _decode_error_response(resp):
    """Try to extract a human-readable error message from the response body."""
    try:
        body = resp.json()
        # Anthropic-style
        if isinstance(body.get("error"), dict):
            return body["error"].get("message", resp.text)
        # OpenAI-style
        if isinstance(body.get("error"), str):
            return body["error"]
        return resp.text[:500]
    except Exception:
        return resp.text[:500]


def _human_error(status_code, reason, body_text):
    """Produce a user-friendly error message for common HTTP errors."""
    hints = {
        401: "API Key 无效或已过期，请检查设置。",
        403: "API Key 无权限访问此模型，请检查账户余额和模型权限。",
        404: "端点或模型不存在。\n请确认：(1) Provider 选择正确 (2) URL 中无多余路径 (3) 模型名正确。",
        429: "请求过于频繁，请稍后再试。",
        500: "服务器内部错误，请稍后重试。",
        502: "网关错误，服务器可能正在维护。",
        503: "服务暂时不可用，请稍后再试。",
    }
    hint = hints.get(status_code, "")
    msg = f"HTTP {status_code} {reason}"
    if hint:
        msg += f"\n\n{hint}"
    if body_text:
        msg += f"\n\n详细信息: {body_text}"
    return msg


def call_anthropic_api(cfg, user_msg):
    """Call Anthropic Messages API (Anthropic, DeepSeek)."""
    url  = _get_active_api_url(cfg)
    key  = _get_active_api_key(cfg)
    model = _get_active_model(cfg)

    headers = {
        "x-api-key":         key,
        "anthropic-version": "2023-06-01",
        "content-type":      "application/json",
    }
    body = {
        "model":      model,
        "max_tokens": cfg.get("max_tokens", 16384),
        "system":     SYSTEM_PROMPT,
        "thinking":   {"type": "disabled"},   # skip reasoning for speed
        "messages":   [{"role": "user", "content": user_msg}],
    }

    resp = requests.post(url, headers=headers, json=body, timeout=180)
    if not resp.ok:
        detail = _decode_error_response(resp)
        raise Exception(_human_error(resp.status_code, resp.reason, detail))

    data = resp.json()
    # Warn if output was truncated by token limit
    stop = data.get("stop_reason", "")
    if stop == "max_tokens":
        print("[AI Analyzer] WARNING: response truncated by token limit! "
              "Consider increasing max_tokens or simplifying input.")
    blocks = data.get("content", [])
    text_parts = [b.get("text", "") for b in blocks if b.get("type") == "text"]
    if text_parts:
        return "\n".join(text_parts)
    # DeepSeek sometimes wraps text in a 'content' string (non-list)
    if isinstance(data.get("content"), str):
        return data["content"]
    if "choices" in data:
        return data["choices"][0]["message"]["content"]
    # Last resort: try to pull any useful string from the response
    if isinstance(data, dict):
        for key in ("message", "output", "response", "text"):
            if isinstance(data.get(key), str) and data[key]:
                return data[key]
    return None


def call_openai_api(cfg, user_msg):
    """Call OpenAI-compatible Chat Completions API."""
    url   = _get_active_api_url(cfg)
    key   = _get_active_api_key(cfg)
    model = _get_active_model(cfg)

    headers = {
        "Authorization": f"Bearer {key}",
        "content-type":  "application/json",
    }
    body = {
        "model":       model,
        "max_tokens":  cfg.get("max_tokens", 4096),
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_msg},
        ],
    }

    resp = requests.post(url, headers=headers, json=body, timeout=180)
    if not resp.ok:
        detail = _decode_error_response(resp)
        raise Exception(_human_error(resp.status_code, resp.reason, detail))

    data = resp.json()
    return data["choices"][0]["message"]["content"]


# ===================================================================
#  Markdown colorizer
# ===================================================================

_SCOLOR_ON  = "\x01"
_SCOLOR_OFF = "\x02"
_CLR_KEYWORD = "\x01"   # blue — ## headings
_CLR_REG     = "\x02"   # light blue — ### subheadings
_CLR_BODY    = "\x05"   # user-chosen body text color

def _colorize_line(line):
    """Apply heading colors; all body text gets bright white."""
    stripped = line.lstrip()
    if stripped.startswith("## ") or stripped.startswith("# "):
        return _SCOLOR_ON + _CLR_KEYWORD + line + _SCOLOR_OFF + _CLR_KEYWORD
    if stripped.startswith("### "):
        return _SCOLOR_ON + _CLR_REG + line + _SCOLOR_OFF + _CLR_REG
    # Body text: explicit bright white
    return _SCOLOR_ON + _CLR_BODY + line + _SCOLOR_OFF + _CLR_BODY


# ===================================================================
#  Result viewer
# ===================================================================

class AnalysisViewer(ida_kernwin.simplecustviewer_t):
    """Scrollable result viewer with markdown colorizing."""

    def __init__(self, title, text, func_ea, cfg):
        ida_kernwin.simplecustviewer_t.__init__(self)
        self._title   = title
        self._text    = text
        self._func_ea = func_ea
        self._cfg     = cfg

    def Create(self, title=""):
        if not ida_kernwin.simplecustviewer_t.Create(self, title or self._title):
            return False
        for line in self._text.split("\n"):
            self.AddLine("\t" + _colorize_line(line))
        self.Jump(0, 0)
        return True

    def OnKeydown(self, vkey, shift):
        if vkey == 27:   # ESC
            self.Close()
            return True
        if vkey == ord("C") and (shift & ida_kernwin.CTRL_KEY):
            self._copy_full_text()
            return True
        return False

    def OnDblClick(self, shift):
        line = self.GetCurrentLine()
        if not line:
            return False
        for m in re.finditer(r"\b(0x[0-9A-Fa-f]{4,16})\b", line):
            addr = int(m.group(1), 16)
            if idc.is_mapped(addr):
                ida_kernwin.jumpto(addr)
                return True
        return False

    def _copy_full_text(self):
        try:
            import ctypes
            encoded = self._text.encode("utf-16-le") + b"\x00\x00"
            ctypes.windll.user32.OpenClipboard(0)
            ctypes.windll.user32.EmptyClipboard()
            h = ctypes.windll.kernel32.GlobalAlloc(0x0042, len(encoded))
            ctypes.windll.kernel32.GlobalLock.restype = ctypes.c_void_p
            ptr = ctypes.windll.kernel32.GlobalLock(h)
            ctypes.memmove(ptr, encoded, len(encoded))
            ctypes.windll.kernel32.GlobalUnlock(h)
            ctypes.windll.user32.SetClipboardData(13, h)
            ctypes.windll.user32.CloseClipboard()
            print("[AI Analyzer] Copied to clipboard!")
        except Exception:
            print("\n" + "=" * 60)
            print(self._text)
            print("=" * 60)


# ===================================================================
#  Config dialog
# ===================================================================

class ConfigForm(ida_kernwin.Form):
    def __init__(self, cfg_in):
        self.cfg = cfg_in.copy()
        provider = self.cfg.get("provider", "anthropic")

        try:
            prov_idx = _PROVIDER_KEYS.index(provider)
        except ValueError:
            prov_idx = 0

        _, _, model_list = _PROVIDER_PRESETS[provider]
        cur_url   = self.cfg.get(f"api_url_{provider}", "")
        cur_key   = self.cfg.get(f"api_key_{provider}", "")
        cur_model = self.cfg.get(f"model_{provider}", "")
        if cur_model not in model_list:
            cur_model = model_list[0]

        F = ida_kernwin.Form
        ida_kernwin.Form.__init__(
            self,
            r"""STARTITEM 0
AI Analyzer - Settings

<Provider:{cProvider}>
<API Key:{strApiKey}>
<API URL:{strApiUrl}>
<Model:{cModel}>
""",
            {
                "cProvider": F.DropdownListControl(
                    items=_PROVIDER_LABELS, readonly=True, selval=prov_idx),
                "strApiKey": F.StringInput(value=cur_key, swidth=80),
                "strApiUrl": F.StringInput(value=cur_url, swidth=80),
                "cModel":    F.DropdownListControl(
                    items=model_list, readonly=False, selval=cur_model),
            })


def show_config_dialog():
    cfg = load_config()
    form = ConfigForm(cfg)
    form, _ = form.Compile()

    ok = form.Execute()
    if ok != 1:
        form.Free()
        return

    prov_idx = form.cProvider.value
    if 0 <= prov_idx < len(_PROVIDER_KEYS):
        new_provider = _PROVIDER_KEYS[prov_idx]
    else:
        new_provider = "anthropic"

    new_api_key = form.strApiKey.value.strip() if form.strApiKey.value else ""
    new_api_url = form.strApiUrl.value.strip() if form.strApiUrl.value else ""
    new_model   = form.cModel.value.strip() if form.cModel.value else ""

    form.Free()

    cfg["provider"] = new_provider
    if new_api_key:
        cfg[f"api_key_{new_provider}"] = new_api_key
    if new_api_url:
        cfg[f"api_url_{new_provider}"] = new_api_url
    if new_model:
        cfg[f"model_{new_provider}"] = new_model

    save_config(cfg)
    ida_kernwin.info(
        "AI Analyzer — 配置已保存\n\n"
        f"Provider : {new_provider}\n"
        f"Model    : {new_model or _get_active_model(cfg)}\n"
        f"URL      : {new_api_url or _get_active_api_url(cfg)}"
    )


# ===================================================================
#  Main analysis
# ===================================================================

def analyze_current_function():
    # -- deps --
    if not HAS_REQUESTS:
        Y = ida_kernwin.ASKBTN_YES
        btn = ida_kernwin.ask_buttons(
            "Install now", "I'll do it manually", "Cancel", Y,
            "Python 'requests' library is not installed.\n\n"
            "Click 'Install now' to install it automatically,\n"
            "or run:  pip install requests"
        )
        if btn == Y:
            _install_requests()
        return

    # -- function --
    func_name, func_ea, code, in_pseudocode = get_current_function_info()
    if not code:
        ida_kernwin.warning(
            "No function found at the current position.\n\n"
            "Please place the cursor inside a function in:\n"
            "  - The decompiler (pseudocode) window, or\n"
            "  - The disassembly window"
        )
        return

    cfg = load_config()

    # -- api key --
    if not _get_active_api_key(cfg):
        Y = ida_kernwin.ASKBTN_YES
        btn = ida_kernwin.ask_buttons(
            "Configure now", "Cancel", "Cancel", Y,
            "AI API key not set!\n\nClick 'Configure now' to set up your API key."
        )
        if btn == Y:
            show_config_dialog()
            cfg = load_config()
            if not _get_active_api_key(cfg):
                return
        else:
            return

    model   = _get_active_model(cfg)
    source  = "Pseudocode" if in_pseudocode else "Disassembly"

    # -- log --
    print(f"\n{'='*60}")
    print(f"  AI Analyzer  |  {func_name}  @  0x{func_ea:X}")
    print(f"  Provider: {cfg['provider']}  |  Model: {model}")
    print(f"  Source: {source}  |  Code: {len(code)} chars")
    print(f"{'='*60}")

    # -- call AI (threaded) --
    ida_kernwin.show_wait_box(f"AI is analyzing {func_name}...")
    t0 = time.time()

    result = [None]
    error  = [None]
    final_text = [""]

    def _run():
        try:
            user_msg = f"Function: {func_name} (0x{func_ea:X})\n\n```c\n{code}\n```"
            if cfg["provider"] == "openai":
                result[0] = call_openai_api(cfg, user_msg)
            else:
                result[0] = call_anthropic_api(cfg, user_msg)
        except Exception as e:
            error[0] = str(e)

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    while t.is_alive():
        t.join(timeout=0.5)
        elapsed = time.time() - t0
        try:
            ida_kernwin.replace_wait_box(
                f"AI is analyzing {func_name}...  [{elapsed:.0f}s]"
            )
        except Exception:
            pass

    elapsed = time.time() - t0
    ida_kernwin.hide_wait_box()

    # -- result --
    if error[0]:
        print(f"[AI Analyzer] ERROR: {error[0]}")
        ida_kernwin.warning(f"AI API call failed:\n\n{error[0]}")
        return

    text = result[0]
    if not text:
        ida_kernwin.warning("AI returned an empty response.")
        return

    print(f"[AI Analyzer] Done in {elapsed:.1f}s  ({len(text)} chars)")

    # -- output --
    title = f"AI: {func_name}"

    viewer = AnalysisViewer(title, text, func_ea, cfg)
    try:
        if viewer.Create():
            viewer.Show()
            return
    except Exception:
        pass

    # Fallback
    print(f"\n{'='*60}")
    print(f"  AI ANALYSIS: {func_name}  @  0x{func_ea:X}")
    print(f"{'='*60}")
    print(text)
    print(f"{'='*60}")


def _install_requests():
    import subprocess
    ida_kernwin.show_wait_box("Installing requests...")
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "requests"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        ida_kernwin.hide_wait_box()
        ida_kernwin.info(
            "requests installed!\n\nPlease re-run the plugin (Ctrl+Shift+A)."
        )
    except Exception as e:
        ida_kernwin.hide_wait_box()
        ida_kernwin.warning(
            f"Auto-install failed:\n\n{e}\n\n"
            f"Please install manually:\n"
            f"  {sys.executable} -m pip install requests"
        )


# ===================================================================
#  Action handlers
# ===================================================================

class _AnalyzeHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        analyze_current_function()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class _ConfigHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        show_config_dialog()
        return 1
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# ===================================================================
#  Plugin
# ===================================================================

class AIFunctionAnalyzer(idaapi.plugin_t):
    flags         = idaapi.PLUGIN_KEEP
    comment       = "Send current function to AI for reverse engineering analysis"
    help          = "Ctrl+Shift+A in any function"
    wanted_name   = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        print(f"[AI Analyzer] v{PLUGIN_VERSION} — Ctrl+Shift+A to analyze")

        for name, label, shortcut, handler in [
            ("ai_analyze:function", "Analyze Function", PLUGIN_HOTKEY, _AnalyzeHandler()),
            ("ai_analyze:config",   "Settings...",      "",            _ConfigHandler()),
        ]:
            idaapi.register_action(
                idaapi.action_desc_t(name, label, handler, shortcut, None, 0))

        idaapi.attach_action_to_menu("Edit/AI Analyzer/", "ai_analyze:function", idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu("Edit/AI Analyzer/", "ai_analyze:config",   idaapi.SETMENU_APP)

        for popup in ("Disassembly/", "Pseudocode/"):
            try:
                idaapi.attach_action_to_menu(popup, "ai_analyze:function", idaapi.SETMENU_INS)
                idaapi.attach_action_to_menu(popup, "ai_analyze:config",   idaapi.SETMENU_INS)
            except Exception:
                pass

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        analyze_current_function()

    def term(self):
        for menu in ("Edit/AI Analyzer/", "Disassembly/", "Pseudocode/"):
            for a in ("ai_analyze:function", "ai_analyze:config"):
                try:
                    idaapi.detach_action_from_menu(menu, a)
                except Exception:
                    pass
        for a in ("ai_analyze:function", "ai_analyze:config"):
            try:
                idaapi.unregister_action(a)
            except Exception:
                pass
        print("[AI Analyzer] Unloaded.")


def PLUGIN_ENTRY():
    return AIFunctionAnalyzer()

if __name__ == "__main__":
    analyze_current_function()
