"""加解密逆向 Agent 运行器 — QThread + agent-core ReAct."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Callable, Optional

from PyQt6.QtCore import QThread, pyqtSignal

from core.ai_config import load_ai_config, resolve_agent_base_url
from core.agent_tools import SessionData, build_crypto_tools
from core.paths import get_app_root

from agent_core import Agent, LLMClient
from agent_core.tools.base import BaseTool

logger = logging.getLogger(__name__)

CRYPTO_SYSTEM_PROMPT = """你是 JavaScript 逆向与 HTTP 加解密分析专家（密桥 Agent）。

工作方式:
1. 必须先用工具只读查询：flow（流量）、hook（Hook 日志）、script（JS/HTML）。
2. flow.list/get 中 seq 是捕获顺序（与界面 #序号一致，#1 最早）；index 是当前送入列表的下标，get 请用 index。
3. Hook 非空时：优先 hook.search（Key/IV/AES/CryptoJS/RSA/JSEncrypt），采信算法与模式；
   再用 flow 确认字段名。但必须先区分「固定密钥」与「随机会话密钥」（见下方模式分类）。
4. JS 全文只在本地索引；对话里禁止通读。硬顺序：script.list → script.enrich（或 outline/ast）→ 必要时 script.search → 定点 script.read。
5. enrich/search 返回短证据即可下结论；script.read 仅用于确认关键几行，禁止为「看完全文」连续翻页。
6. script.search 会返回 match_offset 与 approx_line；用该 offset 最多 read 一次同一处。
7. 禁止对同一 url+offset 重复 read；证据足够应立即给出结论（含 crypto_pattern）。
8. 小程序/页面里 crypto-js、NIM、libs 是库文件，不要翻页。
9. 不要编造密钥；不确定时 confidence=low。
10. 禁止声称已改写流量或已写入工程。
11. 调查够用就收工；最终回复必须含可解析的 JSON（含 steps 数组）。
12. JSON 另含 code_locations（源码位置，仅供人工跳转找代码），与 steps 无关，禁止把位置写进 steps.params。

加密模式分类（通用，先判定再写 steps）:
- fixed_symmetric：对称密钥/IV 在 JS 或配置里写死（同一 Key 可解多条流量）。
- hybrid_session_key：先随机对称 Key(/IV) 加密业务数据，再用非对称(RSA/SM2 等)加密该会话 Key(/IV)；
  流量常同时有「数据密文」+「密钥密文」(+「IV 密文」) 多个字段；Hook 常同时打出 AES 与 RSA/公钥。
- asymmetric_only：整段业务数据直接 RSA/SM2 等加密。
- sign_only：主要是 Hash/HMAC/排序签名，无对称解密需求。

hybrid_session_key 硬规则（禁止简化成单字段固定 AES）:
- 识别线索（满足多项即倾向 hybrid）：同请求多字段（数据密文+key/iv/secret 类密文）；
  JS 有 random/WordArray.random/getRandomValues 后再 AES，再 encrypt(key)；
  Hook 同一次既有对称 Key 又有 PUBLIC KEY / JSEncrypt / RSA。
- 加密端：**禁止**把 Hook 捕获的「这一次」AES Key/IV 写死进 🔒 加密字段的 key/iv；
  公钥 PEM（固定）才可 🔑 定义密钥或写入 RSA 步骤的 key；
  会话 Key/IV 用 🎲 生成随机数（或等价）每请求新生，再 🔒 AES 业务字段，再 🔒 RSA/非对称 包会话材料到密钥字段。
- 解密端：无私钥时不要假装可用固定 AES Key 长期解密；可说明仅能用当次 Hook Key 离线验证该条采样，
  confidence=low，steps 要么留空对称长期方案、要么按「先非对称解 Key/IV → 再对称解数据」写骨架并标注需私钥。
- summary 必须点明模式；JSON 建议带 "crypto_pattern":"hybrid_session_key" 等。
"""

_STEPS_JSON_EXAMPLE = (
    '{"summary":"AES-CBC PKCS7 解密 body 字段 data（固定密钥）","confidence":"high",'
    '"crypto_pattern":"fixed_symmetric",'
    '"code_locations":[{"url":"https://example.com/app.js","approx_line":1284,'
    '"offset":45678,"what":"CryptoJS.AES.encrypt","snippet":"CryptoJS.AES.encrypt(pwd, key,{mode:CryptoJS.mode.CBC..."}],'
    '"steps":[{"type":"🔓 解密字段","params":{"field":"data","algo":"AES","mode":"CBC",'
    '"key":"从Hook填写","iv":"从Hook填写","padding":"PKCS7","scope":"📋 Body (Form)"}}]}'
)

_HYBRID_ENCRYPT_JSON_HINT = (
    " hybrid_session_key 加密端原则（通用，字段名按本站替换）："
    "①🔑 定义密钥 存公钥 PEM（Hook/JS 里的 PUBLIC KEY，固定可用）；"
    "②每请求新生对称 Key/IV（🎲 生成随机数或等价），禁止填 Hook 采样到的那一次；"
    "③🔒 AES/SM4 等加密业务明文 → 数据密文字段；"
    "④🔒 RSA/SM2 等把会话 Key、IV（编码跟 JS 一致，常见 Base64/Utf8 字符串）"
    "分别写入密钥密文、IV 密文字段；"
    "⑤summary 写清字段对应关系；crypto_pattern 必须为 hybrid_session_key。"
)

RECOGNIZE_GOAL = (
    "请用 flow / hook / script 工具查阅当前素材，识别加解密算法、模式、padding、"
    "密钥/IV、密文字段与编码，并判定 crypto_pattern（fixed_symmetric|hybrid_session_key|"
    "asymmetric_only|sign_only）。先简短中文结论，**末尾必须附带唯一 JSON**："
    + _STEPS_JSON_EXAMPLE
    + " 策略：先 hook 与 flow；再 script.enrich（或 outline）看 cryptoHints/apiCalls；"
    "必要时 script.search 后按 match_offset 最多读一次。"
    "禁止通读全文 / 禁止连续翻页 read。"
    "固定密钥：Hook Key 可写入 params.key；混合/动态会话密钥：禁止把单次 Hook Key 固化为加密端长期 key。"
    "type 必须是「🔓 解密字段」等带 emoji 的完整步骤名。"
    "有 JS 命中时必须填 code_locations（url + approx_line + what），与 steps 分开，不参与生成 plugin。"
)

GENERATE_DECRYPT_GOAL = (
    "目标：生成「解密端」代理步骤。"
    "请先用 flow/hook/script 调查（JS 优先 script.enrich），最终只输出一个 JSON（可先一句摘要），格式示例："
    + _STEPS_JSON_EXAMPLE
    + " 请求解密用 🔓 解密字段；响应密文用 🔓 解密响应字段。"
    "先判 crypto_pattern。固定对称：Hook Key 写入 steps。"
    "hybrid_session_key：应「先解密钥字段(RSA/SM2 等)→再解数据字段(AES/…)」；"
    "无私钥则 confidence=low，勿用当次 Hook AES Key 冒充长期解密方案。"
    "禁止 key/mode/padding/algo 为 unknown。"
    "Form 登录体 scope 用 📋 Body (Form)；JSON 体用 📋 Body (JSON)。"
    "另填 code_locations（源码 url/行号），仅供找代码，勿写入 steps。"
)

GENERATE_ENCRYPT_GOAL = (
    "目标：生成「加密端」代理步骤。"
    "请先用 flow/hook/script 调查（JS 优先 script.enrich），最终只输出一个 JSON，格式示例："
    '{"summary":"...","confidence":"high","crypto_pattern":"fixed_symmetric",'
    '"code_locations":[{"url":"...","approx_line":100,"offset":0,"what":"加密调用","snippet":"..."}],'
    '"steps":[{"type":"🔒 加密字段","params":'
    '{"field":"data","algo":"AES","mode":"CBC","key":"...","iv":"...","padding":"PKCS7",'
    '"scope":"📋 Body (Form)"}}]}。'
    "请求加密用 🔒 加密字段；可含签名 Header。"
    "先判 crypto_pattern。fixed_symmetric：可用稳定 Key。"
    "hybrid_session_key：公钥可固定；AES Key/IV 必须每请求随机，"
    "禁止把 Hook 采样到的一次性 Key/IV 写进加密端 steps；"
    "步骤应覆盖：生成会话材料 → AES 业务字段 → 非对称封装 Key/IV 到对应字段。"
    + _HYBRID_ENCRYPT_JSON_HINT
    + " 禁止 key/mode/padding/algo 为 unknown。"
    "code_locations 仅供人工定位源码，与 steps/plugin 无关。"
)

_ANTI_DEBUG_JSON_EXAMPLE = (
    '{"summary":"字面量 debugger + 递归（sojson）",'
    '"confidence":"high",'
    '"patterns":["literal-debugger+recursion","empty-while"],'
    '"script_urls":["https://example.com/encrypt.html"],'
    '"inject_opts":{"functionHook":true,"evalHook":true,"timerHook":true,'
    '"timerNuke":false,"consoleClear":true,"sizeSpoof":true,'
    '"rewriteResponse":true,"anti_debug":true,"cdp_skip_pauses":true},'
    '"hook_js":"(function(){try{console.log(\\"[密桥] 站点补丁已加载\\");}catch(e){}})();",'
    '"advice":"勾选响应改写+CDP，已附 hook_js 站点补丁；重启浏览器后再分析加解密"}'
)

ANTI_DEBUG_GOAL = (
    "目标：分析当前采集的 JS / Hook 中「无限 debugger / 反调试」实现方式，"
    "给出「注入」勾选，并尽量写一段可注入的站点补丁 hook_js。"
    "不要分析加解密算法，不要输出 steps。"
    "请先 script.list → script.enrich（业务 HTML/JS），再 script.search: debugger、\\u0064、\\x64、"
    "constructor、setInterval、setTimeout、eval、Devtools、outerWidth、console.clear；"
    "混淆站还要搜 fromCharCode、\"de\"+\"bugger\"。"
    "命中后按 match_offset 用 script.read 读相关片段（每个命中最多读一次）。"
    "先用简短中文说明触发方式与关键位置。"
    "**末尾必须附带唯一 JSON**（不要 markdown 代码块），格式示例："
    + _ANTI_DEBUG_JSON_EXAMPLE
    + " inject_opts 字段含义："
    "functionHook=Hook Function/constructor；evalHook=Hook eval；"
    "timerHook=温和定时器；timerNuke=定时器整段置空(激进)；"
    "consoleClear=禁清控制台；sizeSpoof=弱化尺寸检测；"
    "rewriteResponse=响应里 debugger→return（治字面量+递归，强烈推荐）；"
    "anti_debug=注入反调试脚本；cdp_skip_pauses=CDP跳过断点。"
    " hook_js：可选，纯 JS 字符串，document_start 额外注入的站点补丁（IIFE，勿含 markdown）；"
    "仅写防御性补丁（如加固 Function/定时器、打日志），禁止外联、禁止恶意代码；"
    "若是字面量 debugger+递归，inject_opts.rewriteResponse 必须为 true，hook_js 可只打日志。"
    "禁止编造不存在的脚本 URL；没找到时 confidence=low。"
)

ANTI_DEBUG_SYSTEM_PROMPT = """你是 Web 反调试 / 无限 debugger 分析专家（密桥 Agent · 反调试模式）。

工作方式:
1. 只用 script / hook 工具；不要分析加解密，不要输出 steps。
2. 先 script.enrich（或 outline）摸结构，再 script.search: debugger、\\u0064、constructor、setInterval、setTimeout、eval、Devtools、outerWidth、console.clear；混淆再搜 fromCharCode。
3. 命中后按 match_offset script.read 一次；禁止重复 read。
4. HTML 页常有 inline 反调试，优先 enrich/读业务页。
5. 识别后给出 inject_opts，并尽量给出短小 hook_js 补丁。
6. 禁止编造脚本 URL；不确定则 confidence=low。
7. 够用就收工；先短中文，末尾唯一 JSON（不要 markdown 代码块）。
"""

ANTI_DEBUG_SYSTEM_EXTRA = """
最终 JSON 字段: summary, confidence, patterns, inject_opts, advice；
可选 script_urls、hook_js（可注入的 JS 字符串）。
常见模式对照:
- setInterval 内 debugger → timerHook/timerNuke + cdp
- Function/constructor("debugger") → functionHook + cdp
- eval("debugger") → evalHook
- console.clear 循环 → consoleClear
- outerWidth 检测 → sizeSpoof
- 字面量 debugger + 递归 / while(!![]){}（sojson）→ rewriteResponse=true + cdp；hook_js 可选
hook_js 必须是合法 JS 单行或含 \\n 的 JSON 字符串，用 IIFE 包裹。
"""

FORCE_ANTI_DEBUG_JSON_USER = (
    "调查阶段结束。请勿再调用任何工具。"
    "现在只输出一个 JSON 对象（不要 markdown 代码块），必须含 summary/confidence/patterns/inject_opts/advice。"
    f"示例: {_ANTI_DEBUG_JSON_EXAMPLE}"
)

_HASH_HOOK_JSON_EXAMPLE = (
    '{"summary":"password 经 Encrypt.oldPwd；用 cbBypass.hookPath 延迟挂钩",'
    '"confidence":"high",'
    '"mode":"bypass",'
    '"fields":["password"],'
    '"targets":["Encrypt.oldPwd"],'
    '"hook_js":"(function(){cbBypass.hookPath(\\"Encrypt.oldPwd\\",'
    'function(orig,args){return cbBypass.keepPlain(\\"oldPwd\\",args[0]);});'
    'cbBypass.hookCryptoJSIdentity();cbBypass.hookGlobalHashIdentity();'
    'cbBypass.patchTransportLog([\\"password\\"]);})();",'
    '"advice":"重启浏览器复测；控制台应出现 hooked …；Burp 见明文后「生成加密」。"}'
)

HASH_HOOK_GOAL = (
    "目标：写 Bypass Hook，使选定字段以明文进入 HTTP 请求（Burp 可见），"
    "用户再用「生成加密」出站重算。不要 steps / 解密插件。"
    "调查：flow.list/get 看字段；script.enrich 看 cryptoHints/函数名；"
    "再 script.search: encrypt,oldPwd,md5,hex_md5,CryptoJS,password,AES,sign；命中后 script.read 一次。"
    "运行时已注入 window.cbBypass（勿重复实现轮询）。hook_js 应调用："
    "cbBypass.hookPath('A.B.fn', function(orig,args){return cbBypass.keepPlain('fn', args[0]);})、"
    "cbBypass.hookCryptoJSIdentity()、cbBypass.hookGlobalHashIdentity()。"
    "禁止只写 if(window.X){...} 一次判断；包装函数必须 return 明文，禁止再调 orig 加密。"
    "**末尾唯一 JSON**（不要 markdown），示例："
    + _HASH_HOOK_JSON_EXAMPLE
)

HASH_HOOK_SYSTEM_PROMPT = """你是前端 Bypass Hook 专家（密桥 · 高成功率模式）。

优先级（从高到低）:
1. 从 JS 找到业务加密函数真实路径（如 Encrypt.oldPwd、u.a.encrypt）→ cbBypass.hookPath
2. CryptoJS → cbBypass.hookCryptoJSIdentity()
3. 全局 md5/hex_md5 → cbBypass.hookGlobalHashIdentity()
4. 仍不确定 → 仍输出 hookPath 候选 + 上述通用调用，confidence=low

硬性规则:
- 必须使用 window.cbBypass.*，禁止一次性 if(window.Encrypt) 无轮询
- identity：return 明文入参，不要 orig.apply
- JSON: summary, confidence, mode=bypass, fields, targets, hook_js, advice
- 禁止 steps / 外联 / 恶意代码
"""

HASH_HOOK_SYSTEM_EXTRA = """
hook_js 尽量短：只写 cbBypass.hookPath(...) 与通用 identity 调用。
日志前缀由运行时打印 [密桥·BypassHook]。
"""

FORCE_HASH_HOOK_JSON_USER = (
    "调查结束，勿再调工具。只输出 JSON："
    "summary/confidence/mode/fields/targets/hook_js/advice。"
    "hook_js 必须用 cbBypass.hookPath / hookCryptoJSIdentity / hookGlobalHashIdentity。"
    "示例: " + _HASH_HOOK_JSON_EXAMPLE
)

_BOT_BYPASS_JSON_EXAMPLE = (
    '{"summary":"检测 navigator.webdriver + Cloudflare Turnstile",'
    '"confidence":"high",'
    '"patterns":["navigator.webdriver","turnstile","canvas-fp"],'
    '"browser_opts":{"browser_channel":"chrome","record_mode":true,"prefer_stealth":true},'
    '"hook_js":"(function(){try{Object.defineProperty(navigator,\'webdriver\','
    '{get:function(){return undefined;}});}catch(e){}})();",'
    '"advice":"已生成本地补丁；请用本机 Chrome + 记录模式重启浏览器；Turnstile 需手动点一次"}'
)

BOT_BYPASS_GOAL = (
    "目标：分析当前站点的「浏览器环境检测 / Bot 检测 / JS 挑战」，"
    "给出可注入的绕过补丁 hook_js，以及浏览器选项建议。"
    "不要分析加解密 steps，不要写解密插件。"
    "分层：密桥底座已通用覆盖 webdriver/chrome/plugins、CDP console(Error→String)、"
    "SwiftShader→Intel WebGL(含 Worker)、Playwright 标记清理。"
    "hook_js 只写本站仍命中的增量（FingerprintJS/业务 DOM/WAF 特有逻辑等），"
    "不要重复写底座已有能力，不要写死某测试页 URL/token。"
    "策略分流：指纹/Bot 扫描站 → prefer_stealth=true；"
    "瑞数等强 JS 挑战/脚本完整性站 → 通关窗口用 use_stealth=false（真实浏览器），"
    "离线本模式仍输出 prefer_stealth=true + hook_js 供拟真通道用。"
    "调查：flow.list 看是否被拦/403/挑战页；先 script.enrich，再 script.search: webdriver、"
    "HeadlessChrome、selenium、puppeteer、playwright、cdc_、driver、chrome.runtime、permissions、"
    "canvas、toDataURL、WebGL、callPhantom、__nightmare、turnstile、cf-challenge、"
    "challenge-platform、FingerprintJS、fpjs、botdetect、isBot、fastBot；命中后 script.read 一次。"
    "hook_js 只写防御性站点补丁（IIFE）；禁止外联、禁止恶意代码、禁止偷 Cookie。"
    "Turnstile/验证码无法完全自动过时，advice 里说明需手动点。"
    "browser_opts 必须 prefer_stealth=true，且不要建议「真实浏览器/不注入」模式。"
    "**末尾唯一 JSON**（不要 markdown），示例："
    + _BOT_BYPASS_JSON_EXAMPLE
)

BOT_BYPASS_SYSTEM_PROMPT = """你是 Web Bot / 浏览器环境检测分析专家（密桥 Agent · 绕过检查模式）。

工作方式:
1. 用 flow / script / hook 工具调查，不要输出加解密 steps。
2. 底座已覆盖 CDP console / SwiftShader WebGL+Worker / PW 标记；hook_js 只补本站增量。
3. 重点搜: FingerprintJS、fpjs、isBot、canvas、WebGL（业务侧）、turnstile、cf-challenge、webdriver。
4. 命中后按 match_offset script.read 一次；禁止重复 read。
5. 输出 browser_opts + hook_js（按 detections 写增量，勿重复底座）。
6. hook_js 必须是合法 JS（IIFE），只做环境拟真，禁止外联。
7. 不确定则 confidence=low；够用就收工。
8. 先短中文，末尾唯一 JSON（不要 markdown 代码块）。
"""

BOT_BYPASS_SYSTEM_EXTRA = """
最终 JSON 字段: summary, confidence, patterns, browser_opts, hook_js, advice。
browser_opts:
- browser_channel: "chrome" | "chromium"（强检测站优先 chrome）
- record_mode: true/false（长期 Cookie 有助于过检）
- prefer_stealth: true（必须；启用密桥通用拟真 + 站点 hook_js）
hook_js 原则:
- 只写本站仍命中的：FingerprintJS/业务 canvas、WAF DOM、站点特有全局变量等
- 不要重复：CDP console Error→String、SwiftShader UNMASKED_*、删 __pwInitScripts（底座已有）
- 不要伪造离谱硬件并发 / 不要随机大面积污染 canvas（易反噬）
- 不要写死某站 URL/token（如 ddtk=…）
"""

FORCE_BOT_BYPASS_JSON_USER = (
    "调查阶段结束。请勿再调用任何工具。"
    "现在只输出一个 JSON 对象（不要 markdown 代码块），"
    "必须含 summary/confidence/patterns/browser_opts/hook_js/advice。"
    f"示例: {_BOT_BYPASS_JSON_EXAMPLE}"
)

# ----------------------------------------------------------------------
# 指纹绕过 HOOK（离线：指纹 API / FingerprintJS → hook_js）
# ----------------------------------------------------------------------

_FINGERPRINT_HOOK_JSON_EXAMPLE = (
    '{"summary":"FingerprintJS + canvas toDataURL + WebGL vendor",'
    '"confidence":"high",'
    '"patterns":["fingerprintjs","canvas-fp","webgl-fp"],'
    '"detections":[{"api":"HTMLCanvasElement.toDataURL",'
    '"url":"https://example.com/fp.js","approx_line":120,"what":"指纹采集"}],'
    '"browser_opts":{"browser_channel":"chrome","record_mode":true,"prefer_stealth":true},'
    '"hook_js":"(function(){try{/* site-specific fp patch */'
    'var o=HTMLCanvasElement.prototype.toDataURL;'
    'HTMLCanvasElement.prototype.toDataURL=function(){return o.apply(this,arguments);};'
    '}catch(e){}})();",'
    '"advice":"已写入站点指纹补丁；保持普通模式（勿开真实浏览器），重启后再测"}'
)

FINGERPRINT_HOOK_GOAL = (
    "目标：分析当前已采集 JS / 流量中的「浏览器指纹采集 / FingerprintJS 类库」，"
    "给出可注入的站点补丁 hook_js，以及浏览器选项建议。"
    "本模式只关注指纹 API（canvas/WebGL/Audio/字体等），不要做验证码通关，不要输出加解密 steps。"
    "分层：底座已覆盖 CDP console、SwiftShader→Intel WebGL(Worker)、Playwright 标记。"
    "hook_js 只补本站指纹库/业务采集点（FingerprintJS、canvas 哈希、Audio 等），勿重复底座。"
    "调查：先 script.enrich（或 outline）；再 script.search: FingerprintJS、fpjs、fingerprint、canvas、"
    "toDataURL、getImageData、WebGL、getParameter、AudioContext、OfflineAudioContext、fonts、"
    "enumerateDevices、speechSynthesis、battery、hardwareConcurrency、deviceMemory、webdriver、"
    "HeadlessChrome、cdc_、isBot、fastBotDetection；命中后 script.read 一次；flow.list 可看是否因指纹被拦。"
    "hook_js 只写防御性环境补丁（IIFE）；优先稳定一致的轻微扰动或拦截已知采集函数；"
    "禁止大面积随机污染 canvas/WebGL；禁止外联、偷 Cookie、改支付逻辑。"
    "Turnstile/验证码若存在，仅在 advice 提醒需手动点，不作为主目标。"
    "browser_opts 必须 prefer_stealth=true；advice 提醒用户不要开「真实浏览器」。"
    "无命中时 confidence=low，hook_js 可为空字符串或最小站点相关补丁。"
    "**末尾唯一 JSON**（不要 markdown），示例："
    + _FINGERPRINT_HOOK_JSON_EXAMPLE
)

FINGERPRINT_HOOK_SYSTEM_PROMPT = """你是浏览器指纹采集分析专家（密桥 Agent · 指纹绕过 HOOK 模式）。

工作方式:
1. 用 script / flow / hook 工具调查，不要输出加解密 steps，不要做验证码通关。
2. 底座已覆盖 CDP/SwiftShader/PW 标记；按本站 detections 写增量 hook_js。
3. 先 script.enrich 摸结构，再搜: FingerprintJS、fpjs、fingerprint、canvas、toDataURL、WebGL、AudioContext、fonts、isBot。
4. 命中后按 match_offset script.read 一次；禁止重复 read。
5. 输出 detections + browser_opts + hook_js（只补本站缺口，勿只回空壳也不要重复底座）。
6. hook_js 必须是合法 JS（IIFE），只做防御性拟真；禁止外联。
7. 与「绕过检查」区别：本模式只关注指纹 API / FingerprintJS，不主攻 WAF/Turnstile。
8. 不确定则 confidence=low；够用就收工。
9. 先短中文，末尾唯一 JSON（不要 markdown 代码块）。
"""

FINGERPRINT_HOOK_SYSTEM_EXTRA = """
最终 JSON 字段: summary, confidence, patterns, detections, browser_opts, hook_js, advice。
detections[]: api, url, approx_line, what（禁止编造不存在的 URL）。
browser_opts:
- browser_channel: "chrome" | "chromium"（强检测站优先 chrome）
- record_mode: true/false
- prefer_stealth: true（必须）
hook_js 原则:
- 只写 detections 中底座未覆盖的：FingerprintJS、业务 canvas/Audio/字体等
- 不要重复：CDP console、SwiftShader UNMASKED_*、删 __pwInitScripts（底座已有）
- 稳定一致的轻微扰动优先于随机噪声
- 不要伪造离谱 hardwareConcurrency / deviceMemory
- 不要随机大面积污染 canvas/WebGL（易反噬）
"""

FORCE_FINGERPRINT_HOOK_JSON_USER = (
    "调查阶段结束。禁止再调用任何工具。"
    "上一条若含散文/伪代码，一律作废。"
    "现在只输出一个 JSON 对象：第一个字符必须是 {，最后一个字符必须是 }。"
    "禁止 markdown、禁止 JSON 外任何文字、禁止先写 JS 再包 JSON。"
    "必须含 summary/confidence/patterns/detections/browser_opts/hook_js/advice；"
    "hook_js 为压缩单行 IIFE 字符串（换行写成 \\n），尽量 <3000 字符，"
    "至少覆盖本站命中：console.* 抗 CDP（Error→String）、删 __pwInitScripts/"
    "__playwright__binding__、WebGL UNMASKED 去 SwiftShader 且 Blob/Worker 一致。"
    f"字段示例: {_FINGERPRINT_HOOK_JSON_EXAMPLE}"
)

# ----------------------------------------------------------------------
# JS 逆向 / JS 解密（解混淆）
# ----------------------------------------------------------------------

_JS_REVERSE_JSON_EXAMPLE = (
    '{"summary":"业务加密在 Encrypt.aesEncrypt，请求字段 data",'
    '"confidence":"high",'
    '"findings":[{"what":"AES-CBC 加密入口","path":"Encrypt.aesEncrypt",'
    '"url":"https://a.com/app.js","approx_line":1284,"snippet":"function aesEncrypt(t){...}"}],'
    '"code_locations":[{"url":"https://a.com/app.js","approx_line":1284,"offset":0,'
    '"what":"AES 入口","snippet":"aesEncrypt"}],'
    '"crypto_hints":{"algo":"AES-CBC","padding":"Pkcs7","fields":["data"],'
    '"pattern":"fixed_symmetric","key_hint":"见 Hook 或相邻常量"},'
    '"next_steps":["可再点「生成解密」写出 plugin","建议勾选密钥 Hook 复测"],'
    '"advice":"先对 data 字段验证；库文件 crypto-js 勿当业务入口"}'
)

JS_REVERSE_GOAL = (
    "目标：对已采集 JS / Hook / 流量做「JS 逆向分析」，"
    "找出加解密/签名相关业务函数路径、源码位置与字段线索。"
    "不要输出加解密 steps，不要写 plugin，不要只做反调试。"
    "调查：先 script.enrich（看 cryptoHints/apiCalls/fn）；再 script.search: encrypt,decrypt,AES,"
    "CryptoJS,sm4,RSA,JSEncrypt,sign,md5,hmac,password,data,random,WordArray；"
    "hook.search: Key,IV,AES,RSA,encrypt；flow.list 看密文字段名（是否多字段：数据+key+iv）。"
    "命中后 script.read 一次（同 url+offset 禁止重复）。"
    "在 crypto_hints 中注明是否像 hybrid_session_key（随机对称密钥 + 非对称封装）。"
    "库文件(crypto-js、vendor)只作旁证，业务入口优先自家脚本。"
    "**末尾唯一 JSON**（不要 markdown），示例："
    + _JS_REVERSE_JSON_EXAMPLE
)

JS_REVERSE_SYSTEM_PROMPT = """你是前端 JS 逆向分析专家（密桥 Agent · JS逆向模式）。

工作方式:
1. 只用 flow / script / hook 工具调查，禁止编造不存在的路径。
2. 目标是定位业务加解密/签名函数与字段，不是解整站、不是写解密 plugin。
3. 先 script.enrich/outline，再 search；命中后按 match_offset 读一次；禁止重复 read。
4. 区分业务脚本与第三方库；库文件不要当成唯一业务入口。
5. 输出 findings + code_locations + crypto_hints + next_steps。
6. 不确定则 confidence=low；够用就收工。
7. 先短中文，末尾唯一 JSON（不要 markdown 代码块）。
"""

JS_REVERSE_SYSTEM_EXTRA = """
最终 JSON 字段: summary, confidence, findings, code_locations, crypto_hints, next_steps, advice。
findings[]: what, path(可选), url, approx_line, snippet。
crypto_hints: algo/mode/padding/fields/key_hint/pattern(fixed_symmetric|hybrid_session_key|...)（未知可省略）。
禁止 steps、禁止 hook_js 恶意代码、禁止外联。
"""

FORCE_JS_REVERSE_JSON_USER = (
    "调查阶段结束。请勿再调用任何工具。"
    "现在只输出一个 JSON 对象（不要 markdown 代码块），"
    "必须含 summary/confidence/findings/code_locations/crypto_hints/next_steps/advice。"
    f"示例: {_JS_REVERSE_JSON_EXAMPLE}"
)

_JS_DEOBFUSCATE_JSON_EXAMPLE = (
    '{"summary":"疑似 sojson 字符串数组 + 控制流平坦化，已还原核心加密片段",'
    '"confidence":"medium",'
    '"techniques":["string_array","control_flow_flatten","hex_string"],'
    '"snippets":[{"title":"还原后 AES 调用","code":"function enc(d){return CryptoJS.AES.encrypt(d,key,{mode:CryptoJS.mode.ECB}).toString();}"}],'
    '"deobfuscated_js":"/* 核心片段 */\\nfunction enc(d){...}\\n",'
    '"code_locations":[{"url":"https://a.com/app.js","approx_line":80,"what":"混淆入口","snippet":"_0xabcd"}],'
    '"advice":"完整文件过长只给核心；可把 snippets 送去「JS逆向」或「生成解密」"}'
)

JS_DEOBFUSCATE_GOAL = (
    "目标：对已采集 JS 做「解密/解混淆」辅助分析："
    "识别混淆手法，还原与加解密相关的可读核心片段。"
    "不要输出加解密 steps，不要写 plugin，不要只报反调试。"
    "调查：先 script.enrich/outline；再 script.search: _0x, sojson, eval(, Function(, atob, "
    "fromCharCode, while(!![]), stringArray, decrypt, encrypt, AES, CryptoJS；命中后 script.read 一次。"
    "优先还原加密/解密/签名相关代码；整文件过大时只输出核心 snippets。"
    "deobfuscated_js 必须是合法 JS 文本（可含注释），禁止外联、禁止恶意代码。"
    "**末尾唯一 JSON**（不要 markdown），示例："
    + _JS_DEOBFUSCATE_JSON_EXAMPLE
)

JS_DEOBFUSCATE_SYSTEM_PROMPT = """你是 JS 解混淆 / 解密辅助专家（密桥 Agent · JS解密模式）。

工作方式:
1. 用 script（必要时 hook/flow）调查混淆与加解密相关代码。
2. 识别常见手法：字符串数组、十六进制串、控制流平坦化、eval/Function 打包、sojson 等。
3. 输出可读核心片段（snippets / deobfuscated_js），不要假装已 100% 还原整站。
4. 命中后 script.read 一次；禁止重复 read。
5. 不确定则 confidence=low；够用就收工。
6. 先短中文，末尾唯一 JSON（不要 markdown 代码块）。
"""

JS_DEOBFUSCATE_SYSTEM_EXTRA = """
最终 JSON 字段: summary, confidence, techniques, snippets, deobfuscated_js, code_locations, advice。
snippets[]: title + code（可读 JS）。
deobfuscated_js: 可选，核心合并文本；过长则截断并说明。
禁止 steps、禁止外联、禁止恶意 payload。
"""

FORCE_JS_DEOBFUSCATE_JSON_USER = (
    "调查阶段结束。请勿再调用任何工具。"
    "现在只输出一个 JSON 对象（不要 markdown 代码块），"
    "必须含 summary/confidence/techniques/snippets/deobfuscated_js/code_locations/advice。"
    f"示例: {_JS_DEOBFUSCATE_JSON_EXAMPLE}"
)

GENERATE_SYSTEM_EXTRA = """
完成工具调查后，最终回复必须包含一个完整 JSON 对象（可先有简短说明，但 JSON 不可省略）。
steps[].type 必须是密桥构建器步骤名（如 🔓 解密字段、🔒 加密字段、📝 签名(Hash) 等），带 emoji。
建议含 crypto_pattern: fixed_symmetric | hybrid_session_key | asymmetric_only | sign_only。
另输出 code_locations 数组（url、approx_line、offset、what、snippet），记录加解密相关源码位置，
仅供人工查找代码；与 steps / plugin 生成无关，禁止写入 steps.params。
有 script.enrich/search 命中时至少填 1 条；库文件(crypto-js 等)不要当作业务位置。
混合加密勿压成「单字段固定 AES」；公钥可固定，随机会话 Key 不可固化 Hook 采样值。
"""

FORCE_JSON_USER = (
    "调查阶段结束。请勿再调用任何工具。"
    "现在只输出一个 JSON 对象（不要 markdown 代码块），必须包含非空 steps 数组。"
    f"示例: {_STEPS_JSON_EXAMPLE}"
    "写入算法/模式/字段名；固定密钥才把 Hook Key/IV 写入 params。"
    "若判定 hybrid_session_key：禁止把单次 Hook AES Key 固化到加密端；"
    "应生成「随机会话材料 + 对称加密业务字段 + 非对称封装密钥字段」步骤。"
    "type 必须写成「🔓 解密字段」或「🔒 加密字段」这种完整名称。"
    "若调查过 JS，一并输出 code_locations 与 crypto_pattern（与 steps 分开）。"
)


def build_agent_system_prompt(mode: str = "chat") -> str:
    if mode in ("generate", "recognize"):
        return CRYPTO_SYSTEM_PROMPT + "\n" + GENERATE_SYSTEM_EXTRA
    if mode == "anti_debug":
        return ANTI_DEBUG_SYSTEM_PROMPT + "\n" + ANTI_DEBUG_SYSTEM_EXTRA
    if mode == "hash_hook":
        return HASH_HOOK_SYSTEM_PROMPT + "\n" + HASH_HOOK_SYSTEM_EXTRA
    if mode == "bot_bypass":
        return BOT_BYPASS_SYSTEM_PROMPT + "\n" + BOT_BYPASS_SYSTEM_EXTRA
    if mode == "fingerprint_hook":
        return FINGERPRINT_HOOK_SYSTEM_PROMPT + "\n" + FINGERPRINT_HOOK_SYSTEM_EXTRA
    if mode == "js_reverse":
        return JS_REVERSE_SYSTEM_PROMPT + "\n" + JS_REVERSE_SYSTEM_EXTRA
    if mode == "js_deobfuscate":
        return JS_DEOBFUSCATE_SYSTEM_PROMPT + "\n" + JS_DEOBFUSCATE_SYSTEM_EXTRA
    return CRYPTO_SYSTEM_PROMPT



def default_workspace_root() -> str:
    """兼容旧调用；Agent 不再提供 file 工具."""
    return os.path.join(get_app_root(), "workspace")


def _proxy_url(cfg: dict) -> str | None:
    if not cfg.get("use_http_proxy"):
        return None
    p = str(cfg.get("http_proxy") or "").strip()
    if not p:
        return None
    if not p.startswith("http"):
        p = f"http://{p}"
    return p


class ProxiedLLMClient(LLMClient):
    """支持可选 HTTP 代理的 Anthropic Messages 客户端."""

    def __init__(
        self,
        *args: Any,
        proxy: str | None = None,
        ai_cfg: dict | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.proxy = proxy
        self.ai_cfg = dict(ai_cfg or {})

    async def chat_raw(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        *,
        thinking: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        from core.ai_config import enrich_ai_headers
        from core.ai_http import AIHttpError, apost_json

        url = f"{self.base_url}/v1/messages"
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "messages": messages,
            "system": system,
        }
        if tools:
            payload["tools"] = tools
        # DeepSeek V4 默认开 thinking，易把 max_tokens 吃光导致无 text/JSON。
        # 无工具的收工/强制 JSON 轮默认关掉 thinking。
        if thinking is not None:
            payload["thinking"] = thinking
        elif "deepseek" in str(self.model or "").lower() and not tools:
            payload["thinking"] = {"type": "disabled"}
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "anthropic-version": "2023-06-01",
        }
        cfg = {
            "api_key": self.api_key,
            "base_url": self.base_url,
            **self.ai_cfg,
        }
        headers = enrich_ai_headers(headers, url=url, cfg=cfg, for_anthropic=True)
        try:
            return await apost_json(
                url,
                headers=headers,
                body=payload,
                proxy=self.proxy,
                timeout=float(self.timeout or 180.0),
            )
        except AIHttpError as e:
            raise RuntimeError(str(e)) from e


def _clip_io_text(text: str, limit: int = 80_000) -> str:
    s = text or ""
    if len(s) <= limit:
        return s
    return s[:limit] + f"\n…(+{len(s) - limit} chars 已省略)"


def format_llm_request_for_ui(
    system: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
    *,
    round_no: int = 1,
) -> str:
    """把发给模型的 system/messages/tools 编成可读文本（供 UI「上下文」页）。"""
    lines = [
        f"======== 发送 #{round_no} ========",
        f"tools: {len(tools or [])} 个",
        "",
        "—— system ——",
        _clip_io_text(system or "", 40_000),
        "",
    ]
    for i, msg in enumerate(messages or []):
        role = str(msg.get("role") or "?")
        content = msg.get("content")
        lines.append(f"—— messages[{i}] role={role} ——")
        if isinstance(content, str):
            lines.append(_clip_io_text(content))
        elif isinstance(content, list):
            try:
                lines.append(_clip_io_text(json.dumps(content, ensure_ascii=False, indent=2)))
            except Exception:
                lines.append(_clip_io_text(str(content)))
        else:
            try:
                lines.append(_clip_io_text(json.dumps(content, ensure_ascii=False, indent=2)))
            except Exception:
                lines.append(_clip_io_text(repr(content)))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def format_llm_response_for_ui(response: dict[str, Any], *, round_no: int = 1) -> str:
    """把模型原始响应编成可读文本。"""
    lines = [f"======== 响应 #{round_no} ========", ""]
    if not isinstance(response, dict):
        lines.append(_clip_io_text(str(response)))
        return "\n".join(lines) + "\n"
    # 常见字段：content / stop_reason / usage
    content = response.get("content")
    if content is not None:
        lines.append("—— content ——")
        if isinstance(content, str):
            lines.append(_clip_io_text(content))
        else:
            try:
                lines.append(_clip_io_text(json.dumps(content, ensure_ascii=False, indent=2)))
            except Exception:
                lines.append(_clip_io_text(str(content)))
        lines.append("")
    stop = response.get("stop_reason") or response.get("stopReason")
    if stop:
        lines.append(f"stop_reason: {stop}")
    usage = response.get("usage")
    if usage is not None:
        try:
            lines.append("usage: " + json.dumps(usage, ensure_ascii=False))
        except Exception:
            lines.append(f"usage: {usage}")
    # 若几乎没解析到，贴精简 raw
    if content is None:
        try:
            lines.append(_clip_io_text(json.dumps(response, ensure_ascii=False, indent=2)))
        except Exception:
            lines.append(_clip_io_text(str(response)))
    return "\n".join(lines).rstrip() + "\n"


class CryptoAgent(Agent):
    """专用工具 schema + 可取消的 ReAct 循环."""

    SYSTEM_PROMPT = CRYPTO_SYSTEM_PROMPT

    def __init__(
        self,
        *args: Any,
        cancel_check: Callable[[], bool] | None = None,
        on_step: Callable[[str], None] | None = None,
        on_llm_io: Callable[[str, str], None] | None = None,
        require_steps_json: bool = False,
        require_anti_debug_json: bool = False,
        require_hash_hook_json: bool = False,
        require_bot_bypass_json: bool = False,
        require_fingerprint_hook_json: bool = False,
        require_js_reverse_json: bool = False,
        require_js_deobfuscate_json: bool = False,
        **kwargs: Any,
    ) -> None:
        kwargs.setdefault("system_prompt", CRYPTO_SYSTEM_PROMPT)
        kwargs.setdefault("verbose", False)
        super().__init__(*args, **kwargs)
        self._cancel_check = cancel_check or (lambda: False)
        self._on_step = on_step
        self._on_llm_io = on_llm_io
        self._llm_round = 0
        self._require_steps_json = require_steps_json
        self._require_anti_debug_json = require_anti_debug_json
        self._require_hash_hook_json = require_hash_hook_json
        self._require_bot_bypass_json = require_bot_bypass_json
        self._require_fingerprint_hook_json = require_fingerprint_hook_json
        self._require_js_reverse_json = require_js_reverse_json
        self._require_js_deobfuscate_json = require_js_deobfuscate_json
        self._forced_json_once = False

    def _emit(self, msg: str) -> None:
        if self._on_step:
            try:
                self._on_step(msg)
            except Exception:
                pass

    def _emit_io(self, kind: str, text: str) -> None:
        if not self._on_llm_io:
            return
        try:
            self._on_llm_io(kind, text)
        except Exception:
            pass

    async def _sleep_cancelable(self, seconds: float) -> None:
        """可被 cancel_check 打断的 sleep。"""
        end = asyncio.get_running_loop().time() + max(0.0, float(seconds))
        while asyncio.get_running_loop().time() < end:
            if self._cancel_check():
                raise RuntimeError("已取消")
            await asyncio.sleep(0.12)

    async def _call_llm(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """调用 LLM；轮询取消标志，可中断进行中的 HTTP 请求。"""
        if self._cancel_check():
            raise RuntimeError("已取消")
        tools = tools if tools is not None else []
        self._llm_round += 1
        round_no = self._llm_round
        self._emit_io(
            "request",
            format_llm_request_for_ui(system, messages, tools, round_no=round_no),
        )
        task = asyncio.create_task(super()._call_llm(system, messages, tools))
        try:
            while True:
                if self._cancel_check():
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
                    raise RuntimeError("已取消")
                done, _ = await asyncio.wait({task}, timeout=0.2)
                if not done:
                    continue
                if task.cancelled():
                    raise RuntimeError("已取消")
                exc = task.exception()
                if exc is not None:
                    raise exc
                result = task.result()
                try:
                    self._emit_io(
                        "response",
                        format_llm_response_for_ui(
                            result if isinstance(result, dict) else {"content": result},
                            round_no=round_no,
                        ),
                    )
                except Exception:
                    pass
                return result
        except asyncio.CancelledError:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            raise RuntimeError("已取消") from None
        finally:
            if not task.done():
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass

    def _build_tool_schemas(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "flow",
                "description": (
                    "只读查询已抓 HTTP 流量。list 摘要；get 需 index；"
                    "search 需 query（URL/Body 关键字）。"
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["list", "get", "search"],
                            "description": "list | get | search",
                        },
                        "query": {"type": "string", "description": "search 关键字"},
                        "index": {"type": "integer", "description": "get 时的流量下标"},
                        "limit": {"type": "integer", "description": "list 条数上限"},
                    },
                    "required": ["action"],
                },
            },
            {
                "name": "hook",
                "description": "只读查询 Hook 日志。list 最近行；search 需 query（AES/Key/IV 等）。",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["list", "search"],
                        },
                        "query": {"type": "string"},
                        "limit": {"type": "integer"},
                    },
                    "required": ["action"],
                },
            },
            {
                "name": "script",
                "description": (
                    "只读查询 JS/小程序源码。list；search 需 query"
                    "（返回 match_offset、approx_line、context）；"
                    "read 需 url + offset（用 search 的 match_offset，亦返回 approx_line）。"
                    "最终 JSON 的 code_locations 请填 url+approx_line+what；"
                    "code_locations 仅供人工找代码，禁止写入 steps。"
                    "禁止对同一 url+offset 重复 read。"
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["list", "search", "read"],
                        },
                        "query": {"type": "string"},
                        "url": {"type": "string", "description": "read 时的脚本 URL"},
                        "path": {"type": "string", "description": "url 别名"},
                        "offset": {
                            "type": "integer",
                            "description": "read 起始字符下标；请用 search 的 match_offset",
                        },
                    },
                    "required": ["action"],
                },
            },
        ]

    async def _execute(self, tool_name: str, action: str, inputs: dict) -> str:
        """覆盖默认截断：script/hook 结果需要更长，否则模型会反复空读同一段。"""
        try:
            tool = self._tools.get(tool_name)
            if tool is None:
                return (
                    f"Error: Tool '{tool_name}' not found. "
                    f"Available: {self._tools.list_tools()}"
                )
            args = {k: v for k, v in inputs.items() if k != "action"}
            if action:
                await tool.validate(action, **args)
            result = await tool.execute(action, **args)
            result_str = json.dumps(result, ensure_ascii=False)
            # script.read 内容大；默认 3000 会截断导致死循环
            limit = 18000 if tool_name in ("script", "hook", "flow") else 6000
            if len(result_str) > limit:
                result_str = (
                    result_str[:limit]
                    + f"...(truncated, total {len(result_str)} chars; "
                    "请换 offset 或改用 search 的 match_offset)"
                )
            return result_str
        except asyncio.CancelledError:
            raise
        except RuntimeError as e:
            if "已取消" in str(e):
                raise
            return f"Error: {e}"
        except Exception as e:
            return f"Error: {e}"

    async def run(self, goal: str) -> str:
        if self._cancel_check():
            raise RuntimeError("已取消")

        system = self._build_system_prompt()
        messages: list[dict[str, Any]] = [{"role": "user", "content": goal}]
        tools = self._build_tool_schemas()
        await self._tools.initialize_all()
        seen_calls: dict[str, int] = {}

        for step in range(1, self.max_steps + 1):
            if self._cancel_check():
                await self._tools.shutdown_all()
                raise RuntimeError("已取消")

            self._emit(f"[step {step}] 思考中…")
            try:
                response = await self._call_llm(system, messages, tools)
            except RuntimeError as e:
                if "已取消" in str(e):
                    await self._tools.shutdown_all()
                    raise
                logger.error("LLM call failed at step %d: %s", step, e)
                self._emit(f"[step {step}] API 错误，重试: {e}")
                try:
                    await self._sleep_cancelable(2)
                except RuntimeError:
                    await self._tools.shutdown_all()
                    raise
                continue
            except asyncio.CancelledError:
                await self._tools.shutdown_all()
                raise RuntimeError("已取消") from None
            except Exception as e:
                logger.error("LLM call failed at step %d: %s", step, e)
                self._emit(f"[step {step}] API 错误，重试: {e}")
                try:
                    await self._sleep_cancelable(2)
                except RuntimeError:
                    await self._tools.shutdown_all()
                    raise
                continue

            thought, tool_calls, _stop = self._parse(response)
            messages.append({"role": "assistant", "content": response.get("content", [])})

            if not tool_calls:
                if (
                    self._require_steps_json
                    and not self._forced_json_once
                    and not self._text_has_steps_json(thought or "")
                ):
                    self._forced_json_once = True
                    self._emit(f"[step {step}] 未含 steps JSON，强制补一轮…")
                    messages.append({"role": "user", "content": FORCE_JSON_USER})
                    continue
                if (
                    self._require_anti_debug_json
                    and not self._forced_json_once
                    and not self._text_has_anti_debug_json(thought or "")
                ):
                    self._forced_json_once = True
                    self._emit(f"[step {step}] 未含 inject_opts JSON，强制补一轮…")
                    messages.append({"role": "user", "content": FORCE_ANTI_DEBUG_JSON_USER})
                    continue
                if (
                    self._require_hash_hook_json
                    and not self._forced_json_once
                    and not self._text_has_hash_hook_json(thought or "")
                ):
                    self._forced_json_once = True
                    self._emit(f"[step {step}] 未含 hook_js JSON，强制补一轮…")
                    messages.append({"role": "user", "content": FORCE_HASH_HOOK_JSON_USER})
                    continue
                if (
                    self._require_bot_bypass_json
                    and not self._forced_json_once
                    and not self._text_has_bot_bypass_json(thought or "")
                ):
                    self._forced_json_once = True
                    self._emit(f"[step {step}] 未含 bot_bypass JSON，强制补一轮…")
                    messages.append({"role": "user", "content": FORCE_BOT_BYPASS_JSON_USER})
                    continue
                if (
                    self._require_fingerprint_hook_json
                    and not self._text_has_fingerprint_hook_json(thought or "")
                ):
                    force_n = int(getattr(self, "_forced_fp_json_n", 0) or 0)
                    if force_n < 2:
                        self._forced_fp_json_n = force_n + 1
                        self._forced_json_once = True
                        self._emit(
                            f"[step {step}] 未含 fingerprint_hook JSON，"
                            f"强制补第 {force_n + 1} 轮…"
                        )
                        messages.append(
                            {"role": "user", "content": FORCE_FINGERPRINT_HOOK_JSON_USER}
                        )
                        continue
                if (
                    self._require_js_reverse_json
                    and not self._forced_json_once
                    and not self._text_has_js_reverse_json(thought or "")
                ):
                    self._forced_json_once = True
                    self._emit(f"[step {step}] 未含 js_reverse JSON，强制补一轮…")
                    messages.append({"role": "user", "content": FORCE_JS_REVERSE_JSON_USER})
                    continue
                if (
                    self._require_js_deobfuscate_json
                    and not self._forced_json_once
                    and not self._text_has_js_deobfuscate_json(thought or "")
                ):
                    self._forced_json_once = True
                    self._emit(f"[step {step}] 未含 js_deobfuscate JSON，强制补一轮…")
                    messages.append({"role": "user", "content": FORCE_JS_DEOBFUSCATE_JSON_USER})
                    continue
                self._emit(f"[step {step}] 完成")
                await self._tools.shutdown_all()
                return thought or "任务完成。"

            tool_results = []
            for tc in tool_calls:
                if self._cancel_check():
                    await self._tools.shutdown_all()
                    raise RuntimeError("已取消")
                tool_name = tc["name"]
                tool_input = tc.get("input", {}) or {}
                action = tool_input.get("action", "")
                # 重复调用指纹：script.read 同 url+offset 计次
                sig = json.dumps(
                    {"t": tool_name, "a": action, "i": tool_input},
                    ensure_ascii=False,
                    sort_keys=True,
                )
                seen_calls[sig] = seen_calls.get(sig, 0) + 1
                if seen_calls[sig] >= 2 and tool_name == "script" and action == "read":
                    self._emit(
                        f"[step {step}] ⚠ 重复 script.read，跳过并要求下结论"
                    )
                    result = json.dumps(
                        {
                            "error": "同一 url+offset 已读过，禁止重复。",
                            "hint": (
                                "请综合已有 hook/flow/script 结果立即给出中文结论与 JSON，"
                                "不要再调用 script.read。系统将不再返回新脚本内容。"
                            ),
                        },
                        ensure_ascii=False,
                    )
                else:
                    self._emit(f"[step {step}] 🔧 {tool_name}.{action}")
                    result = await self._execute(tool_name, action, tool_input)
                    preview = result.replace("\n", " ")[:220]
                    self._emit(f"  → {preview}")
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tc.get("id", ""),
                        "content": result,
                    }
                )
            messages.append({"role": "user", "content": tool_results})

        await self._tools.shutdown_all()
        if self._require_steps_json:
            self._emit("步数用尽，强制补一轮 steps JSON…")
            try:
                messages.append({"role": "user", "content": FORCE_JSON_USER})
                response = await self._call_llm(system, messages, tools=[])
                thought, tool_calls, _stop = self._parse(response)
                if thought and self._text_has_steps_json(thought):
                    return thought
                if thought:
                    return thought
            except Exception as e:
                logger.error("force json failed: %s", e)
        if self._require_anti_debug_json:
            self._emit("步数用尽，强制补一轮 inject_opts JSON…")
            try:
                messages.append({"role": "user", "content": FORCE_ANTI_DEBUG_JSON_USER})
                response = await self._call_llm(system, messages, tools=[])
                thought, tool_calls, _stop = self._parse(response)
                if thought:
                    return thought
            except Exception as e:
                logger.error("force anti_debug json failed: %s", e)
        if self._require_hash_hook_json:
            self._emit("步数用尽，强制补一轮 hook_js JSON…")
            try:
                messages.append({"role": "user", "content": FORCE_HASH_HOOK_JSON_USER})
                response = await self._call_llm(system, messages, tools=[])
                thought, tool_calls, _stop = self._parse(response)
                if thought:
                    return thought
            except Exception as e:
                logger.error("force hash_hook json failed: %s", e)
        if self._require_bot_bypass_json:
            self._emit("步数用尽，强制补一轮 bot_bypass JSON…")
            try:
                messages.append({"role": "user", "content": FORCE_BOT_BYPASS_JSON_USER})
                response = await self._call_llm(system, messages, tools=[])
                thought, tool_calls, _stop = self._parse(response)
                if thought:
                    return thought
            except Exception as e:
                logger.error("force bot_bypass json failed: %s", e)
        if self._require_fingerprint_hook_json:
            thought = ""
            for i in range(2):
                self._emit(f"步数用尽，强制补 fingerprint_hook JSON（{i + 1}/2）…")
                try:
                    messages.append(
                        {"role": "user", "content": FORCE_FINGERPRINT_HOOK_JSON_USER}
                    )
                    response = await self._call_llm(system, messages, tools=[])
                    thought, tool_calls, _stop = self._parse(response)
                    if thought and self._text_has_fingerprint_hook_json(thought):
                        return thought
                    if thought:
                        messages.append({"role": "assistant", "content": thought})
                except Exception as e:
                    logger.error("force fingerprint_hook json failed: %s", e)
                    break
            if thought:
                return thought
        if self._require_js_reverse_json:
            self._emit("步数用尽，强制补一轮 js_reverse JSON…")
            try:
                messages.append({"role": "user", "content": FORCE_JS_REVERSE_JSON_USER})
                response = await self._call_llm(system, messages, tools=[])
                thought, tool_calls, _stop = self._parse(response)
                if thought:
                    return thought
            except Exception as e:
                logger.error("force js_reverse json failed: %s", e)
        if self._require_js_deobfuscate_json:
            self._emit("步数用尽，强制补一轮 js_deobfuscate JSON…")
            try:
                messages.append({"role": "user", "content": FORCE_JS_DEOBFUSCATE_JSON_USER})
                response = await self._call_llm(system, messages, tools=[])
                thought, tool_calls, _stop = self._parse(response)
                if thought:
                    return thought
            except Exception as e:
                logger.error("force js_deobfuscate json failed: %s", e)
        return (
            "已达最大步数仍未收工。常见原因：对同一脚本片段重复 read。"
            "请再跑一次；系统已禁止重复 read，并会优先采信 Hook 中的 Key。"
        )

    @staticmethod
    def _text_has_steps_json(text: str) -> bool:
        if not text or "steps" not in text:
            return False
        try:
            from core.ai_analyzer import _extract_json

            obj = _extract_json(text)
            steps = obj.get("steps")
            return isinstance(steps, list) and len(steps) > 0
        except Exception:
            return False

    @staticmethod
    def _text_has_anti_debug_json(text: str) -> bool:
        if not text or "inject_opts" not in text:
            return False
        try:
            from core.ai_analyzer import _extract_json

            obj = _extract_json(text)
            return isinstance(obj, dict) and isinstance(obj.get("inject_opts"), dict)
        except Exception:
            return False

    @staticmethod
    def _text_has_hash_hook_json(text: str) -> bool:
        if not text or "hook_js" not in text:
            return False
        try:
            from core.ai_analyzer import _extract_json

            obj = _extract_json(text)
            return isinstance(obj, dict) and bool(str(obj.get("hook_js") or "").strip())
        except Exception:
            return False

    @staticmethod
    def _text_has_bot_bypass_json(text: str) -> bool:
        if not text:
            return False
        if "browser_opts" not in text and "hook_js" not in text:
            return False
        try:
            from core.ai_analyzer import _extract_json

            obj = _extract_json(text)
            if not isinstance(obj, dict):
                return False
            if isinstance(obj.get("browser_opts"), dict):
                return True
            return bool(str(obj.get("hook_js") or "").strip())
        except Exception:
            return False

    @staticmethod
    def _text_has_fingerprint_hook_json(text: str) -> bool:
        if not text:
            return False
        if "hook_js" not in text and "detections" not in text and "patterns" not in text:
            return False
        try:
            from core.ai_analyzer import _extract_json

            obj = _extract_json(text)
            if not isinstance(obj, dict):
                return False
            if bool(str(obj.get("hook_js") or "").strip()):
                return True
            if isinstance(obj.get("detections"), list) and obj.get("detections"):
                return True
            return isinstance(obj.get("patterns"), list) and bool(obj.get("patterns"))
        except Exception:
            return False

    @staticmethod
    def _text_has_js_reverse_json(text: str) -> bool:
        if not text:
            return False
        if "findings" not in text and "code_locations" not in text:
            return False
        try:
            from core.ai_analyzer import _extract_json

            obj = _extract_json(text)
            if not isinstance(obj, dict):
                return False
            if isinstance(obj.get("findings"), list):
                return True
            return isinstance(obj.get("code_locations"), list)
        except Exception:
            return False

    @staticmethod
    def _text_has_js_deobfuscate_json(text: str) -> bool:
        if not text:
            return False
        if (
            "snippets" not in text
            and "deobfuscated_js" not in text
            and "techniques" not in text
        ):
            return False
        try:
            from core.ai_analyzer import _extract_json

            obj = _extract_json(text)
            if not isinstance(obj, dict):
                return False
            if isinstance(obj.get("snippets"), list) and obj.get("snippets"):
                return True
            if str(obj.get("deobfuscated_js") or "").strip():
                return True
            return isinstance(obj.get("techniques"), list)
        except Exception:
            return False


class AgentWorker(QThread):
    """后台运行加解密 Agent，不阻塞 GUI."""

    log = pyqtSignal(str)
    llm_io = pyqtSignal(str, str)  # kind=request|response, text
    finished_ok = pyqtSignal(str)
    failed = pyqtSignal(str)

    def __init__(
        self,
        goal: str,
        session: SessionData,
        cfg: dict | None = None,
        *,
        mode: str = "chat",
        parent=None,
    ):
        super().__init__(parent)
        self.goal = (goal or "").strip()
        self.session = session
        self.cfg = dict(cfg or load_ai_config())
        self.mode = mode or "chat"
        self._cancelled = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._task: asyncio.Task | None = None

    def cancel(self) -> None:
        """请求停止：置标志并取消正在跑的 asyncio 任务（打断 HTTP）。"""
        self._cancelled = True
        try:
            self.log.emit("收到停止请求，正在中断当前 API/步骤…")
        except Exception:
            pass
        loop = self._loop
        task = self._task
        if loop is not None and task is not None and not task.done():
            try:
                loop.call_soon_threadsafe(task.cancel)
            except Exception:
                pass

    def run(self) -> None:
        loop: asyncio.AbstractEventLoop | None = None
        try:
            api_key = str(self.cfg.get("api_key") or "").strip()
            if not api_key:
                self.failed.emit("请先在「配置」填写 API Key")
                return
            if not self.goal:
                self.failed.emit("请输入 Agent 任务")
                return

            base = resolve_agent_base_url(self.cfg)
            model = str(self.cfg.get("model") or "deepseek-chat").strip()
            try:
                max_steps = int(self.cfg.get("agent_max_steps") or 50)
            except (TypeError, ValueError):
                max_steps = 50
            if self.mode in (
                "generate",
                "recognize",
                "anti_debug",
                "hash_hook",
                "bot_bypass",
                "fingerprint_hook",
                "js_reverse",
                "js_deobfuscate",
            ):
                max_steps = max(max_steps, 50)
            max_steps = max(3, min(max_steps, 80))

            proxy = _proxy_url(self.cfg)
            self.log.emit(f"模型: {model} · 模式: {self.mode}")
            self.log.emit(f"Agent 端点: {base}/v1/messages")
            if proxy:
                self.log.emit(f"代理: {proxy}")

            llm = ProxiedLLMClient(
                api_key=api_key,
                base_url=base,
                model=model,
                max_tokens=4096,
                temperature=0.2,
                timeout=180.0,
                proxy=proxy,
                ai_cfg=self.cfg,
            )
            def _emit_llm_io(kind: str, text: str) -> None:
                try:
                    self.llm_io.emit(str(kind or ""), str(text or ""))
                except Exception:
                    pass

            agent = CryptoAgent(
                llm=llm,
                max_steps=max_steps,
                system_prompt=build_agent_system_prompt(self.mode),
                cancel_check=lambda: self._cancelled,
                on_step=lambda m: self.log.emit(m),
                on_llm_io=_emit_llm_io,
                require_steps_json=self.mode in ("generate", "recognize"),
                require_anti_debug_json=self.mode == "anti_debug",
                require_hash_hook_json=self.mode == "hash_hook",
                require_bot_bypass_json=self.mode == "bot_bypass",
                require_fingerprint_hook_json=self.mode == "fingerprint_hook",
                require_js_reverse_json=self.mode == "js_reverse",
                require_js_deobfuscate_json=self.mode == "js_deobfuscate",
            )
            for tool in build_crypto_tools(self.session):
                agent.register_tool(tool)

            async def _amain() -> str:
                return await agent.run(self.goal)

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop
            task = loop.create_task(_amain())
            self._task = task
            try:
                result = loop.run_until_complete(task)
            except asyncio.CancelledError:
                self.failed.emit("已取消")
                return

            if self._cancelled:
                self.failed.emit("已取消")
                return
            self.finished_ok.emit(result)
        except RuntimeError as e:
            msg = str(e)
            if "已取消" in msg or self._cancelled:
                self.failed.emit("已取消")
            else:
                self.failed.emit(msg)
        except Exception as e:
            logger.exception("AgentWorker failed")
            if self._cancelled:
                self.failed.emit("已取消")
            else:
                self.failed.emit(str(e))
        finally:
            self._task = None
            self._loop = None
            if loop is not None:
                try:
                    loop.run_until_complete(loop.shutdown_asyncgens())
                except Exception:
                    pass
                try:
                    loop.close()
                except Exception:
                    pass
