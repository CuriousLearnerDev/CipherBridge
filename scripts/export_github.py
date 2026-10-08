"""Export clean source into ./github for uploading (no secrets / test data).

打包完成后会扫描敏感信息与测试数据；命中则失败退出（非 0），避免误传 GitHub。
"""

from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# 默认导出到同级 github/（解密框架2/github），便于直接推 GitHub
DEST = ROOT.parent / "github"

INCLUDE_DIRS = [
    "analyzer",
    "browser_ext",  # CB Hook / ReRes 扩展源码（不含 vendor 下载）
    "burp_ext",     # Burp 扩展 Java 源码（不含 out/ 构建产物）
    "config",
    "core",
    "extensions",
    "gui",
    "hooks",
    "img",
    "plugins",
    "profiles",
    "replay",
    "scripts",
    "sdk",
    "vendor",  # agent_core 等纯源码依赖，无密钥
    "tools",   # App 逆向说明目录（不含 jar/exe/jre）
    "mcp_server",  # MCP 服务（供外部智能体调用）
]

INCLUDE_FILES = [
    ".gitignore",
    "README.md",
    "requirements.txt",
    "config.yaml",
    "algorithms.py",
    "body_parser.py",
    "codegen.py",
    "encoding_utils.py",
    "forwarder.py",
    "gui.py",
    "handler.py",
    "main.py",
    "mitmdump_entry.py",
    "signers.py",
    "sm_crypto.py",
]

EXCLUDE_DIR_NAMES = {
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".git",
    ".idea",
    ".vscode",
    ".mitmproxy",
    "build",
    "workspace",
    "github",
    "portable",
    "node_modules",
    "dist",
    "out",  # burp_ext/out 等构建输出
    "data",  # 浏览器档案 / 本地缓存，勿发布
    "agent-transcripts",
}

EXCLUDE_FILES = {
    "ai.yaml",
    "CLAUDE.md",
    "test_wxapkg.py",
    "export_github.py",
    "_scan_github_export.py",
    "pack_to_github.cmd",
    "desktop.ini",
    "Thumbs.db",
    ".DS_Store",
    "package-lock.json",  # 体积大且可由 npm i 再生；保留 package.json
    # 本地靶场/探测脚本，勿随源码发布
    "probe_paidui_blank.py",
    "fetch_paidui_js.py",
    "test_env_bypass_fpscanner.py",
    "encrypt_labs_app.js",
}

EXCLUDE_SUFFIXES = {".pyc", ".pyo", ".cbproj.zip", ".log"}

GITIGNORE = """# Python
__pycache__/
*.py[cod]
*.egg-info/
.venv/
venv/
env/

# 打包临时目录
build/
build/portable/

# IDE
.idea/
.vscode/
*.swp
*.swo

# 本地配置与密钥（勿提交）
config/ai.yaml
.env
.env.*

# 用户生成的项目（保留 _template 模板与 plugin 基类）
profiles/*.yaml
!profiles/_template*.yaml
profiles/*_proxy.pac

plugins/*/
!plugins/plugin.py
!plugins/__init__.py

# 项目导出包（可能含密钥/抓包数据）
*.cbproj.zip

# 小程序反编译 / 抓包工作区
workspace/
!workspace/.gitkeep

# mitmproxy 证书
.mitmproxy/

# App 逆向绿色工具（体积大，本机自备）
tools/apktool/*.jar
tools/jadx-gui/*.exe
tools/jadx-gui/jre/
tools/burp/*.jar

# Burp 扩展构建产物
burp_ext/out/

# 浏览器扩展下载与本机生成
browser_ext/vendor/
browser_ext/scripts/
data/browser_profile/
data/browser_profile_chrome/

# 系统
.DS_Store
Thumbs.db
desktop.ini
"""


def should_skip(rel: Path) -> bool:
    if set(rel.parts) & EXCLUDE_DIR_NAMES:
        return True
    if rel.name in EXCLUDE_FILES:
        return True
    if rel.suffix.lower() in EXCLUDE_SUFFIXES:
        return True

    # tools: 只导出说明与空目录，不打包 jar/exe/jre（GitHub 大文件）
    if rel.parts and rel.parts[0] == "tools":
        if "jre" in rel.parts:
            return True
        if rel.suffix.lower() in {".jar", ".exe", ".dll"}:
            return True

    # browser_ext: 源码与说明可提交；vendor/scripts 为本机下载/生成
    if rel.parts and rel.parts[0] == "browser_ext":
        if len(rel.parts) >= 2 and rel.parts[1] in ("vendor", "scripts"):
            return True

    # burp_ext: 源码可提交；out/ 为 javac 产物
    if rel.parts and rel.parts[0] == "burp_ext":
        if "out" in rel.parts:
            return True

    # plugins: only base files, not user project folders
    if len(rel.parts) >= 2 and rel.parts[0] == "plugins":
        second = rel.parts[1]
        if second not in ("plugin.py", "__init__.py"):
            return True

    # profiles: templates only
    if len(rel.parts) >= 2 and rel.parts[0] == "profiles":
        fname = rel.name
        if fname.endswith(".yaml") and not fname.startswith("_template"):
            return True
        if fname.endswith(".pac"):
            return True

    return False


# ---------------------------------------------------------------------------
# 敏感信息 / 测试数据扫描（打包门禁）
# ---------------------------------------------------------------------------

_BINARY_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".svg", ".ico", ".gif", ".bin",
    ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".7z",
    ".jar", ".exe", ".dll", ".so", ".dylib",
}

# 路径/文件名黑名单（测试产物、本机档案）
_FORBIDDEN_PATH_PARTS = {
    "browser_profile",
    "browser_profile_chrome",
    "browser_agent_profile",
    "browser_agent_profile_chrome",
    "paidui_js",
    "env_bypass",
    "apk_decode",
    "miniprogram",
}

_FORBIDDEN_NAME_RES = (
    re.compile(r"^paidui_", re.I),
    re.compile(r"^env_bypass_", re.I),
    re.compile(r"encrypt_labs", re.I),
    re.compile(r"probe_paidui", re.I),
    re.compile(r"fpscanner", re.I),
    re.compile(r"\.cbproj\.zip$", re.I),
    re.compile(r"^ai\.yaml$", re.I),
    re.compile(r"^\.env", re.I),
    re.compile(r"credentials", re.I),
    re.compile(r"secret", re.I),
)

# 内容黑名单：测试站 / 真实业务痕迹（通用靶场探测勿进仓库）
_TEST_HOST_RES = (
    re.compile(r"paidui\.coc\.10086\.cn", re.I),
    re.compile(r"gjy\.icbc\.com\.cn", re.I),
    re.compile(r"localhost:3000/test/dev-source", re.I),
    re.compile(r"192\.168\.\d{1,3}\.\d{1,3}/encrypt-labs", re.I),
    re.compile(r"ddtk=f7eac1bcf71c4f8927814e30435e1d3e", re.I),
)

# 敏感内容模式
_SECRET_RES: list[tuple[str, re.Pattern[str]]] = [
    ("openai-sk", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    ("aws-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-pat", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    ("github-oauth", re.compile(r"\bgho_[A-Za-z0-9]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("api_key_yaml", re.compile(r"(?im)^\s*api_key\s*:\s*['\"]?(?!your-api-key|changeme|xxx|<'|\s*$)[^\s'\"]{8,}")),
    ("password_assign", re.compile(r"(?i)(password|passwd|secret_key)\s*=\s*['\"][^'\"]{6,}['\"]")),
]

# 允许的假阳性片段（文档示例 / 占位符）
_ALLOW_SNIPPETS = (
    "your-api-key",
    "your_api_key",
    "api_key_here",
    "sk-xxx",
    "sk-test",
    "sk-example",
    "changeme",
    "password123",
    "example.com",
    "BEGIN PUBLIC KEY",  # 公钥可公开；私钥另检
    "1234567890123456",  # 常见靶场固定 AES 教学密钥（文档）
)


def _is_allowed_context(text: str, match: str) -> bool:
    """命中附近若是占位符/示例，则放行。"""
    low = text.lower()
    mlow = match.lower()
    for a in _ALLOW_SNIPPETS:
        if a.lower() in mlow or a.lower() in low:
            # 仅当允许词与命中相关或文件整体是示例配置
            if a.lower() in mlow or "example" in low or "placeholder" in low:
                return True
    # yaml example 文件整体放宽 api_key 占位
    return False


def _scan_path_issues(dest: Path) -> list[str]:
    hits: list[str] = []
    for f in dest.rglob("*"):
        if not f.is_file():
            continue
        rel = f.relative_to(dest)
        parts_l = {p.lower() for p in rel.parts}
        for bad in _FORBIDDEN_PATH_PARTS:
            if bad.lower() in parts_l:
                hits.append(f"{rel} [路径禁区:{bad}]")
                break
        for rx in _FORBIDDEN_NAME_RES:
            if rx.search(rel.name):
                # workspace/.gitkeep、ai.yaml.example 例外
                if rel.name.endswith(".example") or rel.name == ".gitkeep":
                    continue
                if rel.as_posix() == "workspace/.gitkeep":
                    continue
                hits.append(f"{rel} [文件名禁区:{rx.pattern}]")
                break
        # 用户插件目录不应出现
        if len(rel.parts) >= 2 and rel.parts[0] == "plugins" and rel.parts[1] not in (
            "plugin.py",
            "__init__.py",
        ):
            hits.append(f"{rel} [用户插件目录]")
        if (
            len(rel.parts) >= 2
            and rel.parts[0] == "profiles"
            and rel.name.endswith(".yaml")
            and not rel.name.startswith("_template")
        ):
            hits.append(f"{rel} [用户 profile]")
    return hits


def _scan_content_issues(dest: Path) -> list[str]:
    hits: list[str] = []
    for f in dest.rglob("*"):
        if not f.is_file():
            continue
        if f.suffix.lower() in _BINARY_SUFFIXES:
            continue
        # 过大文件跳过正文正则（防误扫压缩包文本）
        try:
            size = f.stat().st_size
        except OSError:
            continue
        if size > 2_000_000:
            hits.append(f"{f.relative_to(dest)} [文件过大>{size}]")
            continue
        try:
            data = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(f.relative_to(dest))
        low = data.lower()

        # 已知历史泄露
        if "sk-373d018548cb4e47bd2a93997d2c559a" in data:
            hits.append(f"{rel} [历史 API Key]")

        for rx in _TEST_HOST_RES:
            if rx.search(data):
                hits.append(f"{rel} [测试站/靶场:{rx.pattern}]")

        # ai.yaml 真实密钥
        if f.name == "ai.yaml" and "api_key:" in data:
            if "your-api-key" not in low and "changeme" not in low:
                hits.append(f"{rel} [ai.yaml 含真实配置]")

        for label, rx in _SECRET_RES:
            for m in rx.finditer(data):
                token = m.group(0)
                # 公钥块不算私钥
                if label == "private-key" and "PUBLIC KEY" in token:
                    continue
                # 密码赋值：过滤明显示例
                if label == "password_assign" and any(
                    x in token.lower() for x in ("example", "demo", "test", "xxx", "changeme")
                ):
                    continue
                # sk- 占位
                if label == "openai-sk" and (
                    "example" in low
                    or "your-api-key" in low
                    or "placeholder" in low
                    or token.lower() in ("sk-xxxxxxxx", "sk-xxx")
                ):
                    # 仍检查是否像真 key（长度够长且非全 x）
                    body = token[3:]
                    if set(body.lower()) <= set("x-_"):
                        continue
                    if "example" in low and len(body) < 40:
                        continue
                if _is_allowed_context(data[max(0, m.start() - 80) : m.end() + 80], token):
                    # openai-sk 真 key 即使附近有 example 也不放：长度>=48 仍报
                    if label == "openai-sk" and len(token) >= 51:
                        pass
                    else:
                        continue
                hits.append(f"{rel} [{label}:{token[:24]}…]")
                break  # 每文件每类报一次
    return hits


def scan_export(dest: Path) -> list[str]:
    """扫描导出目录，返回问题列表（空=通过）。"""
    issues = _scan_path_issues(dest) + _scan_content_issues(dest)
    # 去重保序
    seen: set[str] = set()
    out: list[str] = []
    for x in issues:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def main(dest: Path | None = None) -> int:
    global DEST
    if dest is not None:
        DEST = Path(dest)
    print("ROOT", ROOT)
    print("DEST", DEST)
    if DEST.exists():
        shutil.rmtree(DEST)
    DEST.mkdir(parents=True)

    copied = 0

    for name in INCLUDE_FILES:
        src = ROOT / name
        if not src.exists():
            print("MISSING FILE", name)
            continue
        if should_skip(Path(name)):
            continue
        dst = DEST / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        copied += 1

    for dname in INCLUDE_DIRS:
        src_root = ROOT / dname
        if not src_root.exists():
            print("MISSING DIR", dname)
            continue
        for src in src_root.rglob("*"):
            rel = src.relative_to(ROOT)
            if should_skip(rel):
                continue
            dst = DEST / rel
            if src.is_dir():
                dst.mkdir(parents=True, exist_ok=True)
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            copied += 1

    (DEST / "workspace").mkdir(exist_ok=True)
    (DEST / "workspace" / ".gitkeep").write_text("", encoding="utf-8")
    (DEST / "plugins").mkdir(exist_ok=True)

    ai = DEST / "config" / "ai.yaml"
    if ai.exists():
        ai.unlink()
        print("REMOVED leaked ai.yaml")

    (DEST / ".gitignore").write_text(GITIGNORE, encoding="utf-8")

    print("\n======== 敏感/测试数据扫描 ========")
    issues = scan_export(DEST)
    total = sum(f.stat().st_size for f in DEST.rglob("*") if f.is_file())
    nfiles = sum(1 for f in DEST.rglob("*") if f.is_file())
    print("copied", copied)
    print("files", nfiles, "bytes", total)
    print("top", sorted(p.name for p in DEST.iterdir()))
    print("ai.yaml present?", (DEST / "config" / "ai.yaml").exists())
    print("ai.example present?", (DEST / "config" / "ai.yaml.example").exists())
    print("burp_ext?", (DEST / "burp_ext").exists())

    if issues:
        print(f"\n[FAIL] 发现 {len(issues)} 处敏感/测试数据，禁止发布：")
        for i, line in enumerate(issues[:80], 1):
            print(f"  {i}. {line}")
        if len(issues) > 80:
            print(f"  … 另有 {len(issues) - 80} 条")
        print("\n已保留导出目录供排查；请清理源码后重新打包。")
        return 1

    print("\n[OK] 扫描通过：未发现敏感密钥 / 测试站 / 用户项目数据")
    print("发布目录:", DEST)
    return 0


if __name__ == "__main__":
    dest_arg = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    raise SystemExit(main(dest_arg))
