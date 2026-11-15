# 密桥 CipherBridge

面向 APP / Web 加解密逆向分析、渗透测试人员的可视化解密框架。

作者：**W啥都学** · 当前版本 **V6.5**（2026.11）

## 为什么选择 CipherBridge？

在 APP 逆向、安全测试和接口联调过程中，经常会遇到：

- 请求体经过 AES / DES / SM4 等加密
- 参数或请求头带有 MD5 / SHA256 / HMAC 等签名
- Burp Suite 抓到的全是密文，无法直接改包重放

密桥就是为了解决这些问题而生的：在本地搭一条

**浏览器 / APP → 解密端 → Burp → 加密端 → 服务器**

的代理链，让你在 Burp 里改明文，两端自动加解密。

## V6.5 更新（当前版本 · 2026.11）

- **AI 浏览器绕过 Agent**  
  独立「绕过 Bot / 挑战」窗口：全量策略扫描（拟真 / 真实 / CDP / 反 DevTools 等）+ 实时通关，也可只扫策略；通关后可一键同步实验室浏览器选项

- **浏览器拟真与反检测**  
  UA / locale / 时区、隐藏 webdriver、JS 挑战重试；反 DevTools 中和可开关（减轻闪一下变 `about:blank`）

- **多模式 Agent**  
  分析密钥 / 分析加密 / 生成解密插件等；可指定请求·响应字段，减少盲目猜测；上下文详情改为可读全文展示

- **加解密自动验证 + AI 修正**  
  生成后对采样流量试算；失败回灌 AI 修正步骤（多轮），并提示不可逆 Hash / HMAC 场景

- **混合加密识别增强**  
  更稳地识别 AES+RSA、会话密钥等混合方案

- **Web UI（FastAPI）**  
  `python -m web` 启动浏览器版，能力对齐桌面：AI 实验室、解析器、构建器、项目管理、代理启停

- **桌面 / Web 双入口**  
  `python gui.py`（PyQt6）与 `python -m web` 共用同一套项目、插件与配置

## 历史版本摘要

<details>
<summary>V5.0（2026.8）</summary>

- 界面抛光：主 Tab / AI 实验室分段、采集栏与 Agent 输入区、彩色图标
- Bypass Hook：选定加密 / 哈希路径改成恒等，明文进 Burp，再「生成加密」
- 密桥 Hook 扩展：弹窗可切换代理（直连 / 解密端 / Burp / 自定义）
- Burp 扩展源码（`burp_ext/`）：上游桥接 + 右键「发送到密桥」
- 不可逆算法提示；目标字段绑定

</details>

<details>
<summary>V4.0 / V3.x</summary>

- **4.0**：AI 实验室加解密 / 反调试分离；debugger 改写、CDP、油猴 + ReRes + 密桥 Hook
- **3.5**：内置代理浏览器、小程序反编译与 AI Agent 优化
- **3.1**：小程序反编译、AI Agent 初版

</details>

## 核心特性

- 一分钟拆出加解密链路
- 浏览器 Hook / 小程序 / App + AI Agent 自动分析生成脚本
- 可视化配置 AES / DES / 3DES / SM4 / RSA 等加解密流程
- 自动生成可直接 `mitmdump -s` 加载的插件代码
- Burp Suite 双向加解密桥接 + 扩展联动
- 自定义 Python 扩展函数
- 内置加解密测试与编码识别（Base64 / Hex / JWT 等）
- 项目导入导出（`.cbproj.zip`）
- 深色 / 浅色主题
- PyQt6 桌面版 + Web UI
- MCP Server：外部智能体可查询项目 / 试算加解密
- Windows / macOS / Linux

## 环境要求

- Python 3.10+
- Windows / macOS / Linux
- （可选）JDK：仅自行编译 `burp_ext` 时需要

## 安装

```bash
git clone https://github.com/CuriousLearnerDev/CipherBridge.git
cd CipherBridge

pip install -r requirements.txt
playwright install chromium

# 桌面 GUI
python gui.py

# 或 Web UI（默认 http://127.0.0.1:8787）
python -m web
# python -m web --host 0.0.0.0 --port 8787
```

### MCP Server（可选）

```bash
pip install "mcp>=1.26,<2" attrs
python -m mcp_server
```

配置与工具列表见 [`mcp_server/README.md`](mcp_server/README.md)。

## 代理拓扑

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/e2f83ef5-edda-4dbf-a8f0-cf24bbc920a1.png)

> 解密端收到密文，解密后交给 Burp；Burp 改完请求后由加密端重新加密发出。  
> 若只需单向解密调试，可只启动解密端。  
> 左侧「打开代理浏览器」可经解密端端口打开 Chromium；AI「网页」启动浏览器时也可自动接入解密端。

通过 AI 生成代码后，浏览器走密桥解密，Burp 设置上游代理再走密桥加密发往服务器：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/11a692ec6c18111830149fe1a79d3605.png)

## 界面预览

### 首页

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20261008165927261.png)

### AI 自动化分析

点击「启动」后会打开浏览器，自动采集页面 JS 以及请求/响应数据，并尝试按内置规则匹配加解密方式。规则未命中时可使用 AI 辅助分析。

支持多种前端检测绕过模式：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/214825548bf48b1ceed5eb6291403c92.png)

可选择 HOOK 功能绕过检测：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/d96a171f9962c8ab2892bfd35d138cc3.png)

分析加解密时可指定字段，减少偏移：

![image-20261008171443260](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20261008171443260.png)

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/6bdabe1ae27017230ae7461a21301ea0.png)

支持查看 AI 分析上下文：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/ae3eaa243aa6fe1fa3fbfa805fb49143.png)

分析完成后会自动验证加解密是否正确：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/1658424ee69c1a5f4af9fc471542e9d2.png)

可继续生成加解密代理代码：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20261008171607904.png)

生成的代理代码支持右键把请求转到解析器里测试：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/0dd48f43ee0500572d733691b4929dbe.png)

多模式 Agent：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/97d79aa96f9d2bca3eb29c80afa4465c.png)

可定位加解密代码位置：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/6a21b1adcd26a1bbdff10c8b30defcf5.png)

AI 绕过前端检测：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20261008171752115.png)

可在密桥内直接打开浏览器并设置挂载：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20261008170630668.png)

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/7b027ac9bf1bfe8eec68b5f896e003d5.png)

可直接走密桥加密或解密，再转发到 Burp：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/11a692ec6c18111830149fe1a79d3605.png)

> 点击左侧流量列表时，请求/响应详情显示在「请求/响应」Tab，不会覆盖 AI 分析结果。

**Bypass Hook**：当加密函数可 Hook 时，可让选定字段以明文进入 Burp，便于改包；确认链路后再「生成加密」写回加密端插件。

### 请求解析器

可右键把请求流量放到解析器：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20261008170859269.png)

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20261008170942322.png)

选择解密方式并填写密钥等参数：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20261008171019098.png)

填写后自动生成代码，可整体测试查看结果：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20261008171829015.png)

### 可视化构建器

无需粘贴报文，可通过步骤列表构建加解密流程，并提供多个案例模板：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20261008172047500.png)

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20261008172124989.png)

### 插件编辑器

复杂逻辑（字符串反转、前后缀拼接、远程取签名等）可在「插件编辑器」编写自定义 Python 函数：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20261008172154710.png)

保存后可在配置步骤时从下拉列表选用：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20261008172224329.png)

### 加密分析

自动识别可能的编码类型（Base64 / Hex / JWT 等）：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20261008172306696.png)

### Burp 扩展

源码在 `burp_ext/`，可用 `python burp_ext/build.py` 编译。预编译 JAR 说明见 `tools/burp/`（体积较大，仓库不附带 jar，需本机构建或按说明放置）。

典型能力：

- 与密桥解密 / 加密端上游协同
- 右键将流量「发送到密桥」AI 实验室继续分析

### 导入导出

左侧项目选择旁的 **⋯** 菜单 →「导出项目…」/「导入项目…」。

每个加解密方案 = 一个独立项目：

```
profiles/{name}.yaml     # 项目配置（名称、角色、匹配规则）
plugins/{name}/
├── plugin.py            # 生成的 mitmdump 插件（mitmdump -s 直接加载）
└── state.json           # 可视化步骤与解析器状态（自动保存，git 忽略）
```

**`.cbproj.zip` 包内文件**

| 文件 | 内容 |
|------|------|
| `manifest.json` | 格式版本、导出时间 |
| `profile.yaml` | 项目配置 |
| `plugin.py` | 加解密插件代码 |
| `state.json` | 可视化步骤（可选） |

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20261008172329291.png)

## HTTPS 证书

解密 HTTPS 流量需要信任 mitmproxy 根证书：

1. 左侧解密端区域查看证书状态
2. 点击「HTTPS 证书」或「设置」→「安装 HTTPS 证书」
3. Windows 支持一键安装；macOS / Linux 会打开证书文件，需手动导入系统信任
4. 重启浏览器后访问 `https://mitm.it` 验证

## 加载方式

「设置」中可选择 mitmdump 加载方式：

| 模式 | 说明 |
|------|------|
| **plugin.py 直接**（默认） | `mitmdump -s plugins/{name}/plugin.py`，改代码后重启即生效 |
| **main.py 框架** | `mitmdump -s main.py`，通过环境变量 `PROFILE` 加载，含匹配 / 日志钩子 |

## 配置

| 文件 | 说明 |
|------|------|
| `config/settings.yaml` | 界面主题（`dark` / `light`）、默认端口等 |
| `config/ai.yaml` | AI 自动化分析 API Key（复制 `config/ai.yaml.example`） |

主题切换：左侧「设置」→「界面主题」→ 保存，即时生效。

## 命令行启动（无需 GUI）

```bash
# 直接加载生成的插件
mitmdump -s plugins/myapp/plugin.py -p 8083

# 框架模式
set PROFILE=myapp          # Windows
export PROFILE=myapp       # macOS / Linux
mitmdump -s main.py -p 8083
```

## 目录说明

```
gui.py                 # PyQt6 GUI 入口
web/                   # Web UI（FastAPI + 静态页）
codegen.py             # 步骤 → 插件代码生成
sdk/                   # 加解密 / 签名 / 编码纯函数库
extensions/            # 自定义扩展（可在构建器中选用）
core/                  # 主题、项目 IO、证书、AI、浏览器实验室等
browser_ext/           # 密桥 Hook / ReRes 扩展源码
burp_ext/              # Burp 扩展 Java 源码
mcp_server/            # MCP Server（Cursor 等智能体可调用）
hooks/                 # 浏览器 Hook 脚本
profiles/              # 项目配置（模板可提交；用户方案 git 忽略）
plugins/               # 各项目生成的插件（用户方案 git 忽略）
tools/                 # App 逆向 / Burp 说明（不含大体积 jar/exe）
config/                # settings + ai.yaml.example
```

## 安全提示

本工具用于**本地安全测试与逆向分析**，请勿在未授权环境使用。

- mitmdump 默认 `--ssl-insecure`，会解密 HTTPS 流量
- `extensions/` 下的自定义代码会被动态加载执行
- 勿将含真实密钥的项目包（`.cbproj.zip`）、`config/ai.yaml`、抓包数据提交到公开仓库
- 上传前可用仓库内导出脚本生成干净的 `github/` 目录（已排除密钥、用户项目、`node_modules`、jar 等）

## 免责声明

CipherBridge 是一款面向 APP/Web 加解密分析、逆向工程、安全测试及教学研究的开源工具。

本项目旨在帮助安全研究人员、开发者和企业提升安全分析、协议调试、接口联调及漏洞验证效率，仅供合法授权的安全测试、教育培训、学术研究和个人学习使用。

使用本项目即表示您理解并同意以下内容：

1. **禁止任何非法用途**
   - 禁止将本项目用于任何未经授权的网络攻击、数据窃取、恶意破解、破坏计算机信息系统等违法行为。
   - 使用者应自行确保其行为符合所在国家或地区的法律法规。

2. **合法授权原则**
   - 对任何目标进行测试、逆向分析或流量处理前，请确保已获得目标系统所有者的明确授权。
   - 未经授权的测试行为所产生的一切法律责任由使用者自行承担。

3. **风险自负**
   - 本项目按 "AS IS"（现状）提供，不提供任何形式的明示或暗示担保，包括但不限于适销性、特定用途适用性及非侵权保证。
   - 作者及贡献者不对因使用或无法使用本项目导致的任何直接、间接、附带或后续损失承担责任。

4. **第三方软件**
   - 本项目可能集成或调用第三方开源组件（如 mitmproxy、Playwright 等），其使用需遵循各自许可证及相关规定。

5. **AI 生成内容**
   - 本项目部分功能可能依赖 AI 自动生成代码、脚本或配置。
   - AI 输出结果仅供参考，使用者应自行审核其正确性、安全性及合法性。

6. **开源协议**
   - 本项目遵循仓库所附 LICENSE 文件发布。
   - 使用、修改、分发本项目时，请遵守对应开源许可证。

如果您不同意上述内容，请立即停止使用本项目。

**W啥都学出品**

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/zuozgzh.png)
