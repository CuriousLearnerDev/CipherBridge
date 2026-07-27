# 密桥 CipherBridge

面向APP/Web 加解密逆向分析、渗透测试人员的可视化解密框架

## ✨ 为什么选择 CipherBridge？

在 APP 逆向、安全测试和接口联调过程中，经常会遇到：

- 请求体经过 AES / DES / SM4 等加密
- 参数或请求头带有 MD5 / SHA256 / HMAC 等签名
- Burp Suite 抓到的全是密文，无法直接改包重放

密桥就是为了解决这些问题而生的。

## 🌉3.5版本（2026.7.27）

- 主要优化了界面
- 增加 内置浏览器
- 优化小程序反编译功能
- 优化AI agent

## 🌉3.1版本（2026.7.24）

- 增加小程序反编译功能
- 添加AI agent
- 主要优化了界面

## 🚀 核心特性

- ✨ 一分钟分出来加解密
- 🤖 浏览器 Hook/ 小程序  + AI agent 自动分析生成脚本
- 🔐 可视化配置 AES / DES / 3DES / SM4 / RSA 等加解密流程
- ✍️ 自动生成 mitmdump 插件代码
- 🌉 Burp Suite 双向加解密桥接
- 🧩 支持扩展自定义 Python 函数
- 🧪 内置加解密测试工具
- 🔍 自动识别 Base64 / Hex / JWT 等编码
- 📦 项目导入导出（`.cbproj.zip`）
- 🎨 深色 / 浅色主题切换
- 🌍 支持 Windows / macOS / Linux

## 环境要求

- Python 3.10+
- Windows / macOS / Linux

## 安装

```bash
# 克隆仓库后进入目录
git clone https://github.com/CuriousLearnerDev/CipherBridge.git
cd CipherBridge

pip install -r requirements.txt

playwright install chromium 
```

启动 GUI：

```bash
python gui.py
```

## 代理拓扑

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/e2f83ef5-edda-4dbf-a8f0-cf24bbc920a1.png)

> 解密端收到密文，解密后交给 Burp；Burp 改完请求后由加密端重新加密发出
> 若只需单向解密调试，可只启动解密端

## 📸 界面预览

### 首页

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260727130628776.png)

### AI 自动化分析

点击「启动」后会打开浏览器，自动采集页面 JS 以及请求/响应数据，并尝试按内置规则匹配加解密方式。若规则未匹配成功，可使用 AI 辅助分析。

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260727130724624.png)

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260616104243352.png)

默认不启用 AI 时，会先按内置规则识别使用的加解密算法：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260616105218603.png)

也可使用 AI 辅助分析加解密逻辑：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260616104443478.png)

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260616105450701.png)

分析完成后，可一键自动生成加解密代理代码：

![分析完成 — 生成代理](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260616110748044.png)

生成的插件代码示例：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260616110818172.png)

生成的步骤与代码会同步到「请求解析器」和「可视化构建器」：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260616110920646.png)

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260616110940326.png)

> 点击左侧流量列表时，请求/响应详情显示在「请求/响应」Tab，不会覆盖 AI 分析结果。

### 请求解析器

粘贴请求/响应报文后点击「解析」，再点击需要解密的密文字段：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260616111131907.png)

选择解密方式并填写密钥等参数：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260616111215670.png)

测试解密成功后点击「确定」：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260616111412311.png)

右侧会自动生成插件源码：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260616111456739.png)

### 可视化构建器

无需粘贴报文，可直接通过步骤列表构建加解密流程，并提供 6 个通用案例模板：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260616111658034.png)

### 插件编辑器

部分接口逻辑较复杂（如字符串反转、前后缀拼接、每次请求远程服务器获取签名字段等），可通过「插件编辑器」编写自定义 Python 函数：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260616112006339.png)

编写并保存的扩展函数，可在配置加解密步骤时从下拉列表中选择调用：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260616112111508.png)

### 加密分析

自动识别数据可能的编码类型（Base64 / Hex / JWT 等），基于本地规则匹配：

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260616112305973.png)

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260616112333191.png)

### 导入导出

若需长期对同一目标做安全测试，或需与他人协作，可使用项目导入/导出功能。左侧项目选择旁的 **⋯** 菜单 →「导出项目…」/「导入项目…」。

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
| `state.json` | 可视化步骤（可选，有则包含） |

![](https://zssnp-1301606049.cos.ap-nanjing.myqcloud.com/img/image-20260616112546242.png)

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
mitmdump -s plugins/myapp/plugin.py -p 8080

# 框架模式
set PROFILE=myapp          # Windows
export PROFILE=myapp       # macOS / Linux
mitmdump -s main.py -p 8080
```

## 目录说明

```
gui.py                 # GUI 入口
codegen.py             # 步骤 → 插件代码生成
sdk/                   # 加解密 / 签名 / 编码纯函数库
extensions/            # 自定义扩展（可在构建器中选用）
core/                  # 主题、项目 IO、证书、AI 等模块
profiles/              # 项目配置
plugins/               # 各项目生成的插件
hooks/                 # 浏览器 Hook 脚本（AI 自动化分析）
```

## 安全提示

本工具用于**本地安全测试与逆向分析**，请勿在未授权环境使用。

- mitmdump 默认 `--ssl-insecure`，会解密 HTTPS 流量
- `extensions/` 下的自定义代码会被动态加载执行
- 勿将含真实密钥的项目包（`.cbproj.zip`）提交到公开仓库



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
