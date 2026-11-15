# App 逆向工具（CipherBridge）

> **大文件不进仓库**：GitHub 不便上传 apktool / JRE 等二进制。  
> 克隆后请自行下载并放到本目录；软件缺少工具时会提示「配置工具」。

## 目录结构

```
tools/
├── README.md
├── apktool/
│   └── apktool_2.x.x.jar     ← 你自己放入（反编译必需，约 25MB）
└── jadx-gui/
    ├── jadx-gui-x.x.x.exe    ← 可选
    └── jre/                  ← 可选（体积大，一般用系统 JDK 即可）
```

## 获取方式

1. **Java（必需）**  
   安装 JDK 8+，保证终端 `java -version` 可用；或设置 `JAVA_HOME`。

2. **apktool（必需）**  
   - 下载：https://apktool.org/  
   - 把 `apktool_*.jar` 放到 `tools/apktool/`

3. **jadx-gui（可选）**  
   - 下载：https://github.com/skylot/jadx/releases  
   - 把 `jadx-gui-*.exe` 放到 `tools/jadx-gui/`

放好后回到密桥 App 页点「配置工具」刷新，或直接再点「反编译」。

## 环境变量（可选）

| 变量 | 含义 |
|------|------|
| `CIPHERBRIDGE_TOOLS` | 工具根目录 |
| `APKTOOL_JAR` | apktool jar 完整路径 |
| `JAVA_HOME` | JDK 目录 |

探测顺序：`tools/` → 环境变量 → 兼容旧版统领 `storage`。
