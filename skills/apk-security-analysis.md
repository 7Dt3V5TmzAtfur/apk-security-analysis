# APK Security Analysis Skill

> **Skill 名称**: apk-security-analysis
> **版本**: v1.0
> **适用场景**: Android APK 恶意行为检测、个人信息泄露分析、应用逆向审计
> **依赖**: Python 3.x, androguard

---

## Skill 触发条件

当用户输入包含以下关键词组合时触发：
- `APK` + `分析`/`拆包`/`逆向`/`安全`/`恶意`/`盗取`/`个人信息`/`上传`

---

## 执行流程

### Phase 0: 环境准备

```powershell
# 检查 Python
python --version

# 安装依赖（如未安装）
pip install androguard

# 可选：设置代理加速
$env:HTTP_PROXY="http://127.0.0.1:7890"
$env:HTTPS_PROXY="http://127.0.0.1:7890"
```

---

### Phase 1: APK 解包

```powershell
Expand-Archive -Path "目标.apk" -DestinationPath "输出目录" -Force
```

---

### Phase 2: 清单分析（一键脚本）

```python
from androguard.core.apk import APK

apk = APK(r"APK文件路径")

print("PACKAGE:", apk.get_package())
print("APP_NAME:", apk.get_app_name())
print()
print("---PERMISSIONS---")
for p in sorted(apk.get_permissions()):
    print(p)
print()
print("---ACTIVITIES---")
for a in sorted(apk.get_activities()):
    print(a)
print()
print("---SERVICES---")
for s in sorted(apk.get_services()):
    print(s)
print()
print("---RECEIVERS---")
for r in sorted(apk.get_receivers()):
    print(r)
print()
print("---PROVIDERS---")
for p in sorted(apk.get_providers()):
    print(p)
```

---

### Phase 3: 字符串提取与关键词扫描（一键脚本）

```python
import os, re

base = r"解包目录"

# 个人信息相关关键词
keywords = [
    "imei", "imsi", "iccid", "android_id", "getDeviceId",
    "getSubscriberId", "getSimSerialNumber", "getLine1Number",
    "getLastKnownLocation", "getLatitude", "getLongitude",
    "contact", "sms", "getAccounts", "AccountManager",
    "getInstalledPackages", "clipboard", "ClipboardManager",
    "camera", "takePicture", "microphone", "AudioRecord",
    "root", "su", "magisk", "xposed",
    "proxy", "vpn", "screenshot",
    "upload", "encrypt", "base64",
    "serial", "fingerprint",
]

found = {}
for root, dirs, files in os.walk(base):
    for f in files:
        fpath = os.path.join(root, f)
        try:
            with open(fpath, "rb") as fh:
                text = fh.read().decode("utf-8", errors="ignore").lower()
                for kw in keywords:
                    if kw in text:
                        if kw not in found:
                            found[kw] = []
                        found[kw].append(os.path.relpath(fpath, base))
        except:
            pass

for kw in sorted(found.keys()):
    print(f"[{kw}] - {len(found[kw])} files")
```

---

### Phase 4: URL 与域名提取（一键脚本）

```python
import os, re

base = r"解包目录"
url_pattern = re.compile(rb'https?://[a-zA-Z0-9._\-/]+')

urls = set()
for root, dirs, files in os.walk(base):
    for f in files:
        fpath = os.path.join(root, f)
        try:
            with open(fpath, "rb") as fh:
                for m in url_pattern.finditer(fh.read()):
                    url = m.group().decode("ascii", errors="ignore")
                    if len(url) > 10:
                        urls.add(url)
        except:
            pass

# 过滤已知无害域名
skip_domains = ["android.com", "schemas.android", "w3.org", "iana.org",
                "google.com", "googlesource", "gcc.gnu", "github.com"]

for u in sorted(urls):
    if not any(skip in u.lower() for skip in skip_domains):
        print(u)
```

---

### Phase 5: DEX 反编译与主 Activity 分析（一键脚本）

```python
from androguard.core.dex import DEX
from androguard.core.analysis.analysis import Analysis

with open(r"解包目录\classes.dex", "rb") as f:
    dex = DEX(f.read())

analysis = Analysis(dex)

# 列出所有类
classes = dex.get_classes_names()
print(f"Total classes: {len(classes)}")

# 查找主应用类（排除已知SDK包名）
sdk_prefixes = ["com/bytedance", "com/ss/android", "com/kwad",
                "com/kuaishou", "com/qq/e", "com/umeng"]

for cls in dex.get_classes():
    name = cls.get_name()
    if not any(name.startswith("L" + p) for p in sdk_prefixes):
        # 打印非SDK类
        if not name.startswith("Ljava/") and not name.startswith("Landroid/"):
            print(name)
            # 打印方法
            for method in cls.get_methods():
                mname = method.get_name()
                if mname in ["onCreate", "onKeyDown", "dispatchKeyEvent",
                              "onStart", "onResume", "a", "b", "c"]:
                    print(f"  {mname}{method.get_descriptor()}")
                    code = method.get_code()
                    if code:
                        for instr in code.get_bc().get_instructions():
                            output = instr.get_output()
                            if output and len(str(output)) > 2:
                                print(f"    {instr.get_name():30s} {output}")
```

---

### Phase 6: 原生库(.so)分析（一键脚本）

```python
import os, glob

lib_dir = r"解包目录\lib\arm64-v8a"

suspicious_patterns = [
    "spy", "inject", "hook", "hide", "root", "encrypt",
    "imei", "imsi", "device", "upload", "http", "url",
    "umeng", "bytedance", "kuaishou", "tencent",
]

for lib_path in glob.glob(os.path.join(lib_dir, "*.so")):
    lib_name = os.path.basename(lib_path)
    with open(lib_path, "rb") as f:
        data = f.read()

    strings = set()
    current = b""
    for byte in data:
        if 32 <= byte < 127:
            current += bytes([byte])
            if len(current) >= 4:
                strings.add(current.decode("ascii", errors="ignore"))
        else:
            current = b""

    matches = []
    for s in strings:
        s_lower = s.lower()
        if any(p in s_lower for p in suspicious_patterns):
            matches.append(s)

    if matches:
        print(f"\n[{lib_name}] {len(matches)} suspicious strings:")
        for m in sorted(set(matches))[:20]:
            print(f"  {m}")
```

---

### Phase 7: 综合判定（决策矩阵）

```python
# 风险评分计算
risk_score = 0

# 1. 包名检查 (15分)
if package_is_random(package_name):
    risk_score += 15

# 2. 功能欺诈检查 (20分)
if is_webview_shell(activities):
    risk_score += 20

# 3. 敏感权限检查 (15分)
risk_score += min(15, count_dangerous_permissions(permissions) * 3)

# 4. 个人信息API检查 (20分)
risk_score += min(20, count_personal_data_apis(found_keywords) * 4)

# 5. 数据外传检查 (20分)
risk_score += min(20, count_external_urls(urls) * 2)

# 6. 恶意行为检查 (10分)
if has_key_interception:
    risk_score += 5
if has_fake_activation:
    risk_score += 5

# 判定
if risk_score >= 70:
    verdict = "HIGH_RISK"
elif risk_score >= 40:
    verdict = "MEDIUM_RISK"
else:
    verdict = "LOW_RISK"
```

---

## 快速查询指令模板

### 模板 1: 完整分析请求

```
请对 [APK文件路径] 进行完整的安全分析，包括：
1. 解包并提取 AndroidManifest.xml 中的权限和组件信息
2. 搜索代码中的个人信息收集 API 调用
3. 提取所有网络通信 URL 和域名
4. 反编译主 Activity 代码分析真实行为
5. 分析原生库(.so)文件
6. 给出综合风险评级和建议
```

### 模板 2: 快速筛查请求

```
请快速筛查 [APK文件路径]：
1. 包名是否随机/伪装？
2. 声明了哪些敏感权限？
3. 是否是 WebView 套壳应用？
4. 嵌入了哪些第三方 SDK？
```

### 模板 3: 深度代码分析请求

```
请对 [APK文件路径] 的 classes.dex 进行深度分析：
1. 反编译所有非 SDK 类的方法字节码
2. 追踪个人信息 API 的调用链
3. 分析数据加密和上传逻辑
```

---

## 报告模板

```markdown
# [应用名] APK 安全分析报告

## 一、基本信息
| 项目 | 内容 |
|------|------|
| 文件名 | |
| 包名 | |
| 应用名 | |
| 主Activity | |

## 二、应用真实行为
[反编译代码分析结果]

## 三、嵌入SDK清单
| SDK | 包名 | 功能 | 服务器 |
|-----|------|------|--------|
| | | | |

## 四、权限分析
| 权限 | 风险等级 | 用途分析 |
|------|---------|---------|
| | | |

## 五、个人信息收集评估
| 数据类型 | 风险等级 | 收集方式 | 上传目标 |
|---------|---------|---------|---------|
| | | | |

## 六、网络通信分析
| URL | 用途 | 风险 |
|-----|------|------|
| | | |

## 七、原生库分析
| 文件名 | 功能 | 风险 |
|--------|------|------|
| | | |

## 八、综合结论
- 风险等级: [🔴高 / 🟡中 / 🟢低]
- 风险评分: [0-100]
- 建议: []
```

---

## 常见恶意模式速查

| 模式 | 代码特征 | 判定 |
|------|---------|------|
| WebView套壳 | `WebView.loadUrl("http...")` + 无其他功能 | 恶意 |
| 按键拦截 | `onKeyDown` 中拦截 `KEYCODE_BACK(4)` | 恶意 |
| 虚假应用名 | SDK初始化 `appName` 与实际不符 | 恶意 |
| 随机包名 | 包名无意义如 `cn.xxxx.yyyyy` | 可疑 |
| 伪装类名 | 类名使用 `org.apache.*` 等知名前缀 | 可疑 |
| 动态加载 | URL 包含 `.apk` 或 `.so` 下载 | 高危 |
| 多SDK聚合 | 嵌入 >= 3 个广告/统计SDK | 可疑 |
| 设备注册 | URL 包含 `device_register` | 数据收集 |

---

## 工具调用速查

| 操作 | 工具 | 代码 |
|------|------|------|
| APK解包 | PowerShell | `Expand-Archive a.apk out/` |
| 清单解析 | androguard | `APK("a.apk").get_permissions()` |
| DEX类列表 | androguard | `DEX(f.read()).get_classes_names()` |
| 字节码提取 | androguard | `method.get_code().get_bc().get_instructions()` |
| 字符串提取 | Python | 逐字节扫描 32-126 范围 |
| URL提取 | Python re | `re.findall(rb'https?://...', data)` |
| 原生库分析 | Python | 同上字符串提取法 |

---

> **Skill 维护**: 每次分析后更新本文档，补充新发现的恶意模式和检测方法
> **版本历史**: v1.0 (2026-05-16) — 基于 Stream0520.apk 分析实战经验