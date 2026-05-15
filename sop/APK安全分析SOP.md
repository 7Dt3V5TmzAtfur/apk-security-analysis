# APK 安全分析标准操作程序 (SOP)

> **文档编号**: SOP-APK-SEC-001
> **版本**: v1.0
> **适用范围**: Android APK 恶意行为检测与个人信息泄露分析
> **制定日期**: 2026-05-16

---

## 1. 目的与范围

### 1.1 目的
建立标准化的 Android APK 安全分析流程，确保每次分析的一致性、完整性和可重复性，快速判断 APK 是否存在恶意行为及个人信息泄露风险。

### 1.2 适用范围
- 来源不明的 APK 文件安全审计
- 疑似恶意应用的逆向分析
- 个人信息泄露风险评估
- 应用功能与宣称一致性验证

### 1.3 前置条件
- 获得 APK 文件
- 具备 Python 3.x 运行环境
- 网络连接（用于安装依赖工具）

---

## 2. 工具与环境准备

### 2.1 环境检查清单

```powershell
# Step 1: 检查 Python 环境
python --version

# Step 2: 检查可用工具
where apktool 2>$null    # APK 解包/重打包
where jadx 2>$null       # DEX 反编译为 Java
where java 2>$null       # Java 运行环境
```

### 2.2 工具安装

```powershell
# 方案A: 安装 androguard（Python库，必装）
pip install androguard

# 方案B: 如有 Java 环境，推荐额外安装
# jadx: https://github.com/skylot/jadx/releases
# apktool: https://apktool.org/
```

### 2.3 代理配置（可选，加速下载）

```powershell
$env:HTTP_PROXY="http://127.0.0.1:7890"
$env:HTTPS_PROXY="http://127.0.0.1:7890"
```

---

## 3. 分析流程

### 阶段一：APK 解包与基础信息提取

#### 步骤 1.1：解包 APK

```powershell
# APK 本质是 ZIP 文件，可直接解压
Expand-Archive -Path "目标.apk" -DestinationPath "输出目录" -Force
```

**产物**: 解包后的目录结构，包含：
- `AndroidManifest.xml`（二进制格式）
- `classes.dex`（Dalvik 字节码）
- `lib/`（原生库 .so 文件）
- `res/`（资源文件）
- `assets/`（附加资源）
- `META-INF/`（签名信息）

#### 步骤 1.2：解析 AndroidManifest.xml

```python
from androguard.core.apk import APK

apk = APK(r"目标.apk")

# 提取关键信息
package_name = apk.get_package()       # 包名
app_name = apk.get_app_name()          # 应用名
permissions = apk.get_permissions()    # 权限列表
activities = apk.get_activities()      # Activity 列表
services = apk.get_services()          # Service 列表
receivers = apk.get_receivers()        # BroadcastReceiver 列表
providers = apk.get_providers()        # ContentProvider 列表
```

**决策节点 1：包名合法性检查**

```
IF 包名符合以下任一条件:
  - 随机无意义字符串（如 cn.mxcxt.azfietux）
  - 与知名应用包名高度相似但有细微差异
  - 与应用名称无任何关联
THEN 标记为 [可疑] → 提高风险等级
```

**决策节点 2：类名伪装检查**

```
IF 主Activity类名符合以下任一条件:
  - 伪装成知名开源项目（如 org.apache.*）
  - 使用与功能无关的知名公司名
THEN 标记为 [伪装] → 提高风险等级
```

---

### 阶段二：权限与组件风险评估

#### 步骤 2.1：敏感权限识别

将权限按风险等级分类：

| 风险等级 | 权限示例 | 含义 |
|---------|---------|------|
| 🔴 高危 | READ_PHONE_STATE | 读取设备IMEI等 |
| 🔴 高危 | ACCESS_FINE_LOCATION | GPS精确定位 |
| 🔴 高危 | READ_CONTACTS | 读取通讯录 |
| 🔴 高危 | READ_SMS / SEND_SMS | 读取/发送短信 |
| 🔴 高危 | CAMERA | 使用相机 |
| 🔴 高危 | RECORD_AUDIO | 录音 |
| 🟡 中危 | READ_EXTERNAL_STORAGE | 读取存储 |
| 🟡 中危 | GET_TASKS | 获取运行任务 |
| 🟡 中危 | QUERY_ALL_PACKAGES | 查询所有应用 |
| 🟡 中危 | REQUEST_INSTALL_PACKAGES | 安装应用 |
| 🟢 低危 | INTERNET | 网络访问 |
| 🟢 低危 | ACCESS_NETWORK_STATE | 网络状态 |

**决策节点 3：权限风险评估**

```
IF 高危权限数量 >= 3
OR (包含定位权限 AND 包含设备标识权限 AND 包含存储权限)
THEN 标记为 [高风险权限组合] → 进入深度代码分析
```

#### 步骤 2.2：第三方 SDK 识别

通过包名模式快速识别嵌入的 SDK：

| SDK 厂商 | 包名前缀 | 典型功能 |
|---------|---------|---------|
| 字节跳动/穿山甲 | com.bytedance.*, com.ss.android.* | 广告+数据收集 |
| 快手 | com.kwad.*, com.kuaishou.* | 广告+动态加载 |
| 腾讯广告 | com.qq.e.* | 广告 |
| 友盟 | com.umeng.* | 统计+数据收集 |

**决策节点 4：SDK 数量评估**

```
IF 嵌入广告/统计SDK数量 >= 3
THEN 标记为 [数据收集能力强] → 重点关注数据外传
```

---

### 阶段三：代码行为深度分析

#### 步骤 3.1：DEX 字符串提取

```python
import re

with open("classes.dex", "rb") as f:
    data = f.read()

# 提取所有可打印字符串（长度 >= 4）
strings = set()
current = b""
for byte in data:
    if 32 <= byte < 127:
        current += bytes([byte])
        if len(current) >= 4:
            strings.add(current.decode("ascii", errors="ignore"))
    else:
        current = b""
```

#### 步骤 3.2：个人信息 API 调用检测

搜索以下关键词在 DEX 中的出现情况：

```python
personal_data_keywords = [
    # 设备标识
    "imei", "imsi", "iccid", "android_id", "getDeviceId",
    "getSubscriberId", "getSimSerialNumber", "serial", "fingerprint",
    # 位置信息
    "getLastKnownLocation", "getLatitude", "getLongitude", "GPS",
    # 通讯录与账户
    "contact", "getAccounts", "AccountManager",
    # 短信
    "sms", "getMessages",
    # 已安装应用
    "getInstalledPackages", "getInstalledApplications",
    # 剪贴板
    "clipboard", "ClipboardManager",
    # 相机与麦克风
    "camera", "takePicture", "microphone", "AudioRecord",
    # Root检测
    "root", "su", "magisk", "xposed",
    # 网络
    "proxy", "vpn",
    # 上传
    "upload", "post", "http://", "https://",
]
```

**决策节点 5：个人信息收集判定**

```
IF 代码中包含以下组合:
  (设备标识API >= 3) AND (网络请求API >= 1)
THEN 标记为 [确认收集个人信息并上传]
```

#### 步骤 3.3：主 Activity 反编译分析

```python
from androguard.core.dex import DEX
from androguard.core.analysis.analysis import Analysis

with open("classes.dex", "rb") as f:
    dex = DEX(f.read())

analysis = Analysis(dex)

# 定位主 Activity 并提取字节码
for cls in dex.get_classes():
    name = cls.get_name()
    if "MainActivity" in name:
        for method in cls.get_methods():
            if method.get_name() == "onCreate":
                code = method.get_code()
                if code:
                    for instr in code.get_bc().get_instructions():
                        print(f"  {instr.get_name():30s} {instr.get_output()}")
```

**决策节点 6：WebView 套壳检测**

```
IF MainActivity.onCreate 中包含:
  WebView.loadUrl("http...")  -- 加载远程URL
  AND 无其他实质性功能代码
THEN 标记为 [WebView套壳应用]
  → 检查加载的URL是否合法
  → 检查是否拦截系统按键
```

#### 步骤 3.4：按键拦截检测

在 `onKeyDown` 或 `dispatchKeyEvent` 方法中搜索：

```
IF 检测到 KEYCODE_BACK (4) 被拦截
OR KEYCODE_HOME (3) 被拦截
THEN 标记为 [恶意按键拦截]
```

---

### 阶段四：网络通信分析

#### 步骤 4.1：URL 与域名提取

```python
import re

url_pattern = re.compile(rb'https?://[a-zA-Z0-9._\-/]+')

urls = set()
for root, dirs, files in os.walk("解包目录"):
    for f in files:
        with open(os.path.join(root, f), "rb") as fh:
            for m in url_pattern.finditer(fh.read()):
                urls.add(m.group().decode("ascii", errors="ignore"))
```

#### 步骤 4.2：域名分类

| 类别 | 示例 | 风险 |
|------|------|------|
| 广告/统计SDK | pangolin.snssdk.com, ulogs.umeng.com | 中 |
| 设备注册/指纹 | tobapplog.ctobsnssdk.com, sdfp.snssdk.com | 高 |
| 动态代码下载 | static.yximgs.com (下载.apk) | 高 |
| 主功能网站 | 应用WebView加载的URL | 视内容而定 |
| 未知第三方 | 非SDK非官方的域名 | 高 |

**决策节点 7：数据外传判定**

```
IF 发现以下类型URL:
  - device_register (设备注册)
  - log_settings (日志配置)
  - 包含 "upload" 或 "post" 的API端点
  - 动态下载 .apk/.so/.jar 的URL
THEN 标记为 [确认数据外传]
```

---

### 阶段五：原生库(.so)分析

#### 步骤 5.1：可疑库识别

```python
# 检查 .so 文件名
suspicious_names = ["spy", "inject", "hook", "hide", "root"]
for lib in os.listdir("lib/arm64-v8a/"):
    for name in suspicious_names:
        if name in lib.lower():
            print(f"[可疑] {lib}")
```

#### 步骤 5.2：原生库字符串提取

```python
# 从 .so 文件中提取 URL 和敏感 API
for lib_path in glob("lib/**/*.so"):
    with open(lib_path, "rb") as f:
        data = f.read()
    # 提取字符串并搜索 URL、API 调用等
```

---

### 阶段六：综合研判与报告

#### 步骤 6.1：风险评分矩阵

| 维度 | 权重 | 评分标准 |
|------|------|---------|
| 包名/类名伪装 | 15% | 随机包名+5, 伪装类名+5, 虚假应用名+5 |
| 功能欺诈 | 20% | WebView套壳+10, 功能不符+10 |
| 敏感权限 | 15% | 每个高危+3, 中危+1 |
| 个人信息API | 20% | 设备ID+5, 位置+5, 通讯录+5, 短信+5 |
| 数据外传 | 20% | 设备注册+5, 日志上报+5, 动态下载+10 |
| 恶意行为 | 10% | 按键拦截+5, 欺诈页面+5 |

**决策节点 8：最终判定**

```
总分 >= 70: 🔴 高风险恶意应用 → 建议立即卸载
总分 40-69: 🟡 中风险可疑应用 → 谨慎使用
总分 < 40:  🟢 低风险正常应用 → 可正常使用
```

#### 步骤 6.2：报告模板

```markdown
# [应用名] APK 安全分析报告

## 一、基本信息
- 文件名/包名/应用名/主Activity

## 二、应用真实行为
- 反编译代码分析结果

## 三、嵌入SDK清单
- SDK名称/包名/功能/服务器

## 四、权限分析
- 敏感权限列表及风险评估

## 五、个人信息收集评估
- 按数据类型分类评估

## 六、网络通信分析
- 所有外联服务器列表

## 七、原生库分析
- .so 文件功能分析

## 八、综合结论与建议
```

---

## 4. 注意事项

### 4.1 法律与道德
- ⚠️ 仅分析自己拥有或有合法授权的 APK
- ⚠️ 不得将分析结果用于非法目的
- ⚠️ 发现恶意行为应报告相关安全机构

### 4.2 技术注意
- 二进制 `AndroidManifest.xml` 需要专门工具解析
- DEX 字符串提取会产生大量噪音，需要精准过滤
- 广告SDK收集数据是行业常态，关键是是否过度+伪装
- 原生库(.so)中的恶意代码更难检测，需要动态分析配合

### 4.3 局限性
- 静态分析无法检测运行时动态加载的代码
- 加密/混淆的字符串可能逃过字符串提取
- 反射调用的API无法通过静态字符串搜索发现
- 需要动态沙箱分析作为补充

---

## 5. 附录

### 5.1 快速检查清单

```
□ 包名是否随机/伪装？
□ 应用名与功能是否一致？
□ 主Activity是否是WebView加载远程URL？
□ 是否声明了 >= 3 个高危权限？
□ 代码中是否有 >= 3 个设备标识API？
□ 是否嵌入了 >= 2 个广告/统计SDK？
□ 是否有按键拦截代码？
□ 是否有动态下载代码的URL？
□ 原生库文件名是否包含 "spy"/"inject" 等？
□ SDK初始化是否使用了虚假应用名？
```

### 5.2 工具速查

| 工具 | 用途 | 命令示例 |
|------|------|---------|
| Expand-Archive | APK解包 | `Expand-Archive a.apk out/` |
| androguard | 清单解析 | `APK("a.apk").get_permissions()` |
| androguard | DEX分析 | `DEX(f.read()).get_classes()` |
| Python strings | 字符串提取 | 自定义脚本 |
| Python re | URL提取 | `re.findall(r'https?://...', data)` |

---

> **SOP 维护**: 每次分析后根据新发现更新本文档
> **版本历史**: v1.0 (2026-05-16) — 初始版本，基于 Stream0520.apk 分析经验