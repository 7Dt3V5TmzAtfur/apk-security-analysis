# APK 恶意行为安全分析 — 经验沉淀文档

> **分析对象**: Stream0520.apk（伪装"Stream抓包"）
> **分析日期**: 2026-05-16
> **文档类型**: 专业经验总结

---

## 一、问题背景

### 1.1 触发场景
用户获得一个名为 `Stream0520.apk` 的 Android 应用安装包，应用显示名称为"Stream抓包"，需要判断该应用是否存在个人信息被盗取并上传至远程服务器的恶意行为。

### 1.2 问题定性
这是一个典型的 **Android APK 逆向安全审计** 任务，核心目标是：
- 识别应用的真实功能与宣称功能是否一致
- 检测是否存在未经授权的个人信息收集行为
- 追踪数据外传的目标服务器
- 评估整体风险等级

---

## 二、分析思路与框架

### 2.1 总体分析策略

采用 **由表及里、逐层深入** 的分析策略，分为五个阶段：

```
静态信息提取 → 权限与组件分析 → 代码行为分析 → 网络通信分析 → 综合研判
```

### 2.2 分析维度矩阵

| 维度 | 分析内容 | 关键指标 |
|------|---------|---------|
| 身份特征 | 包名、应用名、签名、类名 | 是否随机/伪装 |
| 权限声明 | AndroidManifest 权限列表 | 敏感权限数量与组合 |
| 组件暴露 | Activity/Service/Receiver/Provider | 可疑组件及命名 |
| 代码行为 | 反编译字节码分析 | 个人信息API调用 |
| 网络通信 | URL/域名/IP 提取 | 数据外传目标 |
| 原生库 | .so 文件分析 | 隐蔽功能模块 |
| 第三方SDK | 嵌入SDK识别 | 数据收集能力 |

---

## 三、关键发现

### 3.1 伪装特征识别

本次分析总结出以下 **恶意/灰色应用常见伪装手法**：

| 伪装手法 | 本案例表现 | 检测方法 |
|---------|-----------|---------|
| 包名随机化 | `cn.mxcxt.azfietux` 无意义随机字符串 | 检查包名是否与开发者/功能相关 |
| 类名伪装 | `org.apache.MainActivity` 冒充 Apache 开源项目 | 检查类名是否与知名框架重名 |
| 功能欺诈 | 名为"抓包工具"实为影视网站浏览器 | 对比宣称功能与实际代码行为 |
| 广告SDK虚假注册 | 以"极速照片恢复"名义注册广告ID | 检查SDK初始化参数中的应用名 |

### 3.2 个人信息收集路径

```
用户设备
    │
    ├── 设备标识符 (IMEI/IMSI/Android ID/序列号)
    │   └── 收集方: 友盟SDK、穿山甲SDK、快手SDK
    │   └── 上传至: ulogs.umeng.com, tobapplog.ctobsnssdk.com
    │
    ├── GPS位置信息
    │   └── 收集方: 穿山甲SDK、快手SDK
    │   └── 上传至: pangolin.snssdk.com, open.e.kuaishou.com
    │
    ├── 已安装应用列表
    │   └── 收集方: 穿山甲SDK
    │   └── 上传至: sdfp.snssdk.com (设备指纹)
    │
    └── 用户行为日志
        └── 收集方: 友盟SDK、字节跳动EmbedAppLog
        └── 上传至: pslog.umeng.com, tobapplog.ctobsnssdk.com
```

### 3.3 恶意行为清单

1. **WebView 套壳** — 核心功能仅为加载第三方网站，无自主功能
2. **按键拦截** — 拦截返回键和 Home 键阻止用户退出
3. **欺诈页面** — BlackActivity 显示"一键激活"诱导点击
4. **动态代码加载** — 快手SDK从服务器下载并执行 .apk/.so 文件
5. **多SDK聚合** — 同时嵌入5个第三方数据收集SDK，最大化数据采集

### 3.4 关键代码证据

**MainActivity 核心逻辑（反编译字节码）**：
```
WebView.loadUrl("https://www.8gdyhd.com")    // 加载盗版影视站
WebView.setWebViewClient(...)                  // 设置自定义客户端
WebSettings.setJavaScriptEnabled(true)         // 启用JavaScript
onKeyDown: 拦截 KEYCODE_BACK (4)              // 阻止返回
```

**GoogleLogin 虚假注册**：
```
SdkConfig.Builder.appId("1131700001")          // 快手广告ID
SdkConfig.Builder.appName("极速照片恢复")       // 虚假应用名
```

---

## 四、解决方案

### 4.1 本次分析的技术方案

由于分析环境中没有预装 Android 逆向工具（apktool、jadx 等），采用了以下替代方案：

| 步骤 | 工具/方法 | 说明 |
|------|----------|------|
| APK解包 | PowerShell `Expand-Archive` | APK 本质是 ZIP 格式 |
| 清单解析 | Python `androguard` 库 | 解析二进制 AndroidManifest.xml |
| DEX反编译 | Python `androguard` 库 | 提取类结构和方法字节码 |
| 字符串提取 | Python 自定义脚本 | 从二进制中提取可读字符串 |
| 模式匹配 | Python 正则表达式 | 搜索URL、权限、API调用等 |
| 原生库分析 | Python 字符串提取 | 分析 .so 文件中的符号和URL |

### 4.2 工具链推荐

对于未来的 APK 分析任务，推荐以下工具组合：

```
首选方案（需预装）:
  jadx          — DEX 反编译为 Java 源码（最推荐）
  apktool       — APK 解包/重打包，Smali 代码
  dex2jar       — DEX 转 JAR

备选方案（纯 Python）:
  androguard    — Python APK/DEX 解析库
  + 自定义脚本  — 字符串提取、模式匹配

在线辅助:
  VirusTotal    — 多引擎扫描
  在线沙箱      — 动态行为分析
```

---

## 五、经验总结

### 5.1 分析效率优化

1. **先广后深**：先快速扫描整体结构（包名、权限、组件），定位可疑点后再深入代码
2. **字符串优先**：在反编译之前，先用 strings 提取可读字符串，URL 和 API 调用往往直接暴露意图
3. **SDK 识别**：第三方 SDK 的包名有规律（com.bytedance、com.kwad、com.qq.e），快速识别可判断数据收集能力
4. **关注异常**：随机包名、伪装类名、虚假应用名、按键拦截都是强恶意信号

### 5.2 关键判断规则

| 信号 | 风险等级 | 说明 |
|------|---------|------|
| 包名随机无意义 | 🔴 高 | 典型恶意软件特征 |
| 类名伪装知名项目 | 🔴 高 | 如 org.apache.* |
| 功能与名称不符 | 🔴 高 | WebView套壳最常见 |
| 拦截系统按键 | 🔴 高 | 阻止用户退出 |
| 嵌入3个以上广告SDK | 🟡 中 | 数据收集能力强 |
| 动态加载远程代码 | 🔴 高 | 可执行任意代码 |
| 使用虚假名注册SDK | 🔴 高 | 故意隐藏身份 |

### 5.3 常见误区

1. ❌ **认为有广告SDK就是恶意的** — 正规应用也可能嵌入广告SDK，关键是看是否过度收集+伪装身份
2. ❌ **只看权限不看代码** — 声明了权限不代表实际使用，需在代码中确认调用
3. ❌ **忽略原生库(.so)** — 很多恶意行为隐藏在 native 代码中，如 `libumeng-spy.so`
4. ❌ **只看主代码不看SDK** — 个人信息往往通过第三方SDK收集，而非应用自身代码

### 5.4 可复用的检测模式

```
恶意套壳应用特征模型:
  IF 包名 = 随机字符串
  AND 主Activity = WebView加载第三方URL
  AND 嵌入 >= 2个广告SDK
  AND (拦截系统按键 OR 使用虚假应用名)
  THEN 高风险恶意应用
```

---

## 六、附录

### 6.1 本次分析文件清单

| 文件 | 说明 |
|------|------|
| `拆包看是否被盗用.txt` | 详细分析报告 |
| `APK安全分析经验文档.md` | 本文档 |
| `sop/APK安全分析SOP.md` | 标准操作程序 |
| `skills/apk-security-analysis.md` | Claude Code Skills 文件 |

### 6.2 参考资料

- Android 权限列表: https://developer.android.com/reference/android/Manifest.permission
- Androguard 文档: https://androguard.readthedocs.io/
- OWASP Mobile Security Testing Guide: https://owasp.org/www-project-mobile-security-testing-guide/

---

> **文档版本**: v1.0
> **最后更新**: 2026-05-16