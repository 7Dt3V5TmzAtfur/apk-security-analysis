# APK Security Analysis Toolkit

> Android APK 安全分析工具包 — 恶意行为检测 · 个人信息泄露评估 · 逆向分析 SOP · 可复用 Claude Code Skills
>
> A comprehensive toolkit for Android APK security analysis: malware detection, personal data leak assessment, reverse engineering SOPs, and reusable Claude Code Skills.

---

## 项目结构 / Project Structure

```
apk-security-analysis/
├── README.md                          # 本文件
├── APK安全分析经验文档.md               # 专业经验沉淀文档
├── 拆包看是否被盗用.txt                 # Stream0520.apk 详细分析报告
├── check_sms_contacts.py              # 短信/通讯录深度验证脚本
├── sop/
│   └── APK安全分析SOP.md              # 标准操作程序（6阶段·8决策节点）
├── skills/
│   └── apk-security-analysis.md      # Claude Code 可复用技能文件
└── stream_unpacked/                   # Stream0520.apk 解包产物（样本）
    ├── AndroidManifest.xml
    ├── classes.dex
    ├── lib/                           # 原生库（含 libumeng-spy.so）
    └── assets/                        # SDK 配置资源
```

## 快速开始 / Quick Start

### 环境准备

```bash
pip install androguard
```

### 分析一个 APK

```bash
# 1. 解包
Expand-Archive -Path "target.apk" -DestinationPath "unpacked/" -Force

# 2. 运行分析脚本
python check_sms_contacts.py   # 短信/通讯录专项检查（可修改路径复用）

# 3. 或使用 Claude Code 加载 Skills 文件一键分析
# "请使用 skills/apk-security-analysis.md 对 target.apk 进行安全分析"
```

## 文档说明 / Documentation

| 文档 | 内容 | 用途 |
|------|------|------|
| [APK安全分析经验文档.md](./APK安全分析经验文档.md) | 分析框架、关键发现、伪装手法、数据收集路径图、判断规则 | 学习参考、知识沉淀 |
| [拆包看是否被盗用.txt](./拆包看是否被盗用.txt) | Stream0520.apk 完整分析报告 | 案例参考 |
| [sop/APK安全分析SOP.md](./sop/APK安全分析SOP.md) | 6阶段标准流程、8个决策节点、风险评分矩阵 | 操作规范、团队培训 |
| [skills/apk-security-analysis.md](./skills/apk-security-analysis.md) | 一键脚本、查询模板、报告模板、恶意模式速查 | Claude Code 复用 |

## 案例：Stream0520.apk 分析结论 / Case Study

| 维度 | 结论 |
|------|------|
| **真实身份** | 伪装"Stream抓包"，实为盗版影视网站 WebView 壳 |
| **包名** | `cn.mxcxt.azfietux`（随机生成，恶意特征） |
| **个人信息收集** | ✅ 确认 — IMEI/IMSI/位置/应用列表/设备指纹 |
| **短信/通讯录** | ❌ 未发现 — 权限未声明，代码无调用 |
| **嵌入 SDK** | 5个（穿山甲、快手、腾讯广告、友盟、字节跳动日志） |
| **恶意行为** | 按键拦截、欺诈页面、虚假应用名注册、动态代码加载 |
| **风险等级** | 🔴 高风险 — 建议立即卸载 |

## 工具链 / Toolchain

| 工具 | 用途 |
|------|------|
| [androguard](https://github.com/androguard/androguard) | APK/DEX 解析、清单分析、字节码提取 |
| PowerShell `Expand-Archive` | APK 解包（APK 本质为 ZIP） |
| Python `re` + 自定义脚本 | 字符串提取、URL 匹配、模式扫描 |

## 许可 / License

MIT

---

> **注意**：本工具包仅供安全研究和学习使用。请仅分析您拥有合法权限的 APK 文件。
> **Note**: This toolkit is for security research and educational purposes only. Only analyze APK files you have legal permission to inspect.