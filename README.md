# openclaw-security-check-openclaw-
OpenClaw 安全巡检脚本：Gate/Inventory/APIKey 泄露审计，默认脱敏与问题摘要，支持隔离/备份删除。 OpenClaw security audit scripts: Gate/Inventory/API key leak scan, masked reports &amp; concise findings, quarantine/backup/delete support.

# OpenClaw Security Check (oc-sec)

一组面向 OpenClaw 自托管环境的“傻瓜化”安全审计脚本：  
- ✅ 安装 Skill 前先扫描（Gate）  
- ✅ 对已安装 Skill 做存量审计（Inventory）  
- ✅ 仅扫描 **API Key 明文泄露**（APIKey Leak Audit，默认过滤示例/测试/报告目录，避免自扫描与误报）

> 目标：**先给审计报告与风险点，再让你决定安装/隔离/删除/退出**。  
> 注意：这是静态扫描（正则 + 结构/路径/语境过滤），是“线索告警”，不是漏洞定性。

---

## Features / 功能一览

### 1) `openclaw-security-check`（统一入口）
交互式菜单：  
1. Skill Gate（安装前扫描）  
2. Skill Inventory（已装审计）  
3. API Key Leak Audit（仅 APIKey 泄露审计）  
（默认选 2，适合日常巡检）

### 2) `oc-skill-gate`（安装前安全闸口）
- 输入 Git URL 或本地路径
- 自动创建临时目录 `/tmp/oc_skill_gate_<ts>`，避免污染原目录
- 自动定位 `SKILL.md`（monorepo 会让你选择）
- 输出脱敏报告（结构、软链、可执行文件、高危/中危规则命中）
- HIGH 风险二次确认，避免误装

### 3) `oc-skill-inventory`（已装 Skill 存量审计）
- 自动探测 skills 目录（支持 workspace/skills、skills、find 兜底）
- 对每个 skill 输出：`RISK / report / reason`
- 风险排序输出 `summary_sorted.tsv`
- 提供后续动作：
  - `Q` 隔离到 `~/.openclaw/skills.quarantine`
  - `D` 删除（先自动打包备份到报告目录）

### 4) `oc-secrets-audit`（仅 APIKey 泄露审计）
- **只扫 API Key**（不扫 bearer/token/cookie）
- 识别两类泄露：
  - 明文形态（Plain Shape）：例如 `sk-...`、`sk-ant-...`、`AIzaSy...`、`gsk_...`
  - 明文赋值（Plain Assignment）：例如 `OPENAI_API_KEY=...`
- 默认过滤，降低误报：
  - 路径过滤：跳过 `security-reports/`、`reports/`、`report/`、`example(s)/`、`sample(s)/`、`demo(s)/`、`test(s)/`、`mock(s)/`、`fixture(s)/`、`tmp/temp/` 等
  - 语境过滤：跳过包含 `example/sample/demo/mock/dummy/fake/placeholder/changeme/your_api_key` 等的行
  - Key 过滤：跳过明显占位值（如大量 `xxxxx/00000/abcdefghijklmnopqrstuvwxyz` 等）
- 输出：
  - `summary.txt`（简易统计）
  - `detail.txt`（详细位置：file:line + 类型）
  - 终端表格渲染（便于人看）
- **默认打码**：只在报告里输出 masked key，避免二次泄露

---

## Requirements / 依赖

- Linux / macOS shell（bash）
- 推荐安装：
  - `ripgrep (rg)`：更快更准（可选，没装会回退 grep）
  - `less`：分页查看（可选，没装回退 tail）

---

## Install / 安装

将 4 个脚本放到同一目录后执行：

```bash
# 1) 去掉 Windows CRLF（如果你在 Windows 上编辑过）
sed -i 's/\r$//' *.sh

# 2) 赋予可执行权限
chmod +x *.sh

# 3) 安装到 /usr/local/bin（需要 root）
sudo install -m 755 oc-skill-gate.sh /usr/local/bin/oc-skill-gate
sudo install -m 755 oc-skill-inventory.sh /usr/local/bin/oc-skill-inventory
sudo install -m 755 oc-secrets-audit.sh /usr/local/bin/oc-secrets-audit
sudo install -m 755 openclaw-security-check.sh /usr/local/bin/openclaw-security-check

# 4) 验证
command -v oc-skill-gate oc-skill-inventory oc-secrets-audit openclaw-security-check
