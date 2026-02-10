# OpenClaw Security Check (oc-sec)

OpenClaw 自托管环境的“傻瓜化安全巡检工具”：  
- ✅ Skill 安装前先审计（Gate）  
- ✅ 已安装 Skill 存量审计（Inventory：风险排序 + 支持隔离/删除/先备份）  
- ✅ API Key 明文泄露审计（仅扫 APIKey：形态+变量赋值；默认脱敏输出）

A fool-proof security audit toolkit for self-hosted OpenClaw:  
- ✅ Pre-install Skill audit (Gate)  
- ✅ Installed Skill inventory audit (Inventory: ranked summary + quarantine/delete with backup)  
- ✅ Plaintext API key leak audit (APIKey only: shape + assignment; masked by default)

> 注意 / Note  
> - 本工具是静态扫描（正则+规则）：输出是“线索告警”，不等于 100% 有漏洞。  
> - 报告默认脱敏（不会完整打印密钥），避免二次泄露。  
> - 适合 VPS/云主机一键巡检；也适合发布到 GitHub 给他人复用。

---

## 🚀 3 分钟上手（复制粘贴就能用） / 3-minute Quick Start

### 0) 前提 / Prerequisites
你已经能 `ssh root@你的VPS` 登录。  
You can already SSH into your VPS as root.

---

### 1) 一键安装（推荐） / One-shot install (recommended)

在 VPS 上复制粘贴：  
Copy & paste on your VPS:

```bash
set -euo pipefail
cd /tmp
rm -rf openclaw-security-check-openclaw-
git clone https://github.com/Pelican0126/openclaw-security-check-openclaw-.git
cd openclaw-security-check-openclaw-

# 如果你在 Windows 上编辑过脚本，去掉 CRLF（不影响则忽略）
sed -i 's/\r$//' ./*.sh || true

# 安装到 /usr/local/bin（需要 root）
install -m 755 oc-skill-gate.sh /usr/local/bin/oc-skill-gate
install -m 755 oc-skill-inventory.sh /usr/local/bin/oc-skill-inventory
install -m 755 oc-secrets-audit.sh /usr/local/bin/oc-secrets-audit
install -m 755 openclaw-security-check.sh /usr/local/bin/openclaw-security-check

echo "✅ Installed:"
command -v oc-skill-gate oc-skill-inventory oc-secrets-audit openclaw-security-check
```

---

### 2) 一键运行（傻瓜入口） / Run (menu entry)

```bash
openclaw-security-check
```

菜单含义 / Menu:
- `1` Skill Gate：安装前审计（输入 Git URL 或本地目录）  
- `2` Skill Inventory：已装审计（默认）  
- `3` APIKey Audit：仅 APIKey 明文泄露审计  
- `R` 退出  

---

### 3) 常用：只跑某一个模块 / Run a single module

```bash
oc-skill-gate        # 安装前审计（Gate）
oc-skill-inventory   # 已装 Skill 存量审计（Inventory）
oc-secrets-audit     # 仅 APIKey 明文泄露审计（APIKey only）
```

---

## ✅ 功能说明 / Features

### 1) `openclaw-security-check`（统一入口 / Unified entry）
- 交互菜单，一键选模块
- 默认选择 Inventory（适合日常巡检）

### 2) `oc-skill-gate`（安装前安全闸口 / Pre-install gate）
- 输入 Git URL 或本地目录
- 自动创建临时工作区（避免污染原目录）
- 自动定位 `SKILL.md`（如果多个会让你选）
- 输出审计报告 + 风险等级（HIGH / MED / LOW）
- HIGH 风险会二次确认，避免误装

### 3) `oc-skill-inventory`（已装 Skill 存量审计 / Installed inventory）
- 自动探测 skills 目录（常见为 `~/.openclaw/workspace/skills`）
- 输出 `summary_sorted.tsv`（按 HIGH → MED → LOW 排序）
- 支持后续动作：
  - `V` 查看摘要
  - `Q` 隔离（移动到隔离区）
  - `D` 删除（删除前自动打包备份）

### 4) `oc-secrets-audit`（仅 APIKey 明文泄露审计 / APIKey-only audit）
- 只扫描 APIKey（不扫 bearer/token/cookie 等杂项）
- 识别两类泄露：
  - **形态命中**：例如 `sk-...`、`sk-ant-...`、`AIzaSy...`、`gsk_...`
  - **变量赋值语境**：例如 `OPENAI_API_KEY=...`
- 默认输出脱敏（masked），避免报告本身成为泄露源
- 输出 summary/detail 便于定位处理

---

## 🧠 结果怎么理解 / How to read results

### Risk 等级（Gate / Inventory） / Risk levels
- **HIGH**：命中高危信号（动态执行/混淆执行链、持久化/系统改动、敏感路径引用等）  
  建议：不要安装或立即隔离；人工复核代码。
- **MED**：命中中危信号（安装依赖链/安装钩子、超长 base64 等）  
  建议：查看报告定位触发点；确认依赖来源与安装脚本行为。
- **LOW**：未命中明显信号（不代表 100% 安全，只是未发现显著风险特征）

### APIKey 泄露审计（oc-secrets-audit） / APIKey audit
- 报告不会打印完整 key（默认脱敏）
- 建议处理流程：定位文件 → 立刻轮换 key → 删除明文 → 再跑一次确认

---

## 🔧 环境变量 / Environment variables

一般不用改。需要时可覆盖：  
Most users don’t need this; override only if necessary.

- `OC_HOME`：OpenClaw 根目录（默认 `~/.openclaw`）
- `REPORT_ROOT`：报告输出目录（默认 `$OC_HOME/security-reports`）
- `SKILLS_DIR`：skills 目录（Inventory 会自动探测；也可手动指定）
- `QUAR_DIR`：隔离目录（默认 `$OC_HOME/skills.quarantine`）

示例 / Example:
```bash
OC_HOME=/data/openclaw REPORT_ROOT=/data/reports oc-secrets-audit
SKILLS_DIR=/data/openclaw/workspace/skills oc-skill-inventory
```

---

## 🧯 一键卸载 / Uninstall

```bash
rm -f /usr/local/bin/oc-skill-gate \
      /usr/local/bin/oc-skill-inventory \
      /usr/local/bin/oc-secrets-audit \
      /usr/local/bin/openclaw-security-check
echo "✅ Uninstalled"
```

---

## 🛟 一键备份 / 一键回滚（防崩） / Backup & rollback

### 备份 / Backup（先做 / run first）
```bash
set -euo pipefail
BK="/root/oc-sec-backup-$(date +%F_%H%M%S)"; mkdir -p "$BK"
for f in oc-skill-gate oc-skill-inventory oc-secrets-audit openclaw-security-check; do
  if [ -f "/usr/local/bin/$f" ]; then cp -a "/usr/local/bin/$f" "$BK/$f"; fi
done
echo "✅ Backup saved to: $BK"
ls -lah "$BK" || true
```

### 回滚 / Rollback（把 BK 改成你上面打印出来的目录 / replace BK）
```bash
set -euo pipefail
BK="/root/oc-sec-backup-YYYY-MM-DD_HHMMSS"  # ← replace with your backup path

for f in oc-skill-gate oc-skill-inventory oc-secrets-audit openclaw-security-check; do
  if [ -f "$BK/$f" ]; then
    cp -a "$BK/$f" "/usr/local/bin/$f"
    chmod 755 "/usr/local/bin/$f"
    echo "RESTORED $f"
  else
    rm -f "/usr/local/bin/$f"
    echo "REMOVED $f (no backup)"
  fi
done
echo "✅ ROLLBACK DONE"
```

---

## ❓ FAQ / 常见问题

### 1) 为什么会误报？/ Why false positives?
静态规则扫描不可避免会误报：示例/占位符、文档里的 demo key、打码残留、随机字符串等都可能命中。  
建议：优先看“命中位置（文件+行号/上下文）”，再判断是否真实泄露。

### 2) 终端里出现 `(END)` 按键没反应？
那是 `less` 分页器：  
- `q` 退出  
- 空格下一页  
- `/` 搜索  
- `n` 下一个匹配

### 3) 我不想用 root 跑可以吗？
可以，原则上更安全。只要该用户能读到 OpenClaw 目录即可。  
安装到 `/usr/local/bin` 需要 root，但运行不一定需要。

---

## 🤝 Contributing / 贡献

欢迎 PR：  
- 增强规则（更多 key 前缀、更多供应链信号）  
- 降低误报（更好的白名单、语境识别）  
- 适配更多 OpenClaw 安装路径与技能布局
