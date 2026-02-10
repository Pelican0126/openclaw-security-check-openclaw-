# OpenClaw Security Check (oc-sec)

OpenClaw 自托管环境的“傻瓜化安全巡检工具”：  
- ✅ Skill 安装前先审计（Gate）  
- ✅ 已安装 Skill 存量审计（Inventory，支持隔离/删除/先备份）  
- ✅ API Key 明文泄露审计（只扫 APIKey，默认脱敏输出）  

A fool-proof security audit toolkit for self-hosted OpenClaw:  
- ✅ Pre-install Skill audit (Gate)  
- ✅ Installed Skill inventory audit (Inventory, with quarantine/delete + backup)  
- ✅ Plaintext API key leak audit (APIKey only, masked by default)

> 注意 / Note  
> - 这是静态扫描（正则+规则）：结果是“线索告警”，不等于 100% 有漏洞。  
> - 报告默认脱敏（不会完整打印密钥），避免二次泄露。

---

## 🚀 3 分钟上手（复制粘贴就能用）

### 0) 前提 / Prerequisites
你已经能 `ssh root@你的VPS` 登录。  
You can already SSH into your VPS as root.

---

### 1) 一键安装 / One-shot install (recommended)

在 VPS 上复制粘贴：  
Copy & paste on your VPS:

```bash
set -euo pipefail
cd /tmp
rm -rf openclaw-security-check-openclaw-
git clone https://github.com/Pelican0126/openclaw-security-check-openclaw-.git
cd openclaw-security-check-openclaw-

# 如果在 Windows 编辑过脚本，先去掉 CRLF
sed -i 's/\r$//' ./*.sh || true

# 安装到 /usr/local/bin（需要 root）
install -m 755 oc-skill-gate.sh /usr/local/bin/oc-skill-gate
install -m 755 oc-skill-inventory.sh /usr/local/bin/oc-skill-inventory
install -m 755 oc-secrets-audit.sh /usr/local/bin/oc-secrets-audit
install -m 755 openclaw-security-check.sh /usr/local/bin/openclaw-security-check

echo "✅ Installed:"
command -v oc-skill-gate oc-skill-inventory oc-secrets-audit openclaw-security-check
